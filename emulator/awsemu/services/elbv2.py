"""Elastic Load Balancing v2 (Application Load Balancer, Query プロトコル)。

- ALB は VPC 内に ENI (サブネットごと) とセキュリティグループを持つ実体として動く (linux データプレーン時)
- ヘルスチェックは ALB の名前空間から実際に HTTP で行い、ターゲットの状態と理由コードを本物と同じ形で返す
- リクエストごとに AWS/ApplicationELB メトリクスとアクセスログ (S3) を出力する
"""
from __future__ import annotations

import fnmatch
import gzip
import ipaddress
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Identity, Metric, Request
from ..iam_policy import evaluate
from ..netplane.alb import AlbListener, ProxyResult, health_check
from ._query import QueryService

ELB_ACCOUNT = "582318560864"   # ap-northeast-1 の ELB アカウント (アクセスログのバケットポリシーで使う)
LOG_FLUSH_SECONDS = float(os.environ.get("AWSEMU_ELB_LOG_FLUSH_SECONDS", "60"))
DEFAULT_LB_ATTRS = {
    "idle_timeout.timeout_seconds": "60", "deletion_protection.enabled": "false",
    "access_logs.s3.enabled": "false", "access_logs.s3.bucket": "", "access_logs.s3.prefix": "",
    "routing.http.drop_invalid_header_fields.enabled": "false", "routing.http2.enabled": "true",
    "load_balancing.cross_zone.enabled": "true",
}
DEFAULT_TG_ATTRS = {
    "deregistration_delay.timeout_seconds": "300", "stickiness.enabled": "false", "stickiness.type": "lb_cookie",
    "load_balancing.algorithm.type": "round_robin", "slow_start.duration_seconds": "0",
}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def hexid(n: int = 16) -> str:
    return secrets.token_hex(n // 2)


def invalid(msg: str) -> AwsError:
    return AwsError("ValidationError", msg)


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@dataclass
class Target:
    id: str
    port: int
    az: str | None = None
    state: str = "initial"
    reason: str | None = "Elb.RegistrationInProgress"
    description: str | None = "Target registration is in progress"
    ok_streak: int = 0
    fail_streak: int = 0
    next_check: float = 0.0
    drain_until: float | None = None


@dataclass
class TargetGroup:
    arn: str
    name: str
    protocol: str
    port: int
    vpc_id: str
    target_type: str
    hc: dict[str, Any]
    attrs: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TG_ATTRS))
    targets: dict[str, Target] = field(default_factory=dict)       # "id:port" -> Target
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def dim(self) -> str:
        return "targetgroup/" + self.arn.split(":targetgroup/", 1)[1]


@dataclass
class Listener:
    arn: str
    lb_arn: str
    port: int
    protocol: str
    default_actions: list[dict[str, Any]]
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)  # rule arn -> {priority, conditions, actions}


@dataclass
class LoadBalancer:
    arn: str
    name: str
    scheme: str
    vpc_id: str
    subnets: list[str]
    sg_ids: list[str]
    created: float
    dns: str
    eni_ids: list[str] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_LB_ATTRS))
    tags: dict[str, str] = field(default_factory=dict)
    access_log_buffer: list[str] = field(default_factory=list)

    @property
    def lb_id(self) -> str:
        return self.arn.rsplit("/", 1)[-1]

    @property
    def dim(self) -> str:
        return "app/" + self.arn.split(":loadbalancer/app/", 1)[1]

    @property
    def host_id(self) -> str:
        return f"elb-{self.lb_id[:12]}"


class ELBv2(QueryService):
    name = "elbv2"
    iam_prefix = "elasticloadbalancing"
    event_source = "elasticloadbalancing.amazonaws.com"
    xml_namespace = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"
    version = "2015-12-01"

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.listeners_dp: dict[str, AlbListener] = {}
        self._checker: threading.Thread | None = None
        self._stop = threading.Event()
        self.reset_state()

    def reset_state(self) -> None:
        self.lbs: dict[str, LoadBalancer] = {}
        self.tgs: dict[str, TargetGroup] = {}
        self.listeners: dict[str, Listener] = {}
        self.last_flush = time.monotonic()

    def reset(self) -> None:
        with self.lock:
            for lb in list(self.lbs.values()):
                self._teardown(lb)
            self.reset_state()

    @property
    def ec2(self):
        return self.emu.services["ec2"]

    def region(self) -> str:
        return "ap-northeast-1"

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        p = self.params(req)
        arn = p.get("LoadBalancerArn") or p.get("TargetGroupArn") or p.get("ListenerArn") or "*"
        return [(f"elasticloadbalancing:{op}", arn)]

    # ================================================================== lookups
    def _lb(self, arn: str | None) -> LoadBalancer:
        lb = self.lbs.get(arn or "")
        if lb is None:
            raise AwsError("LoadBalancerNotFound", f"Load balancers '[{arn}]' not found")
        return lb

    def _tg(self, arn: str | None) -> TargetGroup:
        tg = self.tgs.get(arn or "")
        if tg is None:
            raise AwsError("TargetGroupNotFound", f"Target groups '[{arn}]' not found")
        return tg

    def _listener(self, arn: str | None) -> Listener:
        lst = self.listeners.get(arn or "")
        if lst is None:
            raise AwsError("ListenerNotFound", f"Listeners '[{arn}]' not found")
        return lst

    def _tg_lbs(self, tg: TargetGroup) -> list[LoadBalancer]:
        arns = set()
        for lst in self.listeners.values():
            actions = list(lst.default_actions) + [a for r in lst.rules.values() for a in r["actions"]]
            if any(tg.arn in self._action_groups(a) for a in actions):
                arns.add(lst.lb_arn)
        return [self.lbs[a] for a in arns if a in self.lbs]

    @staticmethod
    def _action_groups(action: dict[str, Any]) -> list[str]:
        if action.get("TargetGroupArn"):
            return [action["TargetGroupArn"]]
        fc = action.get("ForwardConfig") or {}
        return [g["TargetGroupArn"] for g in as_list(fc.get("TargetGroups"))]

    def dns_records(self, vpc_id: str) -> dict[str, list[str]]:
        """インスタンスの hosts ファイル用: ALB の DNS 名 -> IP。"""
        out = {}
        for lb in self.lbs.values():
            enis = [self.ec2.enis[e] for e in lb.eni_ids if e in self.ec2.enis]
            if lb.scheme == "internet-facing":
                out[lb.dns] = [e.public_ip for e in enis if e.public_ip]
            elif lb.vpc_id == vpc_id:
                out[lb.dns] = [e.private_ip for e in enis]
        return out

    # ================================================================== data plane
    def _provision(self, lb: LoadBalancer) -> None:
        ec2 = self.ec2
        with ec2.lock:
            for i, sid in enumerate(lb.subnets):
                subnet = ec2.subnets[sid]
                eni = ec2.create_eni(subnet, lb.sg_ids, f"ELB {lb.dim}", requester_managed=True)
                lb.eni_ids.append(eni.id)
                if lb.scheme == "internet-facing":
                    ec2.assign_public_ip(eni)
                if ec2.netplane.enabled:
                    if i == 0:
                        ec2.netplane.ensure_host(lb.host_id)
                    ec2.attach_eni_dataplane(eni, lb.host_id, device=f"eth{i}", default_route=(i == 0))
                    if i > 0:
                        # 2 本目以降の ENI からの応答は、その ENI のサブネットのゲートウェイから出す
                        ec2.netplane.source_route(lb.host_id, f"eth{i}", eni.private_ip, subnet.gateway, subnet.cidr,
                                                  100 + i)
                else:
                    eni.owner = lb.host_id
            ec2.sync_security(lb.vpc_id)
            ec2.sync_vpc(ec2.vpcs[lb.vpc_id])
            if ec2.flowlogs_collector:
                ec2.flowlogs_collector.refresh()
        ec2.refresh_dns()

    def _teardown(self, lb: LoadBalancer) -> None:
        for arn in [a for a, lst in self.listeners.items() if lst.lb_arn == lb.arn]:
            self._stop_listener(arn)
        ec2 = self.ec2
        with ec2.lock:
            ec2.netplane.delete_host(lb.host_id)
            for eid in lb.eni_ids:
                if eid in ec2.enis:
                    ec2.delete_eni(ec2.enis[eid])
            if lb.vpc_id in ec2.vpcs:
                ec2.sync_vpc(ec2.vpcs[lb.vpc_id])
        ec2.refresh_dns()

    def _start_listener(self, lst: Listener) -> None:
        lb = self.lbs[lst.lb_arn]
        if not self.ec2.netplane.enabled or lst.arn in self.listeners_dp:
            return
        arn = lst.arn

        def router(method: str, path: str, headers: dict[str, str], port: int) -> dict[str, Any]:
            with self.lock:
                return self._route(arn, method, path, headers)

        def reporter(result: ProxyResult, info: dict[str, Any]) -> None:
            with self.lock:
                self._report(lb.arn, result, info)
        dp = AlbListener(self.ec2.netplane.host_ns(lb.host_id), lst.port, router, reporter)
        dp.start()
        self.listeners_dp[arn] = dp

    def _stop_listener(self, arn: str) -> None:
        dp = self.listeners_dp.pop(arn, None)
        if dp:
            dp.stop()

    def _target_ip(self, tg: TargetGroup, t: Target) -> tuple[str | None, str | None]:
        """(IP, AZ) を返す。インスタンスが動いていなければ IP は None。"""
        ec2 = self.ec2
        if tg.target_type == "ip":
            subnet = next((s for s in ec2.subnets.values() if s.vpc_id == tg.vpc_id and
                           ipaddress.ip_address(t.id) in s.net), None)
            return t.id, subnet.az if subnet else None
        inst = ec2.instances.get(t.id)
        if inst is None:
            return None, None
        ec2._refresh(inst)
        eni = ec2.enis.get(inst.eni_id)
        az = ec2.subnets[inst.subnet_id].az if inst.subnet_id in ec2.subnets else None
        if inst.state not in ("running",) or eni is None:
            return None, az
        return eni.private_ip, az

    def _route(self, listener_arn: str, method: str, path: str, headers: dict[str, str]) -> dict[str, Any]:
        lst = self.listeners.get(listener_arn)
        trace = f"Root=1-{int(time.time()):08x}-{hexid(24)}"
        if lst is None:
            return {"type": "fixed-response", "status": 503, "trace_id": trace}
        lb = self.lbs[lst.lb_arn]
        actions, priority = lst.default_actions, "default"
        host = headers.get("Host", "").split(":", 1)[0]
        for rule in sorted(lst.rules.values(), key=lambda r: int(r["priority"])):
            if self._conditions_match(rule["conditions"], host, path.split("?", 1)[0], headers):
                actions, priority = rule["actions"], str(rule["priority"])
                break
        action = sorted(actions, key=lambda a: int(a.get("Order", 1)))[-1]
        base = {"trace_id": trace, "rule_priority": priority, "idle_timeout": lb.attrs["idle_timeout.timeout_seconds"]}
        kind = action.get("Type")
        if kind == "fixed-response":
            cfg = action.get("FixedResponseConfig") or {}
            return {**base, "type": "fixed-response", "status": int(cfg.get("StatusCode", 503)),
                    "body": cfg.get("MessageBody", ""), "content_type": cfg.get("ContentType", "text/plain")}
        if kind == "redirect":
            cfg = action.get("RedirectConfig") or {}
            loc = f"{cfg.get('Protocol', 'https').lower()}://{cfg.get('Host', host).replace('#{host}', host)}" \
                  f":{cfg.get('Port', '443')}{cfg.get('Path', '/#{path}').replace('#{path}', path.lstrip('/'))}"
            return {**base, "type": "redirect", "location": loc,
                    "status": 301 if cfg.get("StatusCode") == "HTTP_301" else 302}
        groups = self._action_groups(action)
        tg = self.tgs.get(groups[0]) if groups else None
        if tg is None:
            return {**base, "type": "forward", "targets": [], "target_group": None}
        lb_azs = {self.ec2.subnets[s].az for s in lb.subnets if s in self.ec2.subnets}
        candidates, healthy = [], []
        for t in tg.targets.values():
            if t.state in ("draining", "unused"):
                continue
            ip, az = self._target_ip(tg, t)
            if ip is None or (az and az not in lb_azs):
                continue
            port = t.port
            candidates.append((ip, port, tg.arn))
            if t.state == "healthy":
                healthy.append((ip, port, tg.arn))
        # 正常なターゲットが 1 つも無いときは、登録済みの全ターゲットに振り分ける (フェイルオープン)
        return {**base, "type": "forward", "targets": healthy or candidates, "target_group": tg.arn}

    @staticmethod
    def _conditions_match(conditions: list[dict[str, Any]], host: str, path: str, headers: dict[str, str]) -> bool:
        for c in conditions:
            fld = c.get("Field")
            if fld == "path-pattern":
                values = as_list((c.get("PathPatternConfig") or {}).get("Values")) or as_list(c.get("Values"))
                if not any(fnmatch.fnmatchcase(path, v) for v in values):
                    return False
            elif fld == "host-header":
                values = as_list((c.get("HostHeaderConfig") or {}).get("Values")) or as_list(c.get("Values"))
                if not any(fnmatch.fnmatch(host.lower(), v.lower()) for v in values):
                    return False
            elif fld == "http-header":
                cfg = c.get("HttpHeaderConfig") or {}
                actual = headers.get(cfg.get("HttpHeaderName", ""), "")
                if not any(fnmatch.fnmatch(actual, v) for v in as_list(cfg.get("Values"))):
                    return False
            elif fld == "http-request-method":
                cfg = c.get("HttpRequestMethodConfig") or {}
                if headers.get(":method") and headers[":method"] not in as_list(cfg.get("Values")):
                    return False
        return True

    # ================================================================== metrics / access logs
    def _report(self, lb_arn: str, r: ProxyResult, info: dict[str, Any]) -> None:
        lb = self.lbs.get(lb_arn)
        if lb is None:
            return
        cw = self.emu.services["cloudwatch"]
        lbdim = {"LoadBalancer": lb.dim}
        tg = self.tgs.get(r.target_group or "")
        metrics = [Metric("AWS/ApplicationELB", "RequestCount", 1.0, lbdim, "Count"),
                   Metric("AWS/ApplicationELB", "ProcessedBytes", float(r.received + r.sent), lbdim, "Bytes")]
        if tg:
            metrics.append(Metric("AWS/ApplicationELB", "RequestCount", 1.0,
                                  {"TargetGroup": tg.dim, "LoadBalancer": lb.dim}, "Count"))
        if r.target_status is None and r.elb_status >= 500:
            metrics += [Metric("AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", 1.0, lbdim, "Count"),
                        Metric("AWS/ApplicationELB", f"HTTPCode_ELB_{r.elb_status}_Count", 1.0, lbdim, "Count")]
            if r.error_reason in ("TargetConnectionError", "TargetConnectionTimeout"):
                metrics.append(Metric("AWS/ApplicationELB", "TargetConnectionErrorCount", 1.0, lbdim, "Count"))
        elif r.target_status is None and r.elb_status >= 400:
            metrics.append(Metric("AWS/ApplicationELB", "HTTPCode_ELB_4XX_Count", 1.0, lbdim, "Count"))
        if r.target_status is not None and tg:
            cls = f"HTTPCode_Target_{r.target_status // 100}XX_Count"
            for dims in (lbdim, {"TargetGroup": tg.dim, "LoadBalancer": lb.dim}):
                metrics.append(Metric("AWS/ApplicationELB", cls, 1.0, dims, "Count"))
                metrics.append(Metric("AWS/ApplicationELB", "TargetResponseTime", r.target_time, dims, "Seconds"))
        cw.ingest(metrics)
        if lb.attrs.get("access_logs.s3.enabled") == "true":
            now = self.clock.now()
            created = now - max(0.0, r.request_time + max(r.target_time, 0) + max(r.response_time, 0))
            fmt = lambda v: "-1" if v < 0 else f"{v:.3f}"  # noqa: E731
            lb.access_log_buffer.append(" ".join([
                "http", iso(now), lb.dim, info["client"], r.target or "-", fmt(r.request_time), fmt(r.target_time),
                fmt(r.response_time), str(r.elb_status), str(r.target_status) if r.target_status else "-",
                str(info["received"]), str(r.sent), f"\"{info['request_line']}\"", f"\"{info['user_agent']}\"",
                "-", "-", r.target_group or "-", f"\"{info['trace_id']}\"", "\"-\"", "\"-\"",
                r.rule_priority if r.rule_priority != "default" else "0", iso(created), f"\"{r.action}\"", "\"-\"",
                f"\"{r.error_reason or '-'}\"", f"\"{r.target or '-'}\"",
                f"\"{r.target_status if r.target_status else '-'}\"", "\"-\"", "\"-\"", f"TID_{hexid(32)}"]))
        if time.monotonic() - self.last_flush >= LOG_FLUSH_SECONDS:
            self.flush_access_logs()

    def flush_access_logs(self) -> None:
        self.last_flush = time.monotonic()
        s3 = self.emu.services["s3"]
        for lb in self.lbs.values():
            if not lb.access_log_buffer:
                continue
            lines, lb.access_log_buffer = lb.access_log_buffer, []
            stamp = datetime.fromtimestamp(self.clock.now(), timezone.utc)
            prefix = lb.attrs.get("access_logs.s3.prefix") or ""
            ip_ = "0.0.0.0"
            if lb.eni_ids and lb.eni_ids[0] in self.ec2.enis:
                ip_ = self.ec2.enis[lb.eni_ids[0]].private_ip
            key = (f"{prefix + '/' if prefix else ''}AWSLogs/{ACCOUNT_ID}/elasticloadbalancing/{self.region()}/"
                   f"{stamp:%Y/%m/%d}/{ACCOUNT_ID}_elasticloadbalancing_{self.region()}_{lb.dim.replace('/', '.')}_"
                   f"{stamp:%Y%m%dT%H%M}Z_{ip_}_{hexid(8)}.log.gz")
            s3.put_internal(lb.attrs["access_logs.s3.bucket"], key, gzip.compress(("\n".join(lines) + "\n").encode()),
                            "application/octet-stream")

    def gauges(self) -> list[Metric]:
        with self.lock:
            self.run_health_checks()
            if time.monotonic() - self.last_flush >= LOG_FLUSH_SECONDS:
                self.flush_access_logs()
            out = []
            for tg in self.tgs.values():
                for lb in self._tg_lbs(tg):
                    healthy = sum(1 for t in tg.targets.values() if t.state == "healthy")
                    unhealthy = sum(1 for t in tg.targets.values() if t.state == "unhealthy")
                    dims = {"TargetGroup": tg.dim, "LoadBalancer": lb.dim}
                    out += [Metric("AWS/ApplicationELB", "HealthyHostCount", float(healthy), dims, "Count"),
                            Metric("AWS/ApplicationELB", "UnHealthyHostCount", float(unhealthy), dims, "Count")]
            return out

    # ================================================================== health checks
    def start_checker(self) -> None:
        if self._checker is not None:
            return

        def loop() -> None:
            while not self._stop.wait(1.0):
                try:
                    self.run_health_checks()
                except Exception as exc:  # noqa: BLE001
                    print(f"[elbv2] health check error: {exc!r}")
        self._checker = threading.Thread(target=loop, name="elb-health", daemon=True)
        self._checker.start()

    def run_health_checks(self) -> None:
        """エミュレータの時計で interval ごとにヘルスチェックする。時計を進めた場合は経過回数ぶん結果を反映する。"""
        now = self.clock.now()
        jobs = []
        with self.lock:
            for tg in self.tgs.values():
                lbs = self._tg_lbs(tg)
                lb_azs = {self.ec2.subnets[s].az for lb in lbs for s in lb.subnets if s in self.ec2.subnets}
                for t in list(tg.targets.values()):
                    if t.state == "draining":
                        if t.drain_until is not None and now >= t.drain_until:
                            del tg.targets[f"{t.id}:{t.port}"]
                        continue
                    if not lbs:
                        self._set(t, "unused", "Target.NotInUse", "Target group is not configured to receive "
                                  "traffic from the load balancer")
                        continue
                    ip, az = self._target_ip(tg, t)
                    if ip is None:
                        self._set(t, "unused", "Target.InvalidState", "Target is in the stopped state")
                        continue
                    if az and az not in lb_azs:
                        self._set(t, "unused", "Target.NotInUse", "Target is in an Availability Zone that is not "
                                  "enabled for the load balancer")
                        continue
                    if t.state == "unused":
                        self._set(t, "initial", "Elb.InitialHealthChecking", "Initial health checks in progress")
                        t.ok_streak = t.fail_streak = 0
                        t.next_check = now
                    if now >= t.next_check:
                        interval = int(tg.hc["HealthCheckIntervalSeconds"])
                        times = 1 + int((now - t.next_check) // interval)
                        t.next_check = now + interval
                        jobs.append((tg, t, ip, lbs[0], times))
        for tg, t, ip, lb, times in jobs:
            result = self._check(tg, t, ip, lb)
            with self.lock:
                self._apply(tg, t, result, times)

    def _check(self, tg: TargetGroup, t: Target, ip: str, lb: LoadBalancer):
        from ..netplane.alb import HealthResult
        if not tg.hc.get("HealthCheckEnabled", True):
            return HealthResult(True)
        if not self.ec2.netplane.enabled:
            return HealthResult(True)  # データプレーンなし: 稼働中のインスタンスは正常とみなす
        port = t.port if tg.hc["HealthCheckPort"] == "traffic-port" else int(tg.hc["HealthCheckPort"])
        return health_check(self.ec2.netplane.host_ns(lb.host_id), ip, port, tg.hc["HealthCheckPath"],
                            float(tg.hc["HealthCheckTimeoutSeconds"]), tg.hc["Matcher"]["HttpCode"])

    def _apply(self, tg: TargetGroup, t: Target, result, times: int) -> None:
        if f"{t.id}:{t.port}" not in tg.targets or t.state in ("draining", "unused"):
            return
        healthy_n, unhealthy_n = int(tg.hc["HealthyThresholdCount"]), int(tg.hc["UnhealthyThresholdCount"])
        if result.ok:
            t.ok_streak, t.fail_streak = t.ok_streak + times, 0
            if t.state != "healthy" and t.ok_streak >= healthy_n:
                self._set(t, "healthy", None, None)
        else:
            t.fail_streak, t.ok_streak = t.fail_streak + times, 0
            if t.state != "unhealthy" and t.fail_streak >= unhealthy_n:
                self._set(t, "unhealthy", result.reason, result.description)
            elif t.state == "unhealthy":
                t.reason, t.description = result.reason, result.description

    @staticmethod
    def _set(t: Target, state: str, reason: str | None, description: str | None) -> None:
        t.state, t.reason, t.description = state, reason, description

    # ================================================================== load balancers
    def _lb_view(self, lb: LoadBalancer) -> dict[str, Any]:
        self._refresh_lb(lb)
        ec2 = self.ec2
        azs = []
        for sid, eid in zip(lb.subnets, lb.eni_ids):
            s = ec2.subnets.get(sid)
            eni = ec2.enis.get(eid)
            az: dict[str, Any] = {"ZoneName": s.az if s else "", "SubnetId": sid}
            if eni:
                az["LoadBalancerAddresses"] = [{"IpAddress": eni.public_ip}] if eni.public_ip else []
            azs.append(az)
        return {"LoadBalancerArn": lb.arn, "DNSName": lb.dns, "CanonicalHostedZoneId": "Z14GRHDCWA56QT",
                "CreatedTime": iso(lb.created), "LoadBalancerName": lb.name, "Scheme": lb.scheme, "VpcId": lb.vpc_id,
                "State": {"Code": lb.attrs.get("_state", "active")}, "Type": "application",
                "AvailabilityZones": azs, "SecurityGroups": lb.sg_ids, "IpAddressType": "ipv4"}

    def _refresh_lb(self, lb: LoadBalancer) -> None:
        if lb.attrs.get("_state") == "provisioning" and self.clock.now() >= lb.created + 3:
            lb.attrs["_state"] = "active"

    def op_CreateLoadBalancer(self, p, req):
        name = p.get("Name", "")
        if not name or len(name) > 32 or name.startswith("internal-") or not all(c.isalnum() or c == "-" for c in name):
            raise invalid(f"Load balancer name '{name}' is invalid")
        if p.get("Type", "application") != "application":
            raise invalid("awsemu supports only application load balancers")
        for lb in self.lbs.values():
            if lb.name == name:
                raise AwsError("DuplicateLoadBalancerName", f"A load balancer with the same name '{name}' exists, "
                               "but with different settings")
        ec2 = self.ec2
        subnet_ids = as_list(p.get("Subnets")) or [m.get("SubnetId") for m in as_list(p.get("SubnetMappings"))]
        subnets = []
        for sid in subnet_ids:
            if sid not in ec2.subnets:
                raise AwsError("SubnetNotFound", f"The subnet ID '{sid}' is not valid")
            subnets.append(ec2.subnets[sid])
        if len({s.az for s in subnets}) < 2:
            raise invalid("At least two subnets in two different Availability Zones must be specified")
        if len({s.az for s in subnets}) != len(subnets):
            raise invalid("You cannot specify multiple subnets in the same Availability Zone")
        vpc_id = subnets[0].vpc_id
        if any(s.vpc_id != vpc_id for s in subnets):
            raise invalid("The subnets must be in the same VPC")
        scheme = p.get("Scheme", "internet-facing")
        if scheme == "internet-facing" and not ec2.vpcs[vpc_id].igw:
            raise AwsError("InvalidSubnet", f"VPC {vpc_id} has no internet gateway")
        sgs = as_list(p.get("SecurityGroups")) or [ec2.vpcs[vpc_id].default_sg]
        for g in sgs:
            if g not in ec2.sgs or ec2.sgs[g].vpc_id != vpc_id:
                raise AwsError("InvalidSecurityGroup", f"One or more security groups are invalid: {g}")
        lb_id = hexid(16)
        dns_prefix = "internal-" if scheme == "internal" else ""
        lb = LoadBalancer(f"arn:aws:elasticloadbalancing:{self.region()}:{ACCOUNT_ID}:loadbalancer/app/{name}/{lb_id}",
                          name, scheme, vpc_id, [s.id for s in subnets], sgs, self.clock.now(),
                          f"{dns_prefix}{name}-{int(lb_id[:8], 16) % 10**10}.{self.region()}.elb.amazonaws.com",
                          tags={t["Key"]: t.get("Value", "") for t in as_list(p.get("Tags"))})
        lb.attrs["_state"] = "provisioning"
        self.lbs[lb.arn] = lb
        self._provision(lb)
        return {"LoadBalancers": [self._lb_view(lb)]}

    def op_DescribeLoadBalancers(self, p, req):
        arns, names = as_list(p.get("LoadBalancerArns")), as_list(p.get("Names"))
        items = list(self.lbs.values())
        if arns:
            items = [self._lb(a) for a in arns]
        if names:
            missing = [n for n in names if n not in {lb.name for lb in self.lbs.values()}]
            if missing:
                raise AwsError("LoadBalancerNotFound", f"Load balancers '[{missing[0]}]' not found")
            items = [lb for lb in items if lb.name in names]
        return {"LoadBalancers": [self._lb_view(lb) for lb in items]}

    def op_DeleteLoadBalancer(self, p, req):
        lb = self._lb(p.get("LoadBalancerArn"))
        if lb.attrs.get("deletion_protection.enabled") == "true":
            raise AwsError("OperationNotPermitted", f"Load balancer '{lb.arn}' cannot be deleted because deletion "
                           "protection is enabled")
        self._teardown(lb)
        for arn in [a for a, lst in self.listeners.items() if lst.lb_arn == lb.arn]:
            del self.listeners[arn]
        del self.lbs[lb.arn]
        return {}

    def op_SetSecurityGroups(self, p, req):
        lb = self._lb(p.get("LoadBalancerArn"))
        sgs = as_list(p.get("SecurityGroups"))
        ec2 = self.ec2
        for g in sgs:
            if g not in ec2.sgs:
                raise AwsError("InvalidSecurityGroup", f"One or more security groups are invalid: {g}")
        lb.sg_ids = sgs
        with ec2.lock:
            for eid in lb.eni_ids:
                if eid in ec2.enis:
                    ec2.enis[eid].sg_ids = list(sgs)
            ec2.sync_security(lb.vpc_id)
        return {"SecurityGroupIds": sgs}

    def _attrs_view(self, attrs: dict[str, str]) -> list[dict[str, str]]:
        return [{"Key": k, "Value": v} for k, v in attrs.items() if not k.startswith("_")]

    def op_DescribeLoadBalancerAttributes(self, p, req):
        return {"Attributes": self._attrs_view(self._lb(p.get("LoadBalancerArn")).attrs)}

    def op_ModifyLoadBalancerAttributes(self, p, req):
        lb = self._lb(p.get("LoadBalancerArn"))
        new = {a["Key"]: str(a.get("Value", "")) for a in as_list(p.get("Attributes"))}
        for k in new:
            if k not in DEFAULT_LB_ATTRS:
                raise invalid(f"Load balancer attribute key '{k}' is not recognized")
        merged = {**lb.attrs, **new}
        if merged.get("access_logs.s3.enabled") == "true":
            self._check_log_bucket(merged.get("access_logs.s3.bucket", ""), merged.get("access_logs.s3.prefix", ""))
        lb.attrs = merged
        return {"Attributes": self._attrs_view(lb.attrs)}

    def _check_log_bucket(self, bucket: str, prefix: str) -> None:
        s3 = self.emu.services["s3"]
        if bucket not in s3.buckets:
            raise AwsError("InvalidConfigurationRequest", f"The value of 'access_logs.s3.bucket' is not valid: {bucket}")
        policy = s3.resource_policy(f"arn:aws:s3:::{bucket}")
        key = f"arn:aws:s3:::{bucket}/{prefix + '/' if prefix else ''}AWSLogs/{ACCOUNT_ID}/x.log.gz"
        principals = [Identity("AWSService", "logdelivery.elasticloadbalancing.amazonaws.com", "elb"),
                      Identity("IAMUser", f"arn:aws:iam::{ELB_ACCOUNT}:root", ELB_ACCOUNT, account=ELB_ACCOUNT)]
        if not policy or not any(evaluate(pr, [], policy, "s3:PutObject", key, {}).allowed for pr in principals):
            raise AwsError("InvalidConfigurationRequest", f"Access Denied for bucket: {bucket}. Please check "
                           "S3bucket permission")

    # ================================================================== target groups
    def _tg_view(self, tg: TargetGroup) -> dict[str, Any]:
        return {"TargetGroupArn": tg.arn, "TargetGroupName": tg.name, "Protocol": tg.protocol, "Port": tg.port,
                "VpcId": tg.vpc_id, "TargetType": tg.target_type, "ProtocolVersion": "HTTP1",
                "IpAddressType": "ipv4", "LoadBalancerArns": [lb.arn for lb in self._tg_lbs(tg)],
                **{k: v for k, v in tg.hc.items()}}

    def op_CreateTargetGroup(self, p, req):
        name = p.get("Name", "")
        if not name or len(name) > 32:
            raise invalid(f"Target group name '{name}' is invalid")
        if any(tg.name == name for tg in self.tgs.values()):
            raise AwsError("DuplicateTargetGroupName", "A target group with the same name '" + name + "' exists, "
                           "but with different settings")
        target_type = p.get("TargetType", "instance")
        if target_type not in ("instance", "ip"):
            raise invalid("awsemu supports target types 'instance' and 'ip'")
        vpc_id = p.get("VpcId")
        if vpc_id not in self.ec2.vpcs:
            raise invalid(f"The VPC ID '{vpc_id}' is not found")
        protocol = p.get("Protocol", "HTTP")
        if protocol not in ("HTTP",):
            raise invalid("awsemu supports only HTTP target groups")
        hc = {"HealthCheckProtocol": p.get("HealthCheckProtocol", "HTTP"),
              "HealthCheckPort": p.get("HealthCheckPort", "traffic-port"),
              "HealthCheckEnabled": str(p.get("HealthCheckEnabled", "true")).lower() == "true",
              "HealthCheckIntervalSeconds": int(p.get("HealthCheckIntervalSeconds", 30)),
              "HealthCheckTimeoutSeconds": int(p.get("HealthCheckTimeoutSeconds", 5)),
              "HealthyThresholdCount": int(p.get("HealthyThresholdCount", 5)),
              "UnhealthyThresholdCount": int(p.get("UnhealthyThresholdCount", 2)),
              "HealthCheckPath": p.get("HealthCheckPath", "/"),
              "Matcher": {"HttpCode": (p.get("Matcher") or {}).get("HttpCode", "200")}}
        if hc["HealthCheckTimeoutSeconds"] >= hc["HealthCheckIntervalSeconds"]:
            raise invalid("Health check interval must be greater than the timeout.")
        tg = TargetGroup(f"arn:aws:elasticloadbalancing:{self.region()}:{ACCOUNT_ID}:targetgroup/{name}/{hexid(16)}",
                         name, protocol, int(p.get("Port", 80)), vpc_id, target_type, hc,
                         tags={t["Key"]: t.get("Value", "") for t in as_list(p.get("Tags"))})
        self.tgs[tg.arn] = tg
        return {"TargetGroups": [self._tg_view(tg)]}

    def op_DescribeTargetGroups(self, p, req):
        items = list(self.tgs.values())
        if p.get("TargetGroupArns"):
            items = [self._tg(a) for a in as_list(p["TargetGroupArns"])]
        if p.get("Names"):
            items = [tg for tg in items if tg.name in as_list(p["Names"])]
        if p.get("LoadBalancerArn"):
            lb = self._lb(p["LoadBalancerArn"])
            items = [tg for tg in items if lb in self._tg_lbs(tg)]
        return {"TargetGroups": [self._tg_view(tg) for tg in items]}

    def op_ModifyTargetGroup(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        for key in ("HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath"):
            if p.get(key):
                tg.hc[key] = p[key]
        for key in ("HealthCheckIntervalSeconds", "HealthCheckTimeoutSeconds", "HealthyThresholdCount",
                    "UnhealthyThresholdCount"):
            if p.get(key):
                tg.hc[key] = int(p[key])
        if p.get("HealthCheckEnabled") is not None:
            tg.hc["HealthCheckEnabled"] = str(p["HealthCheckEnabled"]).lower() == "true"
        if (p.get("Matcher") or {}).get("HttpCode"):
            tg.hc["Matcher"] = {"HttpCode": p["Matcher"]["HttpCode"]}
        return {"TargetGroups": [self._tg_view(tg)]}

    def op_DeleteTargetGroup(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        if self._tg_lbs(tg):
            raise AwsError("ResourceInUse", f"Target group '{tg.arn}' is currently in use by a listener or a rule")
        del self.tgs[tg.arn]
        return {}

    def op_DescribeTargetGroupAttributes(self, p, req):
        return {"Attributes": self._attrs_view(self._tg(p.get("TargetGroupArn")).attrs)}

    def op_ModifyTargetGroupAttributes(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        for a in as_list(p.get("Attributes")):
            if a["Key"] not in DEFAULT_TG_ATTRS:
                raise invalid(f"Target group attribute key '{a['Key']}' is not recognized")
            tg.attrs[a["Key"]] = str(a.get("Value", ""))
        return {"Attributes": self._attrs_view(tg.attrs)}

    def op_RegisterTargets(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        ec2 = self.ec2
        bad = []
        for spec in as_list(p.get("Targets")):
            tid = spec.get("Id", "")
            port = int(spec.get("Port") or tg.port)
            if tg.target_type == "instance":
                inst = ec2.instances.get(tid)
                if inst is None:
                    raise AwsError("InvalidTarget", f"The following targets are not valid instances: '{tid}'")
                ec2._refresh(inst)
                if inst.vpc_id != tg.vpc_id:
                    raise AwsError("InvalidTarget", f"The following targets are not in the target group VPC "
                                   f"'{tg.vpc_id}': '{tid}'")
                if inst.state not in ("running", "pending"):
                    bad.append(tid)
                    continue
            key = f"{tid}:{port}"
            existing = tg.targets.get(key)
            if existing and existing.state != "draining":
                continue
            tg.targets[key] = Target(tid, port, next_check=self.clock.now())
            if self._tg_lbs(tg):
                self._set(tg.targets[key], "initial", "Elb.RegistrationInProgress", "Target registration is in progress")
        if bad:
            raise AwsError("InvalidTarget", "The following targets are not in a running state and cannot be "
                           f"registered: '{', '.join(bad)}'")
        return {}

    def op_DeregisterTargets(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        delay = int(tg.attrs["deregistration_delay.timeout_seconds"])
        for spec in as_list(p.get("Targets")):
            key = f"{spec.get('Id')}:{int(spec.get('Port') or tg.port)}"
            t = tg.targets.get(key)
            if t is None:
                raise AwsError("InvalidTarget", f"The following targets are not registered in target group "
                               f"'{tg.arn}': '{spec.get('Id')}'")
            self._set(t, "draining", "Target.DeregistrationInProgress", "Target deregistration is in progress")
            t.drain_until = self.clock.now() + delay
        return {}

    def op_DescribeTargetHealth(self, p, req):
        tg = self._tg(p.get("TargetGroupArn"))
        self.run_health_checks()
        wanted = as_list(p.get("Targets"))
        out = []
        for t in tg.targets.values():
            if wanted and not any(w.get("Id") == t.id and int(w.get("Port") or t.port) == t.port for w in wanted):
                continue
            _, az = self._target_ip(tg, t)
            health: dict[str, Any] = {"State": t.state}
            if t.reason:
                health["Reason"] = t.reason
            if t.description:
                health["Description"] = t.description
            out.append({"Target": {"Id": t.id, "Port": t.port, "AvailabilityZone": az},
                        "HealthCheckPort": str(t.port) if tg.hc["HealthCheckPort"] == "traffic-port"
                        else tg.hc["HealthCheckPort"], "TargetHealth": health})
        for w in wanted:
            if not any(w.get("Id") == t.id for t in tg.targets.values()):
                out.append({"Target": {"Id": w.get("Id"), "Port": int(w.get("Port") or tg.port)},
                            "TargetHealth": {"State": "unused", "Reason": "Target.NotRegistered",
                                             "Description": "Target is not registered to the target group"}})
        return {"TargetHealthDescriptions": out}

    # ================================================================== listeners / rules
    def _validate_actions(self, actions: list[dict[str, Any]], lb: LoadBalancer) -> list[dict[str, Any]]:
        if not actions:
            raise invalid("A default action must be specified")
        for a in actions:
            if a.get("Type") not in ("forward", "fixed-response", "redirect"):
                raise invalid(f"Action type '{a.get('Type')}' is not supported by awsemu")
            for arn in self._action_groups(a):
                tg = self._tg(arn)
                if tg.vpc_id != lb.vpc_id:
                    raise invalid(f"Target group '{arn}' is not in the same VPC as the load balancer")
                others = [x for x in self._tg_lbs(tg) if x.arn != lb.arn]
                if others:
                    raise AwsError("TargetGroupAssociationLimit", "The following target groups cannot be associated "
                                   f"with more than one load balancer: {arn}")
        return actions

    def _listener_view(self, lst: Listener) -> dict[str, Any]:
        return {"ListenerArn": lst.arn, "LoadBalancerArn": lst.lb_arn, "Port": lst.port, "Protocol": lst.protocol,
                "DefaultActions": lst.default_actions}

    def op_CreateListener(self, p, req):
        lb = self._lb(p.get("LoadBalancerArn"))
        port = int(p.get("Port") or 0)
        if not 1 <= port <= 65535:
            raise invalid("Port must be between 1 and 65535")
        if p.get("Protocol", "HTTP") != "HTTP":
            raise AwsError("UnsupportedProtocol", "awsemu supports only HTTP listeners")
        if any(lst.lb_arn == lb.arn and lst.port == port for lst in self.listeners.values()):
            raise AwsError("DuplicateListener", "A listener already exists on this port for this load balancer")
        actions = self._validate_actions(as_list(p.get("DefaultActions")), lb)
        lst = Listener(f"arn:aws:elasticloadbalancing:{self.region()}:{ACCOUNT_ID}:listener/app/{lb.name}/"
                       f"{lb.lb_id}/{hexid(16)}", lb.arn, port, "HTTP", actions)
        self.listeners[lst.arn] = lst
        for tg_arn in {g for a in actions for g in self._action_groups(a)}:
            for t in self.tgs[tg_arn].targets.values():
                if t.state == "unused":
                    self._set(t, "initial", "Elb.InitialHealthChecking", "Initial health checks in progress")
        self._start_listener(lst)
        return {"Listeners": [self._listener_view(lst)]}

    def op_DescribeListeners(self, p, req):
        items = list(self.listeners.values())
        if p.get("ListenerArns"):
            items = [self._listener(a) for a in as_list(p["ListenerArns"])]
        if p.get("LoadBalancerArn"):
            self._lb(p["LoadBalancerArn"])
            items = [lst for lst in items if lst.lb_arn == p["LoadBalancerArn"]]
        return {"Listeners": [self._listener_view(lst) for lst in items]}

    def op_ModifyListener(self, p, req):
        lst = self._listener(p.get("ListenerArn"))
        if p.get("DefaultActions"):
            lst.default_actions = self._validate_actions(as_list(p["DefaultActions"]), self.lbs[lst.lb_arn])
        if p.get("Port") and int(p["Port"]) != lst.port:
            self._stop_listener(lst.arn)
            lst.port = int(p["Port"])
            self._start_listener(lst)
        return {"Listeners": [self._listener_view(lst)]}

    def op_DeleteListener(self, p, req):
        lst = self._listener(p.get("ListenerArn"))
        self._stop_listener(lst.arn)
        del self.listeners[lst.arn]
        return {}

    def _rule_view(self, arn: str, rule: dict[str, Any]) -> dict[str, Any]:
        return {"RuleArn": arn, "Priority": str(rule["priority"]), "Conditions": rule["conditions"],
                "Actions": rule["actions"], "IsDefault": rule["priority"] == "default"}

    def op_CreateRule(self, p, req):
        lst = self._listener(p.get("ListenerArn"))
        priority = int(p.get("Priority") or 0)
        if not 1 <= priority <= 50000:
            raise invalid("Priority must be between 1 and 50000")
        if any(int(r["priority"]) == priority for r in lst.rules.values()):
            raise AwsError("PriorityInUse", f"Priority '{priority}' is currently in use")
        conditions = as_list(p.get("Conditions"))
        for c in conditions:
            for key in ("PathPatternConfig", "HostHeaderConfig", "HttpHeaderConfig", "HttpRequestMethodConfig"):
                if key in c and "Values" in c[key]:
                    c[key]["Values"] = as_list(c[key]["Values"])
            if "Values" in c:
                c["Values"] = as_list(c["Values"])
        rule = {"priority": priority, "conditions": conditions,
                "actions": self._validate_actions(as_list(p.get("Actions")), self.lbs[lst.lb_arn])}
        arn = lst.arn.replace(":listener/", ":listener-rule/") + f"/{hexid(16)}"
        lst.rules[arn] = rule
        return {"Rules": [self._rule_view(arn, rule)]}

    def op_DescribeRules(self, p, req):
        out = []
        for lst in self.listeners.values():
            if p.get("ListenerArn") and lst.arn != p["ListenerArn"]:
                continue
            for arn, rule in sorted(lst.rules.items(), key=lambda x: int(x[1]["priority"])):
                if p.get("RuleArns") and arn not in as_list(p["RuleArns"]):
                    continue
                out.append(self._rule_view(arn, rule))
            if not p.get("RuleArns"):
                out.append(self._rule_view(lst.arn.replace(":listener/", ":listener-rule/") + "/default",
                                           {"priority": "default", "conditions": [], "actions": lst.default_actions}))
        return {"Rules": out}

    def op_DeleteRule(self, p, req):
        for lst in self.listeners.values():
            if p.get("RuleArn") in lst.rules:
                del lst.rules[p["RuleArn"]]
                return {}
        raise AwsError("RuleNotFound", f"Rules '[{p.get('RuleArn')}]' not found")

    # ================================================================== tags
    def _tags_of(self, arn: str) -> dict[str, str]:
        for table in (self.lbs, self.tgs):
            if arn in table:
                return table[arn].tags
        raise AwsError("LoadBalancerNotFound", f"Load balancers '[{arn}]' not found")

    def op_AddTags(self, p, req):
        for arn in as_list(p.get("ResourceArns")):
            self._tags_of(arn).update({t["Key"]: t.get("Value", "") for t in as_list(p.get("Tags"))})
        return {}

    def op_DescribeTags(self, p, req):
        return {"TagDescriptions": [{"ResourceArn": arn, "Tags": [{"Key": k, "Value": v}
                                                                  for k, v in self._tags_of(arn).items()]}
                                    for arn in as_list(p.get("ResourceArns"))]}

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            return {
                "load_balancers": {lb.name: {"arn": lb.arn, "dns": lb.dns, "scheme": lb.scheme,
                                             "addresses": [self.ec2.enis[e].public_ip or self.ec2.enis[e].private_ip
                                                           for e in lb.eni_ids if e in self.ec2.enis],
                                             "security_groups": lb.sg_ids,
                                             "listeners": [lst.port for lst in self.listeners.values()
                                                           if lst.lb_arn == lb.arn]}
                                   for lb in self.lbs.values()},
                "target_groups": {tg.name: {t_key: {"state": t.state, "reason": t.reason, "description": t.description}
                                            for t_key, t in tg.targets.items()} for tg in self.tgs.values()},
            }

    def load(self, data: dict[str, Any]) -> None:
        pass

    def dump(self) -> dict[str, Any]:
        return {"note": "ELBv2 のスナップショットは未対応です"}

