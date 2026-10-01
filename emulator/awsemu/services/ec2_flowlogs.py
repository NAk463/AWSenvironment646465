"""VPC フローログの集計と配信 (CloudWatch Logs / S3)。

AWS と同じく、配信先が CloudWatch Logs の場合は DeliverLogsPermissionArn のロールを評価し、
信頼ポリシーや権限が足りなければ配信に失敗する (DescribeFlowLogs の DeliverLogsStatus = FAILED)。
"""
from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from ..core import ACCOUNT_ID, Identity
from ..iam_policy import as_list, evaluate, principal_matches

FLUSH_SECONDS = float(os.environ.get("AWSEMU_FLOWLOG_FLUSH_SECONDS", "10"))
PROTOCOLS = {6: "6", 17: "17", 1: "1"}


class FlowLogCollector:
    def __init__(self, ec2: Any) -> None:
        self.ec2 = ec2
        self.readers: dict[str, Any] = {}
        self.flows: dict[tuple, list[int]] = {}
        self.lock = threading.Lock()
        self.ip_map: dict[str, dict[str, str]] = {}      # netns -> {ip: eni id}
        self._stop = threading.Event()

    # ------------------------------------------------------------------ readers
    def refresh(self) -> None:
        """フローログが必要な名前空間に NFLOG リーダーを用意する (EC2 のロックを保持した状態で呼ぶ)。"""
        from ..netplane.nflog import NflogReader
        ec2 = self.ec2
        np = ec2.netplane
        if not np.enabled:
            return
        wanted: dict[str, dict[str, str]] = {}
        for eni in ec2.enis.values():
            if eni.owner and ec2._eni_active(eni) and ec2._flowlog_enabled(eni):
                wanted.setdefault(np.host_ns(eni.owner), {})[eni.private_ip] = eni.id
        for vpc in ec2.vpcs.values():
            enis = {e.private_ip: e.id for e in ec2.enis.values() if e.vpc_id == vpc.id and ec2._flowlog_enabled(e)}
            if enis:
                wanted[np.vpc_ns(vpc.idx)] = enis
        self.ip_map = wanted
        for ns in list(self.readers):
            if ns not in wanted:
                self.readers.pop(ns).stop()
        for ns in wanted:
            if ns not in self.readers:
                reader = NflogReader(ns, self.on_packet)
                reader.start()
                if reader.error:
                    print(f"[flowlogs] {ns}: NFLOG を開始できませんでした: {reader.error}")
                self.readers[ns] = reader

    def on_packet(self, ns: str, pkt: tuple) -> None:
        prefix, src, dst, sport, dport, proto, length = pkt
        ips = self.ip_map.get(ns, {})
        if dst in ips:
            eni, direction = ips[dst], "ingress"
        elif src in ips:
            eni, direction = ips[src], "egress"
        else:
            return
        action = "ACCEPT" if prefix.startswith("A") else "REJECT"
        now = int(self.ec2.clock.now())
        key = (eni, direction, src, dst, sport, dport, proto, action)
        with self.lock:
            entry = self.flows.get(key)
            if entry is None:
                self.flows[key] = [1, length, now, now]
            else:
                entry[0] += 1
                entry[1] += length
                entry[3] = now

    # ------------------------------------------------------------------ delivery
    def start_flusher(self) -> None:
        def loop() -> None:
            while not self._stop.wait(FLUSH_SECONDS):
                try:
                    self.flush()
                except Exception as exc:  # noqa: BLE001
                    print(f"[flowlogs] flush error: {exc!r}")
        threading.Thread(target=loop, name="flowlog-flush", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        for reader in self.readers.values():
            reader.stop()
        self.readers.clear()

    def flush(self) -> None:
        with self.lock:
            flows, self.flows = self.flows, {}
        if not flows:
            return
        ec2 = self.ec2
        with ec2.lock:
            by_log: dict[str, list[str]] = {}
            for (eni_id, direction, src, dst, sport, dport, proto, action), (pk, by, start, end) in flows.items():
                eni = ec2.enis.get(eni_id)
                if eni is None:
                    continue
                subnet = ec2.subnets.get(eni.subnet_id)
                fields = {
                    "version": "2", "account-id": ACCOUNT_ID, "interface-id": eni.id, "srcaddr": src,
                    "dstaddr": dst, "srcport": str(sport), "dstport": str(dport), "protocol": PROTOCOLS.get(proto, str(proto)),
                    "packets": str(pk), "bytes": str(by), "start": str(start), "end": str(end + 1), "action": action,
                    "log-status": "OK", "vpc-id": eni.vpc_id, "subnet-id": eni.subnet_id,
                    "instance-id": eni.instance_id or "-", "tcp-flags": "0", "type": "IPv4", "pkt-srcaddr": src,
                    "pkt-dstaddr": dst, "region": ec2.region(), "flow-direction": direction,
                    "az-id": f"apne1-az{'acd'.index(subnet.az[-1]) + 1}" if subnet else "-",
                }
                for fl in ec2.flow_logs.values():
                    if fl.resource_id not in (eni.id, eni.subnet_id, eni.vpc_id):
                        continue
                    if fl.traffic_type != "ALL" and fl.traffic_type != action:
                        continue
                    line = re.sub(r"\$\{([a-z0-9-]+)\}", lambda m: fields.get(m.group(1), "-"), fl.log_format)
                    by_log.setdefault(fl.id, []).append((eni.id, start, line))
            for fl_id, rows in by_log.items():
                fl = ec2.flow_logs.get(fl_id)
                if fl is not None:
                    self._deliver(fl, rows)

    def _deliver(self, fl: Any, rows: list[tuple[str, int, str]]) -> None:
        emu = self.ec2.emu
        if fl.destination_type == "cloud-watch-logs":
            error = self._check_role(fl.role_arn)
            if error:
                fl.deliver_status, fl.deliver_error = "FAILED", error
                return
            logs = emu.services["logs"]
            with logs.lock:
                if fl.log_group not in logs.groups:
                    logs.op_CreateLogGroup({"logGroupName": fl.log_group}, None)
            streams: dict[str, list[tuple[int, str]]] = {}
            for eni_id, start, line in rows:
                streams.setdefault(eni_id, []).append((start * 1000, line))
            for stream, events in streams.items():
                logs.deliver(fl.log_group, stream, sorted(events))
        else:
            bucket = (fl.destination or "").removeprefix("arn:aws:s3:::").split("/", 1)
            name, prefix = bucket[0], (bucket[1].rstrip("/") + "/" if len(bucket) > 1 and bucket[1] else "")
            now = datetime.fromtimestamp(self.ec2.clock.now(), timezone.utc)
            key = (f"{prefix}AWSLogs/{ACCOUNT_ID}/vpcflowlogs/{self.ec2.region()}/{now:%Y/%m/%d}/"
                   f"{ACCOUNT_ID}_vpcflowlogs_{self.ec2.region()}_{fl.id}_{now:%Y%m%dT%H%M}Z_{secrets.token_hex(4)}.log.gz")
            header = re.sub(r"\$\{([a-z0-9-]+)\}", r"\1", fl.log_format)
            body = "\n".join([header] + [line for _, _, line in rows]) + "\n"
            err = emu.services["s3"].put_internal(name, key, gzip.compress(body.encode()), "application/octet-stream")
            if err:
                fl.deliver_status, fl.deliver_error = "FAILED", "Access error"
                return
        fl.deliver_status, fl.deliver_error = "SUCCESS", None

    def _check_role(self, role_arn: str | None) -> str | None:
        iam = self.ec2.emu.services["iam"]
        role = iam.roles.get((role_arn or "").rsplit("/", 1)[-1])
        if role is None:
            return "Access error"
        trust = json.loads(role.trust_policy or "{}")
        service = Identity("AWSService", "vpc-flow-logs.amazonaws.com", "vpc-flow-logs")
        if not any(st.get("Effect") == "Allow" and principal_matches(st.get("Principal"), service)
                   for st in as_list(trust.get("Statement"))):
            return "Access error"
        ident = Identity("AssumedRole", f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role.name}/flowlogs",
                         f"{role.id}:flowlogs", role_arn=role.arn, role_id=role.id)
        for action in ("logs:CreateLogStream", "logs:PutLogEvents"):
            if not evaluate(ident, iam.identity_policies(ident), None, action, "arn:aws:logs:*:*:log-group:*", {}).allowed:
                return "Access error"
        return None
