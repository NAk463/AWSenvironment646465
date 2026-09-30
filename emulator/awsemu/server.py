"""HTTP サーバとリクエストのディスパッチ、および /_emulator 管理 API。

1 リクエストの流れ:
  ルーティング → 認証 (アクセスキー → IAM ID) → 障害注入 → 認可 (IAM ポリシー評価) → 処理
  → CloudWatch メトリクス発行 → CloudTrail 記録 → awsemu イベントログ
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote

from .core import ANONYMOUS, ROOT_IDENTITY, AwsError, Clock, EventLog, FaultInjector, Identity, Request, Response, Service
from .iam_policy import base_context, denial_message
from .services.cloudtrail import CloudTrail
from .services.cloudwatch import CloudWatch
from .services.dynamodb import DynamoDB
from .services.iam import IAM
from .services.logs import Logs
from .services.s3 import S3
from .services.sqs import SQS
from .services.sts import STS

CREDENTIAL_RE = re.compile(r"Credential=([^/,\s]+)/\d{8}/([^/]+)/([^/]+)/aws4_request")
QUERY_CREDENTIAL_RE = re.compile(r"^([^/]+)/\d{8}/([^/]+)/([^/]+)/aws4_request$")
CONTROL_PREFIX = "/_emulator"
MAX_LOGGED_PARAMS = 4000
SERVICE_CLASSES = (S3, SQS, DynamoDB, STS, IAM, CloudTrail, CloudWatch, Logs)
SCOPE_TO_SERVICE = {"s3": "s3", "sqs": "sqs", "dynamodb": "dynamodb", "sts": "sts", "iam": "iam",
                    "monitoring": "cloudwatch", "logs": "logs", "cloudtrail": "cloudtrail"}
TARGET_TO_SERVICE = (("DynamoDB_", "dynamodb"), ("AmazonSQS", "sqs"), ("Logs_", "logs"),
                     ("com.amazonaws.cloudtrail", "cloudtrail"), ("GraniteServiceVersion20100801", "cloudwatch"))


def credential_scope(req: Request) -> tuple[str | None, str | None, str | None]:
    """(アクセスキー ID, リージョン, サービス名) を署名情報から取り出す。"""
    auth = req.header("Authorization") or ""
    m = CREDENTIAL_RE.search(auth)
    if m:
        return m.group(1), m.group(2), m.group(3)
    if auth.startswith("AWS ") and ":" in auth:
        return auth[4:].split(":", 1)[0], None, None
    cred = req.query.get("X-Amz-Credential")
    if cred:
        m = QUERY_CREDENTIAL_RE.match(unquote(cred))
        if m:
            return m.group(1), m.group(2), m.group(3)
    if req.query.get("AWSAccessKeyId"):
        return req.query["AWSAccessKeyId"], None, None
    return None, None, None


class Emulator:
    def __init__(self, iam_mode: str | None = None) -> None:
        self.clock = Clock()
        self.events = EventLog()
        self.faults = FaultInjector()
        self.services: dict[str, Service] = {cls.name: cls(self.clock) for cls in SERVICE_CLASSES}
        for svc in self.services.values():
            svc.emu = self
        self.iam_mode = iam_mode or os.environ.get("AWSEMU_IAM", "enforce")
        self.iam.root_keys = {k.strip() for k in os.environ.get("AWSEMU_ROOT_ACCESS_KEYS", "test").split(",")
                              if k.strip()}
        self.metrics_interval = float(os.environ.get("AWSEMU_METRICS_INTERVAL", "60"))
        self.started = time.time()
        self._stop = threading.Event()

    @property
    def iam(self) -> IAM:
        return self.services["iam"]  # type: ignore[return-value]

    @property
    def cloudwatch(self) -> CloudWatch:
        return self.services["cloudwatch"]  # type: ignore[return-value]

    # ------------------------------------------------------------------ background
    def start_background(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.metrics_interval):
                try:
                    self.tick()
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
        threading.Thread(target=loop, name="awsemu-sampler", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def tick(self, at: float | None = None) -> None:
        """ゲージ系メトリクス (キュー滞留数など) をサンプリングし、アラームを評価する。"""
        metrics = []
        for svc in self.services.values():
            for m in svc.gauges():
                if m.timestamp is None and at is not None:
                    m.timestamp = at
                metrics.append(m)
        self.cloudwatch.ingest(metrics)
        with self.cloudwatch.lock:
            self.cloudwatch.evaluate_alarms()

    def advance(self, seconds: float) -> None:
        """時計を進め、その間のゲージを 1 分ごとに補完してアラームを評価する。"""
        old = self.clock.now()
        self.clock.advance(seconds)
        new = self.clock.now()
        points = [t for t in range(math.ceil(old / 60) * 60, int(new), 60)][-1440:]
        for t in points:
            metrics = [m for svc in self.services.values() for m in svc.gauges() if m.timestamp is None]
            for m in metrics:
                m.timestamp = float(t)
            self.cloudwatch.ingest(metrics)
        self.tick()

    def alarm_action(self, arn: str, alarm: dict[str, Any]) -> tuple[bool, str]:
        """アラームのアクション (SNS 通知、EC2 操作など)。フェーズ 2 以降で実装する。"""
        service = arn.split(":")[2] if arn.count(":") >= 2 else "unknown"
        return False, f"{service} actions are not implemented yet in awsemu (planned for a later phase)"

    # ------------------------------------------------------------------ routing
    def route(self, req: Request) -> Service:
        target = req.header("X-Amz-Target") or ""
        for prefix, name in TARGET_TO_SERVICE:
            if target.startswith(prefix):
                return self.services[name]
        if req.path.startswith("/service/GraniteServiceVersion20100801/"):
            return self.services["cloudwatch"]
        _, _, scope = credential_scope(req)
        if scope == "sqs":
            raise AwsError("InvalidAction", "awsemu supports only the JSON protocol for SQS (use a recent SDK/CLI)")
        if scope == "monitoring":
            raise AwsError("InvalidAction", "awsemu supports only the JSON/CBOR protocols for CloudWatch "
                           "(use a recent SDK/CLI)")
        if scope in SCOPE_TO_SERVICE:
            return self.services[SCOPE_TO_SERVICE[scope]]
        if b"Action=" in req.body[:300] and "form-urlencoded" in (req.header("Content-Type") or ""):
            return self.services["sts"]
        return self.services["s3"]

    # ------------------------------------------------------------------ authentication / authorization
    def authenticate(self, req: Request, svc: Service) -> AwsError | None:
        key, region, _ = credential_scope(req)
        if region:
            req.region = region
        if key is None:
            if self.iam_mode == "off":
                req.identity = ROOT_IDENTITY
            elif svc.name == "s3":
                req.identity = ANONYMOUS
            else:
                return AwsError("MissingAuthenticationTokenException" if svc.name in ("dynamodb", "logs")
                                else "MissingAuthenticationToken", "Missing Authentication Token", 403)
            return None
        with self.iam.lock:
            result = self.iam.authenticate(key, svc.event_source, req.region)
        if isinstance(result, Identity):
            req.identity = result
            return None
        if self.iam_mode == "off":
            req.identity = Identity(**{**ROOT_IDENTITY.__dict__, "access_key": key})
            return None
        if result.code == "ExpiredToken":
            return AwsError(getattr(svc, "expired_token_code", "ExpiredToken"),
                            "The security token included in the request is expired",
                            getattr(svc, "expired_token_status", 403))
        return AwsError(svc.invalid_token_code, svc.invalid_token_message, svc.invalid_token_status)

    def authorize(self, req: Request, svc: Service, op: str) -> AwsError | None:
        if self.iam_mode != "enforce":
            return None
        try:
            checks = svc.authz(req, op)
            extra = svc.authz_context(req, op)
        except AwsError:
            return None  # リクエスト自体が不正。ハンドラ側で本来のエラーを返させる
        ident = req.identity
        for action, resource in checks:
            ctx = base_context(ident, req.region, req.client_ip, self.clock.now())
            ctx.update({k.lower(): v for k, v in extra.items() if v is not None})
            policy = svc.resource_policy(resource) if resource != "*" else None
            with self.iam.lock:
                decision = self.iam.authorize(ident, action, resource, policy, ctx)
            if not decision.allowed:
                if ident.type == "Anonymous":
                    return AwsError(svc.access_denied_code, "Access Denied", svc.access_denied_status)
                return AwsError(svc.access_denied_code, denial_message(ident, action, resource, decision),
                                svc.access_denied_status)
        return None

    # ------------------------------------------------------------------ dispatch
    def dispatch(self, req: Request) -> Response:
        if req.path.startswith(CONTROL_PREFIX):
            return self.control(req)
        started = time.perf_counter()
        try:
            svc = self.route(req)
        except AwsError as err:
            return self.services["sts"].error_response(req, err)
        op = svc.operation(req)
        error = self.authenticate(req, svc)
        fault = None
        resource = ""
        resp: Response | None = None
        if error is None:
            try:
                resource = svc.resource(req, op)
            except AwsError:
                resource = ""
            fault = self.faults.check(svc.name, op, resource)
            if fault and fault.latency_ms:
                time.sleep(fault.latency_ms / 1000)
            if fault and fault.error_code:
                error = AwsError(fault.error_code, fault.error_message or f"Injected fault ({fault.id})",
                                 fault.status, sender_fault=fault.status < 500)
        if error is None:
            error = self.authorize(req, svc, op)
        if error is None:
            try:
                resp = svc.handle(req, op)
            except AwsError as err:
                error = err
            except Exception as exc:  # noqa: BLE001 - 想定外の例外も AWS 形式の 500 で返す
                traceback.print_exc()
                error = AwsError("InternalFailure", f"awsemu internal error: {exc!r}", 500, sender_fault=False)
        if error is not None:
            resp = svc.error_response(req, error)
        assert resp is not None
        resp.headers.setdefault("x-amzn-RequestId", req.request_id)
        resp.headers.setdefault("x-amz-request-id", req.request_id)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)

        try:
            self.cloudwatch.ingest(svc.metrics(req, op, resp.status, error, duration_ms))
            self.services["cloudtrail"].record(req, svc, op, resp.status, error)
        except Exception:  # noqa: BLE001 - 観測系の失敗でリクエストを失敗させない
            traceback.print_exc()

        params = svc.params_for_log(req, op) if error is None or error.code not in ("SerializationException",) else None
        dumped = json.dumps(params, ensure_ascii=False, default=str)
        req.event = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": req.request_id,
            "service": svc.name,
            "operation": op,
            "principal": req.identity.arn,
            "region": req.region,
            "resource": resource,
            "status": resp.status,
            "error": {"code": error.code, "message": error.message} if error else None,
            "fault_id": fault.id if fault else None,
            "duration_ms": duration_ms,
            "params": params if len(dumped) <= MAX_LOGGED_PARAMS else {"_truncated": dumped[:MAX_LOGGED_PARAMS]},
        }
        self.events.add(req.event)
        return resp

    # ------------------------------------------------------------------ snapshot
    def dump(self) -> dict[str, Any]:
        return {"version": 1, "clock_offset": self.clock.offset,
                "services": {n: s.dump() for n, s in self.services.items()}}

    def load(self, data: dict[str, Any]) -> None:
        self.clock.offset = data.get("clock_offset", 0.0)
        for name, svc in self.services.items():
            svc.reset()
            if name in data.get("services", {}):
                svc.load(data["services"][name])

    # ------------------------------------------------------------------ control plane
    def control(self, req: Request) -> Response:
        parts = [p for p in req.path[len(CONTROL_PREFIX):].split("/") if p]
        m = req.method
        try:
            body = json.loads(req.body) if req.body.strip() else {}
        except ValueError:
            return _json({"error": "invalid JSON body"}, 400)
        head = parts[0] if parts else "health"

        if head == "health" and m == "GET":
            return _json({"status": "running", "services": sorted(self.services), "iam": self.iam_mode,
                          "uptime_seconds": round(time.time() - self.started, 1),
                          "clock_offset_seconds": self.clock.offset})
        if head == "state" and m == "GET":
            if len(parts) > 1:
                svc = self.services.get(parts[1])
                if svc is None:
                    return _json({"error": f"unknown service {parts[1]}"}, 404)
                return _json(svc.state())
            return _json({n: s.state() for n, s in self.services.items()})
        if head == "reset" and m == "POST":
            targets = [req.query["service"]] if req.query.get("service") else list(self.services)
            for n in targets:
                if n not in self.services:
                    return _json({"error": f"unknown service {n}"}, 404)
                self.services[n].reset()
            if not req.query.get("service"):
                self.events.clear()
                self.faults.clear()
                self.clock.offset = 0.0
            return _json({"reset": targets})
        if head == "events":
            if m == "DELETE":
                self.events.clear()
                return _json({"cleared": True})
            q = req.query
            return _json(self.events.query(
                service=q.get("service"), operation=q.get("operation"),
                errors_only=q.get("errors") in ("1", "true"), since=int(q.get("since", 0)),
                limit=int(q.get("limit", 100))))
        if head == "faults":
            if m == "GET":
                return _json([r.__dict__ for r in self.faults.rules])
            if m == "POST":
                try:
                    return _json(self.faults.add(body).__dict__, 201)
                except (TypeError, ValueError) as exc:
                    return _json({"error": str(exc)}, 400)
            if m == "DELETE":
                if len(parts) > 1:
                    return _json({"removed": self.faults.remove(parts[1])})
                self.faults.clear()
                return _json({"cleared": True})
        if head == "config":
            if m in ("POST", "PUT"):
                if "iam" in body:
                    if body["iam"] not in ("enforce", "off"):
                        return _json({"error": "iam must be 'enforce' or 'off'"}, 400)
                    self.iam_mode = body["iam"]
                if "root_access_keys" in body:
                    self.iam.root_keys = set(body["root_access_keys"])
            return _json({"iam": self.iam_mode, "root_access_keys": sorted(self.iam.root_keys),
                          "metrics_interval_seconds": self.metrics_interval})
        if head == "tick" and m == "POST":
            self.tick()
            return _json({"sampled": True})
        if head == "time":
            if m == "POST":
                self.advance(float(body.get("advance_seconds", 0)))
            return _json({"now": datetime.fromtimestamp(self.clock.now(), timezone.utc).isoformat(),
                          "offset_seconds": self.clock.offset})
        if head == "snapshot":
            if m == "GET":
                return _json(self.dump())
            if m in ("PUT", "POST"):
                self.load(body)
                return _json({"restored": True})
        return _json({"error": f"unknown control endpoint {m} {req.path}"}, 404)


def _json(data: Any, status: int = 200) -> Response:
    return Response(status, json.dumps(data, ensure_ascii=False, indent=2, default=str).encode(),
                    {"Content-Type": "application/json; charset=utf-8"})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "awsemu"
    emulator: Emulator
    verbose = True

    def _read_body(self) -> bytes:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(out)
                out += self.rfile.read(size)
                self.rfile.readline()
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _handle(self) -> None:
        req = Request(self.command, self.path, self.headers, self._read_body(), client_ip=self.client_address[0])
        resp = self.emulator.dispatch(req)
        self.send_response(resp.status)
        headers = {"Date": formatdate(usegmt=True), **resp.headers}
        if self.command != "HEAD" or "Content-Length" not in headers:
            headers["Content-Length"] = str(len(resp.body))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and resp.status not in (204, 304):
            self.wfile.write(resp.body)
        e = getattr(req, "event", None)
        if self.verbose and e:
            err = f" {e['error']['code']}" if e["error"] else ""
            print(f"{e['time'][11:23]} {e['service']:<8} {e['operation']:<26} {e['resource'][:50]:<50} "
                  f"{e['status']}{err} {e['duration_ms']}ms", file=sys.stderr, flush=True)

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = do_PATCH = _handle

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


def make_server(host: str, port: int, emulator: Emulator | None = None, verbose: bool = True,
                background: bool = True) -> ThreadingHTTPServer:
    emulator = emulator or Emulator()
    if background:
        emulator.start_background()
    handler = type("BoundHandler", (Handler,), {"emulator": emulator, "verbose": verbose})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.emulator = emulator  # type: ignore[attr-defined]
    return server
