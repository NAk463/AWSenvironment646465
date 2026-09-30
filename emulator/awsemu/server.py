"""HTTP サーバとリクエストのディスパッチ、および /_emulator 管理 API。"""
from __future__ import annotations

import json
import re
import sys
import time
import traceback
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .core import AwsError, Clock, EventLog, FaultInjector, Request, Response, Service
from .services.dynamodb import DynamoDB
from .services.s3 import S3
from .services.sqs import SQS
from .services.sts import STS

CREDENTIAL_RE = re.compile(r"Credential=[^/]+/\d{8}/([^/]+)/([^/]+)/aws4_request")
QUERY_CREDENTIAL_RE = re.compile(r"X-Amz-Credential=[^&]*?%2F\d{8}%2F([^%&]+)%2F([^%&]+)%2Faws4_request", re.I)
CONTROL_PREFIX = "/_emulator"
MAX_LOGGED_PARAMS = 4000


class Emulator:
    def __init__(self) -> None:
        self.clock = Clock()
        self.events = EventLog()
        self.faults = FaultInjector()
        self.services: dict[str, Service] = {
            cls.name: cls(self.clock) for cls in (S3, SQS, DynamoDB, STS)
        }
        self.started = time.time()

    # ------------------------------------------------------------------ routing
    def route(self, req: Request) -> Service:
        target = req.header("X-Amz-Target") or ""
        scope = CREDENTIAL_RE.search(req.header("Authorization") or "") or QUERY_CREDENTIAL_RE.search(req.query_string)
        if scope:
            req.region = scope.group(1)
        if target.startswith("DynamoDB_"):
            return self.services["dynamodb"]
        if target.startswith("AmazonSQS"):
            return self.services["sqs"]
        service = scope.group(2) if scope else ""
        if service == "sqs":
            raise AwsError("InvalidAction", "awsemu supports only the JSON protocol for SQS (use a recent SDK/CLI)")
        if service in self.services:
            return self.services[service]
        if b"Action=" in req.body[:200] and "form-urlencoded" in (req.header("Content-Type") or ""):
            return self.services["sts"]
        return self.services["s3"]

    def dispatch(self, req: Request) -> Response:
        if req.path.startswith(CONTROL_PREFIX):
            return self.control(req)
        started = time.perf_counter()
        try:
            svc = self.route(req)
        except AwsError as err:
            svc = self.services["sts"]
            return svc.error_response(req, err)
        op = svc.operation(req)
        resource = svc.resource(req, op)
        fault = self.faults.check(svc.name, op, resource)
        error: AwsError | None = None
        resp: Response | None = None
        if fault and fault.latency_ms:
            time.sleep(fault.latency_ms / 1000)
        if fault and fault.error_code:
            error = AwsError(fault.error_code, fault.error_message or f"Injected fault ({fault.id})",
                             fault.status, sender_fault=fault.status < 500)
        else:
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

        params = svc.params_for_log(req, op)
        dumped = json.dumps(params, ensure_ascii=False, default=str)
        req.event = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": req.request_id,
            "service": svc.name,
            "operation": op,
            "region": req.region,
            "resource": resource,
            "status": resp.status,
            "error": {"code": error.code, "message": error.message} if error else None,
            "fault_id": fault.id if fault else None,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
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
            return _json({"status": "running", "services": sorted(self.services),
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
        if head == "time":
            if m == "POST":
                self.clock.advance(float(body.get("advance_seconds", 0)))
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
        req = Request(self.command, self.path, self.headers, self._read_body())
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


def make_server(host: str, port: int, emulator: Emulator | None = None, verbose: bool = True) -> ThreadingHTTPServer:
    emulator = emulator or Emulator()
    handler = type("BoundHandler", (Handler,), {"emulator": emulator, "verbose": verbose})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.emulator = emulator  # type: ignore[attr-defined]
    return server
