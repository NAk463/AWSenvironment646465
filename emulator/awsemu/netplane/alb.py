"""ALB のデータプレーン: ALB の名前空間 (VPC 内の ENI を持つ) で動く HTTP リバースプロキシとヘルスチェッカー。

ALB 自身もセキュリティグループの内側にあり、ターゲットへの通信は実際の VPC 経路 (SG / NACL / ルート) を通る。
そのため「ターゲット側 SG が ALB の SG を許可していない」「ターゲットのプロセスが落ちた」といった原因から、
本物と同じく 502 / 503 / 504 やヘルスチェック失敗 (Target.Timeout など) が発生する。
"""
from __future__ import annotations

import http.client
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .linux import call_in_netns

HOP_HEADERS = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"}
CONNECT_TIMEOUT = 10.0      # ALB のターゲットへの接続タイムアウト (秒)


def error_page(status: int, reason: str) -> bytes:
    return (f"<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n"
            f"<center><h1>{status} {reason}</h1></center>\r\n</body>\r\n</html>\r\n").encode()


@dataclass
class ProxyResult:
    """1 リクエストの結果 (メトリクスとアクセスログ用)。"""

    elb_status: int
    target_status: int | None
    target: str | None
    target_group: str | None
    request_time: float
    target_time: float
    response_time: float
    received: int
    sent: int
    error_reason: str | None
    action: str
    rule_priority: str


@dataclass
class HealthResult:
    ok: bool
    reason: str | None = None        # Target.Timeout | Target.ResponseCodeMismatch | Target.FailedHealthChecks
    description: str | None = None


def health_check(ns: str, ip: str, port: int, path: str, timeout: float, matcher: str) -> HealthResult:
    """ALB の名前空間から HTTP ヘルスチェックを行う。"""
    def check() -> HealthResult:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "ELB-HealthChecker/2.0", "Host": f"{ip}:{port}"})
            resp = conn.getresponse()
            resp.read()
        except socket.timeout:
            return HealthResult(False, "Target.Timeout", "Request timed out")
        except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            if isinstance(exc, (TimeoutError,)):
                return HealthResult(False, "Target.Timeout", "Request timed out")
            return HealthResult(False, "Target.FailedHealthChecks", "Health checks failed")
        finally:
            conn.close()
        if code_matches(resp.status, matcher):
            return HealthResult(True)
        return HealthResult(False, "Target.ResponseCodeMismatch",
                            f"Health checks failed with these codes: [{resp.status}]")
    return call_in_netns(ns, check)


def code_matches(status: int, matcher: str) -> bool:
    for part in matcher.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= status <= int(hi):
                return True
        elif part and int(part) == status:
            return True
    return False


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)   # 逆引き DNS を避ける
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


Router = Callable[[str, str, dict[str, str], int], dict[str, Any]]
Reporter = Callable[[ProxyResult, dict[str, Any]], None]


class AlbListener:
    """ALB の 1 リスナー (ポート)。router が返すアクションに従ってリクエストを処理する。

    router(method, path, headers, port) -> {"type": "forward", "targets": [(ip, port, group_arn)], "idle_timeout": s,
                                            "rule_priority": "1"} | {"type": "fixed-response", ...} | {"type": "redirect", ...}
    """

    def __init__(self, ns: str, port: int, router: Router, reporter: Reporter) -> None:
        self.ns, self.port, self.router, self.reporter = ns, port, router, reporter
        self.server: _Server | None = None
        self._rr = 0
        self._lock = threading.Lock()

    def pick(self, targets: list[tuple[str, int, str]]) -> tuple[str, int, str]:
        with self._lock:
            self._rr += 1
            return targets[self._rr % len(targets)]

    def start(self) -> None:
        listener = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "awselb/2.0"
            sys_version = ""

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> int:
                self.send_response(status)
                for k, v in {"Server": "awselb/2.0", "Content-Type": "text/html", **(headers or {})}.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return len(body)

            def _handle(self) -> None:
                started = time.monotonic()
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k: v for k, v in self.headers.items()}
                action = listener.router(self.command, self.path, headers, listener.port)
                info = {"client": f"{self.client_address[0]}:{self.client_address[1]}",
                        "request_line": f"{self.command} http://{headers.get('Host', '')}{self.path} {self.request_version}",
                        "user_agent": headers.get("User-Agent", "-"), "trace_id": action.get("trace_id", "-"),
                        "received": len(body) + sum(len(k) + len(v) + 4 for k, v in headers.items())}
                kind = action["type"]
                if kind == "fixed-response":
                    sent = self._send(int(action["status"]), action.get("body", "").encode(),
                                      {"Content-Type": action.get("content_type", "text/plain")})
                    listener.reporter(ProxyResult(int(action["status"]), None, None, None, 0.0, -1, 0.0,
                                                  info["received"], sent, None, "fixed-response",
                                                  action.get("rule_priority", "0")), info)
                    return
                if kind == "redirect":
                    sent = self._send(int(action["status"]), b"", {"Location": action["location"]})
                    listener.reporter(ProxyResult(int(action["status"]), None, None, None, 0.0, -1, 0.0,
                                                  info["received"], sent, None, "redirect",
                                                  action.get("rule_priority", "0")), info)
                    return
                targets = action.get("targets") or []
                group = action.get("target_group")
                if not targets:
                    sent = self._send(503, error_page(503, "Service Temporarily Unavailable"))
                    listener.reporter(ProxyResult(503, None, None, group, -1, -1, -1, info["received"], sent,
                                                  None, "forward", action.get("rule_priority", "0")), info)
                    return
                ip, port, group = listener.pick(targets)
                fwd = {k: v for k, v in headers.items() if k.lower() not in HOP_HEADERS}
                xff = headers.get("X-Forwarded-For")
                fwd["X-Forwarded-For"] = f"{xff}, {self.client_address[0]}" if xff else self.client_address[0]
                fwd["X-Forwarded-Proto"] = "http"
                fwd["X-Forwarded-Port"] = str(listener.port)
                fwd["X-Amzn-Trace-Id"] = action.get("trace_id", "")
                fwd["Connection"] = "close"
                req_time = time.monotonic() - started
                t0 = time.monotonic()
                idle = float(action.get("idle_timeout", 60))
                conn = None
                try:
                    conn = call_in_netns(listener.ns, lambda: _connect(ip, port, min(CONNECT_TIMEOUT, idle)))
                    conn.sock.settimeout(idle)
                    conn.request(self.command, self.path, body=body or None, headers=fwd)
                    resp = conn.getresponse()
                    data = resp.read()
                    target_time = time.monotonic() - t0
                    out_headers = {k: v for k, v in resp.getheaders() if k.lower() not in HOP_HEADERS
                                   and k.lower() not in ("content-length", "server")}
                    self.send_response(resp.status, resp.reason)
                    for k, v in out_headers.items():
                        self.send_header(k, v)
                    self.send_header("Server", resp.getheader("Server") or "awselb/2.0")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                    listener.reporter(ProxyResult(resp.status, resp.status, f"{ip}:{port}", group, req_time,
                                                  target_time, 0.0, info["received"], len(data), None, "forward",
                                                  action.get("rule_priority", "0")), info)
                except (socket.timeout, TimeoutError):
                    sent = self._send(504, error_page(504, "Gateway Time-out"))
                    listener.reporter(ProxyResult(504, None, f"{ip}:{port}", group, req_time, -1, -1,
                                                  info["received"], sent, "TargetResponseTimeout"
                                                  if conn and conn.sock else "TargetConnectionTimeout", "forward",
                                                  action.get("rule_priority", "0")), info)
                except (ConnectionRefusedError, ConnectionResetError, http.client.HTTPException, OSError) as exc:
                    sent = self._send(502, error_page(502, "Bad Gateway"))
                    reason = "TargetConnectionError" if isinstance(exc, ConnectionRefusedError) else \
                        "TargetResponseError"
                    listener.reporter(ProxyResult(502, None, f"{ip}:{port}", group, req_time, -1, -1,
                                                  info["received"], sent, reason, "forward",
                                                  action.get("rule_priority", "0")), info)
                finally:
                    if conn:
                        conn.close()

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _handle

        self.server = call_in_netns(self.ns, lambda: _Server(("0.0.0.0", self.port), Handler))
        threading.Thread(target=self.server.serve_forever, name=f"alb:{self.ns}:{self.port}", daemon=True).start()

    def stop(self) -> None:
        if self.server:
            srv, self.server = self.server, None
            threading.Thread(target=lambda: (srv.shutdown(), srv.server_close()), daemon=True).start()


def _connect(ip: str, port: int, timeout: float) -> http.client.HTTPConnection:
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    conn.connect()
    return conn
