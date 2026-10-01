"""インスタンスメタデータサービス (169.254.169.254)。

AWS と同じくインスタンスのポートを消費しないよう、VPC ルーターの名前空間で待ち受け、
送信元 IP から呼び出し元インスタンスを特定する。セキュリティグループの影響も受けない。
"""
from __future__ import annotations

import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .linux import call_in_netns

IMDS_IP = "169.254.169.254"
Responder = Callable[[str, str, dict[str, str], str], "tuple[int, bytes | None, dict[str, str]]"]


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self) -> None:
        # HTTPServer.server_bind は逆引き DNS (getfqdn) を行い、リンクローカルアドレスでは長時間ブロックするため使わない
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = IMDS_IP, 80


class ImdsServer:
    def __init__(self, ns: str, responder: Responder) -> None:
        self.ns = ns
        self.responder = responder
        self.server: _Server | None = None

    def start(self) -> None:
        responder = self.responder

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "EC2ws"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                status, body, headers = responder(self.command, self.path, dict(self.headers.items()),
                                                  self.client_address[0])
                if body is None:  # エンドポイント無効: 応答せずに切断
                    self.close_connection = True
                    return
                self.send_response(status)
                for k, v in {"Content-Type": "text/plain", **headers}.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_PUT = do_HEAD = do_POST = _handle

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        self.server = call_in_netns(self.ns, lambda: _Server((IMDS_IP, 80), Handler))
        threading.Thread(target=self.server.serve_forever, name=f"imds:{self.ns}", daemon=True).start()

    def stop(self) -> None:
        if self.server:
            srv, self.server = self.server, None
            threading.Thread(target=lambda: (srv.shutdown(), srv.server_close()), daemon=True).start()


