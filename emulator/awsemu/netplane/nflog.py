"""VPC フローログ: iptables の NFLOG でパケットを受け取り、ENI ごと・5 タプルごとに集計する。

- ENI の名前空間 (インスタンス / ALB) の SG で ACCEPT / REJECT されたパケット
- VPC ルーターの NACL で拒否されたパケット (REJECT)
を netlink (NETLINK_NETFILTER / NFULNL) で読み取る。外部ライブラリは使わない。
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Callable

from .linux import NFLOG_GROUP, setns

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10
CMD_BIND, CMD_PF_BIND, CMD_PF_UNBIND = 1, 3, 4
NLM_F_REQUEST, NLM_F_ACK = 1, 4
COPY_PACKET = 2

Packet = tuple[str, str, str, int, int, int, int]   # (prefix, src, dst, sport, dport, proto, length)


def _attr(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + b"\0" * ((4 - length % 4) % 4)


def _config(seq: int, family: int, res_id: int, attrs: bytes) -> bytes:
    body = struct.pack("BB", family, 0) + struct.pack(">H", res_id) + attrs
    return struct.pack("=IHHII", 16 + len(body), (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
                       NLM_F_REQUEST | NLM_F_ACK, seq, 0) + body


def parse_messages(data: bytes) -> list[Packet]:
    out = []
    pos = 0
    while pos + 16 <= len(data):
        length, mtype, _, _, _ = struct.unpack_from("=IHHII", data, pos)
        if length < 16:
            break
        if mtype == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
            prefix, payload = "", b""
            apos = pos + 16 + 4
            end = pos + length
            while apos + 4 <= end:
                alen, atype = struct.unpack_from("=HH", data, apos)
                if alen < 4:
                    break
                value = data[apos + 4:apos + alen]
                atype &= 0x3FFF
                if atype == NFULA_PREFIX:
                    prefix = value.rstrip(b"\0").decode(errors="replace")
                elif atype == NFULA_PAYLOAD:
                    payload = value
                apos += (alen + 3) & ~3
            pkt = parse_ipv4(prefix, payload)
            if pkt:
                out.append(pkt)
        pos += (length + 3) & ~3
    return out


def parse_ipv4(prefix: str, b: bytes) -> Packet | None:
    if len(b) < 20 or b[0] >> 4 != 4:
        return None
    ihl = (b[0] & 0x0F) * 4
    total = struct.unpack_from(">H", b, 2)[0]
    proto = b[9]
    src, dst = socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20])
    sport = dport = 0
    if proto in (6, 17) and len(b) >= ihl + 4:
        sport, dport = struct.unpack_from(">HH", b, ihl)
    return prefix, src, dst, sport, dport, proto, total


class NflogReader:
    """1 つのネットワーク名前空間の NFLOG を読み続けるスレッド。"""

    def __init__(self, ns: str, callback: Callable[[str, Packet], None]) -> None:
        self.ns = ns
        self.callback = callback
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.error: Exception | None = None
        self.thread = threading.Thread(target=self._run, name=f"nflog:{ns}", daemon=True)

    def start(self) -> None:
        self.thread.start()
        self.ready.wait(3)

    def stop(self) -> None:
        self.stop_event.set()

    def _run(self) -> None:
        try:
            setns(self.ns)
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
            sock.bind((0, 0))
            sock.settimeout(1.0)
            for msg in [
                _config(1, socket.AF_INET, 0, _attr(NFULA_CFG_CMD, bytes([CMD_PF_UNBIND]))),
                _config(2, socket.AF_INET, 0, _attr(NFULA_CFG_CMD, bytes([CMD_PF_BIND]))),
                _config(3, socket.AF_UNSPEC, NFLOG_GROUP, _attr(NFULA_CFG_CMD, bytes([CMD_BIND]))),
                _config(4, socket.AF_UNSPEC, NFLOG_GROUP, _attr(NFULA_CFG_MODE, struct.pack(">IBB", 96, COPY_PACKET, 0))),
            ]:
                sock.send(msg)
                try:
                    sock.recv(65536)
                except socket.timeout:
                    pass
        except Exception as exc:  # noqa: BLE001
            self.error = exc
            self.ready.set()
            return
        self.ready.set()
        while not self.stop_event.is_set():
            try:
                data = sock.recv(1 << 20)
            except socket.timeout:
                continue
            except OSError:
                break
            for pkt in parse_messages(data):
                try:
                    self.callback(self.ns, pkt)
                except Exception:  # noqa: BLE001
                    pass
        sock.close()
