"""最小限の CBOR (RFC 8949) エンコーダ / デコーダ。CloudWatch の smithy-rpc-v2-cbor プロトコル用。"""
from __future__ import annotations

import struct
from typing import Any


class Timestamp(float):
    """CBOR のタグ 1 (エポック秒) として出力する時刻。"""


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)


def dumps(value: Any) -> bytes:
    out = bytearray()
    _encode(value, out)
    return bytes(out)


def _encode(v: Any, out: bytearray) -> None:
    if isinstance(v, Timestamp):
        out += b"\xc1" + b"\xfb" + struct.pack(">d", float(v))
    elif v is None:
        out.append(0xF6)
    elif v is True:
        out.append(0xF5)
    elif v is False:
        out.append(0xF4)
    elif isinstance(v, int):
        out += _head(0, v) if v >= 0 else _head(1, -1 - v)
    elif isinstance(v, float):
        out += b"\xfb" + struct.pack(">d", v)
    elif isinstance(v, str):
        data = v.encode()
        out += _head(3, len(data)) + data
    elif isinstance(v, (bytes, bytearray)):
        out += _head(2, len(v)) + bytes(v)
    elif isinstance(v, (list, tuple)):
        out += _head(4, len(v))
        for item in v:
            _encode(item, out)
    elif isinstance(v, dict):
        out += _head(5, len(v))
        for k, item in v.items():
            _encode(k, out)
            _encode(item, out)
    else:
        raise TypeError(f"cannot CBOR-encode {type(v)!r}")


def loads(data: bytes) -> Any:
    if not data:
        return None
    value, _ = _decode(data, 0)
    return value


BREAK = object()


def _decode(data: bytes, pos: int) -> tuple[Any, int]:
    first = data[pos]
    pos += 1
    major, info = first >> 5, first & 0x1F
    if first == 0xFF:
        return BREAK, pos
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info in (22, 23):
            return None, pos
        if info == 25:
            return _half(data[pos:pos + 2]), pos + 2
        if info == 26:
            return struct.unpack(">f", data[pos:pos + 4])[0], pos + 4
        if info == 27:
            return struct.unpack(">d", data[pos:pos + 8])[0], pos + 8
        return None, pos
    if info < 24:
        n = info
    elif info == 24:
        n, pos = data[pos], pos + 1
    elif info == 25:
        n, pos = struct.unpack(">H", data[pos:pos + 2])[0], pos + 2
    elif info == 26:
        n, pos = struct.unpack(">I", data[pos:pos + 4])[0], pos + 4
    elif info == 27:
        n, pos = struct.unpack(">Q", data[pos:pos + 8])[0], pos + 8
    elif info == 31:
        n = -1  # 不定長
    else:
        raise ValueError("invalid CBOR additional info")

    if major == 0:
        return n, pos
    if major == 1:
        return -1 - n, pos
    if major in (2, 3):
        if n < 0:
            chunks = []
            while True:
                chunk, pos = _decode(data, pos)
                if chunk is BREAK:
                    break
                chunks.append(chunk)
            joined = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks)
            return (joined if major == 2 else joined.decode()), pos
        raw = data[pos:pos + n]
        return (bytes(raw) if major == 2 else raw.decode()), pos + n
    if major == 4:
        items = []
        while n < 0 or len(items) < n:
            item, pos = _decode(data, pos)
            if item is BREAK:
                break
            items.append(item)
        return items, pos
    if major == 5:
        obj: dict[Any, Any] = {}
        count = 0
        while n < 0 or count < n:
            k, pos = _decode(data, pos)
            if k is BREAK:
                break
            obj[k], pos = _decode(data, pos)
            count += 1
        return obj, pos
    if major == 6:
        value, pos = _decode(data, pos)
        return (Timestamp(value) if n == 1 else value), pos
    raise ValueError("invalid CBOR major type")


def _half(b: bytes) -> float:
    h = struct.unpack(">H", b)[0]
    exp, mant = (h >> 10) & 0x1F, h & 0x3FF
    if exp == 0:
        val = mant * 2 ** -24
    elif exp == 31:
        val = float("inf") if mant == 0 else float("nan")
    else:
        val = (mant + 1024) * 2 ** (exp - 25)
    return -val if h & 0x8000 else val
