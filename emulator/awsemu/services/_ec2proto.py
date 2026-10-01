"""EC2 プロトコル (Query 形式の入力 + EC2 独自の XML 出力) と、Describe 系の Filter 処理。

入出力の要素名は EC2 では不規則 (Reservations -> reservationSet/item, SecurityGroups -> groupSet …) なため、
botocore のモデルから生成した awsemu/models/ec2.json に従って変換する。
"""
from __future__ import annotations

import base64
import fnmatch
import json
import pathlib
import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs
from xml.sax.saxutils import escape

from ..core import AwsError, Request, Response, Service

MODEL = json.loads((pathlib.Path(__file__).resolve().parent.parent / "models" / "ec2.json").read_text())
SHAPES: dict[str, dict[str, Any]] = MODEL["shapes"]
NAMESPACE = MODEL["metadata"]["xmlNamespace"]


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ============================================================================ input
def _parse(shape_name: str, key: str, flat: dict[str, str], keys: list[str]) -> Any:
    shape = SHAPES[shape_name]
    t = shape["t"]
    if t == "s":
        out = {}
        for member, (sub, query, _) in shape["m"].items():
            value = _parse(sub, f"{key}.{query}" if key else query, flat, keys)
            if value is not None:
                out[member] = value
        return out if out or not key else None
    if t == "l":
        items = []
        i = 1
        while True:
            item_key = f"{key}.{i}"
            if item_key not in flat and not any(k.startswith(item_key + ".") for k in keys):
                break
            value = _parse(shape["m"], item_key, flat, keys)
            if value is not None:
                items.append(value)
            i += 1
        return items or None
    if key not in flat:
        return None
    raw = flat[key]
    if t in ("integer", "long"):
        try:
            return int(raw)
        except ValueError:
            raise AwsError("InvalidParameterValue", f"Value ({raw}) for parameter {key} is invalid.")
    if t in ("double", "float"):
        return float(raw)
    if t == "boolean":
        return raw.lower() == "true"
    if t == "blob":
        return base64.b64decode(raw)
    return raw


def parse_input(op: str, req: Request) -> dict[str, Any]:
    body = {}
    if req.body:
        body = {k: v[-1] for k, v in parse_qs(req.body.decode(), keep_blank_values=True).items()}
    flat = {**req.query, **body}
    shape = MODEL["operations"][op]["i"]
    if not shape:
        return {}
    keys = list(flat)
    return _parse(shape, "", flat, keys) or {}


# ============================================================================ output
def _ser(shape_name: str, value: Any) -> str:
    shape = SHAPES[shape_name]
    t = shape["t"]
    if t == "s":
        if not isinstance(value, dict):
            raise TypeError(f"{shape_name}: expected dict, got {type(value).__name__}")
        parts = []
        members = shape["m"]
        for k, v in value.items():
            if v is None:
                continue
            if k not in members:
                raise KeyError(f"{shape_name} has no member {k}")
            sub, _, loc = members[k]
            parts.append(f"<{loc}>{_ser(sub, v)}</{loc}>")
        return "".join(parts)
    if t == "l":
        tag = shape["n"]
        return "".join(f"<{tag}>{_ser(shape['m'], v)}</{tag}>" for v in value)
    if t == "boolean":
        return "true" if value else "false"
    if t == "timestamp":
        return iso(value) if isinstance(value, (int, float)) else escape(str(value))
    if t == "blob":
        return base64.b64encode(value if isinstance(value, bytes) else str(value).encode()).decode()
    return escape(str(value))


def serialize_output(op: str, data: dict[str, Any] | None, request_id: str) -> bytes:
    shape = MODEL["operations"][op]["o"]
    inner = _ser(shape, data or {}) if shape else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<{op}Response xmlns="{NAMESPACE}">'
            f"<requestId>{request_id}</requestId>{inner}</{op}Response>").encode()


def error_body(err: AwsError, request_id: str) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<Response><Errors><Error><Code>{escape(err.code)}</Code>'
            f"<Message>{escape(err.message)}</Message></Error></Errors><RequestID>{request_id}</RequestID>"
            f"</Response>").encode()


class Ec2ProtocolService(Service):
    """EC2 プロトコルのサービス基底クラス。オペレーションは op_<Name>(params, req) で実装する。"""

    def flat(self, req: Request) -> dict[str, str]:
        if "_flat" not in req.ctx:
            body = {}
            if req.body:
                body = {k: v[-1] for k, v in parse_qs(req.body.decode(), keep_blank_values=True).items()}
            req.ctx["_flat"] = {**req.query, **body}
        return req.ctx["_flat"]

    def operation(self, req: Request) -> str:
        return self.flat(req).get("Action", "Unknown")

    def params(self, req: Request, op: str) -> dict[str, Any]:
        if "_params" not in req.ctx:
            if op not in MODEL["operations"]:
                raise AwsError("InvalidAction", f"The action {op} is not valid for this web service.")
            req.ctx["_params"] = parse_input(op, req)
        return req.ctx["_params"]

    def params_for_log(self, req: Request, op: str) -> Any:
        try:
            p = dict(self.params(req, op))
        except AwsError:
            return None
        if "UserData" in p:
            p["UserData"] = "<sensitiveDataRemoved>"
        return p

    def handle(self, req: Request, op: str) -> Response:
        p = self.params(req, op)
        method = getattr(self, f"op_{op}", None)
        if method is None:
            raise AwsError("InvalidAction", f"The action {op} is not valid for this web service.")
        if p.get("DryRun"):
            raise AwsError("DryRunOperation", "Request would have succeeded, but DryRun flag is set.", 412)
        with self.lock:
            result = method(p, req)
        return Response(200, serialize_output(op, result, req.request_id), {"Content-Type": "text/xml;charset=UTF-8"})

    def error_response(self, req: Request, err: AwsError) -> Response:
        return Response(err.status, error_body(err, req.request_id), {"Content-Type": "text/xml;charset=UTF-8"})


# ============================================================================ filters
def tag_filters(tags: dict[str, str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"tag-key": list(tags), "tag-value": list(tags.values())}
    for k, v in tags.items():
        out[f"tag:{k}"] = [v]
    return out


def apply_filters(items: Iterable[Any], filters: list[dict[str, Any]] | None,
                  extract: Callable[[Any], dict[str, Any]]) -> list[Any]:
    """EC2 の Filter (名前ごとに OR、フィルタ間は AND、* ? のワイルドカード) を適用する。"""
    items = list(items)
    if not filters:
        return items
    out = []
    for item in items:
        fields = extract(item)
        ok = True
        for f in filters:
            name, wanted = f.get("Name", ""), f.get("Values") or []
            actual = fields.get(name)
            if name not in fields and not name.startswith("tag:"):
                raise AwsError("InvalidParameterValue", f"The filter '{name}' is invalid")
            actual_values = [str(a).lower() if isinstance(a, bool) else str(a)
                             for a in (actual if isinstance(actual, (list, tuple, set)) else [actual]) if a is not None]
            if not any(fnmatch.fnmatchcase(a, w) for a in actual_values for w in wanted):
                ok = False
                break
        if ok:
            out.append(item)
    return out


def tag_list(tags: dict[str, str]) -> list[dict[str, str]] | None:
    return [{"Key": k, "Value": v} for k, v in tags.items()] or None


def tags_from_specs(specs: list[dict[str, Any]] | None, resource_type: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for spec in specs or []:
        if spec.get("ResourceType") in (resource_type, None):
            for t in spec.get("Tags") or []:
                out[t["Key"]] = t.get("Value", "")
    return out


ID_RE = re.compile(r"^[a-z]+-[0-9a-f]{8,17}$")
