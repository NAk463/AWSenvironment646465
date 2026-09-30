"""AWS Query プロトコル (IAM / STS など: フォーム形式のリクエスト、XML レスポンス) の共通処理。"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs
from xml.sax.saxutils import escape

from ..core import AwsError, Request, Response, Service


def nest_params(flat: dict[str, str]) -> dict[str, Any]:
    """`A.member.1.B=x` 形式のフラットなパラメータを入れ子の dict / list に変換する。"""
    root: dict[str, Any] = {}
    for key, value in flat.items():
        parts = key.split(".")
        cur = root
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
            if not isinstance(cur, dict):
                break
        else:
            cur[parts[-1]] = value

    def convert(node: Any) -> Any:
        if not isinstance(node, dict):
            return node
        if set(node) == {"member"} and isinstance(node["member"], dict):
            items = node["member"]
            return [convert(items[k]) for k in sorted(items, key=lambda x: int(x) if x.isdigit() else 0)]
        if node and all(k.isdigit() for k in node):
            return [convert(node[k]) for k in sorted(node, key=int)]
        return {k: convert(v) for k, v in node.items()}

    return convert(root)


def to_xml(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return "".join(f"<{k}>{to_xml(v)}</{k}>" for k, v in value.items() if v is not None)
    if isinstance(value, list):
        return "".join(f"<member>{to_xml(v)}</member>" for v in value)
    return escape(str(value))


class QueryService(Service):
    xml_namespace = ""
    version = ""

    def flat_params(self, req: Request) -> dict[str, str]:
        cached = req.ctx.get("_query_params")
        if cached is None:
            body = {}
            if req.body and "json" not in (req.header("Content-Type") or ""):
                body = {k: v[-1] for k, v in parse_qs(req.body.decode(), keep_blank_values=True).items()}
            cached = {**req.query, **body}
            req.ctx["_query_params"] = cached
        return cached

    def operation(self, req: Request) -> str:
        return self.flat_params(req).get("Action", "Unknown")

    def params(self, req: Request) -> dict[str, Any]:
        flat = {k: v for k, v in self.flat_params(req).items()
                if k not in ("Action", "Version") and not k.startswith("X-Amz-")}
        return nest_params(flat)

    def params_for_log(self, req: Request, op: str) -> Any:
        p = self.params(req)
        for secret in ("PolicyDocument", "AssumeRolePolicyDocument"):
            if secret in p and len(p[secret]) > 500:
                p[secret] = p[secret][:500] + "..."
        return p

    def handle(self, req: Request, op: str) -> Response:
        method = getattr(self, f"op_{op}", None)
        if method is None:
            raise AwsError("InvalidAction", f"Could not find operation {op} for version {self.version}")
        with self.lock:
            result = method(self.params(req), req)
        inner = f"<{op}Result>{to_xml(result)}</{op}Result>" if result is not None else ""
        body = (f'<{op}Response xmlns="{self.xml_namespace}">{inner}'
                f"<ResponseMetadata><RequestId>{req.request_id}</RequestId></ResponseMetadata></{op}Response>")
        return Response(200, body.encode(), {"Content-Type": "text/xml"})

    def error_response(self, req: Request, err: AwsError) -> Response:
        body = (f'<ErrorResponse xmlns="{self.xml_namespace}"><Error>'
                f'<Type>{"Sender" if err.sender_fault else "Receiver"}</Type>'
                f"<Code>{escape(err.code)}</Code><Message>{escape(err.message)}</Message></Error>"
                f"<RequestId>{req.request_id}</RequestId></ErrorResponse>")
        return Response(err.status, body.encode(), {"Content-Type": "text/xml"})


def require(p: dict[str, Any], *names: str) -> None:
    for n in names:
        if not p.get(n):
            raise AwsError("ValidationError",
                           f"1 validation error detected: Value null at '{n[0].lower() + n[1:]}' failed to satisfy "
                           "constraint: Member must not be null")


NAME_RE = re.compile(r"^[\w+=,.@-]{1,128}$")
