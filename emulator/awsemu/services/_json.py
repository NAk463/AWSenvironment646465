"""awsJson1.0 プロトコル (X-Amz-Target ヘッダでオペレーションを指定) の共通処理。"""
from __future__ import annotations

import json
from typing import Any

from ..core import AwsError, Request, Response, Service


class JsonService(Service):
    target_prefix = ""
    json_version = "1.0"
    error_namespace = ""
    # awsQueryCompatible なサービス (SQS) 用: 新エラーコード -> 旧 Query API のエラーコード
    query_error_codes: dict[str, str] = {}

    def operation(self, req: Request) -> str:
        target = req.header("X-Amz-Target") or ""
        return target.rsplit(".", 1)[1] if "." in target else "Unknown"

    def params(self, req: Request) -> dict[str, Any]:
        if not req.body:
            return {}
        try:
            data = json.loads(req.body)
        except ValueError:
            raise AwsError("SerializationException", "Request body is not valid JSON")
        if not isinstance(data, dict):
            raise AwsError("SerializationException", "Request body must be a JSON object")
        return data

    def params_for_log(self, req: Request, op: str) -> Any:
        try:
            return self.params(req)
        except AwsError:
            return None

    def handle(self, req: Request, op: str) -> Response:
        method = getattr(self, f"op_{op}", None)
        if method is None:
            raise AwsError("UnknownOperationException", f"Operation {op} is not implemented by awsemu")
        result = method(self.params(req), req)
        return Response(200, json.dumps(result or {}).encode(),
                        {"Content-Type": f"application/x-amz-json-{self.json_version}"})

    def error_response(self, req: Request, err: AwsError) -> Response:
        headers = {"Content-Type": f"application/x-amz-json-{self.json_version}", "x-amzn-ErrorType": err.code}
        if self.query_error_codes:
            legacy = self.query_error_codes.get(err.code, err.code)
            headers["x-amzn-query-error"] = f"{legacy};{'Sender' if err.sender_fault else 'Receiver'}"
        body = {"__type": f"{self.error_namespace}#{err.code}", "message": err.message, **err.extra}
        return Response(err.status, json.dumps(body).encode(), headers)


def require(params: dict[str, Any], *names: str) -> None:
    for name in names:
        if params.get(name) in (None, ""):
            raise AwsError("ValidationException", f"1 validation error detected: Value null at '{name}' "
                           "failed to satisfy constraint: Member must not be null")
