"""STS (Query プロトコル)。認証まわりの呼び出しが通るよう最小限を実装。"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs
from xml.sax.saxutils import escape

from ..core import ACCOUNT_ID, AwsError, Request, Response, Service

NS = "https://sts.amazonaws.com/doc/2011-06-15/"


class STS(Service):
    name = "sts"

    def _params(self, req: Request) -> dict[str, str]:
        body = {k: v[-1] for k, v in parse_qs(req.body.decode(), keep_blank_values=True).items()}
        return {**req.query, **body}

    def operation(self, req: Request) -> str:
        return self._params(req).get("Action", "Unknown")

    def params_for_log(self, req: Request, op: str) -> Any:
        return {k: v for k, v in self._params(req).items() if k not in ("Action", "Version")}

    def handle(self, req: Request, op: str) -> Response:
        p = self._params(req)
        if op == "GetCallerIdentity":
            inner = (f"<Arn>arn:aws:iam::{ACCOUNT_ID}:root</Arn><UserId>{ACCOUNT_ID}</UserId>"
                     f"<Account>{ACCOUNT_ID}</Account>")
        elif op in ("AssumeRole", "GetSessionToken"):
            inner = self._credentials(int(p.get("DurationSeconds", 3600)))
            if op == "AssumeRole":
                if not p.get("RoleArn") or not p.get("RoleSessionName"):
                    raise AwsError("ValidationError", "RoleArn and RoleSessionName are required")
                role = p["RoleArn"].rsplit("/", 1)[-1]
                inner += (f"<AssumedRoleUser><AssumedRoleId>AROAEMULATOR:{escape(p['RoleSessionName'])}</AssumedRoleId>"
                          f"<Arn>arn:aws:sts::{ACCOUNT_ID}:assumed-role/{escape(role)}/{escape(p['RoleSessionName'])}</Arn>"
                          "</AssumedRoleUser>")
        else:
            raise AwsError("InvalidAction", f"Could not find operation {op} for version 2011-06-15")
        body = (f'<{op}Response xmlns="{NS}"><{op}Result>{inner}</{op}Result>'
                f"<ResponseMetadata><RequestId>{req.request_id}</RequestId></ResponseMetadata></{op}Response>")
        return Response(200, body.encode(), {"Content-Type": "text/xml"})

    def _credentials(self, duration: int) -> str:
        exp = (datetime.fromtimestamp(self.clock.now(), timezone.utc) + timedelta(seconds=duration))
        return ("<Credentials>"
                f"<AccessKeyId>ASIA{secrets.token_hex(8).upper()}</AccessKeyId>"
                f"<SecretAccessKey>{secrets.token_urlsafe(30)}</SecretAccessKey>"
                f"<SessionToken>{secrets.token_urlsafe(60)}</SessionToken>"
                f"<Expiration>{exp.strftime('%Y-%m-%dT%H:%M:%SZ')}</Expiration>"
                "</Credentials>")

    def error_response(self, req: Request, err: AwsError) -> Response:
        body = (f'<ErrorResponse xmlns="{NS}"><Error><Type>{"Sender" if err.sender_fault else "Receiver"}</Type>'
                f"<Code>{escape(err.code)}</Code><Message>{escape(err.message)}</Message></Error>"
                f"<RequestId>{req.request_id}</RequestId></ErrorResponse>")
        return Response(err.status, body.encode(), {"Content-Type": "text/xml"})

    def reset(self) -> None:
        pass

    def state(self) -> dict[str, Any]:
        return {"account_id": ACCOUNT_ID}

    def load(self, data: dict[str, Any]) -> None:
        pass
