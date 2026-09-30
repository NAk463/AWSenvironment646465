"""STS (Query プロトコル)。AssumeRole は信頼ポリシーと ID ポリシーを評価して一時認証情報を発行する。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Identity, Request
from ..iam_policy import as_list, base_context, principal_matches
from ._query import QueryService, require


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class STS(QueryService):
    name = "sts"
    iam_prefix = "sts"
    event_source = "sts.amazonaws.com"
    xml_namespace = "https://sts.amazonaws.com/doc/2011-06-15/"
    version = "2011-06-15"

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        # GetCallerIdentity は権限不要。AssumeRole は信頼ポリシーと合わせてハンドラ内で評価する
        return []

    @property
    def iam(self):
        return self.emu.services["iam"]

    def _credentials(self, session) -> dict[str, Any]:
        return {"AccessKeyId": session.access_key, "SecretAccessKey": session.secret,
                "SessionToken": session.token, "Expiration": iso(session.expiration)}

    def op_GetCallerIdentity(self, p, req):
        ident = req.identity
        user_id = ident.account if ident.is_root else ident.principal_id
        return {"UserId": user_id, "Account": ident.account, "Arn": ident.arn}

    def op_AssumeRole(self, p, req):
        require(p, "RoleArn", "RoleSessionName")
        caller = req.identity
        role_arn, session_name = p["RoleArn"], p["RoleSessionName"]
        duration = int(p.get("DurationSeconds") or 3600)
        denied = AwsError("AccessDenied", f"User: {caller.arn} is not authorized to perform: sts:AssumeRole "
                                          f"on resource: {role_arn}", 403)
        with self.iam.lock:
            role = self.iam.roles.get(role_arn.rsplit("/", 1)[-1])
            if role is None or role.arn != role_arn:
                raise denied
            trust = json.loads(role.trust_policy or "{}")
            ctx = base_context(caller, req.region, req.client_ip, self.clock.now())
            decision = self.iam.authorize(caller, "sts:AssumeRole", role_arn, trust, ctx)
            # 信頼ポリシーが呼び出し元 (またはそのアカウント) を Principal に含み、かつ許可されていること
            if not decision.allowed or not self._trusts(trust, caller):
                raise denied
            max_duration = 3600 if caller.type == "AssumedRole" else role.max_session
            if not 900 <= duration <= max_duration:
                raise AwsError("ValidationError", "The requested DurationSeconds exceeds the MaxSessionDuration "
                               "set for this role." if duration > max_duration else
                               "1 validation error detected: Value at 'durationSeconds' failed to satisfy "
                               "constraint: Member must have value greater than or equal to 900")
            identity = Identity(
                "AssumedRole", f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role.name}/{session_name}",
                f"{role.id}:{session_name}", role_arn=role.arn, role_id=role.id, session_name=session_name)
            session = self.iam.create_session(identity, duration, "role", role.name)
        req.ctx["trail_response"] = {
            "credentials": {"accessKeyId": session.access_key, "expiration": iso(session.expiration)},
            "assumedRoleUser": {"assumedRoleId": identity.principal_id, "arn": identity.arn}}
        return {"Credentials": self._credentials(session),
                "AssumedRoleUser": {"AssumedRoleId": identity.principal_id, "Arn": identity.arn}}

    @staticmethod
    def _trusts(trust: dict[str, Any], caller: Identity) -> bool:
        """信頼ポリシーの Principal が呼び出し元 (またはそのアカウント) を含むか。"""
        return any(st.get("Effect") == "Allow" and principal_matches(st.get("Principal"), caller)
                   for st in as_list(trust.get("Statement")))

    def op_GetSessionToken(self, p, req):
        caller = req.identity
        if caller.type == "AssumedRole":
            raise AwsError("AccessDenied", "Cannot call GetSessionToken with session credentials", 403)
        duration = int(p.get("DurationSeconds") or 43200)
        if not 900 <= duration <= 129600:
            raise AwsError("ValidationError", "DurationSeconds must be between 900 and 129600")
        with self.iam.lock:
            session = self.iam.create_session(caller, duration, "user", caller.user_name or "root")
        return {"Credentials": self._credentials(session)}

    def reset(self) -> None:
        pass

    def state(self) -> dict[str, Any]:
        return {"account_id": ACCOUNT_ID}

    def load(self, data: dict[str, Any]) -> None:
        pass
