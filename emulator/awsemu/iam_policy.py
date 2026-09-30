"""IAM ポリシーの評価エンジン。

AWS のポリシー評価ロジック (明示的 Deny > Allow > 暗黙的 Deny) を再現する。
対応: Action/NotAction, Resource/NotResource, Principal/NotPrincipal, Condition (主要な演算子、
IfExists、ForAnyValue/ForAllValues)、ポリシー変数 ${aws:username} など。
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .core import AwsError, Identity

VARIABLE_RE = re.compile(r"\$\{([^}]+)\}")


@dataclass
class Decision:
    effect: str                                   # Allow | ExplicitDeny | ImplicitDeny
    source: str = ""                              # identity | resource
    matched: list[dict[str, Any]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == "Allow"


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_document(text: str | dict, identity_policy: bool = True) -> dict[str, Any]:
    """ポリシー文書を検証してパースする。不正なら MalformedPolicyDocument。"""
    if isinstance(text, dict):
        doc = text
    else:
        try:
            doc = json.loads(text)
        except ValueError:
            raise AwsError("MalformedPolicyDocument", "Syntax errors in policy.")
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise AwsError("MalformedPolicyDocument", "Syntax errors in policy.")
    for st in as_list(doc["Statement"]):
        if not isinstance(st, dict):
            raise AwsError("MalformedPolicyDocument", "Syntax errors in policy.")
        if st.get("Effect") not in ("Allow", "Deny"):
            raise AwsError("MalformedPolicyDocument", "Policy statement must contain an effect")
        if "Action" not in st and "NotAction" not in st:
            raise AwsError("MalformedPolicyDocument", "Policy statement must contain actions.")
        if identity_policy:
            if "Principal" in st or "NotPrincipal" in st:
                raise AwsError("MalformedPolicyDocument", "Policy document should not specify a principal.")
            if "Resource" not in st and "NotResource" not in st:
                raise AwsError("MalformedPolicyDocument", "Policy statement must contain resources.")
        elif "Principal" not in st and "NotPrincipal" not in st:
            raise AwsError("MalformedPolicyDocument", "Missing required field Principal")
    return doc


# ============================================================================ matching
def _wildcard(pattern: str, value: str, case_sensitive: bool = True) -> bool:
    if not case_sensitive:
        pattern, value = pattern.lower(), value.lower()
    # fnmatch の [] 解釈を避けるため * と ? 以外はエスケープする
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, value, re.S) is not None


def _substitute(text: str, ctx: dict[str, Any]) -> str:
    def repl(m: re.Match) -> str:
        key = m.group(1)
        if key in ("*", "?", "$"):
            return key
        value = ctx.get(key.lower())
        return str(value) if value is not None else m.group(0)
    return VARIABLE_RE.sub(repl, text)


def _action_match(patterns: list[str], action: str) -> bool:
    return any(_wildcard(p, action, case_sensitive=False) for p in patterns)


def _resource_match(patterns: list[str], resource: str, ctx: dict[str, Any]) -> bool:
    return any(_wildcard(_substitute(p, ctx), resource) for p in patterns)


def principal_matches(spec: Any, identity: Identity) -> str | None:
    """Principal との照合結果。"direct" は本人を名指し、"account" はアカウント全体への委任 (ID ポリシーの許可も必要)。"""
    if spec == "*":
        return "direct"
    if not isinstance(spec, dict):
        return None
    if identity.type == "AWSService":
        return "direct" if identity.arn in as_list(spec.get("Service")) else None
    result = None
    for value in as_list(spec.get("AWS")):
        if value == "*":
            return "direct"
        if any(_wildcard(value, arn) for arn in identity.principal_arns()):
            return "direct"
        if value in (identity.account, f"arn:aws:iam::{identity.account}:root") and identity.type != "Anonymous":
            result = "account"
    return result


# ============================================================================ conditions
def _to_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_date(v: Any) -> float | None:
    if v is None:
        return None
    n = _to_number(v)
    if n is not None:
        return n
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _compare(op: str, actual: Any, expected: Any) -> bool:
    base = op
    if base.startswith("String"):
        a, e = str(actual), str(expected)
        if base == "StringEquals":
            return a == e
        if base == "StringNotEquals":
            return a != e
        if base == "StringEqualsIgnoreCase":
            return a.lower() == e.lower()
        if base == "StringNotEqualsIgnoreCase":
            return a.lower() != e.lower()
        if base == "StringLike":
            return _wildcard(e, a)
        if base == "StringNotLike":
            return not _wildcard(e, a)
    if base.startswith("Numeric"):
        a, e = _to_number(actual), _to_number(expected)
        if a is None or e is None:
            return False
        return {"NumericEquals": a == e, "NumericNotEquals": a != e, "NumericLessThan": a < e,
                "NumericLessThanEquals": a <= e, "NumericGreaterThan": a > e,
                "NumericGreaterThanEquals": a >= e}.get(base, False)
    if base.startswith("Date"):
        a, e = _to_date(actual), _to_date(expected)
        if a is None or e is None:
            return False
        return {"DateEquals": a == e, "DateNotEquals": a != e, "DateLessThan": a < e,
                "DateLessThanEquals": a <= e, "DateGreaterThan": a > e,
                "DateGreaterThanEquals": a >= e}.get(base, False)
    if base == "Bool":
        return str(actual).lower() == str(expected).lower()
    if base in ("IpAddress", "NotIpAddress"):
        try:
            inside = ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
        return inside if base == "IpAddress" else not inside
    if base in ("ArnEquals", "ArnLike"):
        return _wildcard(str(expected), str(actual))
    if base in ("ArnNotEquals", "ArnNotLike"):
        return not _wildcard(str(expected), str(actual))
    raise AwsError("MalformedPolicyDocument", f"Unsupported condition operator: {op}")


NEGATED = {"StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "NumericNotEquals",
           "DateNotEquals", "NotIpAddress", "ArnNotEquals", "ArnNotLike"}


def conditions_match(conditions: dict[str, Any], ctx: dict[str, Any]) -> bool:
    for raw_op, entries in (conditions or {}).items():
        qualifier, _, op = raw_op.rpartition(":")
        if_exists = op.endswith("IfExists")
        op = op[: -len("IfExists")] if if_exists else op
        for key, expected in entries.items():
            actual = ctx.get(key.lower())
            expected_values = [_substitute(str(v), ctx) if isinstance(v, str) else v for v in as_list(expected)]
            if op == "Null":
                is_null = actual is None or actual == []
                if not any(str(v).lower() == str(is_null).lower() for v in expected_values):
                    return False
                continue
            if actual is None or actual == []:
                if if_exists:
                    continue
                # 否定系演算子はキーが無いと true (AWS の仕様)
                if op in NEGATED and qualifier != "ForAnyValue":
                    continue
                if qualifier == "ForAllValues":
                    continue
                return False
            actuals = as_list(actual)
            negated = op in NEGATED
            if qualifier == "ForAllValues":
                ok = all(any(_compare(op, a, e) for e in expected_values) if not negated
                         else all(_compare(op, a, e) for e in expected_values) for a in actuals)
            elif negated:
                ok = all(_compare(op, a, e) for a in actuals for e in expected_values)
            else:
                ok = any(_compare(op, a, e) for a in actuals for e in expected_values)
            if not ok:
                return False
    return True


# ============================================================================ evaluation
def statement_matches(st: dict[str, Any], action: str, resource: str, ctx: dict[str, Any],
                      identity: Identity | None = None) -> str | bool:
    if "Action" in st and not _action_match(as_list(st["Action"]), action):
        return False
    if "NotAction" in st and _action_match(as_list(st["NotAction"]), action):
        return False
    if "Resource" in st and not _resource_match(as_list(st["Resource"]), resource, ctx):
        return False
    if "NotResource" in st and _resource_match(as_list(st["NotResource"]), resource, ctx):
        return False
    principal: str | bool = True
    if identity is not None:
        if "Principal" in st:
            principal = principal_matches(st["Principal"], identity) or False
            if not principal:
                return False
        if "NotPrincipal" in st and principal_matches(st["NotPrincipal"], identity):
            return False
        if "NotPrincipal" in st:
            principal = "direct"
    if not conditions_match(st.get("Condition", {}), ctx):
        return False
    return principal


def evaluate(identity: Identity, identity_policies: list[dict[str, Any]], resource_policy: dict[str, Any] | None,
             action: str, resource: str, ctx: dict[str, Any]) -> Decision:
    allow_identity: list[dict] = []
    allow_resource: list[dict] = []
    for doc in identity_policies:
        for st in as_list(doc.get("Statement")):
            if statement_matches(st, action, resource, ctx):
                if st["Effect"] == "Deny":
                    return Decision("ExplicitDeny", "identity", [st])
                allow_identity.append(st)
    if resource_policy:
        for st in as_list(resource_policy.get("Statement")):
            match = statement_matches(st, action, resource, ctx, identity)
            if match:
                if st["Effect"] == "Deny":
                    return Decision("ExplicitDeny", "resource", [st])
                # アカウント全体への委任は、それだけでは許可にならない (ID ポリシー側の許可が必要)
                if match == "direct":
                    allow_resource.append(st)
    if allow_identity:
        return Decision("Allow", "identity", allow_identity)
    if allow_resource:
        return Decision("Allow", "resource", allow_resource)
    return Decision("ImplicitDeny")


def base_context(identity: Identity, req_region: str, source_ip: str, now: float) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "aws:principalarn": identity.role_arn or identity.arn,
        "aws:principalaccount": identity.account,
        "aws:principaltype": identity.type,
        "aws:userid": identity.principal_id,
        "aws:sourceip": source_ip,
        "aws:securetransport": "false",
        "aws:currenttime": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aws:epochtime": str(int(now)),
        "aws:requestedregion": req_region,
        "aws:multifactorauthpresent": "false",
    }
    if identity.type == "IAMUser":
        ctx["aws:username"] = identity.user_name
    return ctx


def denial_message(identity: Identity, action: str, resource: str, decision: Decision) -> str:
    who = "Anonymous caller" if identity.type == "Anonymous" else f"User: {identity.arn}"
    base = f"{who} is not authorized to perform: {action} on resource: {resource}"
    if decision.effect == "ExplicitDeny":
        where = "a resource-based policy" if decision.source == "resource" else "an identity-based policy"
        return f"{base} with an explicit deny in {where}"
    return f"{base} because no identity-based policy allows the {action} action"


