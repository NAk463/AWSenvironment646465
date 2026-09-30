"""IAM (Query プロトコル)。ユーザー・グループ・ロール・ポリシー・アクセスキーと、認証/認可の中核。"""
from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ..core import ACCOUNT_ID, ROOT_IDENTITY, AwsError, Identity, Request
from ..iam_policy import Decision, as_list, base_context, evaluate, parse_document
from ._query import NAME_RE, QueryService, require

ALNUM = string.ascii_uppercase + string.digits


def new_id(prefix: str) -> str:
    return prefix + "".join(secrets.choice(ALNUM) for _ in range(17))


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _statement(actions: list[str], resource: str = "*", not_action: bool = False) -> dict[str, Any]:
    return {"Effect": "Allow", ("NotAction" if not_action else "Action"): actions, "Resource": resource}


# AWS 管理ポリシー (主要なものを簡略化して収録)
AWS_MANAGED: dict[str, list[dict[str, Any]]] = {
    "AdministratorAccess": [_statement(["*"])],
    "PowerUserAccess": [_statement(["iam:*", "organizations:*", "account:*"], not_action=True),
                        _statement(["iam:CreateServiceLinkedRole", "iam:ListRoles", "organizations:DescribeOrganization"])],
    "ReadOnlyAccess": [_statement(["*:Describe*", "*:Get*", "*:List*", "*:Lookup*", "*:BatchGet*", "dynamodb:Query",
                                   "dynamodb:Scan", "logs:FilterLogEvents", "logs:StartQuery", "logs:StopQuery",
                                   "logs:TestMetricFilter", "iam:Simulate*"])],
    "AmazonS3FullAccess": [_statement(["s3:*", "s3-object-lambda:*"])],
    "AmazonS3ReadOnlyAccess": [_statement(["s3:Get*", "s3:List*", "s3:Describe*", "s3-object-lambda:Get*",
                                           "s3-object-lambda:List*"])],
    "AmazonSQSFullAccess": [_statement(["sqs:*"])],
    "AmazonSQSReadOnlyAccess": [_statement(["sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ListDeadLetterSourceQueues",
                                            "sqs:ListQueues", "sqs:ListQueueTags", "sqs:ListMessageMoveTasks"])],
    "AmazonDynamoDBFullAccess": [_statement(["dynamodb:*", "cloudwatch:DeleteAlarms", "cloudwatch:DescribeAlarms",
                                             "cloudwatch:GetMetricData", "cloudwatch:PutMetricAlarm"])],
    "AmazonDynamoDBReadOnlyAccess": [_statement(["dynamodb:BatchGetItem", "dynamodb:Describe*", "dynamodb:List*",
                                                 "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan",
                                                 "dynamodb:PartiQLSelect", "cloudwatch:GetMetricData",
                                                 "cloudwatch:GetMetricStatistics", "cloudwatch:DescribeAlarms"])],
    "CloudWatchFullAccess": [_statement(["cloudwatch:*", "logs:*", "sns:*", "autoscaling:Describe*"])],
    "CloudWatchReadOnlyAccess": [_statement(["cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
                                             "logs:Get*", "logs:List*", "logs:Describe*", "logs:StartQuery",
                                             "logs:StopQuery", "logs:TestMetricFilter", "logs:FilterLogEvents",
                                             "logs:StartLiveTail", "logs:StopLiveTail", "sns:Get*", "sns:List*"])],
    "CloudWatchLogsFullAccess": [_statement(["logs:*"])],
    "CloudWatchLogsReadOnlyAccess": [_statement(["logs:Describe*", "logs:Get*", "logs:List*", "logs:StartQuery",
                                                 "logs:StopQuery", "logs:TestMetricFilter", "logs:FilterLogEvents",
                                                 "logs:StartLiveTail", "logs:StopLiveTail"])],
    "AWSCloudTrail_FullAccess": [_statement(["cloudtrail:*"])],
    "AWSCloudTrail_ReadOnlyAccess": [_statement(["cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
                                                 "cloudtrail:LookupEvents"])],
    "IAMFullAccess": [_statement(["iam:*"])],
    "IAMReadOnlyAccess": [_statement(["iam:Generate*", "iam:Get*", "iam:List*", "iam:Simulate*"])],
}


@dataclass
class Entity:
    kind: str                         # user | group | role
    name: str
    id: str
    arn: str
    path: str
    created: float
    inline: dict[str, str] = field(default_factory=dict)
    attached: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)          # user のみ
    trust_policy: str | None = None                          # role のみ
    description: str | None = None
    max_session: int = 3600


@dataclass
class ManagedPolicy:
    arn: str
    name: str
    id: str
    path: str
    created: float
    versions: dict[str, tuple[str, float]]
    default: str = "v1"
    next_version: int = 2
    description: str | None = None
    aws_managed: bool = False


@dataclass
class AccessKey:
    id: str
    secret: str
    user: str
    created: float
    status: str = "Active"
    last_used: dict[str, Any] | None = None


@dataclass
class Session:
    access_key: str
    secret: str
    token: str
    expiration: float
    identity: Identity
    source_kind: str                  # role | user
    source_name: str


class IAM(QueryService):
    name = "iam"
    iam_prefix = "iam"
    event_source = "iam.amazonaws.com"
    xml_namespace = "https://iam.amazonaws.com/doc/2010-05-08/"
    version = "2010-05-08"

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.root_keys = {"test"}
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.users: dict[str, Entity] = {}
            self.groups: dict[str, Entity] = {}
            self.roles: dict[str, Entity] = {}
            self.policies: dict[str, ManagedPolicy] = {}
            self.keys: dict[str, AccessKey] = {}
            self.sessions: dict[str, Session] = {}
            for name, statements in AWS_MANAGED.items():
                doc = json.dumps({"Version": "2012-10-17", "Statement": statements})
                arn = f"arn:aws:iam::aws:policy/{name}"
                self.policies[arn] = ManagedPolicy(arn, name, new_id("ANPA"), "/", 0.0, {"v1": (doc, 0.0)},
                                                   aws_managed=True)

    # ================================================================== authentication
    def authenticate(self, access_key: str | None, service: str, region: str) -> Identity | AwsError:
        now = self.clock.now()
        if access_key in self.root_keys:
            return Identity(**{**ROOT_IDENTITY.__dict__, "access_key": access_key})
        key = self.keys.get(access_key or "")
        if key is not None:
            if key.status != "Active":
                return AwsError("InvalidClientTokenId", "The security token included in the request is invalid.")
            user = self.users.get(key.user)
            if user is None:
                return AwsError("InvalidClientTokenId", "The security token included in the request is invalid.")
            key.last_used = {"LastUsedDate": now, "ServiceName": service, "Region": region}
            return Identity("IAMUser", user.arn, user.id, user_name=user.name, access_key=key.id)
        session = self.sessions.get(access_key or "")
        if session is not None:
            if session.expiration <= now:
                return AwsError("ExpiredToken", "The security token included in the request is expired")
            return session.identity
        return AwsError("InvalidClientTokenId", "The security token included in the request is invalid.")

    def identity_policies(self, identity: Identity) -> list[dict[str, Any]]:
        """呼び出し元に適用される ID ベースポリシー (インライン + 管理 + グループ経由)。"""
        docs: list[str] = []
        entities: list[Entity] = []
        if identity.type == "IAMUser" and identity.user_name in self.users:
            user = self.users[identity.user_name]
            entities = [user] + [self.groups[g] for g in user.groups if g in self.groups]
        elif identity.type == "AssumedRole" and identity.role_arn:
            role = self.roles.get(identity.role_arn.rsplit("/", 1)[-1])
            if role:
                entities = [role]
        for e in entities:
            docs.extend(e.inline.values())
            for arn in e.attached:
                p = self.policies.get(arn)
                if p:
                    docs.append(p.versions[p.default][0])
        return [json.loads(d) for d in docs]

    def authorize(self, identity: Identity, action: str, resource: str, resource_policy: dict | None,
                  ctx: dict[str, Any]) -> Decision:
        if identity.is_root:
            # root はすべて許可されるが、リソースポリシーの明示的 Deny は root にも効く
            denied = evaluate(identity, [], resource_policy, action, resource, ctx)
            return denied if denied.effect == "ExplicitDeny" else Decision("Allow", "identity")
        return evaluate(identity, self.identity_policies(identity), resource_policy, action, resource, ctx)

    # ================================================================== helpers
    def _entity(self, kind: str, name: str | None) -> Entity:
        table = {"user": self.users, "group": self.groups, "role": self.roles}[kind]
        if not name or name not in table:
            label = {"user": "user", "group": "group", "role": "role"}[kind]
            raise AwsError("NoSuchEntity", f"The {label} with name {name} cannot be found.", 404)
        return table[name]

    def _create_entity(self, kind: str, name: str, path: str | None) -> Entity:
        if not name or not NAME_RE.match(name):
            raise AwsError("ValidationError", f"The specified value for {kind}Name is invalid.")
        table = {"user": self.users, "group": self.groups, "role": self.roles}[kind]
        if name in table:
            raise AwsError("EntityAlreadyExists", f"{kind.capitalize()} with name {name} already exists.", 409)
        path = path or "/"
        prefix = {"user": "AIDA", "group": "AGPA", "role": "AROA"}[kind]
        e = Entity(kind, name, new_id(prefix), f"arn:aws:iam::{ACCOUNT_ID}:{kind}{path}{name}", path, self.clock.now())
        table[name] = e
        return e

    def _policy(self, arn: str | None) -> ManagedPolicy:
        p = self.policies.get(arn or "")
        if p is None:
            raise AwsError("NoSuchEntity", f"Policy {arn} does not exist or is not attachable.", 404)
        return p

    def _attachment_count(self, arn: str) -> int:
        return sum(arn in e.attached for t in (self.users, self.groups, self.roles) for e in t.values())

    @staticmethod
    def _doc(text: str | None, identity_policy: bool = True) -> str:
        if not text:
            raise AwsError("ValidationError", "1 validation error detected: Value null at 'policyDocument' "
                           "failed to satisfy constraint: Member must not be null")
        parse_document(text, identity_policy)
        return text

    def _user_xml(self, u: Entity) -> dict[str, Any]:
        return {"Path": u.path, "UserName": u.name, "UserId": u.id, "Arn": u.arn, "CreateDate": iso(u.created)}

    def _group_xml(self, g: Entity) -> dict[str, Any]:
        return {"Path": g.path, "GroupName": g.name, "GroupId": g.id, "Arn": g.arn, "CreateDate": iso(g.created)}

    def _role_xml(self, r: Entity) -> dict[str, Any]:
        return {"Path": r.path, "RoleName": r.name, "RoleId": r.id, "Arn": r.arn, "CreateDate": iso(r.created),
                "AssumeRolePolicyDocument": quote(r.trust_policy or ""), "Description": r.description,
                "MaxSessionDuration": r.max_session}

    def _policy_xml(self, p: ManagedPolicy) -> dict[str, Any]:
        return {"PolicyName": p.name, "PolicyId": p.id, "Arn": p.arn, "Path": p.path,
                "DefaultVersionId": p.default, "AttachmentCount": self._attachment_count(p.arn),
                "PermissionsBoundaryUsageCount": 0, "IsAttachable": True, "Description": p.description,
                "CreateDate": iso(p.created), "UpdateDate": iso(max(t for _, t in p.versions.values()))}

    def _caller_user(self, p: dict[str, Any], req: Request) -> Entity:
        if p.get("UserName"):
            return self._entity("user", p["UserName"])
        if req.identity.type == "IAMUser":
            return self._entity("user", req.identity.user_name)
        raise AwsError("ValidationError", "Must specify userName when calling with non-User credentials")

    # ================================================================== users
    def op_CreateUser(self, p, req):
        require(p, "UserName")
        return {"User": self._user_xml(self._create_entity("user", p["UserName"], p.get("Path")))}

    def op_GetUser(self, p, req):
        if not p.get("UserName") and req.identity.is_root:
            return {"User": {"UserId": ACCOUNT_ID, "Arn": req.identity.arn, "CreateDate": iso(0)}}
        return {"User": self._user_xml(self._caller_user(p, req))}

    def op_ListUsers(self, p, req):
        prefix = p.get("PathPrefix", "/")
        return {"Users": [self._user_xml(u) for u in sorted(self.users.values(), key=lambda x: x.name)
                          if u.path.startswith(prefix)], "IsTruncated": False}

    def op_DeleteUser(self, p, req):
        u = self._entity("user", p.get("UserName"))
        if any(k.user == u.name for k in self.keys.values()):
            raise AwsError("DeleteConflict", "Cannot delete entity, must delete access keys first.", 409)
        if u.inline or u.attached:
            raise AwsError("DeleteConflict", "Cannot delete entity, must delete policies first.", 409)
        if u.groups:
            raise AwsError("DeleteConflict", "Cannot delete entity, must remove users from group first.", 409)
        del self.users[u.name]

    # ================================================================== access keys
    def op_CreateAccessKey(self, p, req):
        u = self._caller_user(p, req)
        if sum(k.user == u.name for k in self.keys.values()) >= 2:
            raise AwsError("LimitExceeded", "Cannot exceed quota for AccessKeysPerUser: 2", 409)
        key = AccessKey(new_id("AKIA")[:20], secrets.token_urlsafe(30)[:40], u.name, self.clock.now())
        self.keys[key.id] = key
        req.ctx["trail_response"] = {"accessKey": {"accessKeyId": key.id, "status": key.status,
                                                   "userName": u.name, "createDate": iso(key.created)}}
        return {"AccessKey": {"UserName": u.name, "AccessKeyId": key.id, "Status": key.status,
                              "SecretAccessKey": key.secret, "CreateDate": iso(key.created)}}

    def op_ListAccessKeys(self, p, req):
        u = self._caller_user(p, req)
        return {"AccessKeyMetadata": [{"UserName": k.user, "AccessKeyId": k.id, "Status": k.status,
                                       "CreateDate": iso(k.created)}
                                      for k in self.keys.values() if k.user == u.name], "IsTruncated": False}

    def _key(self, p, req) -> AccessKey:
        require(p, "AccessKeyId")
        key = self.keys.get(p["AccessKeyId"])
        if key is None:
            raise AwsError("NoSuchEntity", f"The Access Key with id {p['AccessKeyId']} cannot be found", 404)
        return key

    def op_UpdateAccessKey(self, p, req):
        require(p, "Status")
        if p["Status"] not in ("Active", "Inactive"):
            raise AwsError("ValidationError", "Status must be Active or Inactive")
        self._key(p, req).status = p["Status"]

    def op_DeleteAccessKey(self, p, req):
        del self.keys[self._key(p, req).id]

    def op_GetAccessKeyLastUsed(self, p, req):
        key = self._key(p, req)
        used = key.last_used or {"ServiceName": "N/A", "Region": "N/A"}
        out = {k: (iso(v) if k == "LastUsedDate" else v) for k, v in used.items()}
        return {"UserName": key.user, "AccessKeyLastUsed": out}

    # ================================================================== groups
    def op_CreateGroup(self, p, req):
        require(p, "GroupName")
        return {"Group": self._group_xml(self._create_entity("group", p["GroupName"], p.get("Path")))}

    def op_GetGroup(self, p, req):
        g = self._entity("group", p.get("GroupName"))
        members = [self._user_xml(u) for u in self.users.values() if g.name in u.groups]
        return {"Group": self._group_xml(g), "Users": members, "IsTruncated": False}

    def op_ListGroups(self, p, req):
        return {"Groups": [self._group_xml(g) for g in sorted(self.groups.values(), key=lambda x: x.name)],
                "IsTruncated": False}

    def op_DeleteGroup(self, p, req):
        g = self._entity("group", p.get("GroupName"))
        if any(g.name in u.groups for u in self.users.values()):
            raise AwsError("DeleteConflict", "Cannot delete entity, must remove users from group first.", 409)
        if g.inline or g.attached:
            raise AwsError("DeleteConflict", "Cannot delete entity, must delete policies first.", 409)
        del self.groups[g.name]

    def op_AddUserToGroup(self, p, req):
        g, u = self._entity("group", p.get("GroupName")), self._entity("user", p.get("UserName"))
        if g.name not in u.groups:
            u.groups.append(g.name)

    def op_RemoveUserFromGroup(self, p, req):
        g, u = self._entity("group", p.get("GroupName")), self._entity("user", p.get("UserName"))
        if g.name in u.groups:
            u.groups.remove(g.name)

    def op_ListGroupsForUser(self, p, req):
        u = self._entity("user", p.get("UserName"))
        return {"Groups": [self._group_xml(self.groups[g]) for g in u.groups if g in self.groups],
                "IsTruncated": False}

    # ================================================================== roles
    def op_CreateRole(self, p, req):
        require(p, "RoleName", "AssumeRolePolicyDocument")
        trust = self._doc(p["AssumeRolePolicyDocument"], identity_policy=False)
        max_session = int(p.get("MaxSessionDuration") or 3600)
        if not 3600 <= max_session <= 43200:
            raise AwsError("ValidationError", "MaxSessionDuration must be between 3600 and 43200 seconds")
        r = self._create_entity("role", p["RoleName"], p.get("Path"))
        r.trust_policy, r.description, r.max_session = trust, p.get("Description"), max_session
        return {"Role": self._role_xml(r)}

    def op_GetRole(self, p, req):
        return {"Role": self._role_xml(self._entity("role", p.get("RoleName")))}

    def op_ListRoles(self, p, req):
        return {"Roles": [self._role_xml(r) for r in sorted(self.roles.values(), key=lambda x: x.name)],
                "IsTruncated": False}

    def op_DeleteRole(self, p, req):
        r = self._entity("role", p.get("RoleName"))
        if r.inline or r.attached:
            raise AwsError("DeleteConflict", "Cannot delete entity, must detach all policies first.", 409)
        del self.roles[r.name]

    def op_UpdateAssumeRolePolicy(self, p, req):
        r = self._entity("role", p.get("RoleName"))
        r.trust_policy = self._doc(p.get("PolicyDocument"), identity_policy=False)

    # ================================================================== managed policies
    def op_CreatePolicy(self, p, req):
        require(p, "PolicyName", "PolicyDocument")
        path = p.get("Path") or "/"
        arn = f"arn:aws:iam::{ACCOUNT_ID}:policy{path}{p['PolicyName']}"
        if arn in self.policies:
            raise AwsError("EntityAlreadyExists", f"A policy called {p['PolicyName']} already exists. "
                           "Duplicate names are not allowed.", 409)
        now = self.clock.now()
        pol = ManagedPolicy(arn, p["PolicyName"], new_id("ANPA"), path, now,
                            {"v1": (self._doc(p["PolicyDocument"]), now)}, description=p.get("Description"))
        self.policies[arn] = pol
        return {"Policy": self._policy_xml(pol)}

    def op_GetPolicy(self, p, req):
        return {"Policy": self._policy_xml(self._policy(p.get("PolicyArn")))}

    def op_ListPolicies(self, p, req):
        scope = p.get("Scope", "All")
        only_attached = str(p.get("OnlyAttached", "false")).lower() == "true"
        out = []
        for pol in sorted(self.policies.values(), key=lambda x: x.name):
            if scope == "Local" and pol.aws_managed or scope == "AWS" and not pol.aws_managed:
                continue
            if only_attached and not self._attachment_count(pol.arn):
                continue
            out.append(self._policy_xml(pol))
        return {"Policies": out, "IsTruncated": False}

    def op_DeletePolicy(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        if pol.aws_managed:
            raise AwsError("AccessDenied", "Cannot delete AWS managed policy", 403)
        if self._attachment_count(pol.arn):
            raise AwsError("DeleteConflict", "Cannot delete a policy attached to entities.", 409)
        del self.policies[pol.arn]

    def op_GetPolicyVersion(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        vid = p.get("VersionId")
        if vid not in pol.versions:
            raise AwsError("NoSuchEntity", f"Policy {pol.arn} version {vid} does not exist or is not attachable.", 404)
        doc, created = pol.versions[vid]
        return {"PolicyVersion": {"Document": quote(doc), "VersionId": vid, "IsDefaultVersion": vid == pol.default,
                                  "CreateDate": iso(created)}}

    def op_CreatePolicyVersion(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        if pol.aws_managed:
            raise AwsError("AccessDenied", "Cannot modify AWS managed policy", 403)
        if len(pol.versions) >= 5:
            raise AwsError("LimitExceeded", "A managed policy can have up to 5 versions. Before you create a new "
                           "version, you must delete an existing version.", 409)
        vid = f"v{pol.next_version}"
        pol.next_version += 1
        now = self.clock.now()
        pol.versions[vid] = (self._doc(p.get("PolicyDocument")), now)
        if str(p.get("SetAsDefault", "false")).lower() == "true":
            pol.default = vid
        return {"PolicyVersion": {"VersionId": vid, "IsDefaultVersion": pol.default == vid, "CreateDate": iso(now)}}

    def op_ListPolicyVersions(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        return {"Versions": [{"VersionId": v, "IsDefaultVersion": v == pol.default, "CreateDate": iso(t)}
                             for v, (_, t) in sorted(pol.versions.items(), reverse=True)], "IsTruncated": False}

    def op_SetDefaultPolicyVersion(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        if p.get("VersionId") not in pol.versions:
            raise AwsError("NoSuchEntity", "Policy version does not exist.", 404)
        pol.default = p["VersionId"]

    def op_DeletePolicyVersion(self, p, req):
        pol = self._policy(p.get("PolicyArn"))
        vid = p.get("VersionId")
        if vid == pol.default:
            raise AwsError("DeleteConflict", "Cannot delete the default version of a policy.", 409)
        if pol.versions.pop(vid, None) is None:
            raise AwsError("NoSuchEntity", "Policy version does not exist.", 404)

    # ================================================================== attach / inline (user/group/role 共通)
    def _attach(self, kind: str, p: dict[str, Any], attach: bool) -> None:
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        pol = self._policy(p.get("PolicyArn"))
        if attach:
            if pol.arn not in e.attached:
                if len(e.attached) >= 10:
                    raise AwsError("LimitExceeded", f"Cannot exceed quota for PoliciesPer{kind.capitalize()}: 10", 409)
                e.attached.append(pol.arn)
        else:
            if pol.arn not in e.attached:
                raise AwsError("NoSuchEntity", f"Policy {pol.arn} was not found.", 404)
            e.attached.remove(pol.arn)

    def _list_attached(self, kind: str, p: dict[str, Any]) -> dict[str, Any]:
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        return {"AttachedPolicies": [{"PolicyName": self.policies[a].name, "PolicyArn": a}
                                     for a in e.attached if a in self.policies], "IsTruncated": False}

    def _put_inline(self, kind: str, p: dict[str, Any]) -> None:
        require(p, "PolicyName")
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        e.inline[p["PolicyName"]] = self._doc(p.get("PolicyDocument"))

    def _get_inline(self, kind: str, p: dict[str, Any]) -> dict[str, Any]:
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        name = p.get("PolicyName")
        if name not in e.inline:
            raise AwsError("NoSuchEntity", f"The {kind} policy with name {name} cannot be found.", 404)
        return {f"{kind.capitalize()}Name": e.name, "PolicyName": name, "PolicyDocument": quote(e.inline[name])}

    def _delete_inline(self, kind: str, p: dict[str, Any]) -> None:
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        if e.inline.pop(p.get("PolicyName"), None) is None:
            raise AwsError("NoSuchEntity", f"The {kind} policy with name {p.get('PolicyName')} cannot be found.", 404)

    def _list_inline(self, kind: str, p: dict[str, Any]) -> dict[str, Any]:
        e = self._entity(kind, p.get(f"{kind.capitalize()}Name"))
        return {"PolicyNames": sorted(e.inline), "IsTruncated": False}

    # ================================================================== simulation
    def _simulate(self, identity: Identity, policies: list[dict[str, Any]], p: dict[str, Any],
                  req: Request) -> dict[str, Any]:
        actions = as_list(p.get("ActionNames"))
        if not actions:
            raise AwsError("ValidationError", "ActionNames must not be empty")
        resources = as_list(p.get("ResourceArns")) or ["*"]
        ctx = base_context(identity, req.region, req.client_ip, self.clock.now())
        for entry in as_list(p.get("ContextEntries")):
            values = as_list(entry.get("ContextKeyValues"))
            ctx[str(entry.get("ContextKeyName", "")).lower()] = values if len(values) != 1 else values[0]
        results = []
        for action in actions:
            for resource in resources:
                d = evaluate(identity, policies, None, action, resource, ctx)
                results.append({
                    "EvalActionName": action,
                    "EvalResourceName": resource,
                    "EvalDecision": {"Allow": "allowed", "ExplicitDeny": "explicitDeny"}.get(d.effect, "implicitDeny"),
                    "MatchedStatements": [{"SourcePolicyId": st.get("Sid", "statement"),
                                           "SourcePolicyType": "IAM Policy"} for st in d.matched],
                    "MissingContextValues": [],
                })
        return {"EvaluationResults": results, "IsTruncated": False}

    def op_SimulatePrincipalPolicy(self, p, req):
        require(p, "PolicySourceArn")
        arn = p["PolicySourceArn"]
        kind, _, name = arn.split(":", 5)[-1].partition("/")
        name = name.rsplit("/", 1)[-1]
        if kind == "user":
            u = self._entity("user", name)
            identity = Identity("IAMUser", u.arn, u.id, user_name=u.name)
        elif kind == "role":
            r = self._entity("role", name)
            identity = Identity("AssumedRole", f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{r.name}/simulation",
                                f"{r.id}:simulation", role_arn=r.arn, role_id=r.id, session_name="simulation")
        else:
            raise AwsError("InvalidInput", f"Invalid PolicySourceArn: {arn}")
        policies = self.identity_policies(identity)
        for doc in as_list(p.get("PolicyInputList")):
            policies.append(parse_document(doc))
        return self._simulate(identity, policies, p, req)

    def op_SimulateCustomPolicy(self, p, req):
        policies = [parse_document(d) for d in as_list(p.get("PolicyInputList"))]
        identity = Identity("IAMUser", f"arn:aws:iam::{ACCOUNT_ID}:user/simulation", "AIDASIMULATION",
                            user_name="simulation")
        return self._simulate(identity, policies, p, req)

    # ================================================================== STS 連携
    def create_session(self, identity: Identity, duration: int, source_kind: str, source_name: str) -> Session:
        akid = new_id("ASIA")[:20]
        session = Session(akid, secrets.token_urlsafe(30)[:40], secrets.token_urlsafe(90),
                          self.clock.now() + duration, identity, source_kind, source_name)
        session.identity = Identity(**{**identity.__dict__, "access_key": akid, "session_created": self.clock.now()})
        self.sessions[akid] = session
        return session

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            now = self.clock.now()
            return {
                "users": {u.name: {"arn": u.arn, "groups": u.groups, "attached_policies": u.attached,
                                   "inline_policies": {k: json.loads(v) for k, v in u.inline.items()},
                                   "access_keys": [{"id": k.id, "status": k.status, "last_used": k.last_used}
                                                   for k in self.keys.values() if k.user == u.name]}
                          for u in self.users.values()},
                "groups": {g.name: {"attached_policies": g.attached,
                                    "inline_policies": {k: json.loads(v) for k, v in g.inline.items()}}
                           for g in self.groups.values()},
                "roles": {r.name: {"arn": r.arn, "trust_policy": json.loads(r.trust_policy or "{}"),
                                   "attached_policies": r.attached,
                                   "inline_policies": {k: json.loads(v) for k, v in r.inline.items()}}
                          for r in self.roles.values()},
                "customer_managed_policies": {p.arn: json.loads(p.versions[p.default][0])
                                              for p in self.policies.values() if not p.aws_managed},
                "active_sessions": [{"access_key": s.access_key, "arn": s.identity.arn,
                                     "expires_in_seconds": round(s.expiration - now)}
                                    for s in self.sessions.values() if s.expiration > now],
                "root_access_keys": sorted(self.root_keys),
            }

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {
                "entities": [e.__dict__ for t in (self.users, self.groups, self.roles) for e in t.values()],
                "policies": [p.__dict__ for p in self.policies.values() if not p.aws_managed],
                "keys": [k.__dict__ for k in self.keys.values()],
                "sessions": [{**s.__dict__, "identity": s.identity.__dict__} for s in self.sessions.values()],
            }

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            for e in data.get("entities", []):
                entity = Entity(**e)
                {"user": self.users, "group": self.groups, "role": self.roles}[entity.kind][entity.name] = entity
            for p in data.get("policies", []):
                pol = ManagedPolicy(**{**p, "versions": {k: tuple(v) for k, v in p["versions"].items()}})
                self.policies[pol.arn] = pol
            for k in data.get("keys", []):
                self.keys[k["id"]] = AccessKey(**k)
            for s in data.get("sessions", []):
                self.sessions[s["access_key"]] = Session(**{**s, "identity": Identity(**s["identity"])})


def _make_entity_op(verb: str, kind: str):
    def op(self: IAM, p: dict[str, Any], req: Request) -> Any:
        if verb in ("Attach", "Detach"):
            return self._attach(kind, p, verb == "Attach")
        return {"ListAttached": self._list_attached, "Put": self._put_inline, "Get": self._get_inline,
                "Delete": self._delete_inline, "List": self._list_inline}[verb](kind, p)
    return op


# op_AttachUserPolicy, op_PutRolePolicy, op_ListGroupPolicies ... を user/group/role 分まとめて定義する
for _kind in ("User", "Group", "Role"):
    for _verb, _suffix in (("Attach", "Policy"), ("Detach", "Policy"), ("ListAttached", "Policies"),
                           ("Put", "Policy"), ("Get", "Policy"), ("Delete", "Policy"), ("List", "Policies")):
        setattr(IAM, f"op_{_verb}{_kind}{_suffix}", _make_entity_op(_verb, _kind.lower()))
