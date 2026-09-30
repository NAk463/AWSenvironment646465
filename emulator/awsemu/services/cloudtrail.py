"""CloudTrail (awsJson1.1)。

- すべての API 呼び出しを本物と同じ形式のレコード (userIdentity, requestParameters, errorCode ...) で記録
- LookupEvents は本物と同じく「管理イベントのみ」を返す (S3 GetObject などのデータイベントは返らない)
- 証跡 (Trail) を作成すると、イベントセレクタに一致したイベントを S3 (gzip) / CloudWatch Logs に配信する
"""
from __future__ import annotations

import gzip
import json
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Identity, Request
from ..iam_policy import evaluate
from ._json import JsonService

MAX_EVENTS = 50000
LOOKUP_ATTRIBUTES = {"EventId", "EventName", "ReadOnly", "Username", "ResourceType", "ResourceName",
                     "EventSource", "AccessKeyId"}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def user_identity(ident: Identity) -> dict[str, Any]:
    if ident.type == "Anonymous":
        return {"type": "AWSAccount", "principalId": "", "accountId": "anonymous"}
    if ident.type == "AWSService":
        return {"type": "AWSService", "invokedBy": ident.arn}
    out: dict[str, Any] = {"type": ident.type, "principalId": ident.principal_id, "arn": ident.arn,
                           "accountId": ident.account}
    if ident.access_key:
        out["accessKeyId"] = ident.access_key
    if ident.type == "IAMUser":
        out["userName"] = ident.user_name
    if ident.type == "AssumedRole":
        out["sessionContext"] = {
            "sessionIssuer": {"type": "Role", "principalId": ident.role_id, "arn": ident.role_arn,
                              "accountId": ident.account, "userName": (ident.role_arn or "").rsplit("/", 1)[-1]},
            "attributes": {"creationDate": iso(ident.session_created or 0), "mfaAuthenticated": "false"},
        }
    return out


def _camel(params: Any) -> Any:
    """requestParameters は先頭小文字のキーで記録される (本物の CloudTrail と同じ)。"""
    if isinstance(params, dict):
        return {(k[:1].lower() + k[1:]): _camel(v) for k, v in params.items()}
    if isinstance(params, list):
        return [_camel(v) for v in params]
    return params


class CloudTrail(JsonService):
    name = "cloudtrail"
    iam_prefix = "cloudtrail"
    event_source = "cloudtrail.amazonaws.com"
    target_prefix = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."
    error_namespace = "com.amazonaws.cloudtrail.v20131101"
    json_version = "1.1"

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self._events_lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
            self.trails: dict[str, dict[str, Any]] = {}

    # ================================================================== 記録と配信
    def record(self, req: Request, svc, op: str, status: int, error: AwsError | None) -> dict[str, Any]:
        now = self.clock.now()
        params = svc.params_for_log(req, op)
        if svc.name == "s3" and isinstance(params, dict):
            params = {"bucketName": params.get("Bucket"), "key": params.get("Key"),
                      "Host": req.header("Host")} | {k: v for k, v in params.items() if k not in ("Bucket", "Key")}
            params = {k: v for k, v in params.items() if v is not None}
        else:
            params = _camel(params) if params else None
        data_event = op in svc.data_events
        event = {
            "eventVersion": "1.09",
            "userIdentity": user_identity(req.identity),
            "eventTime": iso(now),
            "eventSource": svc.event_source,
            "eventName": op,
            "awsRegion": req.region,
            "sourceIPAddress": req.client_ip,
            "userAgent": req.header("User-Agent") or "",
            "requestParameters": params,
            "responseElements": req.ctx.get("trail_response"),
            "requestID": req.request_id,
            "eventID": str(uuid.uuid4()),
            "readOnly": svc.read_only(op),
            "resources": svc.trail_resources(req, op) or None,
            "eventType": "AwsApiCall",
            "managementEvent": not data_event,
            "recipientAccountId": ACCOUNT_ID,
            "eventCategory": "Data" if data_event else "Management",
        }
        if error is not None:
            event["errorCode"] = error.code
            event["errorMessage"] = error.message
        event = {k: v for k, v in event.items() if v is not None or k in ("requestParameters", "responseElements")}
        with self._events_lock:
            self.events.append({"_ts": now, **event})
        self._deliver(event, now)
        return event

    def _selected(self, trail: dict[str, Any], event: dict[str, Any]) -> bool:
        data = event["eventCategory"] == "Data"
        if trail.get("advanced"):
            for sel in trail["advanced"]:
                if all(self._field_match(f, event) for f in sel.get("FieldSelectors", [])):
                    return True
            return False
        for sel in trail["selectors"]:
            rw = sel.get("ReadWriteType", "All")
            if rw == "ReadOnly" and not event["readOnly"] or rw == "WriteOnly" and event["readOnly"]:
                continue
            if not data and sel.get("IncludeManagementEvents", True):
                return True
            if data:
                for dr in sel.get("DataResources", []):
                    for res in event.get("resources") or []:
                        if res["type"] == dr.get("Type") and any(
                                res["ARN"].startswith(v) for v in dr.get("Values", [])):
                            return True
        return False

    @staticmethod
    def _field_match(fs: dict[str, Any], event: dict[str, Any]) -> bool:
        name = fs.get("Field")
        if name == "resources.type":
            values = [r["type"] for r in event.get("resources") or []]
        elif name == "resources.ARN":
            values = [r["ARN"] for r in event.get("resources") or []]
        elif name == "readOnly":
            values = [str(event["readOnly"]).lower()]
        else:
            values = [str(event.get(name, ""))]
        checks = [
            ("Equals", lambda v, x: v == x), ("StartsWith", lambda v, x: v.startswith(x)),
            ("EndsWith", lambda v, x: v.endswith(x)),
        ]
        for key, fn in checks:
            if key in fs and not any(fn(v, x) for v in values for x in fs[key]):
                return False
            neg = "Not" + key
            if neg in fs and any(fn(v, x) for v in values for x in fs[neg]):
                return False
        return True

    def _deliver(self, event: dict[str, Any], now: float) -> None:
        with self.lock:
            trails = [t for t in self.trails.values() if t["logging"] and self._selected(t, event)]
        for t in trails:
            body = json.dumps(event, ensure_ascii=False)
            if t.get("S3BucketName"):
                stamp = datetime.fromtimestamp(now, timezone.utc)
                region = t["HomeRegion"]
                prefix = f"{t['S3KeyPrefix']}/" if t.get("S3KeyPrefix") else ""
                key = (f"{prefix}AWSLogs/{ACCOUNT_ID}/CloudTrail/{region}/{stamp:%Y/%m/%d}/"
                       f"{ACCOUNT_ID}_CloudTrail_{region}_{stamp:%Y%m%dT%H%MZ}_{uuid.uuid4().hex[:16]}.json.gz")
                data = gzip.compress(json.dumps({"Records": [event]}).encode())
                err = self.emu.services["s3"].put_internal(t["S3BucketName"], key, data, "application/x-gzip")
                t["status"]["LatestDeliveryError" if err else "LatestDeliveryTime"] = err or now
            if t.get("CloudWatchLogsLogGroupArn"):
                group = t["CloudWatchLogsLogGroupArn"].split(":log-group:", 1)[-1].split(":", 1)[0]
                err = self.emu.services["logs"].deliver(group, f"{ACCOUNT_ID}_CloudTrail_{t['HomeRegion']}",
                                                        [(int(now * 1000), body)])
                key = "LatestCloudWatchLogsDeliveryError" if err else "LatestCloudWatchLogsDeliveryTime"
                t["status"][key] = err or now

    # ================================================================== LookupEvents
    def op_LookupEvents(self, p, req):
        attrs = p.get("LookupAttributes") or []
        if len(attrs) > 1:
            raise AwsError("InvalidLookupAttributesException", "You cannot specify more than one lookup attribute.")
        for a in attrs:
            if a.get("AttributeKey") not in LOOKUP_ATTRIBUTES:
                raise AwsError("InvalidLookupAttributesException", f"Invalid attribute key: {a.get('AttributeKey')}")
        max_results = int(p.get("MaxResults") or 50)
        if not 1 <= max_results <= 50:
            raise AwsError("InvalidMaxResultsException", "MaxResults must be between 1 and 50.")
        now = self.clock.now()
        start = float(p.get("StartTime") or now - 90 * 86400)
        end = float(p.get("EndTime") or now + 1)
        if start > end:
            raise AwsError("InvalidTimeRangeException", "Start time must not be later than end time.")
        with self._events_lock:
            events = [e for e in reversed(self.events)
                      if e["eventCategory"] == "Management" and start <= e["_ts"] <= end]
        if attrs:
            key, value = attrs[0]["AttributeKey"], attrs[0].get("AttributeValue", "")
            events = [e for e in events if value in self._attribute_values(e, key)]
        offset = int(p.get("NextToken") or 0)
        page = events[offset:offset + max_results]
        result: dict[str, Any] = {"Events": [self._lookup_view(e) for e in page]}
        if offset + max_results < len(events):
            result["NextToken"] = str(offset + max_results)
        return result

    @staticmethod
    def _username(e: dict[str, Any]) -> str | None:
        ident = e["userIdentity"]
        if ident.get("type") == "Root":
            return "root"
        if ident.get("type") == "IAMUser":
            return ident.get("userName")
        if ident.get("type") == "AssumedRole":
            return ident["arn"].rsplit("/", 1)[-1]
        return None

    def _attribute_values(self, e: dict[str, Any], key: str) -> list[str]:
        res = e.get("resources") or []
        return {
            "EventId": [e["eventID"]], "EventName": [e["eventName"]], "ReadOnly": [str(e["readOnly"]).lower()],
            "Username": [self._username(e) or ""], "EventSource": [e["eventSource"]],
            "AccessKeyId": [e["userIdentity"].get("accessKeyId", "")],
            "ResourceType": [r["type"] for r in res], "ResourceName": [r["ARN"] for r in res] +
            [r["ARN"].rsplit("/", 1)[-1].rsplit(":", 1)[-1] for r in res],
        }[key]

    def _lookup_view(self, e: dict[str, Any]) -> dict[str, Any]:
        record = {k: v for k, v in e.items() if k != "_ts"}
        out = {
            "EventId": e["eventID"], "EventName": e["eventName"], "ReadOnly": str(e["readOnly"]).lower(),
            "EventTime": e["_ts"], "EventSource": e["eventSource"],
            "Resources": [{"ResourceType": r["type"], "ResourceName": r["ARN"]} for r in e.get("resources") or []],
            "CloudTrailEvent": json.dumps(record, ensure_ascii=False),
        }
        if e["userIdentity"].get("accessKeyId"):
            out["AccessKeyId"] = e["userIdentity"]["accessKeyId"]
        if self._username(e):
            out["Username"] = self._username(e)
        return out

    # ================================================================== trails
    def _trail(self, name: str | None) -> dict[str, Any]:
        key = (name or "").rsplit("/", 1)[-1]
        t = self.trails.get(key)
        if t is None:
            raise AwsError("TrailNotFoundException",
                           f"Unknown trail: arn:aws:cloudtrail:ap-northeast-1:{ACCOUNT_ID}:trail/{key} "
                           f"for the user: {ACCOUNT_ID}")
        return t

    def _validate_destinations(self, t: dict[str, Any]) -> None:
        s3 = self.emu.services["s3"]
        bucket = t.get("S3BucketName")
        if bucket:
            if bucket not in s3.buckets:
                raise AwsError("S3BucketDoesNotExistException", f"S3 bucket {bucket} does not exist.")
            policy = s3.resource_policy(f"arn:aws:s3:::{bucket}")
            prefix = f"{t['S3KeyPrefix']}/" if t.get("S3KeyPrefix") else ""
            service = Identity("AWSService", "cloudtrail.amazonaws.com", "cloudtrail.amazonaws.com")
            checks = [("s3:GetBucketAcl", f"arn:aws:s3:::{bucket}"),
                      ("s3:PutObject", f"arn:aws:s3:::{bucket}/{prefix}AWSLogs/{ACCOUNT_ID}/CloudTrail/x.json.gz")]
            if not policy or not all(evaluate(service, [], policy, a, r, {}).allowed for a, r in checks):
                raise AwsError("InsufficientS3BucketPolicyException",
                               f"Incorrect S3 bucket policy is detected for bucket: {bucket}")
        if t.get("CloudWatchLogsLogGroupArn"):
            if not t.get("CloudWatchLogsRoleArn"):
                raise AwsError("InvalidCloudWatchLogsRoleArnException",
                               "You must specify a role ARN for CloudWatch Logs delivery.")
            role = t["CloudWatchLogsRoleArn"].rsplit("/", 1)[-1]
            if role not in self.emu.services["iam"].roles:
                raise AwsError("InvalidCloudWatchLogsRoleArnException", "Access denied. Verify in IAM that the "
                               "role has adequate permissions.")
            group = t["CloudWatchLogsLogGroupArn"].split(":log-group:", 1)[-1].split(":", 1)[0]
            if group not in self.emu.services["logs"].groups:
                raise AwsError("InvalidCloudWatchLogsLogGroupArnException",
                               "CloudTrail cannot validate the specified log group ARN.")

    def _view(self, t: dict[str, Any]) -> dict[str, Any]:
        keys = ("Name", "S3BucketName", "S3KeyPrefix", "IncludeGlobalServiceEvents", "IsMultiRegionTrail",
                "HomeRegion", "TrailARN", "LogFileValidationEnabled", "CloudWatchLogsLogGroupArn",
                "CloudWatchLogsRoleArn", "IsOrganizationTrail")
        out = {k: t.get(k) for k in keys if t.get(k) is not None}
        out["HasCustomEventSelectors"] = bool(t.get("advanced")) or t["selectors"] != self._default_selectors()
        out["HasInsightSelectors"] = False
        return out

    @staticmethod
    def _default_selectors() -> list[dict[str, Any]]:
        return [{"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": [],
                 "ExcludeManagementEventSources": []}]

    def op_CreateTrail(self, p, req):
        name = p.get("Name")
        if not name:
            raise AwsError("InvalidTrailNameException", "Trail name cannot be empty.")
        if name in self.trails:
            raise AwsError("TrailAlreadyExistsException", f"Trail {name} already exists for customer: {ACCOUNT_ID}")
        t = {
            "Name": name, "S3BucketName": p.get("S3BucketName"), "S3KeyPrefix": p.get("S3KeyPrefix"),
            "IncludeGlobalServiceEvents": p.get("IncludeGlobalServiceEvents", True),
            "IsMultiRegionTrail": bool(p.get("IsMultiRegionTrail")), "HomeRegion": req.region,
            "TrailARN": f"arn:aws:cloudtrail:{req.region}:{ACCOUNT_ID}:trail/{name}",
            "LogFileValidationEnabled": bool(p.get("EnableLogFileValidation")),
            "CloudWatchLogsLogGroupArn": p.get("CloudWatchLogsLogGroupArn"),
            "CloudWatchLogsRoleArn": p.get("CloudWatchLogsRoleArn"), "IsOrganizationTrail": False,
            "logging": False, "selectors": self._default_selectors(), "advanced": None, "status": {},
        }
        if not t["S3BucketName"]:
            raise AwsError("InvalidParameterException", "S3BucketName is required.")
        self._validate_destinations(t)
        self.trails[name] = t
        return self._view(t)

    def op_UpdateTrail(self, p, req):
        t = self._trail(p.get("Name"))
        updated = dict(t)
        for k in ("S3BucketName", "S3KeyPrefix", "IncludeGlobalServiceEvents", "IsMultiRegionTrail",
                  "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn"):
            if k in p:
                updated[k] = p[k]
        self._validate_destinations(updated)
        t.update(updated)
        return self._view(t)

    def op_DeleteTrail(self, p, req):
        del self.trails[self._trail(p.get("Name"))["Name"]]

    def op_DescribeTrails(self, p, req):
        names = p.get("trailNameList")
        trails = [self._trail(n) for n in names] if names else list(self.trails.values())
        return {"trailList": [self._view(t) for t in trails]}

    def op_GetTrail(self, p, req):
        return {"Trail": self._view(self._trail(p.get("Name")))}

    def op_ListTrails(self, p, req):
        return {"Trails": [{"TrailARN": t["TrailARN"], "Name": t["Name"], "HomeRegion": t["HomeRegion"]}
                           for t in self.trails.values()]}

    def op_StartLogging(self, p, req):
        t = self._trail(p.get("Name"))
        t["logging"] = True
        t["status"]["StartLoggingTime"] = self.clock.now()

    def op_StopLogging(self, p, req):
        t = self._trail(p.get("Name"))
        t["logging"] = False
        t["status"]["StopLoggingTime"] = self.clock.now()

    def op_GetTrailStatus(self, p, req):
        t = self._trail(p.get("Name"))
        return {"IsLogging": t["logging"], **t["status"]}

    def op_PutEventSelectors(self, p, req):
        t = self._trail(p.get("TrailName"))
        if p.get("EventSelectors") and p.get("AdvancedEventSelectors"):
            raise AwsError("InvalidParameterCombinationException",
                           "You cannot specify both EventSelectors and AdvancedEventSelectors.")
        if p.get("AdvancedEventSelectors"):
            t["advanced"], t["selectors"] = p["AdvancedEventSelectors"], []
            return {"TrailARN": t["TrailARN"], "AdvancedEventSelectors": t["advanced"]}
        t["selectors"] = [{"ReadWriteType": s.get("ReadWriteType", "All"),
                           "IncludeManagementEvents": s.get("IncludeManagementEvents", True),
                           "DataResources": s.get("DataResources", []),
                           "ExcludeManagementEventSources": s.get("ExcludeManagementEventSources", [])}
                          for s in p.get("EventSelectors") or []]
        t["advanced"] = None
        return {"TrailARN": t["TrailARN"], "EventSelectors": t["selectors"]}

    def op_GetEventSelectors(self, p, req):
        t = self._trail(p.get("TrailName"))
        if t.get("advanced"):
            return {"TrailARN": t["TrailARN"], "AdvancedEventSelectors": t["advanced"]}
        return {"TrailARN": t["TrailARN"], "EventSelectors": t["selectors"]}

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            return {
                "trails": {n: {**self._view(t), "IsLogging": t["logging"], "status": t["status"]}
                           for n, t in self.trails.items()},
                "event_count": len(self.events),
                "management_events": sum(1 for e in self.events if e["eventCategory"] == "Management"),
            }

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {"trails": self.trails, "events": list(self.events)[-5000:]}

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.trails = data.get("trails", {})
            self.events = deque(data.get("events", []), maxlen=MAX_EVENTS)
