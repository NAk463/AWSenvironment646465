"""CloudWatch Logs (awsJson1.1)。

ロググループ / ストリーム / イベント、FilterLogEvents (フィルタパターン)、メトリクスフィルタ (ログ → メトリクス)、
Logs Insights (StartQuery / GetQueryResults)、保持期間、AWS/Logs メトリクスを再現する。
"""
from __future__ import annotations

import bisect
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Metric, Request
from ._json import JsonService
from .logs_filter import compile_pattern, extract_value
from .logs_insights import build_record, run_query

GROUP_NAME_RE = re.compile(r"^[.\-_/#A-Za-z0-9]{1,512}$")
STREAM_NAME_RE = re.compile(r"^[^:*]{1,512}$")
RETENTION_DAYS = {1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922,
                  3288, 3653}
MAX_BATCH_BYTES = 1_048_576


def not_found(what: str) -> AwsError:
    return AwsError("ResourceNotFoundException", f"The specified {what} does not exist.")


def invalid(msg: str) -> AwsError:
    return AwsError("InvalidParameterException", msg)


@dataclass
class Event:
    timestamp: int
    ingestion: int
    message: str
    id: str


@dataclass
class Stream:
    name: str
    created: int
    events: list[Event] = field(default_factory=list)
    last_ingestion: int | None = None

    def insert(self, ev: Event) -> None:
        bisect.insort_right(self.events, ev, key=lambda e: e.timestamp)


@dataclass
class Group:
    name: str
    created: int
    retention: int | None = None
    streams: dict[str, Stream] = field(default_factory=dict)
    metric_filters: dict[str, dict[str, Any]] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    group_class: str = "STANDARD"

    def arn(self, region: str) -> str:
        return f"arn:aws:logs:{region}:{ACCOUNT_ID}:log-group:{self.name}"


class Logs(JsonService):
    name = "logs"
    iam_prefix = "logs"
    event_source = "logs.amazonaws.com"
    target_prefix = "Logs_20140328."
    error_namespace = "com.amazonaws.logs"
    json_version = "1.1"
    data_events = frozenset({"PutLogEvents", "GetLogEvents", "FilterLogEvents", "GetQueryResults"})
    access_denied_code = "AccessDeniedException"
    access_denied_status = 400
    invalid_token_code = "UnrecognizedClientException"
    invalid_token_status = 400
    expired_token_code = "ExpiredTokenException"
    expired_token_status = 400

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.groups: dict[str, Group] = {}
            self.queries: dict[str, dict[str, Any]] = {}

    def handle(self, req, op):
        with self.lock:
            return super().handle(req, op)

    # ================================================================== IAM / CloudTrail / メトリクス
    def resource(self, req: Request, op: str) -> str:
        p = self.params_for_log(req, op) or {}
        return p.get("logGroupName") or p.get("logGroupIdentifier") or p.get("queryId") or ""

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        p = self.params_for_log(req, op) or {}
        group = self._group_name(p, required=False)
        names = [group] if group else list(p.get("logGroupNames") or []) + [
            n.split(":log-group:")[-1] for n in p.get("logGroupIdentifiers") or []]
        if not names:
            return [(f"logs:{op}", "*")]
        base = f"arn:aws:logs:{req.region}:{ACCOUNT_ID}:log-group:"
        if p.get("logStreamName"):
            return [(f"logs:{op}", f"{base}{names[0]}:log-stream:{p['logStreamName']}")]
        return [(f"logs:{op}", f"{base}{n}:*") for n in names]

    def trail_resources(self, req: Request, op: str) -> list[dict[str, str]]:
        return [{"accountId": ACCOUNT_ID, "type": "AWS::Logs::LogGroup", "ARN": arn.removesuffix(":*")}
                for _, arn in self.authz(req, op) if arn != "*"]

    def metrics(self, req: Request, op: str, status: int, error, duration_ms: float) -> list[Metric]:
        stats = req.ctx.get("logs")
        if not stats or error is not None:
            return []
        dims = {"LogGroupName": stats["group"]}
        return [Metric("AWS/Logs", "IncomingLogEvents", float(stats["events"]), dims, "Count"),
                Metric("AWS/Logs", "IncomingBytes", float(stats["bytes"]), dims, "Bytes")]

    # ================================================================== helpers
    @staticmethod
    def _group_name(p: dict[str, Any], required: bool = True) -> str | None:
        name = p.get("logGroupName") or p.get("logGroupIdentifier")
        if name and name.startswith("arn:"):
            name = name.split(":log-group:", 1)[-1].removesuffix(":*")
        if required and not name:
            raise invalid("Either logGroupName or logGroupIdentifier must be specified.")
        return name

    def _group(self, p: dict[str, Any]) -> Group:
        name = self._group_name(p)
        g = self.groups.get(name)
        if g is None:
            raise not_found("log group")
        self._expire(g)
        return g

    def _stream(self, g: Group, name: str | None) -> Stream:
        s = g.streams.get(name or "")
        if s is None:
            raise not_found("log stream")
        return s

    def _now_ms(self) -> int:
        return int(self.clock.now() * 1000)

    def _expire(self, g: Group) -> None:
        if not g.retention:
            return
        cutoff = self._now_ms() - g.retention * 86400 * 1000
        for s in g.streams.values():
            if s.events and s.events[0].timestamp < cutoff:
                s.events = [e for e in s.events if e.timestamp >= cutoff]

    def _group_view(self, g: Group, region: str) -> dict[str, Any]:
        out = {"logGroupName": g.name, "creationTime": g.created, "metricFilterCount": len(g.metric_filters),
               "arn": g.arn(region) + ":*", "logGroupArn": g.arn(region), "logGroupClass": g.group_class,
               "storedBytes": sum(len(e.message.encode()) for s in g.streams.values() for e in s.events)}
        if g.retention:
            out["retentionInDays"] = g.retention
        return out

    # ================================================================== groups / streams
    def op_CreateLogGroup(self, p, req):
        name = p.get("logGroupName") or ""
        if not GROUP_NAME_RE.match(name):
            raise invalid("1 validation error detected: Value at 'logGroupName' failed to satisfy constraint: "
                          "Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+")
        if name in self.groups:
            raise AwsError("ResourceAlreadyExistsException", "The specified log group already exists")
        self.groups[name] = Group(name, self._now_ms(), tags=dict(p.get("tags") or {}),
                                  group_class=p.get("logGroupClass", "STANDARD"))

    def op_DeleteLogGroup(self, p, req):
        del self.groups[self._group(p).name]

    def op_DescribeLogGroups(self, p, req):
        prefix, pattern = p.get("logGroupNamePrefix"), p.get("logGroupNamePattern")
        if prefix and pattern:
            raise invalid("LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters.")
        names = sorted(n for n in self.groups
                       if (not prefix or n.startswith(prefix)) and (not pattern or pattern.lower() in n.lower()))
        start, limit = int(p.get("nextToken") or 0), int(p.get("limit") or 50)
        page = names[start:start + limit]
        result: dict[str, Any] = {"logGroups": [self._group_view(self.groups[n], req.region) for n in page]}
        if start + limit < len(names):
            result["nextToken"] = str(start + limit)
        return result

    def op_PutRetentionPolicy(self, p, req):
        g = self._group(p)
        days = int(p.get("retentionInDays") or 0)
        if days not in RETENTION_DAYS:
            raise invalid("1 validation error detected: Value at 'retentionInDays' failed to satisfy constraint: "
                          "Member must satisfy enum value set: " + str(sorted(RETENTION_DAYS)))
        g.retention = days

    def op_DeleteRetentionPolicy(self, p, req):
        self._group(p).retention = None

    def op_CreateLogStream(self, p, req):
        g = self._group(p)
        name = p.get("logStreamName") or ""
        if not STREAM_NAME_RE.match(name):
            raise invalid("1 validation error detected: Value at 'logStreamName' failed to satisfy constraint: "
                          "Member must satisfy regular expression pattern: [^:*]*")
        if name in g.streams:
            raise AwsError("ResourceAlreadyExistsException", "The specified log stream already exists")
        g.streams[name] = Stream(name, self._now_ms())

    def op_DeleteLogStream(self, p, req):
        g = self._group(p)
        del g.streams[self._stream(g, p.get("logStreamName")).name]

    def op_DescribeLogStreams(self, p, req):
        g = self._group(p)
        prefix = p.get("logStreamNamePrefix")
        order = p.get("orderBy", "LogStreamName")
        if prefix and order == "LastEventTime":
            raise invalid("Cannot order by LastEventTime with a logStreamNamePrefix.")
        streams = [s for s in g.streams.values() if not prefix or s.name.startswith(prefix)]
        if order == "LastEventTime":
            streams.sort(key=lambda s: s.events[-1].timestamp if s.events else 0, reverse=bool(p.get("descending")))
        else:
            streams.sort(key=lambda s: s.name, reverse=bool(p.get("descending")))
        start, limit = int(p.get("nextToken") or 0), int(p.get("limit") or 50)
        page = streams[start:start + limit]
        views = []
        for s in page:
            v: dict[str, Any] = {"logStreamName": s.name, "creationTime": s.created,
                                 "arn": f"{g.arn(req.region)}:log-stream:{s.name}", "storedBytes": 0}
            if s.events:
                v.update(firstEventTimestamp=s.events[0].timestamp, lastEventTimestamp=s.events[-1].timestamp)
            if s.last_ingestion:
                v.update(lastIngestionTime=s.last_ingestion, uploadSequenceToken=str(s.last_ingestion))
            views.append(v)
        result: dict[str, Any] = {"logStreams": views}
        if start + limit < len(streams):
            result["nextToken"] = str(start + limit)
        return result

    # ================================================================== ingestion
    def op_PutLogEvents(self, p, req):
        g = self._group(p)
        s = self._stream(g, p.get("logStreamName"))
        events = p.get("logEvents") or []
        if not 1 <= len(events) <= 10000:
            raise invalid("1 validation error detected: Value at 'logEvents' failed to satisfy constraint: "
                          "Member must have length less than or equal to 10000")
        stamps = [int(e["timestamp"]) for e in events]
        if stamps != sorted(stamps):
            raise invalid("Log events in a single PutLogEvents request must be in chronological order.")
        if stamps[-1] - stamps[0] > 24 * 3600 * 1000:
            raise invalid("The batch of log events in a single PutLogEvents request cannot span more than 24 hours.")
        size = sum(len(e["message"].encode()) + 26 for e in events)
        if size > MAX_BATCH_BYTES:
            raise invalid("Upload too large: 1048576 bytes exceeds limit")
        now = self._now_ms()
        too_old = now - 14 * 86400 * 1000
        expired = now - g.retention * 86400 * 1000 if g.retention else None
        too_new = now + 2 * 3600 * 1000
        rejected: dict[str, int] = {}
        accepted = []
        for i, e in enumerate(events):
            ts = int(e["timestamp"])
            if ts > too_new:
                rejected.setdefault("tooNewLogEventStartIndex", i)
            elif expired is not None and ts < expired:
                rejected["expiredLogEventEndIndex"] = i
            elif ts < too_old:
                rejected["tooOldLogEventEndIndex"] = i
            else:
                accepted.append((ts, e["message"]))
        self._ingest(g, s, accepted, now)
        req.ctx["logs"] = {"group": g.name, "events": len(accepted),
                           "bytes": sum(len(m.encode()) for _, m in accepted)}
        result: dict[str, Any] = {"nextSequenceToken": uuid.uuid4().hex}
        if rejected:
            result["rejectedLogEventsInfo"] = rejected
        return result

    def _ingest(self, g: Group, s: Stream, events: list[tuple[int, str]], now: int) -> None:
        metrics: list[Metric] = []
        for ts, message in events:
            s.insert(Event(ts, now, message, f"{ts}{uuid.uuid4().int % 10**20:020d}"))
            for f in g.metric_filters.values():
                matched, extracted = f["_matcher"](message)
                for mt in f["metricTransformations"]:
                    if matched:
                        raw = extract_value(mt["metricValue"], extracted)
                        try:
                            value = float(raw)
                        except (TypeError, ValueError):
                            continue
                    elif "defaultValue" in mt:
                        value = float(mt["defaultValue"])
                    else:
                        continue
                    dims = {k: str(extract_value(v, extracted)) for k, v in (mt.get("dimensions") or {}).items()} \
                        if matched else {}
                    if matched or not mt.get("dimensions"):
                        metrics.append(Metric(mt["metricNamespace"], mt["metricName"], value, dims,
                                              mt.get("unit", "None"), ts / 1000))
        s.last_ingestion = now
        if metrics and self.emu:
            self.emu.services["cloudwatch"].ingest(metrics)

    def deliver(self, group: str, stream: str, events: list[tuple[int, str]]) -> str | None:
        """AWS サービス (CloudTrail など) からのログ配信。失敗時はエラーコードを返す。"""
        with self.lock:
            g = self.groups.get(group)
            if g is None:
                return "ResourceNotFoundException"
            s = g.streams.setdefault(stream, Stream(stream, self._now_ms()))
            self._ingest(g, s, events, self._now_ms())
            return None

    # ================================================================== reading
    def op_GetLogEvents(self, p, req):
        g = self._group(p)
        s = self._stream(g, p.get("logStreamName"))
        start, end = p.get("startTime"), p.get("endTime")
        events = [e for e in s.events if (start is None or e.timestamp >= start) and (end is None or e.timestamp < end)]
        limit = min(int(p.get("limit") or 10000), 10000)
        token = p.get("nextToken")
        if token:
            direction, _, idx = token.partition("/")
            idx = int(idx)
            if direction == "f":
                lo, hi = idx, min(len(events), idx + limit)
            else:
                lo, hi = max(0, idx - limit), idx
        elif p.get("startFromHead"):
            lo, hi = 0, min(len(events), limit)
        else:
            lo, hi = max(0, len(events) - limit), len(events)
        page = events[lo:hi]
        return {"events": [{"timestamp": e.timestamp, "message": e.message, "ingestionTime": e.ingestion}
                           for e in page],
                "nextForwardToken": f"f/{hi:056d}", "nextBackwardToken": f"b/{lo:056d}"}

    def _collect(self, p: dict[str, Any], groups: list[Group]) -> list[tuple[Group, Stream, Event]]:
        names = set(p.get("logStreamNames") or [])
        prefix = p.get("logStreamNamePrefix")
        if names and prefix:
            raise invalid("logStreamNames and logStreamNamePrefix are mutually exclusive.")
        start, end = p.get("startTime"), p.get("endTime")
        out = []
        for g in groups:
            for s in g.streams.values():
                if names and s.name not in names or prefix and not s.name.startswith(prefix):
                    continue
                for e in s.events:
                    if (start is None or e.timestamp >= start) and (end is None or e.timestamp <= end):
                        out.append((g, s, e))
        out.sort(key=lambda x: (x[2].timestamp, x[2].id))
        return out

    def op_FilterLogEvents(self, p, req):
        g = self._group(p)
        matcher = compile_pattern(p.get("filterPattern"))
        events = [(s, e) for _, s, e in self._collect(p, [g]) if matcher(e.message)[0]]
        start = int(p.get("nextToken") or 0)
        limit = min(int(p.get("limit") or 10000), 10000)
        page = events[start:start + limit]
        result: dict[str, Any] = {
            "events": [{"logStreamName": s.name, "timestamp": e.timestamp, "message": e.message,
                        "ingestionTime": e.ingestion, "eventId": e.id} for s, e in page],
            "searchedLogStreams": [],
        }
        if start + limit < len(events):
            result["nextToken"] = str(start + limit)
        return result

    # ================================================================== metric filters
    def op_PutMetricFilter(self, p, req):
        g = self._group(p)
        transforms = p.get("metricTransformations") or []
        if len(transforms) != 1:
            raise invalid("metricTransformations must contain exactly one element.")
        for mt in transforms:
            if mt.get("metricNamespace", "").startswith("AWS/"):
                raise invalid("Invalid metric namespace: AWS/ is reserved.")
            if mt.get("dimensions") and "defaultValue" in mt:
                raise invalid("Metric filters with dimensions cannot have a default value.")
        if len(g.metric_filters) >= 100 and p["filterName"] not in g.metric_filters:
            raise AwsError("LimitExceededException", "Resource limit exceeded.")
        try:
            matcher = compile_pattern(p.get("filterPattern"))
        except AwsError:
            raise invalid("Invalid metric filter pattern")
        g.metric_filters[p["filterName"]] = {
            "filterName": p["filterName"], "filterPattern": p.get("filterPattern", ""),
            "metricTransformations": transforms, "creationTime": self._now_ms(), "logGroupName": g.name,
            "_matcher": matcher,
        }

    def op_DescribeMetricFilters(self, p, req):
        groups = [self._group(p)] if p.get("logGroupName") else list(self.groups.values())
        out = []
        for g in groups:
            for f in g.metric_filters.values():
                if p.get("filterNamePrefix") and not f["filterName"].startswith(p["filterNamePrefix"]):
                    continue
                mts = f["metricTransformations"]
                if p.get("metricName") and not any(m["metricName"] == p["metricName"] for m in mts):
                    continue
                if p.get("metricNamespace") and not any(m["metricNamespace"] == p["metricNamespace"] for m in mts):
                    continue
                out.append({k: v for k, v in f.items() if not k.startswith("_")})
        return {"metricFilters": out}

    def op_DeleteMetricFilter(self, p, req):
        g = self._group(p)
        if g.metric_filters.pop(p.get("filterName"), None) is None:
            raise not_found("filter")

    def op_TestMetricFilter(self, p, req):
        matcher = compile_pattern(p.get("filterPattern"))
        matches = []
        for i, message in enumerate(p.get("logEventMessages") or [], start=1):
            ok, extracted = matcher(message)
            if ok:
                values = {f"${k}": str(v) for k, v in extracted.items() if k != "$json"}
                matches.append({"eventNumber": i, "eventMessage": message, "extractedValues": values})
        return {"matches": matches}

    # ================================================================== Logs Insights
    def op_StartQuery(self, p, req):
        names = ([self._group_name(p)] if p.get("logGroupName") or p.get("logGroupIdentifier") else []) + \
            list(p.get("logGroupNames") or []) + \
            [n.split(":log-group:")[-1].removesuffix(":*") for n in p.get("logGroupIdentifiers") or []]
        if not names:
            raise invalid("Log group name or log group identifiers must be specified")
        groups = []
        for n in names:
            if n not in self.groups:
                raise AwsError("ResourceNotFoundException", f"Log group '{n}' does not exist for account ID "
                               f"'{ACCOUNT_ID}' (Service: AWSLogs; Status Code: 400)")
            self._expire(self.groups[n])
            groups.append(self.groups[n])
        start, end = int(p["startTime"]) * 1000, int(p["endTime"]) * 1000 + 999
        if end < start:
            raise invalid("End time cannot be less than start time")
        collected = self._collect({"startTime": start, "endTime": end}, groups)
        records = [build_record(e.timestamp, e.message, e.ingestion, s.name, f"{ACCOUNT_ID}:{g.name}",
                                f"{g.name}/{s.name}/{e.id}") for g, s, e in collected]
        results, matched = run_query(p.get("queryString") or "", records, int(p.get("limit") or 1000))
        query_id = str(uuid.uuid4())
        self.queries[query_id] = {
            "queryId": query_id, "queryString": p.get("queryString"), "status": "Complete",
            "createTime": self._now_ms(), "logGroupName": names[0], "results": results,
            "statistics": {"recordsMatched": float(matched), "recordsScanned": float(len(records)),
                           "bytesScanned": float(sum(len(r["@message"].encode()) for r in records))},
        }
        return {"queryId": query_id}

    def op_GetQueryResults(self, p, req):
        q = self.queries.get(p.get("queryId"))
        if q is None:
            raise AwsError("ResourceNotFoundException", "Query does not exist.")
        return {"status": q["status"], "results": q["results"], "statistics": q["statistics"]}

    def op_StopQuery(self, p, req):
        if p.get("queryId") not in self.queries:
            raise AwsError("ResourceNotFoundException", "Query does not exist.")
        return {"success": False}

    def op_DescribeQueries(self, p, req):
        return {"queries": [{k: q[k] for k in ("queryId", "queryString", "status", "createTime", "logGroupName")}
                            for q in self.queries.values()
                            if not p.get("status") or q["status"] == p["status"]]}

    # ================================================================== tags
    def op_TagResource(self, p, req):
        name = p.get("resourceArn", "").split(":log-group:", 1)[-1].removesuffix(":*")
        self._group({"logGroupName": name}).tags.update(p.get("tags") or {})

    def op_ListTagsForResource(self, p, req):
        name = p.get("resourceArn", "").split(":log-group:", 1)[-1].removesuffix(":*")
        return {"tags": self._group({"logGroupName": name}).tags}

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            out = {}
            for g in self.groups.values():
                self._expire(g)
                out[g.name] = {
                    "retention_days": g.retention,
                    "metric_filters": {n: {"pattern": f["filterPattern"],
                                           "metric": [f"{m['metricNamespace']}/{m['metricName']}"
                                                      for m in f["metricTransformations"]]}
                                       for n, f in g.metric_filters.items()},
                    "streams": {s.name: {"event_count": len(s.events),
                                         "last_events": [e.message for e in s.events[-5:]]}
                                for s in g.streams.values()},
                }
            return out

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {n: {"created": g.created, "retention": g.retention, "tags": g.tags, "class": g.group_class,
                        "metric_filters": [{k: v for k, v in f.items() if not k.startswith("_")}
                                           for f in g.metric_filters.values()],
                        "streams": {s.name: {"created": s.created, "last_ingestion": s.last_ingestion,
                                             "events": [e.__dict__ for e in s.events]}
                                    for s in g.streams.values()}}
                    for n, g in self.groups.items()}

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.groups = {}
            for n, d in data.items():
                g = Group(n, d["created"], d.get("retention"), tags=d.get("tags", {}),
                          group_class=d.get("class", "STANDARD"))
                for f in d.get("metric_filters", []):
                    g.metric_filters[f["filterName"]] = {**f, "_matcher": compile_pattern(f["filterPattern"])}
                for sn, sd in d.get("streams", {}).items():
                    g.streams[sn] = Stream(sn, sd["created"], [Event(**e) for e in sd["events"]],
                                           sd.get("last_ingestion"))
                self.groups[n] = g

