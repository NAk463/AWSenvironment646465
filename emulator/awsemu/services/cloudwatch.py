"""CloudWatch メトリクス / アラーム (awsJson1.0 と smithy-rpc-v2-cbor の両方に対応, awsQueryCompatible)。

- 各サービスが発行する AWS/* メトリクスと、PutMetricData のカスタムメトリクスを保存
- GetMetricData (Metric Math の四則演算・METRICS()・SUM/AVG/MIN/MAX/FILL 対応)、GetMetricStatistics、ListMetrics
- アラームはエミュレータの時計に従って評価され、状態遷移と履歴 (DescribeAlarmHistory) が残る
"""
from __future__ import annotations

import ast
import json
import math
import re
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .. import cbor
from ..core import ACCOUNT_ID, AwsError, Metric, Request, Response, Service

OPERATION_PATH = re.compile(r"^/service/GraniteServiceVersion20100801/operation/(\w+)$")
TARGET_PREFIX = "GraniteServiceVersion20100801."
MAX_SAMPLES_PER_METRIC = 200_000
STATISTICS = ("SampleCount", "Average", "Sum", "Minimum", "Maximum")
COMPARATORS: dict[str, tuple[str, Callable[[float, float], bool]]] = {
    "GreaterThanThreshold": ("greater than", lambda v, t: v > t),
    "GreaterThanOrEqualToThreshold": ("greater than or equal to", lambda v, t: v >= t),
    "LessThanThreshold": ("less than", lambda v, t: v < t),
    "LessThanOrEqualToThreshold": ("less than or equal to", lambda v, t: v <= t),
}
QUERY_CODES = {
    "InvalidParameterValueException": "InvalidParameterValue",
    "MissingRequiredParameterException": "MissingParameter",
    "InvalidParameterCombinationException": "InvalidParameterCombination",
    "LimitExceededException": "LimitExceeded",
    "ResourceNotFound": "ResourceNotFound",
    "ResourceNotFoundException": "ResourceNotFoundException",
    "InvalidNextToken": "InvalidNextToken",
    "InternalServiceFault": "InternalServiceError",
}


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def short_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%m/%y %H:%M:%S")


def invalid(msg: str) -> AwsError:
    return AwsError("InvalidParameterValueException", msg)


@dataclass
class Sample:
    ts: float
    total: float
    count: float
    minimum: float
    maximum: float
    values: list[float] | None
    unit: str


@dataclass
class Agg:
    total: float = 0.0
    count: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf
    values: list[float] = field(default_factory=list)
    unit: str = "None"

    def add(self, s: Sample) -> None:
        self.total += s.total
        self.count += s.count
        self.minimum = min(self.minimum, s.minimum)
        self.maximum = max(self.maximum, s.maximum)
        if s.values:
            self.values.extend(s.values)
        self.unit = s.unit

    def stat(self, name: str) -> float | None:
        if self.count == 0:
            return None
        if name == "Sum":
            return self.total
        if name == "SampleCount":
            return self.count
        if name == "Average":
            return self.total / self.count
        if name == "Minimum":
            return self.minimum
        if name == "Maximum":
            return self.maximum
        m = re.fullmatch(r"p(\d+(?:\.\d+)?)", name)
        if m:
            vals = sorted(self.values) or [self.total / self.count]
            rank = max(0, math.ceil(float(m.group(1)) / 100 * len(vals)) - 1)
            return vals[min(rank, len(vals) - 1)]
        raise invalid(f"The value {name} for parameter Stat is invalid.")


MetricKey = tuple[str, str, tuple[tuple[str, str], ...]]


def metric_key(namespace: str, name: str, dims: dict[str, str] | list[dict[str, str]] | None) -> MetricKey:
    if isinstance(dims, list):
        dims = {d["Name"]: d["Value"] for d in dims}
    return namespace, name, tuple(sorted((dims or {}).items()))


class CloudWatch(Service):
    name = "cloudwatch"
    iam_prefix = "cloudwatch"
    event_source = "monitoring.amazonaws.com"
    data_events = frozenset({"PutMetricData", "GetMetricData", "GetMetricStatistics", "ListMetrics"})

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self._data_lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.data: dict[MetricKey, list[Sample]] = defaultdict(list)
            self.alarms: dict[str, dict[str, Any]] = {}
            self.history: list[dict[str, Any]] = []
            self.dashboards: dict[str, dict[str, Any]] = {}

    # ================================================================== protocol
    @staticmethod
    def _is_cbor(req: Request) -> bool:
        return req.path.startswith("/service/")

    def operation(self, req: Request) -> str:
        target = req.header("X-Amz-Target") or ""
        if target.startswith(TARGET_PREFIX):
            return target[len(TARGET_PREFIX):]
        m = OPERATION_PATH.match(req.path)
        return m.group(1) if m else "Unknown"

    def params(self, req: Request) -> dict[str, Any]:
        if "_params" not in req.ctx:
            try:
                if self._is_cbor(req):
                    req.ctx["_params"] = cbor.loads(req.body) or {}
                else:
                    req.ctx["_params"] = json.loads(req.body or b"{}")
            except (ValueError, IndexError, UnicodeDecodeError):
                raise AwsError("SerializationException", "Request body could not be parsed")
        return req.ctx["_params"]

    def _encode(self, req: Request, status: int, data: dict[str, Any], extra: dict[str, str] | None = None) -> Response:
        if self._is_cbor(req):
            headers = {"Content-Type": "application/cbor", "smithy-protocol": "rpc-v2-cbor"}
            body = cbor.dumps(data)
        else:
            headers = {"Content-Type": "application/x-amz-json-1.0"}
            body = json.dumps(data).encode()
        return Response(status, body, {**headers, **(extra or {})})

    def params_for_log(self, req: Request, op: str) -> Any:
        try:
            p = self.params(req)
        except AwsError:
            return None
        if op == "PutMetricData":
            return {"namespace": p.get("Namespace"), "metricCount": len(p.get("MetricData") or [])}
        return json.loads(json.dumps(p, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))

    def resource(self, req: Request, op: str) -> str:
        p = self.params_for_log(req, op) or {}
        return p.get("AlarmName") or p.get("Namespace") or p.get("namespace") or ""

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        p = self.params(req)
        names = [p["AlarmName"]] if p.get("AlarmName") else p.get("AlarmNames") or []
        if names and op in ("PutMetricAlarm", "DeleteAlarms", "SetAlarmState", "EnableAlarmActions",
                            "DisableAlarmActions", "DescribeAlarmHistory"):
            return [(f"cloudwatch:{op}", f"arn:aws:cloudwatch:{req.region}:{ACCOUNT_ID}:alarm:{n}") for n in names]
        return [(f"cloudwatch:{op}", "*")]

    def handle(self, req: Request, op: str) -> Response:
        method = getattr(self, f"op_{op}", None)
        if method is None:
            raise AwsError("UnknownOperationException", f"Operation {op} is not implemented by awsemu")
        with self.lock:
            result = method(self.params(req), req)
        return self._encode(req, 200, result or {})

    def error_response(self, req: Request, err: AwsError) -> Response:
        legacy = QUERY_CODES.get(err.code, err.code)
        body = {"__type": f"com.amazonaws.cloudwatch#{err.code}", "message": err.message}
        return self._encode(req, err.status, body,
                            {"x-amzn-query-error": f"{legacy};{'Sender' if err.sender_fault else 'Receiver'}"})

    # ================================================================== ingest / query
    def ingest(self, metrics: list[Metric]) -> None:
        now = self.clock.now()
        with self._data_lock:
            for m in metrics:
                ts = m.timestamp if m.timestamp is not None else now
                self.data[metric_key(m.namespace, m.name, m.dimensions)].append(
                    Sample(ts, m.value, 1.0, m.value, m.value, [m.value], m.unit))
                self._trim(metric_key(m.namespace, m.name, m.dimensions))

    def _trim(self, key: MetricKey) -> None:
        samples = self.data[key]
        if len(samples) > MAX_SAMPLES_PER_METRIC:
            del samples[: len(samples) - MAX_SAMPLES_PER_METRIC]

    def aggregate(self, key: MetricKey, start: float, end: float, period: int) -> dict[float, Agg]:
        buckets: dict[float, Agg] = {}
        with self._data_lock:
            samples = list(self.data.get(key, ()))
        for s in samples:
            if start <= s.ts < end:
                b = math.floor(s.ts / period) * period
                buckets.setdefault(b, Agg()).add(s)
        return buckets

    def series(self, key: MetricKey, start: float, end: float, period: int, stat: str,
               unit: str | None = None) -> dict[float, float]:
        out = {}
        for ts, agg in self.aggregate(key, start, end, period).items():
            if unit and agg.unit != unit:
                continue
            v = agg.stat(stat)
            if v is not None:
                out[ts] = v
        return out

    # ================================================================== PutMetricData
    def op_PutMetricData(self, p, req):
        ns = p.get("Namespace")
        if not ns:
            raise AwsError("MissingRequiredParameterException", "The parameter Namespace is required.")
        if ns.startswith("AWS/"):
            raise invalid("The value AWS/ for parameter Namespace is invalid.")
        data = p.get("MetricData") or []
        if not 1 <= len(data) <= 1000:
            raise invalid("The collection MetricData must not contain more than 1000 items.")
        now = self.clock.now()
        with self._data_lock:
            for i, d in enumerate(data, start=1):
                ts = float(d.get("Timestamp") or now)
                if ts > now + 7200:
                    raise invalid(f"The parameter MetricData.member.{i}.Timestamp must specify a time no more "
                                  "than two hours in the future.")
                if ts < now - 14 * 86400:
                    raise invalid(f"The parameter MetricData.member.{i}.Timestamp must specify a time within the "
                                  "past two weeks.")
                dims = d.get("Dimensions") or []
                if len(dims) > 30:
                    raise invalid("The collection MetricData.member.Dimensions must not contain more than 30 items.")
                key = metric_key(ns, d["MetricName"], dims)
                unit = d.get("Unit", "None")
                if "StatisticValues" in d:
                    sv = d["StatisticValues"]
                    self.data[key].append(Sample(ts, float(sv["Sum"]), float(sv["SampleCount"]),
                                                 float(sv["Minimum"]), float(sv["Maximum"]), None, unit))
                elif "Values" in d:
                    counts = d.get("Counts") or [1.0] * len(d["Values"])
                    for v, c in zip(d["Values"], counts):
                        self.data[key].append(Sample(ts, float(v) * c, float(c), float(v), float(v),
                                                     [float(v)] * int(c), unit))
                else:
                    v = float(d.get("Value", 0.0))
                    self.data[key].append(Sample(ts, v, 1.0, v, v, [v], unit))
                self._trim(key)

    # ================================================================== GetMetricStatistics
    @staticmethod
    def _check_period(period: int, start: float, end: float) -> None:
        if period < 1 or (period >= 60 and period % 60) or (period < 60 and period not in (1, 5, 10, 30)):
            raise invalid("The parameter Period must be a multiple of 60.")
        if end <= start:
            raise invalid("The parameter StartTime must be less than the parameter EndTime.")
        points = (end - start) / period
        if points > 1440:
            raise AwsError("InvalidParameterCombinationException",
                           f"You have requested up to {int(points)} datapoints, which exceeds the limit of 1,440. "
                           "You may reduce the datapoints requested by increasing Period, or decreasing the time range.")

    def op_GetMetricStatistics(self, p, req):
        for name in ("Namespace", "MetricName", "StartTime", "EndTime", "Period"):
            if p.get(name) in (None, ""):
                raise AwsError("MissingRequiredParameterException", f"The parameter {name} is required.")
        stats = (p.get("Statistics") or []) + (p.get("ExtendedStatistics") or [])
        if not stats:
            raise AwsError("MissingRequiredParameterException",
                           "Must specify either Statistics or ExtendedStatistics.")
        start, end, period = float(p["StartTime"]), float(p["EndTime"]), int(p["Period"])
        self._check_period(period, start, end)
        key = metric_key(p["Namespace"], p["MetricName"], p.get("Dimensions"))
        points = []
        for ts, agg in sorted(self.aggregate(key, start, end, period).items()):
            if p.get("Unit") and agg.unit != p["Unit"]:
                continue
            dp: dict[str, Any] = {"Timestamp": cbor.Timestamp(ts), "Unit": agg.unit}
            for s in p.get("Statistics") or []:
                dp[s] = agg.stat(s)
            if p.get("ExtendedStatistics"):
                dp["ExtendedStatistics"] = {s: agg.stat(s) for s in p["ExtendedStatistics"]}
            points.append(dp)
        return {"Label": p["MetricName"], "Datapoints": points}

    # ================================================================== GetMetricData
    def _evaluate_queries(self, queries: list[dict[str, Any]], start: float, end: float) -> dict[str, dict[float, float]]:
        results: dict[str, dict[float, float]] = {}
        pending = []
        for q in queries:
            if "MetricStat" in q:
                ms = q["MetricStat"]
                metric = ms.get("Metric") or {}
                key = metric_key(metric.get("Namespace", ""), metric.get("MetricName", ""), metric.get("Dimensions"))
                period = int(ms.get("Period") or 60)
                results[q["Id"]] = self.series(key, start, end, period, ms.get("Stat", "Average"), ms.get("Unit"))
            elif "Expression" in q:
                pending.append(q)
            else:
                raise invalid("Each MetricDataQuery must contain either MetricStat or Expression.")
        for _ in range(len(pending) + 1):
            progress = False
            for q in list(pending):
                try:
                    value = MathEvaluator(results, [x["Id"] for x in queries if "MetricStat" in x]).run(q["Expression"])
                except KeyError:
                    continue
                if not isinstance(value, dict):
                    value = {}
                results[q["Id"]] = value
                pending.remove(q)
                progress = True
            if not progress:
                break
        if pending:
            raise invalid(f"Error in expression '{pending[0]['Id']}': Unrecognized metric id or syntax error")
        return results

    def op_GetMetricData(self, p, req):
        queries = p.get("MetricDataQueries") or []
        if not queries:
            raise AwsError("MissingRequiredParameterException", "The parameter MetricDataQueries is required.")
        if len(queries) > 500:
            raise invalid("The collection MetricDataQueries must not contain more than 500 items.")
        ids = [q.get("Id") for q in queries]
        if len(set(ids)) != len(ids):
            raise invalid("The values for parameter Id in MetricDataQueries are not unique.")
        for i in ids:
            if not i or not re.fullmatch(r"[a-z][a-zA-Z0-9_]*", i):
                raise invalid(f"The value {i} for parameter MetricDataQueries.member.Id is invalid.")
        start, end = float(p["StartTime"]), float(p["EndTime"])
        results = self._evaluate_queries(queries, start, end)
        descending = p.get("ScanBy", "TimestampDescending") == "TimestampDescending"
        out = []
        for q in queries:
            if q.get("ReturnData") is False:
                continue
            points = sorted(results[q["Id"]].items(), reverse=descending)
            label = q.get("Label") or (q.get("MetricStat", {}).get("Metric", {}).get("MetricName") or q["Id"])
            out.append({"Id": q["Id"], "Label": label, "StatusCode": "Complete",
                        "Timestamps": [cbor.Timestamp(t) for t, _ in points], "Values": [v for _, v in points]})
        return {"MetricDataResults": out, "Messages": []}

    # ================================================================== ListMetrics
    def op_ListMetrics(self, p, req):
        now = self.clock.now()
        wanted = p.get("Dimensions") or []
        out = []
        with self._data_lock:
            keys = [(k, v[-1].ts if v else 0) for k, v in self.data.items()]
        for (ns, name, dims), last in sorted(keys):
            if p.get("Namespace") and ns != p["Namespace"]:
                continue
            if p.get("MetricName") and name != p["MetricName"]:
                continue
            dmap = dict(dims)
            if any(f["Name"] not in dmap or ("Value" in f and dmap[f["Name"]] != f["Value"]) for f in wanted):
                continue
            if p.get("RecentlyActive") == "PT3H" and last < now - 3 * 3600:
                continue
            out.append({"Namespace": ns, "MetricName": name,
                        "Dimensions": [{"Name": k, "Value": v} for k, v in dims]})
        start = int(p.get("NextToken") or 0)
        result: dict[str, Any] = {"Metrics": out[start:start + 500]}
        if start + 500 < len(out):
            result["NextToken"] = str(start + 500)
        return result

    # ================================================================== alarms
    def _arn(self, name: str) -> str:
        return f"arn:aws:cloudwatch:ap-northeast-1:{ACCOUNT_ID}:alarm:{name}"

    def _add_history(self, alarm: str, kind: str, summary: str, data: dict[str, Any] | None = None) -> None:
        ts = getattr(self, "_eval_time", None) or self.clock.now()
        self.history.append({"AlarmName": alarm, "AlarmType": "MetricAlarm", "Timestamp": ts,
                             "HistoryItemType": kind, "HistorySummary": summary,
                             "HistoryData": json.dumps(data or {})})

    def op_PutMetricAlarm(self, p, req):
        name = p.get("AlarmName")
        if not name:
            raise AwsError("MissingRequiredParameterException", "The parameter AlarmName is required.")
        if p.get("ComparisonOperator") not in COMPARATORS:
            raise invalid(f"The value {p.get('ComparisonOperator')} for parameter ComparisonOperator is invalid.")
        n = int(p.get("EvaluationPeriods") or 0)
        m = int(p.get("DatapointsToAlarm") or n)
        if n < 1 or not 1 <= m <= n:
            raise invalid("DatapointsToAlarm must be between 1 and EvaluationPeriods.")
        if p.get("Metrics"):
            if p.get("MetricName") or p.get("Namespace"):
                raise AwsError("InvalidParameterCombinationException",
                               "Metrics list and MetricName/Namespace cannot be specified together.")
            if sum(1 for q in p["Metrics"] if q.get("ReturnData", True)) != 1:
                raise invalid("Exactly one element of the metrics list should return data.")
        else:
            for f in ("MetricName", "Namespace", "Period"):
                if not p.get(f):
                    raise AwsError("MissingRequiredParameterException", f"The parameter {f} is required.")
            if not (p.get("Statistic") or p.get("ExtendedStatistic")):
                raise AwsError("MissingRequiredParameterException",
                               "Must specify either Statistic or ExtendedStatistic.")
        now = self.clock.now()
        existing = self.alarms.get(name)
        alarm = {
            "AlarmName": name, "AlarmArn": self._arn(name), "AlarmDescription": p.get("AlarmDescription"),
            "ActionsEnabled": p.get("ActionsEnabled", True), "OKActions": p.get("OKActions") or [],
            "AlarmActions": p.get("AlarmActions") or [],
            "InsufficientDataActions": p.get("InsufficientDataActions") or [],
            "MetricName": p.get("MetricName"), "Namespace": p.get("Namespace"), "Statistic": p.get("Statistic"),
            "ExtendedStatistic": p.get("ExtendedStatistic"), "Dimensions": p.get("Dimensions") or [],
            "Period": p.get("Period"), "Unit": p.get("Unit"), "EvaluationPeriods": n, "DatapointsToAlarm": m,
            "Threshold": float(p.get("Threshold", 0.0)), "ComparisonOperator": p["ComparisonOperator"],
            "TreatMissingData": p.get("TreatMissingData", "missing"), "Metrics": p.get("Metrics"),
            "AlarmConfigurationUpdatedTimestamp": now,
            "StateValue": existing["StateValue"] if existing else "INSUFFICIENT_DATA",
            "StateReason": existing["StateReason"] if existing else "Unchecked: Initial alarm creation",
            "StateUpdatedTimestamp": existing["StateUpdatedTimestamp"] if existing else now,
            "StateTransitionedTimestamp": existing["StateTransitionedTimestamp"] if existing else now,
        }
        self.alarms[name] = alarm
        self._add_history(name, "ConfigurationUpdate",
                          f'Alarm "{name}" {"updated" if existing else "created"}',
                          {"type": "Update" if existing else "Create", "version": "1.0"})
        self.evaluate_alarms()

    def _alarm_series(self, a: dict[str, Any], start: float, end: float) -> tuple[dict[float, float], int]:
        if a.get("Metrics"):
            results = self._evaluate_queries(a["Metrics"], start, end)
            target = next(q for q in a["Metrics"] if q.get("ReturnData", True))
            period = int(target.get("Period") or target.get("MetricStat", {}).get("Period") or
                         next((q["MetricStat"]["Period"] for q in a["Metrics"] if "MetricStat" in q), 60))
            return results[target["Id"]], period
        period = int(a["Period"])
        key = metric_key(a["Namespace"], a["MetricName"], a["Dimensions"])
        return self.series(key, start, end, period, a.get("Statistic") or a["ExtendedStatistic"], a.get("Unit")), period

    def evaluate_alarms(self, at: float | None = None) -> None:
        """全アラームを評価する (AWS では 1 分ごと)。at を指定するとその時刻での評価として扱う。"""
        self._eval_time = at
        try:
            self._evaluate_alarms(self.clock.now() if at is None else at)
        finally:
            self._eval_time = None

    def _evaluate_alarms(self, now: float) -> None:
        for a in list(self.alarms.values()):
            period = int(a.get("Period") or 60)
            n, m = a["EvaluationPeriods"], a["DatapointsToAlarm"]
            end = math.floor(now / period) * period
            start = end - n * period
            series, period = self._alarm_series(a, start, end)
            label, compare = COMPARATORS[a["ComparisonOperator"]]
            threshold = a["Threshold"]
            points = [(ts, series.get(ts)) for ts in (end - (i + 1) * period for i in range(n))]
            treat = a.get("TreatMissingData", "missing")
            present = [(ts, v) for ts, v in points if v is not None]
            if not present and treat in ("missing", "ignore"):
                if treat == "missing":
                    self._set_state(a, "INSUFFICIENT_DATA",
                                    f"Insufficient Data: {n} datapoint{'s were' if n > 1 else ' was'} unknown.",
                                    period, [])
                continue
            breaching = [(ts, v) for ts, v in present if compare(v, threshold)]
            missing = n - len(present)
            bad = len(breaching) + (missing if treat == "breaching" else 0)
            good = len(present) - len(breaching) + (missing if treat == "notBreaching" else 0)
            desc = ", ".join(f"{v} ({short_time(ts)})" for ts, v in present[:5])

            def reason(count: int, negate: bool, minimum: int, transition: str) -> str:
                verb = f"{'not ' if negate else ''}{label}"
                if n == 1:
                    return f"Threshold Crossed: 1 datapoint [{desc}] was {verb} the threshold ({threshold})."
                return (f"Threshold Crossed: {count} out of the last {n} datapoints [{desc}] were {verb} the "
                        f"threshold ({threshold}) (minimum {minimum} datapoint{'s' if minimum > 1 else ''} "
                        f"for {transition} transition).")
            if bad >= m:
                self._set_state(a, "ALARM", reason(bad, False, m, "OK -> ALARM"), period, present)
            elif good >= n - m + 1:
                self._set_state(a, "OK", reason(good, True, n - m + 1, "ALARM -> OK"), period, present)
            # どちらとも判定できない場合 (欠損が多い) は現在の状態を維持する (AWS と同じ)

    def _set_state(self, a: dict[str, Any], state: str, reason: str, period: int,
                   points: list[tuple[float, float]], manual: bool = False) -> None:
        if a["StateValue"] == state and not manual:
            return
        now = getattr(self, "_eval_time", None) or self.clock.now()
        old = {"stateValue": a["StateValue"], "stateReason": a["StateReason"]}
        reason_data = {"version": "1.0", "queryDate": fmt_time(now), "statistic": a.get("Statistic"),
                       "period": period, "recentDatapoints": [v for _, v in points],
                       "threshold": a["Threshold"],
                       "evaluatedDatapoints": [{"timestamp": fmt_time(ts), "value": v} for ts, v in points]}
        a.update(StateValue=state, StateReason=reason, StateReasonData=json.dumps(reason_data),
                 StateUpdatedTimestamp=now, StateTransitionedTimestamp=now)
        self._add_history(a["AlarmName"], "StateUpdate", f"Alarm updated from {old['stateValue']} to {state}",
                          {"version": "1.0", "oldState": old,
                           "newState": {"stateValue": state, "stateReason": reason,
                                        "stateReasonData": reason_data}})
        actions = {"ALARM": a["AlarmActions"], "OK": a["OKActions"],
                   "INSUFFICIENT_DATA": a["InsufficientDataActions"]}[state]
        if a["ActionsEnabled"]:
            for arn in actions:
                ok, detail = self.emu.alarm_action(arn, a) if self.emu else (False, "no emulator")
                summary = (f"Successfully executed action {arn}" if ok else
                           f"Failed to execute action {arn}. Received error: \"{detail}\"")
                self._add_history(a["AlarmName"], "Action", summary, {"actionState": "Succeeded" if ok else "Failed",
                                                                      "notificationResource": arn})

    def _alarm_view(self, a: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in a.items() if v not in (None, [])}
        for k in ("AlarmConfigurationUpdatedTimestamp", "StateUpdatedTimestamp", "StateTransitionedTimestamp"):
            if k in out:
                out[k] = cbor.Timestamp(out[k])
        for k in ("OKActions", "AlarmActions", "InsufficientDataActions", "Dimensions"):
            out.setdefault(k, a.get(k) or [])
        return out

    def op_DescribeAlarms(self, p, req):
        self.evaluate_alarms()
        names = p.get("AlarmNames")
        out = []
        for a in sorted(self.alarms.values(), key=lambda x: x["AlarmName"]):
            if names and a["AlarmName"] not in names:
                continue
            if p.get("AlarmNamePrefix") and not a["AlarmName"].startswith(p["AlarmNamePrefix"]):
                continue
            if p.get("StateValue") and a["StateValue"] != p["StateValue"]:
                continue
            if p.get("ActionPrefix") and not any(x.startswith(p["ActionPrefix"]) for x in
                                                 a["AlarmActions"] + a["OKActions"] + a["InsufficientDataActions"]):
                continue
            out.append(self._alarm_view(a))
        types = p.get("AlarmTypes") or ["MetricAlarm"]
        return {"MetricAlarms": out if "MetricAlarm" in types else [], "CompositeAlarms": []}

    def op_DescribeAlarmsForMetric(self, p, req):
        self.evaluate_alarms()
        dims = metric_key("", "", p.get("Dimensions"))[2]
        out = [self._alarm_view(a) for a in self.alarms.values()
               if a["MetricName"] == p.get("MetricName") and a["Namespace"] == p.get("Namespace")
               and (not p.get("Dimensions") or metric_key("", "", a["Dimensions"])[2] == dims)
               and (not p.get("Statistic") or a["Statistic"] == p["Statistic"])
               and (not p.get("Period") or a["Period"] == p["Period"])]
        return {"MetricAlarms": out}

    def op_DeleteAlarms(self, p, req):
        names = p.get("AlarmNames") or []
        missing = [n for n in names if n not in self.alarms]
        if missing:
            raise AwsError("ResourceNotFound", f"Alarm(s) not found: {', '.join(missing)}", 404)
        for n in names:
            del self.alarms[n]

    def op_SetAlarmState(self, p, req):
        a = self.alarms.get(p.get("AlarmName"))
        if a is None:
            raise AwsError("ResourceNotFound", f"Alarm {p.get('AlarmName')} not found", 404)
        if p.get("StateValue") not in ("OK", "ALARM", "INSUFFICIENT_DATA"):
            raise invalid(f"The value {p.get('StateValue')} for parameter StateValue is invalid.")
        self._set_state(a, p["StateValue"], p.get("StateReason", ""), int(a.get("Period") or 60), [], manual=True)

    def _toggle_actions(self, p, enabled: bool) -> None:
        for n in p.get("AlarmNames") or []:
            if n in self.alarms:
                self.alarms[n]["ActionsEnabled"] = enabled

    def op_EnableAlarmActions(self, p, req):
        self._toggle_actions(p, True)

    def op_DisableAlarmActions(self, p, req):
        self._toggle_actions(p, False)

    def op_DescribeAlarmHistory(self, p, req):
        self.evaluate_alarms()
        start = float(p.get("StartDate") or 0)
        end = float(p.get("EndDate") or math.inf)
        items = [h for h in self.history
                 if (not p.get("AlarmName") or h["AlarmName"] == p["AlarmName"])
                 and (not p.get("HistoryItemType") or h["HistoryItemType"] == p["HistoryItemType"])
                 and start <= h["Timestamp"] <= end]
        items.sort(key=lambda h: h["Timestamp"], reverse=p.get("ScanBy", "TimestampDescending") != "TimestampAscending")
        limit = int(p.get("MaxRecords") or 100)
        return {"AlarmHistoryItems": [{**h, "Timestamp": cbor.Timestamp(h["Timestamp"])} for h in items[:limit]]}

    # ================================================================== dashboards
    def op_PutDashboard(self, p, req):
        try:
            json.loads(p.get("DashboardBody") or "")
        except ValueError:
            raise invalid("The field DashboardBody must be a valid JSON object")
        self.dashboards[p["DashboardName"]] = {"body": p["DashboardBody"], "updated": self.clock.now()}
        return {"DashboardValidationMessages": []}

    def op_GetDashboard(self, p, req):
        d = self.dashboards.get(p.get("DashboardName"))
        if d is None:
            raise AwsError("ResourceNotFound", "Dashboard does not exist", 404)
        return {"DashboardArn": f"arn:aws:cloudwatch::{ACCOUNT_ID}:dashboard/{p['DashboardName']}",
                "DashboardBody": d["body"], "DashboardName": p["DashboardName"]}

    def op_ListDashboards(self, p, req):
        return {"DashboardEntries": [
            {"DashboardName": n, "DashboardArn": f"arn:aws:cloudwatch::{ACCOUNT_ID}:dashboard/{n}",
             "LastModified": cbor.Timestamp(d["updated"]), "Size": len(d["body"])}
            for n, d in sorted(self.dashboards.items())
            if not p.get("DashboardNamePrefix") or n.startswith(p["DashboardNamePrefix"])]}

    def op_DeleteDashboards(self, p, req):
        for n in p.get("DashboardNames") or []:
            self.dashboards.pop(n, None)

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            self.evaluate_alarms()
        with self._data_lock:
            metrics = sorted({f"{ns} {name} {dict(dims)}" for ns, name, dims in self.data})
        return {
            "metric_count": len(metrics),
            "metrics": metrics[:500],
            "alarms": {n: {"state": a["StateValue"], "reason": a["StateReason"],
                           "metric": a.get("MetricName") or "metric math", "threshold": a["Threshold"]}
                       for n, a in self.alarms.items()},
        }

    def dump(self) -> dict[str, Any]:
        with self._data_lock:
            data = [{"key": [ns, name, list(dims)], "samples": [s.__dict__ for s in samples[-20000:]]}
                    for (ns, name, dims), samples in self.data.items()]
        return {"data": data, "alarms": self.alarms, "history": self.history[-5000:], "dashboards": self.dashboards}

    def load(self, data: dict[str, Any]) -> None:
        with self.lock, self._data_lock:
            self.data = defaultdict(list)
            for entry in data.get("data", []):
                ns, name, dims = entry["key"]
                self.data[(ns, name, tuple(tuple(d) for d in dims))] = [Sample(**s) for s in entry["samples"]]
            self.alarms = data.get("alarms", {})
            self.history = data.get("history", [])
            self.dashboards = data.get("dashboards", {})


class MathEvaluator:
    """Metric Math の簡易評価器。時系列同士の四則演算と主要な関数に対応する。"""

    def __init__(self, results: dict[str, dict[float, float]], metric_ids: list[str]) -> None:
        self.results = results
        self.metric_ids = metric_ids

    def run(self, expr: str) -> Any:
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError:
            raise invalid(f"Error in expression: syntax error in '{expr}'")
        return self._eval(tree.body)

    def _eval(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name):
            if node.id not in self.results:
                raise KeyError(node.id)
            return self.results[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return self._binary(0.0, self._eval(node.operand), lambda a, b: a - b)
        if isinstance(node, ast.BinOp):
            ops = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
                   ast.Div: lambda a, b: a / b if b else math.nan}
            fn = ops.get(type(node.op))
            if fn is None:
                raise invalid("Unsupported operator in expression")
            return self._binary(self._eval(node.left), self._eval(node.right), fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id.upper()
            if name == "METRICS":
                return [self.results[i] for i in self.metric_ids if i in self.results]
            args = [self._eval(a) for a in node.args]
            if name in ("SUM", "AVG", "MIN", "MAX"):
                series = args[0] if len(args) == 1 and isinstance(args[0], list) else args
                agg = {"SUM": sum, "AVG": lambda v: sum(v) / len(v), "MIN": min, "MAX": max}[name]
                if all(isinstance(s, dict) for s in series):
                    times = sorted({t for s in series for t in s})
                    return {t: agg([s[t] for s in series if t in s]) for t in times}
                s = series[0]
                return agg(list(s.values())) if s else math.nan
            if name == "ABS":
                return self._binary(args[0], 0.0, lambda a, _: abs(a))
            if name == "FILL":
                # 他の系列に存在する時刻のうち、この系列に値が無いものを指定値で埋める
                series, value = args
                grid = {t for s in self.results.values() for t in s}
                filled = {t: value for t in grid if isinstance(value, float)}
                filled.update(series)
                return filled
            raise invalid(f"Unsupported function {name} in expression")
        raise invalid("Unsupported expression")

    @staticmethod
    def _binary(a: Any, b: Any, fn: Callable[[float, float], float]) -> Any:
        if isinstance(a, dict) and isinstance(b, dict):
            return {t: fn(a[t], b[t]) for t in a if t in b}
        if isinstance(a, dict):
            return {t: fn(v, b) for t, v in a.items()}
        if isinstance(b, dict):
            return {t: fn(a, v) for t, v in b.items()}
        return fn(a, b)
