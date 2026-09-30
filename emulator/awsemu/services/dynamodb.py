"""DynamoDB (awsJson1.0)。

テーブル/GSI/LSI、条件付き書き込み、Query/Scan のページング、トランザクション、TTL、
削除保護などを再現する。旧式パラメータ (Expected, AttributeUpdates, KeyConditions など) は非対応。
"""
from __future__ import annotations

import copy
import math
import json
import os
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Metric, Request
from ._json import JsonService
from .ddb_expr import (AV, apply_update, av_type, canonical, evaluate, item_size, parse_condition,
                       parse_projection, parse_update, project, sort_value)

MAX_ITEM_SIZE = 400 * 1024
TTL_DELAY = float(os.environ.get("AWSEMU_DDB_TTL_DELAY", "0"))
LEGACY_PARAMS = ("Expected", "AttributeUpdates", "KeyConditions", "ScanFilter", "QueryFilter",
                 "AttributesToGet", "ConditionalOperator")


def invalid(msg: str) -> AwsError:
    return AwsError("ValidationException", msg)


def not_found(msg: str = "Requested resource not found") -> AwsError:
    return AwsError("ResourceNotFoundException", msg)


INITIAL_BURST_SECONDS = float(os.environ.get("AWSEMU_DDB_INITIAL_BURST", "60"))
THROTTLE_TABLE_MSG = ("The level of configured provisioned throughput for the table was exceeded. "
                      "Consider increasing your provisioning level with the UpdateTable API.")
THROTTLE_GSI_MSG = ("The level of configured provisioned throughput for one or more global secondary indexes of the "
                    "table was exceeded. Consider increasing your provisioning level for the under-provisioned global "
                    "secondary indexes with the UpdateTable API")
ITEM_OPS = {"GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan", "BatchGetItem", "BatchWriteItem",
            "TransactGetItems", "TransactWriteItems"}
READ_OPS = {"GetItem", "Query", "Scan", "BatchGetItem", "TransactGetItems"}


@dataclass
class TokenBucket:
    """プロビジョンドキャパシティ。未使用分は最大 300 秒ぶんバーストとして蓄積される (AWS と同じ)。"""

    rate: float
    tokens: float
    last: float

    def refill(self, now: float) -> None:
        self.tokens = min(self.rate * 300, self.tokens + max(0.0, now - self.last) * self.rate)
        self.last = now


def rcu(size: int, consistent: bool) -> float:
    return max(1, math.ceil(size / 4096)) * (1.0 if consistent else 0.5)


def wcu(size: int) -> float:
    return float(max(1, math.ceil(size / 1024)))


@dataclass
class Index:
    name: str
    hash_key: str
    range_key: str | None
    projection: dict[str, Any]
    key_schema: list[dict[str, str]]
    throughput: dict[str, int] | None = None
    local: bool = False


@dataclass
class Table:
    name: str
    key_schema: list[dict[str, str]]
    attr_defs: list[dict[str, str]]
    billing_mode: str
    throughput: dict[str, int] | None
    created: float
    region: str
    indexes: dict[str, Index] = field(default_factory=dict)
    items: dict[tuple, dict[str, AV]] = field(default_factory=dict)
    ttl_attribute: str | None = None
    deletion_protection: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    stream: dict[str, Any] | None = None
    buckets: dict[str, TokenBucket] = field(default_factory=dict)

    @property
    def hash_key(self) -> str:
        return next(k["AttributeName"] for k in self.key_schema if k["KeyType"] == "HASH")

    @property
    def range_key(self) -> str | None:
        return next((k["AttributeName"] for k in self.key_schema if k["KeyType"] == "RANGE"), None)

    @property
    def key_names(self) -> list[str]:
        return [n for n in (self.hash_key, self.range_key) if n]

    @property
    def arn(self) -> str:
        return f"arn:aws:dynamodb:{self.region}:{ACCOUNT_ID}:table/{self.name}"

    def attr_type(self, name: str) -> str | None:
        return next((d["AttributeType"] for d in self.attr_defs if d["AttributeName"] == name), None)

    def key_of(self, item: dict[str, AV]) -> tuple:
        return tuple(canonical(item.get(k)) for k in self.key_names)


def validate_av(av: Any, path: str = "") -> None:
    if not isinstance(av, dict) or len(av) != 1:
        raise invalid("Supplied AttributeValue is empty, must contain exactly one of the supported datatypes")
    t, v = next(iter(av.items()))
    if t == "N":
        try:
            Decimal(v)
        except (InvalidOperation, TypeError):
            raise invalid("A value provided cannot be converted into a number")
    elif t in ("SS", "NS", "BS"):
        if not v:
            kind = {"SS": "string", "NS": "number", "BS": "binary"}[t]
            raise invalid(f"One or more parameter values were invalid: An {kind} set  may not be empty")
        if t == "NS":
            for x in v:
                validate_av({"N": x})
        members = [Decimal(x) for x in v] if t == "NS" else list(v)
        if len(set(members)) != len(members):
            raise invalid(f"Input collection {v} contains duplicates.")
    elif t == "L":
        for x in v:
            validate_av(x)
    elif t == "M":
        for x in v.values():
            validate_av(x)
    elif t not in ("S", "B", "BOOL", "NULL"):
        raise invalid(f"Supplied AttributeValue has unsupported datatype: {t}")


class DynamoDB(JsonService):
    name = "dynamodb"
    target_prefix = "DynamoDB_20120810."
    error_namespace = "com.amazonaws.dynamodb.v20120810"
    iam_prefix = "dynamodb"
    event_source = "dynamodb.amazonaws.com"
    data_events = frozenset(ITEM_OPS)
    access_denied_code = "AccessDeniedException"
    access_denied_status = 400
    invalid_token_code = "UnrecognizedClientException"
    invalid_token_status = 400
    expired_token_code = "ExpiredTokenException"
    expired_token_status = 400

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.tables: dict[str, Table] = {}

    def resource(self, req: Request, op: str) -> str:
        p = self.params_for_log(req, op) or {}
        if "TableName" in p:
            return p["TableName"]
        if "RequestItems" in p:
            return ",".join(p["RequestItems"])
        if "TransactItems" in p:
            return ",".join(sorted({next(iter(i.values())).get("TableName", "") for i in p["TransactItems"]}))
        return ""

    def handle(self, req, op):
        with self.lock:
            return super().handle(req, op)

    # ================================================================== IAM / CloudTrail / メトリクス
    def _table_arn(self, name: str, region: str) -> str:
        return f"arn:aws:dynamodb:{region}:{ACCOUNT_ID}:table/{name}"

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        p = self.params_for_log(req, op) or {}
        if op == "ListTables":
            return [("dynamodb:ListTables", "*")]
        if op in ("BatchWriteItem", "BatchGetItem"):
            return [(f"dynamodb:{op}", self._table_arn(n, req.region)) for n in p.get("RequestItems") or {}]
        if op in ("TransactWriteItems", "TransactGetItems"):
            action = {"Put": "PutItem", "Update": "UpdateItem", "Delete": "DeleteItem",
                      "ConditionCheck": "ConditionCheckItem", "Get": "GetItem"}
            out = []
            for entry in p.get("TransactItems") or []:
                for kind, spec in entry.items():
                    out.append((f"dynamodb:{action.get(kind, kind)}", self._table_arn(spec.get("TableName", ""), req.region)))
            return out
        if op in ("TagResource", "UntagResource", "ListTagsOfResource"):
            return [(f"dynamodb:{op}", p.get("ResourceArn", "*"))]
        arn = self._table_arn(p.get("TableName", ""), req.region)
        if op in ("Query", "Scan") and p.get("IndexName"):
            arn += f"/index/{p['IndexName']}"
        return [(f"dynamodb:{op}", arn)]

    def authz_context(self, req: Request, op: str) -> dict[str, Any]:
        p = self.params_for_log(req, op) or {}
        t = self.tables.get(p.get("TableName", ""))
        if t is None or op not in ("GetItem", "PutItem", "UpdateItem", "DeleteItem"):
            return {}
        key = p.get("Item") if op == "PutItem" else p.get("Key")
        value = (key or {}).get(t.hash_key)
        return {"dynamodb:leadingkeys": next(iter(value.values())) if isinstance(value, dict) and value else None}

    def trail_resources(self, req: Request, op: str) -> list[dict[str, str]]:
        return [{"accountId": ACCOUNT_ID, "type": "AWS::DynamoDB::Table", "ARN": arn}
                for _, arn in self.authz(req, op) if arn != "*"]

    def metrics(self, req: Request, op: str, status: int, error, duration_ms: float) -> list[Metric]:
        ctx = req.ctx.get("ddb") or {}
        table = ctx.get("table") or (self.params_for_log(req, op) or {}).get("TableName")
        ns = "AWS/DynamoDB"
        out: list[Metric] = []
        tdims = {"TableName": table} if table else {}
        if error is None:
            if table:
                out.append(Metric(ns, "SuccessfulRequestLatency", duration_ms, {**tdims, "Operation": op}, "Milliseconds"))
            if op in ("Query", "Scan") and table:
                out.append(Metric(ns, "ReturnedItemCount", float(ctx.get("returned", 0)), {**tdims, "Operation": op}, "Count"))
        elif error.code in ("ProvisionedThroughputExceededException", "ThrottlingException",
                            "RequestLimitExceeded"):
            if table:
                out.append(Metric(ns, "ThrottledRequests", 1.0, {**tdims, "Operation": op}, "Count"))
                kind = ctx.get("throttled") or ("read" if op in READ_OPS else "write")
                name = "ReadThrottleEvents" if kind == "read" else "WriteThrottleEvents"
                out.append(Metric(ns, name, 1.0, tdims, "Count"))
                if ctx.get("throttled_gsi"):
                    out.append(Metric(ns, name, 1.0, {**tdims, "GlobalSecondaryIndexName": ctx["throttled_gsi"]}, "Count"))
        elif error.code == "ConditionalCheckFailedException":
            if table:
                out.append(Metric(ns, "ConditionalCheckFailedRequests", 1.0, tdims, "Count"))
        elif error.status >= 500:
            if table:
                out.append(Metric(ns, "SystemErrors", 1.0, {**tdims, "Operation": op}, "Count"))
        else:
            out.append(Metric(ns, "UserErrors", 1.0, {}, "Count"))
        if table and ctx.get("rcu"):
            out.append(Metric(ns, "ConsumedReadCapacityUnits", ctx["rcu"], tdims, "Count"))
        if table and ctx.get("wcu"):
            out.append(Metric(ns, "ConsumedWriteCapacityUnits", ctx["wcu"], tdims, "Count"))
        for gsi, units in (ctx.get("gsi_wcu") or {}).items():
            out.append(Metric(ns, "ConsumedWriteCapacityUnits", units, {**tdims, "GlobalSecondaryIndexName": gsi}, "Count"))
        return out

    def gauges(self) -> list[Metric]:
        with self.lock:
            out = []
            for t in self.tables.values():
                if t.billing_mode != "PROVISIONED" or not t.throughput:
                    continue
                dims = {"TableName": t.name}
                out.append(Metric("AWS/DynamoDB", "ProvisionedReadCapacityUnits",
                                  float(t.throughput.get("ReadCapacityUnits", 0)), dims, "Count"))
                out.append(Metric("AWS/DynamoDB", "ProvisionedWriteCapacityUnits",
                                  float(t.throughput.get("WriteCapacityUnits", 0)), dims, "Count"))
            return out

    # ================================================================== capacity
    def _sync_buckets(self, t: Table) -> None:
        """テーブル / GSI のプロビジョンド容量に合わせてトークンバケットを用意する。"""
        now = self.clock.now()
        wanted: dict[str, float] = {}
        if t.billing_mode == "PROVISIONED" and t.throughput:
            wanted["read"] = float(t.throughput.get("ReadCapacityUnits", 0))
            wanted["write"] = float(t.throughput.get("WriteCapacityUnits", 0))
            for idx in t.indexes.values():
                if not idx.local and idx.throughput:
                    wanted[f"gsi:{idx.name}:read"] = float(idx.throughput.get("ReadCapacityUnits", 0))
                    wanted[f"gsi:{idx.name}:write"] = float(idx.throughput.get("WriteCapacityUnits", 0))
        for name in list(t.buckets):
            if name not in wanted:
                del t.buckets[name]
        for name, rate in wanted.items():
            b = t.buckets.get(name)
            if b is None:
                t.buckets[name] = TokenBucket(rate, rate * INITIAL_BURST_SECONDS, now)
            else:
                b.refill(now)
                b.rate = rate

    def _consume(self, t: Table, req: Request | None, read: float = 0.0, write: float = 0.0,
                 index: str | None = None, gsi_writes: dict[str, float] | None = None) -> None:
        """キャパシティを消費する。プロビジョンドで不足していれば ProvisionedThroughputExceededException。"""
        ctx = req.ctx.setdefault("ddb", {"table": t.name, "rcu": 0.0, "wcu": 0.0, "gsi_wcu": {}}) if req else {}
        gsi_writes = gsi_writes or {}
        if t.billing_mode == "PROVISIONED":
            self._sync_buckets(t)
            needs: list[tuple[str, float, str | None]] = []
            if read:
                key = f"gsi:{index}:read" if index and f"gsi:{index}:read" in t.buckets else "read"
                needs.append((key, read, None))
            for gsi, units in gsi_writes.items():
                if f"gsi:{gsi}:write" in t.buckets:
                    needs.append((f"gsi:{gsi}:write", units, gsi))
            if write:
                needs.append(("write", write, None))
            for key, units, gsi in needs:
                if t.buckets[key].tokens < units:
                    ctx["throttled"] = "read" if key.endswith("read") else "write"
                    if gsi:
                        ctx["throttled_gsi"] = gsi
                    raise AwsError("ProvisionedThroughputExceededException",
                                   THROTTLE_GSI_MSG if gsi else THROTTLE_TABLE_MSG)
            for key, units, _ in needs:
                t.buckets[key].tokens -= units
        if ctx:
            ctx["rcu"] += read
            ctx["wcu"] += write
            for gsi, units in gsi_writes.items():
                ctx["gsi_wcu"][gsi] = ctx["gsi_wcu"].get(gsi, 0.0) + units

    def _gsi_writes(self, t: Table, old: dict | None, new: dict | None, factor: float) -> dict[str, float]:
        out = {}
        for idx in t.indexes.values():
            if idx.local:
                continue
            touched = [i for i in (old, new) if i and self._in_index(idx, i)]
            if touched:
                out[idx.name] = sum(wcu(item_size(i)) for i in touched[-1:]) * factor
        return out

    # ================================================================== helpers
    def _table(self, name: str | None) -> Table:
        if not name:
            raise invalid("1 validation error detected: Value null at 'tableName' failed to satisfy constraint: Member must not be null")
        t = self.tables.get(name)
        if t is None:
            raise not_found()
        self._expire_ttl(t)
        return t

    def _expire_ttl(self, t: Table) -> None:
        if not t.ttl_attribute:
            return
        cutoff = self.clock.now() - TTL_DELAY
        expired = [k for k, item in t.items.items()
                   if "N" in item.get(t.ttl_attribute, {}) and Decimal(item[t.ttl_attribute]["N"]) <= Decimal(cutoff)]
        for k in expired:
            del t.items[k]

    @staticmethod
    def _reject_legacy(p: dict[str, Any]) -> None:
        for name in LEGACY_PARAMS:
            if name in p:
                raise invalid(f"awsemu does not support the legacy parameter {name}; use expression parameters instead")

    def _key(self, t: Table, key: dict[str, AV] | None) -> dict[str, AV]:
        key = key or {}
        names = t.key_names
        if set(key) != set(names):
            raise invalid("The provided key element does not match the schema")
        for n in names:
            validate_av(key[n])
            if av_type(key[n]) != t.attr_type(n):
                raise invalid("The provided key element does not match the schema")
        return key

    def _validate_item(self, t: Table, item: dict[str, AV]) -> None:
        for name, av in item.items():
            validate_av(av)
        for n in t.key_names:
            if n not in item:
                raise invalid(f"One or more parameter values were invalid: Missing the key {n} in the item")
            actual, expected = av_type(item[n]), t.attr_type(n)
            if actual != expected:
                raise invalid(f"One or more parameter values were invalid: Type mismatch for key {n} expected: {expected} actual: {actual}")
            if actual in ("S", "B") and not item[n][actual]:
                raise invalid(f"One or more parameter values are not valid. The AttributeValue for a key attribute "
                              f"cannot contain an empty {'string' if actual == 'S' else 'binary'} value. Key: {n}")
        for idx in t.indexes.values():
            for n in (idx.hash_key, idx.range_key):
                if n and n in item:
                    actual, expected = av_type(item[n]), t.attr_type(n)
                    if actual != expected:
                        raise invalid(f"One or more parameter values were invalid: Type mismatch for Index Key {n} "
                                      f"Expected: {expected} Actual: {actual} IndexName: {idx.name}")
                    if actual in ("S", "B") and not item[n][actual]:
                        raise invalid(f"One or more parameter values are not valid. A value specified for a secondary "
                                      f"index key is not supported. The AttributeValue for a key attribute cannot "
                                      f"contain an empty string value. IndexName: {idx.name}, IndexKey: {n}")
        if item_size(item) > MAX_ITEM_SIZE:
            raise invalid("Item size has exceeded the maximum allowed size")

    @staticmethod
    def _expressions(p: dict[str, Any], condition_fields=(), update: bool = False, projection: bool = False):
        """リクエスト内の式をまとめて解析し、未使用のプレースホルダも検出する。"""
        names, values = p.get("ExpressionAttributeNames"), p.get("ExpressionAttributeValues")
        for v in (values or {}).values():
            validate_av(v)
        parsed: dict[str, Any] = {}
        used_n: set[str] = set()
        used_v: set[str] = set()
        for fld in condition_fields:
            if p.get(fld):
                parsed[fld], parser = parse_condition(p[fld], names, values, fld)
                used_n |= parser.used_names
                used_v |= parser.used_values
        if update and p.get("UpdateExpression"):
            parsed["UpdateExpression"], parser = parse_update(p["UpdateExpression"], names, values)
            used_n |= parser.used_names
            used_v |= parser.used_values
        if projection and p.get("ProjectionExpression"):
            parsed["ProjectionExpression"], parser = parse_projection(p["ProjectionExpression"], names)
            used_n |= parser.used_names
        if values and not parsed:
            raise invalid("ExpressionAttributeValues can only be specified when using expressions")
        if names and not parsed:
            raise invalid("ExpressionAttributeNames can only be specified when using expressions")
        unused_v = set(values or {}) - used_v
        if unused_v:
            raise invalid(f"Value provided in ExpressionAttributeValues unused in expressions: keys: {{{', '.join(sorted(unused_v))}}}")
        unused_n = set(names or {}) - used_n
        if unused_n:
            raise invalid(f"Value provided in ExpressionAttributeNames unused in expressions: keys: {{{', '.join(sorted(unused_n))}}}")
        return parsed

    @staticmethod
    def _condition_failed(p: dict[str, Any], old: dict[str, AV] | None) -> AwsError:
        extra = {}
        if p.get("ReturnValuesOnConditionCheckFailure") == "ALL_OLD" and old:
            extra["Item"] = old
        return AwsError("ConditionalCheckFailedException", "The conditional request failed", extra=extra)

    @staticmethod
    def _capacity(p: dict[str, Any], t: Table, units: float = 1.0) -> dict[str, Any]:
        if p.get("ReturnConsumedCapacity") in ("TOTAL", "INDEXES"):
            return {"ConsumedCapacity": {"TableName": t.name, "CapacityUnits": units}}
        return {}

    def _describe(self, t: Table, status: str = "ACTIVE") -> dict[str, Any]:
        desc: dict[str, Any] = {
            "TableName": t.name,
            "TableStatus": status,
            "TableArn": t.arn,
            "TableId": f"{zlib.crc32(t.name.encode()):08x}-0000-0000-0000-000000000000",
            "KeySchema": t.key_schema,
            "AttributeDefinitions": t.attr_defs,
            "CreationDateTime": t.created,
            "ItemCount": len(t.items),
            "TableSizeBytes": sum(item_size(i) for i in t.items.values()),
            "DeletionProtectionEnabled": t.deletion_protection,
            "ProvisionedThroughput": {
                "NumberOfDecreasesToday": 0,
                "ReadCapacityUnits": (t.throughput or {}).get("ReadCapacityUnits", 0),
                "WriteCapacityUnits": (t.throughput or {}).get("WriteCapacityUnits", 0),
            },
        }
        if t.billing_mode == "PAY_PER_REQUEST":
            desc["BillingModeSummary"] = {"BillingMode": "PAY_PER_REQUEST"}
        gsis = [i for i in t.indexes.values() if not i.local]
        lsis = [i for i in t.indexes.values() if i.local]
        if gsis:
            desc["GlobalSecondaryIndexes"] = [
                {"IndexName": i.name, "KeySchema": i.key_schema, "Projection": i.projection, "IndexStatus": "ACTIVE",
                 "IndexArn": f"{t.arn}/index/{i.name}", "ItemCount": sum(1 for x in t.items.values() if self._in_index(i, x)),
                 "ProvisionedThroughput": {"ReadCapacityUnits": (i.throughput or {}).get("ReadCapacityUnits", 0),
                                           "WriteCapacityUnits": (i.throughput or {}).get("WriteCapacityUnits", 0)}}
                for i in gsis
            ]
        if lsis:
            desc["LocalSecondaryIndexes"] = [
                {"IndexName": i.name, "KeySchema": i.key_schema, "Projection": i.projection,
                 "IndexArn": f"{t.arn}/index/{i.name}"}
                for i in lsis
            ]
        if t.stream:
            desc["StreamSpecification"] = t.stream
        return desc

    @staticmethod
    def _in_index(idx: Index, item: dict[str, AV]) -> bool:
        return idx.hash_key in item and (not idx.range_key or idx.range_key in item)

    # ================================================================== tables
    def _make_index(self, spec: dict[str, Any], local: bool) -> Index:
        ks = spec["KeySchema"]
        return Index(
            name=spec["IndexName"],
            hash_key=next(k["AttributeName"] for k in ks if k["KeyType"] == "HASH"),
            range_key=next((k["AttributeName"] for k in ks if k["KeyType"] == "RANGE"), None),
            projection=spec.get("Projection") or {"ProjectionType": "ALL"},
            key_schema=ks,
            throughput=spec.get("ProvisionedThroughput"),
            local=local,
        )

    def op_CreateTable(self, p, req):
        name = p.get("TableName")
        if not name:
            raise invalid("1 validation error detected: Value null at 'tableName' failed to satisfy constraint: Member must not be null")
        if name in self.tables:
            raise AwsError("ResourceInUseException", f"Table already exists: {name}")
        key_schema = p.get("KeySchema") or []
        attr_defs = p.get("AttributeDefinitions") or []
        billing = p.get("BillingMode", "PROVISIONED")
        throughput = p.get("ProvisionedThroughput")
        if billing == "PROVISIONED" and not throughput:
            raise invalid("One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must "
                          "both be specified when BillingMode is PROVISIONED")
        if billing == "PROVISIONED":
            for gsi in p.get("GlobalSecondaryIndexes") or []:
                if not gsi.get("ProvisionedThroughput"):
                    raise invalid("One or more parameter values were invalid: ProvisionedThroughput must be "
                                  f"specified for index: {gsi.get('IndexName')}")
        if billing == "PAY_PER_REQUEST" and throughput:
            raise invalid("One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits "
                          "can be specified when BillingMode is PAY_PER_REQUEST")
        if [k["KeyType"] for k in key_schema] not in (["HASH"], ["HASH", "RANGE"]):
            raise invalid("1 validation error detected: Invalid KeySchema: The first KeySchemaElement is not a HASH key type")
        indexes = [self._make_index(s, False) for s in p.get("GlobalSecondaryIndexes") or []] + \
                  [self._make_index(s, True) for s in p.get("LocalSecondaryIndexes") or []]
        used = {k["AttributeName"] for k in key_schema}
        for idx in indexes:
            used |= {k["AttributeName"] for k in idx.key_schema}
        defined = {d["AttributeName"] for d in attr_defs}
        if used - defined:
            raise invalid(f"One or more parameter values were invalid: Some index key attributes are not defined in "
                          f"AttributeDefinitions. Keys: {sorted(used - defined)}, AttributeDefinitions: {sorted(defined)}")
        if defined - used:
            raise invalid("One or more parameter values were invalid: Number of attributes in KeySchema does not "
                          "exactly match number of attributes defined in AttributeDefinitions")
        t = Table(name, key_schema, attr_defs, billing, throughput, self.clock.now(), req.region,
                  {i.name: i for i in indexes},
                  deletion_protection=bool(p.get("DeletionProtectionEnabled")),
                  tags={x["Key"]: x["Value"] for x in p.get("Tags") or []},
                  stream=p.get("StreamSpecification"))
        self.tables[name] = t
        self._sync_buckets(t)
        return {"TableDescription": self._describe(t, "ACTIVE")}

    def op_DescribeTable(self, p, req):
        name = p.get("TableName")
        if name not in self.tables:
            raise not_found(f"Requested resource not found: Table: {name} not found")
        return {"Table": self._describe(self._table(name))}

    def op_ListTables(self, p, req):
        names = sorted(self.tables)
        start = p.get("ExclusiveStartTableName")
        if start:
            names = [n for n in names if n > start]
        limit = int(p.get("Limit") or 100)
        result: dict[str, Any] = {"TableNames": names[:limit]}
        if len(names) > limit:
            result["LastEvaluatedTableName"] = names[limit - 1]
        return result

    def op_DeleteTable(self, p, req):
        t = self._table(p.get("TableName"))
        if t.deletion_protection:
            raise invalid("Resource cannot be deleted as it is currently protected against deletion. "
                          "Disable deletion protection first.")
        desc = self._describe(t, "DELETING")
        del self.tables[t.name]
        return {"TableDescription": desc}

    def op_UpdateTable(self, p, req):
        t = self._table(p.get("TableName"))
        if "BillingMode" in p:
            t.billing_mode = p["BillingMode"]
            if t.billing_mode == "PAY_PER_REQUEST":
                t.throughput = None
        if "ProvisionedThroughput" in p:
            t.throughput = p["ProvisionedThroughput"]
        if "DeletionProtectionEnabled" in p:
            t.deletion_protection = bool(p["DeletionProtectionEnabled"])
        if "StreamSpecification" in p:
            t.stream = p["StreamSpecification"]
        for d in p.get("AttributeDefinitions") or []:
            if not t.attr_type(d["AttributeName"]):
                t.attr_defs.append(d)
        for upd in p.get("GlobalSecondaryIndexUpdates") or []:
            if "Create" in upd:
                idx = self._make_index(upd["Create"], False)
                if idx.name in t.indexes:
                    raise invalid(f"One or more parameter values were invalid: Index {idx.name} already exists")
                for k in idx.key_schema:
                    if not t.attr_type(k["AttributeName"]):
                        raise invalid("One or more parameter values were invalid: Global Secondary Index key "
                                      f"attribute {k['AttributeName']} is not defined in AttributeDefinitions")
                t.indexes[idx.name] = idx
            elif "Delete" in upd:
                if t.indexes.pop(upd["Delete"]["IndexName"], None) is None:
                    raise not_found(f"Requested resource not found: Index: {upd['Delete']['IndexName']} not found")
            elif "Update" in upd:
                idx = t.indexes.get(upd["Update"]["IndexName"])
                if idx is None:
                    raise not_found()
                idx.throughput = upd["Update"].get("ProvisionedThroughput")
        self._sync_buckets(t)
        return {"TableDescription": self._describe(t, "UPDATING")}

    def op_UpdateTimeToLive(self, p, req):
        t = self._table(p.get("TableName"))
        spec = p.get("TimeToLiveSpecification") or {}
        if spec.get("Enabled"):
            if t.ttl_attribute:
                raise invalid("TimeToLive is already enabled")
            t.ttl_attribute = spec["AttributeName"]
        else:
            if not t.ttl_attribute:
                raise invalid("TimeToLive is already disabled")
            t.ttl_attribute = None
        return {"TimeToLiveSpecification": spec}

    def op_DescribeTimeToLive(self, p, req):
        t = self._table(p.get("TableName"))
        if t.ttl_attribute:
            return {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED", "AttributeName": t.ttl_attribute}}
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}

    def _table_by_arn(self, arn: str) -> Table:
        return self._table(str(arn).rsplit("/", 1)[-1])

    def op_TagResource(self, p, req):
        self._table_by_arn(p.get("ResourceArn")).tags.update({x["Key"]: x["Value"] for x in p.get("Tags") or []})

    def op_UntagResource(self, p, req):
        t = self._table_by_arn(p.get("ResourceArn"))
        for k in p.get("TagKeys") or []:
            t.tags.pop(k, None)

    def op_ListTagsOfResource(self, p, req):
        t = self._table_by_arn(p.get("ResourceArn"))
        return {"Tags": [{"Key": k, "Value": v} for k, v in t.tags.items()]}

    # ================================================================== items
    def _put(self, p: dict[str, Any], req: Request | None = None, factor: float = 1.0) -> tuple[Table, dict | None, dict]:
        t = self._table(p.get("TableName"))
        item = p.get("Item") or {}
        self._validate_item(t, item)
        exprs = self._expressions(p, ("ConditionExpression",))
        old = t.items.get(t.key_of(item))
        # 条件チェックに失敗した書き込みも WCU を消費する (AWS と同じ)
        self._consume(t, req, write=wcu(max(item_size(item), item_size(old or {}))) * factor,
                      gsi_writes=self._gsi_writes(t, old, item, factor))
        if "ConditionExpression" in exprs and not evaluate(exprs["ConditionExpression"], old or {}):
            raise self._condition_failed(p, old)
        return t, old, item

    def op_PutItem(self, p, req):
        self._reject_legacy(p)
        t, old, item = self._put(p, req)
        t.items[t.key_of(item)] = copy.deepcopy(item)
        result: dict[str, Any] = self._capacity(p, t, req.ctx["ddb"]["wcu"])
        if p.get("ReturnValues") == "ALL_OLD" and old:
            result["Attributes"] = old
        elif p.get("ReturnValues") not in (None, "NONE", "ALL_OLD"):
            raise invalid("ReturnValues can only be ALL_OLD or NONE")
        return result

    def op_GetItem(self, p, req):
        self._reject_legacy(p)
        t = self._table(p.get("TableName"))
        key = self._key(t, p.get("Key"))
        exprs = self._expressions(p, projection=True)
        item = t.items.get(t.key_of(key))
        units = rcu(item_size(item or {}), bool(p.get("ConsistentRead")))
        self._consume(t, req, read=units)
        result: dict[str, Any] = self._capacity(p, t, units)
        if item is not None:
            result["Item"] = project(item, exprs["ProjectionExpression"]) if "ProjectionExpression" in exprs else item
        return result

    def _delete(self, p: dict[str, Any], req: Request | None = None, factor: float = 1.0) -> tuple[Table, dict | None]:
        t = self._table(p.get("TableName"))
        key = self._key(t, p.get("Key"))
        exprs = self._expressions(p, ("ConditionExpression",))
        old = t.items.get(t.key_of(key))
        self._consume(t, req, write=wcu(item_size(old or {})) * factor,
                      gsi_writes=self._gsi_writes(t, old, None, factor))
        if "ConditionExpression" in exprs and not evaluate(exprs["ConditionExpression"], old or {}):
            raise self._condition_failed(p, old)
        return t, old

    def op_DeleteItem(self, p, req):
        self._reject_legacy(p)
        t, old = self._delete(p, req)
        if old is not None:
            del t.items[t.key_of(old)]
        result: dict[str, Any] = self._capacity(p, t, req.ctx["ddb"]["wcu"])
        if p.get("ReturnValues") == "ALL_OLD" and old:
            result["Attributes"] = old
        return result

    def _update(self, p: dict[str, Any], req: Request | None = None,
                factor: float = 1.0) -> tuple[Table, dict | None, dict, list]:
        t = self._table(p.get("TableName"))
        key = self._key(t, p.get("Key"))
        exprs = self._expressions(p, ("ConditionExpression",), update=True)
        old = t.items.get(t.key_of(key))
        actions = exprs.get("UpdateExpression", [])
        for _, path, _ in actions:
            if path[0] in t.key_names:
                raise invalid(f"One or more parameter values were invalid: Cannot update attribute {path[0]}. "
                              "This attribute is part of the key")
        condition_ok = "ConditionExpression" not in exprs or evaluate(exprs["ConditionExpression"], old or {})
        new = apply_update(actions, old or copy.deepcopy(key)) if condition_ok else (old or key)
        self._consume(t, req, write=wcu(max(item_size(new), item_size(old or {}))) * factor,
                      gsi_writes=self._gsi_writes(t, old, new, factor))
        if not condition_ok:
            raise self._condition_failed(p, old)
        self._validate_item(t, new)
        return t, old, new, actions

    def op_UpdateItem(self, p, req):
        self._reject_legacy(p)
        t, old, new, actions = self._update(p, req)
        t.items[t.key_of(new)] = new
        result: dict[str, Any] = self._capacity(p, t, req.ctx["ddb"]["wcu"])
        rv = p.get("ReturnValues", "NONE")
        touched = {a[1][0] for a in actions}
        if rv == "ALL_OLD" and old:
            result["Attributes"] = old
        elif rv == "ALL_NEW":
            result["Attributes"] = new
        elif rv == "UPDATED_OLD" and old:
            attrs = {k: v for k, v in old.items() if k in touched}
            if attrs:
                result["Attributes"] = attrs
        elif rv == "UPDATED_NEW":
            attrs = {k: v for k, v in new.items() if k in touched}
            if attrs:
                result["Attributes"] = attrs
        return result

    # ================================================================== query / scan
    def _index_for(self, t: Table, p: dict[str, Any]) -> Index | None:
        name = p.get("IndexName")
        if not name:
            return None
        idx = t.indexes.get(name)
        if idx is None:
            raise invalid(f"The table does not have the specified index: {name}")
        if not idx.local and p.get("ConsistentRead"):
            raise invalid("Consistent reads are not supported on global secondary indexes")
        return idx

    def _order(self, t: Table, idx: Index | None, item: dict[str, AV]) -> tuple:
        names = ([idx.hash_key, idx.range_key] if idx else []) + t.key_names
        return tuple(sort_value(item[n]) if n and n in item else "" for n in names)

    def _index_projection(self, t: Table, idx: Index | None, item: dict[str, AV]) -> dict[str, AV]:
        if idx is None or idx.projection.get("ProjectionType", "ALL") == "ALL":
            return item
        keep = set(t.key_names) | {idx.hash_key, idx.range_key}
        if idx.projection.get("ProjectionType") == "INCLUDE":
            keep |= set(idx.projection.get("NonKeyAttributes") or [])
        return {k: v for k, v in item.items() if k in keep}

    def _page(self, t: Table, idx: Index | None, p: dict[str, Any], items: list[dict[str, AV]],
              exprs: dict[str, Any], req: Request, forward: bool = True) -> dict[str, Any]:
        items.sort(key=lambda i: self._order(t, idx, i), reverse=not forward)
        start = p.get("ExclusiveStartKey")
        if start:
            s = self._order(t, idx, start)
            items = [i for i in items if (self._order(t, idx, i) > s if forward else self._order(t, idx, i) < s)]
        limit = p.get("Limit")
        if limit is not None and int(limit) < 1:
            raise invalid("1 validation error detected: Value at 'limit' failed to satisfy constraint: Member must have value greater than or equal to 1")
        scanned = items[: int(limit)] if limit else items
        filt = exprs.get("FilterExpression")
        # Query / Scan は読み取ったアイテムの合計サイズで RCU を消費する (フィルタ前)
        units = rcu(sum(item_size(i) for i in scanned), bool(p.get("ConsistentRead")))
        self._consume(t, req, read=units, index=idx.name if idx else None)
        matched = [i for i in scanned if not filt or evaluate(filt, i)]
        req.ctx["ddb"]["returned"] = len(matched)
        select = p.get("Select", "ALL_ATTRIBUTES")
        result: dict[str, Any] = {"Count": len(matched), "ScannedCount": len(scanned), **self._capacity(p, t, units)}
        if select != "COUNT":
            out = [self._index_projection(t, idx, i) for i in matched]
            if "ProjectionExpression" in exprs:
                out = [project(i, exprs["ProjectionExpression"]) for i in out]
            result["Items"] = out
        if limit and len(scanned) == int(limit):
            last = scanned[-1]
            names = set(t.key_names) | ({idx.hash_key, idx.range_key} - {None} if idx else set())
            result["LastEvaluatedKey"] = {k: last[k] for k in names if k in last}
        return result

    def op_Query(self, p, req):
        self._reject_legacy(p)
        t = self._table(p.get("TableName"))
        idx = self._index_for(t, p)
        if not p.get("KeyConditionExpression"):
            raise invalid("Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.")
        exprs = self._expressions(p, ("KeyConditionExpression", "FilterExpression"), projection=True)
        hash_key, range_key = (idx.hash_key, idx.range_key) if idx else (t.hash_key, t.range_key)
        self._check_key_condition(exprs["KeyConditionExpression"], hash_key, range_key)
        cond = exprs["KeyConditionExpression"]
        candidates = [i for i in t.items.values() if (not idx or self._in_index(idx, i)) and evaluate(cond, i)]
        return self._page(t, idx, p, candidates, exprs, req, forward=p.get("ScanIndexForward", True))

    @staticmethod
    def _check_key_condition(node: tuple, hash_key: str, range_key: str | None) -> None:
        conjuncts: list[tuple] = []

        def flatten(n: tuple) -> None:
            if n[0] == "and":
                flatten(n[1])
                flatten(n[2])
            elif n[0] in ("or", "not", "in"):
                raise invalid(f"Invalid operator used in KeyConditionExpression: {n[0].upper()}")
            else:
                conjuncts.append(n)

        flatten(node)
        seen: dict[str, tuple] = {}
        for c in conjuncts:
            if c[0] == "func":
                if c[1] != "begins_with":
                    raise invalid(f"Invalid operator used in KeyConditionExpression: {c[1]}")
                attr = c[2][0][1]
            elif c[0] in ("cmp", "between"):
                if c[0] == "cmp" and c[1] == "<>":
                    raise invalid("Unsupported operator in KeyConditionExpression: <>")
                if c[2 if c[0] == "cmp" else 1][0] != "path":
                    raise invalid("Invalid KeyConditionExpression: The left-hand side of a key condition must be an attribute")
                attr = c[2][1] if c[0] == "cmp" else c[1][1]
            else:
                raise invalid("Invalid KeyConditionExpression")
            if len(attr) != 1 or attr[0] not in (hash_key, range_key):
                raise invalid(f"Query condition missed key schema element: {hash_key}" if attr[0] != hash_key
                              else "KeyConditionExpressions must only contain one condition per key")
            if attr[0] in seen:
                raise invalid("KeyConditionExpressions must only contain one condition per key")
            seen[attr[0]] = c
        h = seen.get(hash_key)
        if h is None:
            raise invalid(f"Query condition missed key schema element: {hash_key}")
        if not (h[0] == "cmp" and h[1] == "="):
            raise invalid("Query key condition not supported")

    def op_Scan(self, p, req):
        self._reject_legacy(p)
        t = self._table(p.get("TableName"))
        idx = self._index_for(t, p)
        exprs = self._expressions(p, ("FilterExpression",), projection=True)
        items = [i for i in t.items.values() if not idx or self._in_index(idx, i)]
        total = p.get("TotalSegments")
        if total:
            seg = int(p.get("Segment", 0))
            items = [i for i in items if zlib.crc32(json.dumps(t.key_of(i), default=str).encode()) % int(total) == seg]
        return self._page(t, idx, p, items, exprs, req)

    # ================================================================== batch
    def op_BatchWriteItem(self, p, req):
        requests = p.get("RequestItems") or {}
        total = sum(len(v) for v in requests.values())
        if total == 0:
            raise invalid("1 validation error detected: Value at 'requestItems' failed to satisfy constraint: Member must have length greater than or equal to 1")
        if total > 25:
            raise invalid("1 validation error detected: Value at 'requestItems' failed to satisfy constraint: "
                          "Map value must satisfy constraint: [Member must have length less than or equal to 25, "
                          "Member must have length greater than or equal to 1]")
        plan = []
        for name, reqs in requests.items():
            t = self._table(name)
            seen = set()
            for r in reqs:
                if "PutRequest" in r:
                    item = r["PutRequest"]["Item"]
                    self._validate_item(t, item)
                    k = t.key_of(item)
                    plan.append((t, k, item, r))
                else:
                    key = self._key(t, r["DeleteRequest"]["Key"])
                    k = t.key_of(key)
                    plan.append((t, k, None, r))
                if k in seen:
                    raise invalid("Provided list of item keys contains duplicates")
                seen.add(k)
        # キャパシティ不足の分は UnprocessedItems として返す (全件不足なら例外)。AWS と同じ挙動
        unprocessed: dict[str, list] = {}
        for t, k, item, r in plan:
            old = t.items.get(k)
            try:
                self._consume(t, req, write=wcu(max(item_size(item or {}), item_size(old or {}))),
                              gsi_writes=self._gsi_writes(t, old, item, 1.0))
            except AwsError:
                unprocessed.setdefault(t.name, []).append(r)
                continue
            if item is None:
                t.items.pop(k, None)
            else:
                t.items[k] = copy.deepcopy(item)
        if len(plan) == sum(len(v) for v in unprocessed.values()):
            raise AwsError("ProvisionedThroughputExceededException", THROTTLE_TABLE_MSG)
        req.ctx["ddb"].pop("throttled", None)
        return {"UnprocessedItems": unprocessed}

    def op_BatchGetItem(self, p, req):
        requests = p.get("RequestItems") or {}
        if sum(len(v.get("Keys") or []) for v in requests.values()) > 100:
            raise invalid("Too many items requested for the BatchGetItem call")
        responses: dict[str, list] = {}
        unprocessed: dict[str, dict] = {}
        for name, spec in requests.items():
            t = self._table(name)
            exprs = self._expressions(spec, projection=True)
            keys = [self._key(t, k) for k in spec.get("Keys") or []]
            if len({t.key_of(k) for k in keys}) != len(keys):
                raise invalid("Provided list of item keys contains duplicates")
            out = []
            for k in keys:
                item = t.items.get(t.key_of(k))
                try:
                    self._consume(t, req, read=rcu(item_size(item or {}), bool(spec.get("ConsistentRead"))))
                except AwsError:
                    unprocessed.setdefault(name, {**{x: y for x, y in spec.items() if x != "Keys"}, "Keys": []})
                    unprocessed[name]["Keys"].append(k)
                    continue
                if item is not None:
                    out.append(project(item, exprs["ProjectionExpression"]) if "ProjectionExpression" in exprs else item)
            responses[name] = out
        total = sum(len(v.get("Keys") or []) for v in requests.values())
        if total and total == sum(len(v["Keys"]) for v in unprocessed.values()):
            raise AwsError("ProvisionedThroughputExceededException", THROTTLE_TABLE_MSG)
        req.ctx.get("ddb", {}).pop("throttled", None)
        return {"Responses": responses, "UnprocessedKeys": unprocessed}

    # ================================================================== transactions
    def op_TransactWriteItems(self, p, req):
        items = p.get("TransactItems") or []
        if not 1 <= len(items) <= 100:
            raise invalid("1 validation error detected: Value at 'transactItems' failed to satisfy constraint: "
                          "Member must have length less than or equal to 100")
        staged, reasons, keys = [], [], set()
        failed = False
        for entry in items:
            (kind, spec), = entry.items()
            t = self._table(spec.get("TableName"))
            if kind == "Put":
                self._validate_item(t, spec.get("Item") or {})
                k = t.key_of(spec["Item"])
            else:
                k = t.key_of(self._key(t, spec.get("Key")))
            if (t.name, k) in keys:
                raise invalid("Transaction request cannot include multiple operations on one item")
            keys.add((t.name, k))
            try:
                if kind == "Put":
                    t, _, item = self._put(spec, req, factor=2.0)
                    staged.append((t, k, copy.deepcopy(item)))
                elif kind == "Update":
                    t, _, new, _ = self._update(spec, req, factor=2.0)
                    staged.append((t, k, new))
                elif kind == "Delete":
                    t, _ = self._delete(spec, req, factor=2.0)
                    staged.append((t, k, None))
                elif kind == "ConditionCheck":
                    exprs = self._expressions(spec, ("ConditionExpression",))
                    self._consume(t, req, write=2.0)
                    old = t.items.get(k)
                    if not evaluate(exprs["ConditionExpression"], old or {}):
                        raise self._condition_failed(spec, old)
                else:
                    raise invalid(f"Unknown transact item type: {kind}")
                reasons.append({"Code": "None"})
            except AwsError as err:
                if err.code != "ConditionalCheckFailedException":
                    raise
                failed = True
                reason = {"Code": "ConditionalCheckFailed", "Message": "The conditional request failed"}
                if "Item" in err.extra:
                    reason["Item"] = err.extra["Item"]
                reasons.append(reason)
        if failed:
            codes = ", ".join(r["Code"] for r in reasons)
            raise AwsError("TransactionCanceledException",
                           f"Transaction cancelled, please refer cancellation reasons for specific reasons [{codes}]",
                           extra={"CancellationReasons": reasons})
        for t, k, item in staged:
            if item is None:
                t.items.pop(k, None)
            else:
                t.items[k] = item
        return {}

    def op_TransactGetItems(self, p, req):
        responses = []
        for entry in p.get("TransactItems") or []:
            spec = entry["Get"]
            t = self._table(spec.get("TableName"))
            exprs = self._expressions(spec, projection=True)
            item = t.items.get(t.key_of(self._key(t, spec.get("Key"))))
            self._consume(t, req, read=rcu(item_size(item or {}), True) * 2)
            if item is None:
                responses.append({})
            else:
                responses.append({"Item": project(item, exprs["ProjectionExpression"])
                                  if "ProjectionExpression" in exprs else item})
        return {"Responses": responses}

    # ================================================================== state
    def reset(self) -> None:
        with self.lock:
            self.tables.clear()

    def state(self) -> dict[str, Any]:
        with self.lock:
            out = {}
            for name, t in sorted(self.tables.items()):
                self._expire_ttl(t)
                out[name] = {
                    "key_schema": {k["KeyType"]: k["AttributeName"] for k in t.key_schema},
                    "billing_mode": t.billing_mode,
                    "created": datetime.fromtimestamp(t.created, timezone.utc).isoformat(),
                    "indexes": {i.name: {"type": "LSI" if i.local else "GSI", "hash": i.hash_key,
                                         "range": i.range_key, "projection": i.projection.get("ProjectionType")}
                                for i in t.indexes.values()},
                    "ttl_attribute": t.ttl_attribute,
                    "deletion_protection": t.deletion_protection,
                    "item_count": len(t.items),
                    "items": [unwrap(i) for i in sorted(t.items.values(), key=lambda i: self._order(t, None, i))],
                }
            return out

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {
                name: {
                    "key_schema": t.key_schema, "attr_defs": t.attr_defs, "billing_mode": t.billing_mode,
                    "throughput": t.throughput, "created": t.created, "region": t.region,
                    "indexes": [{**i.__dict__} for i in t.indexes.values()],
                    "items": list(t.items.values()), "ttl_attribute": t.ttl_attribute,
                    "deletion_protection": t.deletion_protection, "tags": t.tags, "stream": t.stream,
                }
                for name, t in self.tables.items()
            }

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.tables = {}
            for name, d in data.items():
                t = Table(name, d["key_schema"], d["attr_defs"], d["billing_mode"], d["throughput"], d["created"],
                          d["region"], {i["name"]: Index(**i) for i in d["indexes"]},
                          ttl_attribute=d["ttl_attribute"], deletion_protection=d["deletion_protection"],
                          tags=d["tags"], stream=d.get("stream"))
                t.items = {t.key_of(i): i for i in d["items"]}
                self.tables[name] = t


def unwrap(value: Any) -> Any:
    """AttributeValue を人が読みやすい素の JSON に変換する (状態表示用)。"""
    if isinstance(value, dict) and len(value) == 1:
        t, v = next(iter(value.items()))
        if t == "S" or t == "BOOL":
            return v
        if t == "N":
            d = Decimal(v)
            return int(d) if d == d.to_integral_value() else float(d)
        if t == "NULL":
            return None
        if t == "B":
            return {"<binary>": v}
        if t in ("SS", "BS"):
            return sorted(v)
        if t == "NS":
            return sorted(unwrap({"N": x}) for x in v)
        if t == "L":
            return [unwrap(x) for x in v]
        if t == "M":
            return {k: unwrap(x) for k, x in v.items()}
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    return value

