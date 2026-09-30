"""SQS (awsJson1.0 / awsQueryCompatible)。

可視性タイムアウト、遅延配信、ロングポーリング、DLQ へのリドライブ、保持期間切れ、
FIFO キューの重複排除を再現する。
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Metric, Request
from ._json import JsonService

DEFAULT_ATTRIBUTES = {
    "VisibilityTimeout": "30",
    "MaximumMessageSize": "262144",
    "MessageRetentionPeriod": "345600",
    "DelaySeconds": "0",
    "ReceiveMessageWaitTimeSeconds": "0",
}
SETTABLE_ATTRIBUTES = set(DEFAULT_ATTRIBUTES) | {
    "RedrivePolicy", "RedriveAllowPolicy", "Policy", "FifoQueue", "ContentBasedDeduplication",
    "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds", "SqsManagedSseEnabled",
    "DeduplicationScope", "FifoThroughputLimit",
}
SYSTEM_ATTRIBUTES = ("SenderId", "SentTimestamp", "ApproximateReceiveCount",
                     "ApproximateFirstReceiveTimestamp", "MessageGroupId", "MessageDeduplicationId",
                     "SequenceNumber", "DeadLetterQueueSourceArn")


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5_of_attributes(attrs: dict[str, Any]) -> str | None:
    """SQS の MD5OfMessageAttributes 計算アルゴリズム (SDK が検証する)。"""
    if not attrs:
        return None
    buf = bytearray()

    def put(b: bytes) -> None:
        buf.extend(struct.pack(">I", len(b)))
        buf.extend(b)

    for name in sorted(attrs):
        attr = attrs[name]
        dtype = attr["DataType"]
        put(name.encode())
        put(dtype.encode())
        if "BinaryValue" in attr:
            value = attr["BinaryValue"]
            buf.append(2)
            put(base64.b64decode(value) if isinstance(value, str) else value)
        else:
            buf.append(1)
            put(attr["StringValue"].encode())
    return md5_hex(bytes(buf))


@dataclass
class Message:
    id: str
    body: str
    attributes: dict[str, Any]
    sent: float
    visible_at: float
    group_id: str | None = None
    dedup_id: str | None = None
    receive_count: int = 0
    first_receive: float | None = None
    receipt_handle: str | None = None
    source_arn: str | None = None
    sequence: int = 0


@dataclass
class Queue:
    name: str
    created: float
    attributes: dict[str, str]
    tags: dict[str, str] = field(default_factory=dict)
    messages: list[Message] = field(default_factory=list)
    dedup: dict[str, float] = field(default_factory=dict)
    last_modified: float = 0.0
    seq: int = 0

    @property
    def fifo(self) -> bool:
        return self.attributes.get("FifoQueue") == "true"

    @property
    def arn(self) -> str:
        region = self.attributes.get("_region", "ap-northeast-1")
        return f"arn:aws:sqs:{region}:{ACCOUNT_ID}:{self.name}"


class SQS(JsonService):
    name = "sqs"
    target_prefix = "AmazonSQS."
    error_namespace = "com.amazonaws.sqs"
    iam_prefix = "sqs"
    event_source = "sqs.amazonaws.com"
    data_events = frozenset({"SendMessage", "SendMessageBatch", "ReceiveMessage", "DeleteMessage",
                             "DeleteMessageBatch", "ChangeMessageVisibility", "ChangeMessageVisibilityBatch"})
    query_error_codes = {
        "QueueDoesNotExist": "AWS.SimpleQueueService.NonExistentQueue",
        "QueueNameExists": "QueueAlreadyExists",
        "MessageNotInflight": "AWS.SimpleQueueService.MessageNotInflight",
        "PurgeQueueInProgress": "AWS.SimpleQueueService.PurgeQueueInProgress",
        "TooManyEntriesInBatchRequest": "AWS.SimpleQueueService.TooManyEntriesInBatchRequest",
        "EmptyBatchRequest": "AWS.SimpleQueueService.EmptyBatchRequest",
        "BatchEntryIdsNotDistinct": "AWS.SimpleQueueService.BatchEntryIdsNotDistinct",
        "UnsupportedOperation": "AWS.SimpleQueueService.UnsupportedOperation",
        "QueueDeletedRecently": "AWS.SimpleQueueService.QueueDeletedRecently",
    }

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.queues: dict[str, Queue] = {}

    # ------------------------------------------------------------------ helpers
    # ------------------------------------------------------------------ IAM / CloudTrail / メトリクス
    BATCH_ACTIONS = {"SendMessageBatch": "SendMessage", "DeleteMessageBatch": "DeleteMessage",
                     "ChangeMessageVisibilityBatch": "ChangeMessageVisibility"}

    def _arn(self, name: str, region: str) -> str:
        q = self.queues.get(name)
        return q.arn if q else f"arn:aws:sqs:{region}:{ACCOUNT_ID}:{name}"

    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        action = f"sqs:{self.BATCH_ACTIONS.get(op, op)}"
        if op == "ListQueues":
            return [(action, "*")]
        return [(action, self._arn(self.resource(req, op), req.region))]

    def resource_policy(self, arn: str) -> dict[str, Any] | None:
        q = self.queues.get(arn.rsplit(":", 1)[-1])
        policy = q.attributes.get("Policy") if q else None
        return json.loads(policy) if policy else None

    def trail_resources(self, req: Request, op: str) -> list[dict[str, str]]:
        name = self.resource(req, op)
        return [{"accountId": ACCOUNT_ID, "type": "AWS::SQS::Queue", "ARN": self._arn(name, req.region)}] if name else []

    def metrics(self, req: Request, op: str, status: int, error, duration_ms: float) -> list[Metric]:
        stats = req.ctx.get("sqs")
        if not stats or error is not None:
            return []
        dims = {"QueueName": stats["queue"]}
        out = []
        if "sent" in stats:
            out.append(Metric("AWS/SQS", "NumberOfMessagesSent", float(stats["sent"]), dims, "Count"))
            out.extend(Metric("AWS/SQS", "SentMessageSize", float(size), dims, "Bytes") for size in stats["sizes"])
        if "received" in stats:
            out.append(Metric("AWS/SQS", "NumberOfMessagesReceived", float(stats["received"]), dims, "Count"))
            out.append(Metric("AWS/SQS", "NumberOfEmptyReceives", 0.0 if stats["received"] else 1.0, dims, "Count"))
        if "deleted" in stats:
            out.append(Metric("AWS/SQS", "NumberOfMessagesDeleted", float(stats["deleted"]), dims, "Count"))
        return out

    def gauges(self) -> list[Metric]:
        with self.lock:
            now = self.clock.now()
            out = []
            for q in self.queues.values():
                self._expire(q, now)
                dims = {"QueueName": q.name}
                visible = sum(1 for m in q.messages if m.visible_at <= now)
                inflight = sum(1 for m in q.messages if m.visible_at > now and m.receive_count)
                oldest = max((now - m.sent for m in q.messages), default=0.0)
                out += [Metric("AWS/SQS", "ApproximateNumberOfMessagesVisible", float(visible), dims, "Count"),
                        Metric("AWS/SQS", "ApproximateNumberOfMessagesNotVisible", float(inflight), dims, "Count"),
                        Metric("AWS/SQS", "ApproximateNumberOfMessagesDelayed",
                               float(len(q.messages) - visible - inflight), dims, "Count"),
                        Metric("AWS/SQS", "ApproximateAgeOfOldestMessage", float(int(oldest)), dims, "Seconds")]
            return out

    def resource(self, req: Request, op: str) -> str:
        p = self.params_for_log(req, op) or {}
        return p.get("QueueName") or str(p.get("QueueUrl", "")).rsplit("/", 1)[-1]

    @staticmethod
    def _require(params: dict[str, Any], *names: str) -> None:
        for n in names:
            if params.get(n) in (None, ""):
                raise AwsError("MissingParameter", f"The request must contain the parameter {n}.")

    def _queue(self, params: dict[str, Any]) -> Queue:
        self._require(params, "QueueUrl")
        name = str(params["QueueUrl"]).rstrip("/").rsplit("/", 1)[-1]
        q = self.queues.get(name)
        if q is None:
            raise AwsError("QueueDoesNotExist", "The specified queue does not exist.")
        return q

    def _url(self, req: Request, name: str) -> str:
        host = req.header("Host") or "localhost:4566"
        return f"http://{host}/{ACCOUNT_ID}/{name}"

    def _expire(self, q: Queue, now: float) -> None:
        retention = int(q.attributes["MessageRetentionPeriod"])
        q.messages = [m for m in q.messages if m.sent + retention > now]
        q.dedup = {k: v for k, v in q.dedup.items() if v > now}

    def _find_by_handle(self, q: Queue, handle: str) -> Message | None:
        for m in q.messages:
            if m.receipt_handle == handle:
                return m
        return None

    @staticmethod
    def _validate_attributes(attrs: dict[str, str]) -> None:
        for k, v in attrs.items():
            if k not in SETTABLE_ATTRIBUTES:
                raise AwsError("InvalidAttributeName", f"Unknown Attribute {k}.")
            if k in DEFAULT_ATTRIBUTES and not str(v).lstrip("-").isdigit():
                raise AwsError("InvalidAttributeValue", f"Invalid value for the parameter {k}.")
        if "VisibilityTimeout" in attrs and not 0 <= int(attrs["VisibilityTimeout"]) <= 43200:
            raise AwsError("InvalidAttributeValue", "Invalid value for the parameter VisibilityTimeout.")
        if "DelaySeconds" in attrs and not 0 <= int(attrs["DelaySeconds"]) <= 900:
            raise AwsError("InvalidAttributeValue", "Invalid value for the parameter DelaySeconds.")
        if "RedrivePolicy" in attrs and attrs["RedrivePolicy"]:
            try:
                policy = json.loads(attrs["RedrivePolicy"])
                int(policy["maxReceiveCount"])
                str(policy["deadLetterTargetArn"])
            except (ValueError, KeyError, TypeError):
                raise AwsError("InvalidAttributeValue", "Invalid value for the parameter RedrivePolicy.")

    # ------------------------------------------------------------------ queues
    def op_CreateQueue(self, p: dict[str, Any], req: Request):
        self._require(p, "QueueName")
        name = p["QueueName"]
        attrs = {k: str(v) for k, v in (p.get("Attributes") or {}).items()}
        self._validate_attributes(attrs)
        if name.endswith(".fifo") != (attrs.get("FifoQueue") == "true"):
            raise AwsError("InvalidParameterValue",
                           "The name of a FIFO queue can only include alphanumeric characters, hyphens, or "
                           "underscores, must end with .fifo suffix.")
        with self.lock:
            existing = self.queues.get(name)
            if existing:
                if any(existing.attributes.get(k) != v for k, v in attrs.items()):
                    raise AwsError("QueueNameExists",
                                   "A queue already exists with the same name and a different value for attribute(s)")
            else:
                now = self.clock.now()
                q = Queue(name, now, {**DEFAULT_ATTRIBUTES, **attrs, "_region": req.region},
                          tags=dict(p.get("tags") or {}), last_modified=now)
                self.queues[name] = q
        return {"QueueUrl": self._url(req, name)}

    def op_GetQueueUrl(self, p, req):
        self._require(p, "QueueName")
        if p["QueueName"] not in self.queues:
            raise AwsError("QueueDoesNotExist", "The specified queue does not exist.")
        return {"QueueUrl": self._url(req, p["QueueName"])}

    def op_ListQueues(self, p, req):
        prefix = p.get("QueueNamePrefix", "")
        names = sorted(n for n in self.queues if n.startswith(prefix))
        start = int(p["NextToken"]) if p.get("NextToken") else 0
        limit = int(p.get("MaxResults") or 1000)
        page = names[start:start + limit]
        result: dict[str, Any] = {"QueueUrls": [self._url(req, n) for n in page]} if page else {}
        if p.get("MaxResults") and start + limit < len(names):
            result["NextToken"] = str(start + limit)
        return result

    def op_DeleteQueue(self, p, req):
        with self.lock:
            q = self._queue(p)
            del self.queues[q.name]

    def op_PurgeQueue(self, p, req):
        with self.lock:
            self._queue(p).messages.clear()

    def op_GetQueueAttributes(self, p, req):
        with self.lock:
            q = self._queue(p)
            now = self.clock.now()
            self._expire(q, now)
            computed = {
                "QueueArn": q.arn,
                "CreatedTimestamp": str(int(q.created)),
                "LastModifiedTimestamp": str(int(q.last_modified)),
                "ApproximateNumberOfMessages": str(sum(
                    1 for m in q.messages if m.visible_at <= now)),
                "ApproximateNumberOfMessagesNotVisible": str(sum(
                    1 for m in q.messages if m.visible_at > now and m.receive_count > 0)),
                "ApproximateNumberOfMessagesDelayed": str(sum(
                    1 for m in q.messages if m.visible_at > now and m.receive_count == 0)),
            }
            everything = {**{k: v for k, v in q.attributes.items() if not k.startswith("_")}, **computed}
            names = p.get("AttributeNames") or []
            if "All" in names:
                return {"Attributes": everything}
            for n in names:
                if n not in everything and n not in SETTABLE_ATTRIBUTES:
                    raise AwsError("InvalidAttributeName", f"Unknown Attribute {n}.")
            selected = {n: everything[n] for n in names if n in everything}
            return {"Attributes": selected} if selected else {}

    def op_SetQueueAttributes(self, p, req):
        with self.lock:
            q = self._queue(p)
            attrs = {k: str(v) for k, v in (p.get("Attributes") or {}).items()}
            self._validate_attributes(attrs)
            q.attributes.update(attrs)
            q.last_modified = self.clock.now()

    def op_TagQueue(self, p, req):
        with self.lock:
            self._queue(p).tags.update(p.get("Tags") or {})

    def op_UntagQueue(self, p, req):
        with self.lock:
            q = self._queue(p)
            for k in p.get("TagKeys") or []:
                q.tags.pop(k, None)

    def op_ListQueueTags(self, p, req):
        q = self._queue(p)
        return {"Tags": dict(q.tags)} if q.tags else {}

    # ------------------------------------------------------------------ messages
    def _enqueue(self, q: Queue, entry: dict[str, Any]) -> dict[str, Any]:
        self._require(entry, "MessageBody")
        body = entry["MessageBody"]
        if len(body.encode()) > int(q.attributes["MaximumMessageSize"]):
            raise AwsError("InvalidParameterValue",
                           f"One or more parameters are invalid. Reason: Message must be shorter than "
                           f"{q.attributes['MaximumMessageSize']} bytes.")
        attrs = entry.get("MessageAttributes") or {}
        now = self.clock.now()
        group_id = entry.get("MessageGroupId")
        dedup_id = entry.get("MessageDeduplicationId")
        if q.fifo:
            if not group_id:
                raise AwsError("MissingParameter", "The request must contain the parameter MessageGroupId.")
            if entry.get("DelaySeconds"):
                raise AwsError("InvalidParameterValue",
                               "Value for parameter DelaySeconds is invalid. Reason: The request include "
                               "parameter that is not valid for this queue type.")
            if not dedup_id:
                if q.attributes.get("ContentBasedDeduplication") != "true":
                    raise AwsError("InvalidParameterValue",
                                   "The queue should either have ContentBasedDeduplication enabled or "
                                   "MessageDeduplicationId provided explicitly")
                dedup_id = hashlib.sha256(body.encode()).hexdigest()
        delay = int(entry.get("DelaySeconds", q.attributes["DelaySeconds"]))
        if not 0 <= delay <= 900:
            raise AwsError("InvalidParameterValue", "Value for parameter DelaySeconds is invalid.")

        self._expire(q, now)
        if q.fifo and dedup_id in q.dedup:
            # 5 分以内の重複送信は受理するがキューには入れない (AWS と同じ挙動)
            msg_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{q.name}/{dedup_id}"))
        else:
            msg_id = str(uuid.uuid4())
            q.seq += 1
            q.messages.append(Message(msg_id, body, attrs, now, now + delay, group_id, dedup_id,
                                      sequence=q.seq))
            if q.fifo:
                q.dedup[dedup_id] = now + 300
        result = {"MessageId": msg_id, "MD5OfMessageBody": md5_hex(body.encode())}
        attr_md5 = md5_of_attributes(attrs)
        if attr_md5:
            result["MD5OfMessageAttributes"] = attr_md5
        if q.fifo:
            result["SequenceNumber"] = str(q.seq).zfill(20)
        return result

    def op_SendMessage(self, p, req):
        with self.lock:
            q = self._queue(p)
            result = self._enqueue(q, p)
            req.ctx["sqs"] = {"queue": q.name, "sent": 1, "sizes": [len(p["MessageBody"].encode())]}
            return result

    @staticmethod
    def _check_batch(entries: list[dict[str, Any]]) -> None:
        if not entries:
            raise AwsError("EmptyBatchRequest", "There should be at least one SendMessageBatchRequestEntry in the request.")
        if len(entries) > 10:
            raise AwsError("TooManyEntriesInBatchRequest", f"Maximum number of entries per request are 10. You have sent {len(entries)}.")
        ids = [e.get("Id") for e in entries]
        if len(set(ids)) != len(ids):
            raise AwsError("BatchEntryIdsNotDistinct", "Id must be distinct among batch entries.")

    def op_SendMessageBatch(self, p, req):
        entries = p.get("Entries") or []
        self._check_batch(entries)
        ok, failed = [], []
        with self.lock:
            q = self._queue(p)
            for e in entries:
                try:
                    ok.append({"Id": e["Id"], **self._enqueue(q, e)})
                except AwsError as err:
                    failed.append({"Id": e["Id"], "SenderFault": err.sender_fault, "Code": err.code,
                                   "Message": err.message})
            req.ctx["sqs"] = {"queue": q.name, "sent": len(ok),
                              "sizes": [len(e["MessageBody"].encode()) for e in entries
                                        if e["Id"] in {x["Id"] for x in ok}]}
        return {"Successful": ok, "Failed": failed}

    def op_ReceiveMessage(self, p, req):
        q = self._queue(p)
        max_n = int(p.get("MaxNumberOfMessages") or 1)
        if not 1 <= max_n <= 10:
            raise AwsError("InvalidParameterValue",
                           "Value for parameter MaxNumberOfMessages is invalid. Reason: Must be between 1 and 10.")
        wait = int(p.get("WaitTimeSeconds", q.attributes["ReceiveMessageWaitTimeSeconds"]))
        if not 0 <= wait <= 20:
            raise AwsError("InvalidParameterValue", "Value for parameter WaitTimeSeconds is invalid. Reason: Must be >= 0 and <= 20.")
        deadline = time.monotonic() + wait
        while True:
            with self.lock:
                if q.name not in self.queues:
                    raise AwsError("QueueDoesNotExist", "The specified queue does not exist.")
                received = self._receive(q, p, max_n)
            if received or time.monotonic() >= deadline:
                req.ctx["sqs"] = {"queue": q.name, "received": len(received)}
                return {"Messages": received} if received else {}
            time.sleep(0.05)

    def _receive(self, q: Queue, p: dict[str, Any], max_n: int) -> list[dict[str, Any]]:
        now = self.clock.now()
        self._expire(q, now)
        visibility = int(p.get("VisibilityTimeout", q.attributes["VisibilityTimeout"]))
        policy = json.loads(q.attributes["RedrivePolicy"]) if q.attributes.get("RedrivePolicy") else None
        wanted_sys = set(p.get("MessageSystemAttributeNames") or []) | set(p.get("AttributeNames") or [])
        wanted_msg = p.get("MessageAttributeNames") or []

        # FIFO: 処理中 (不可視) のメッセージがあるグループはブロックされる
        blocked_groups = {m.group_id for m in q.messages if q.fifo and m.visible_at > now and m.receive_count}
        out = []
        for m in list(q.messages):
            if len(out) >= max_n:
                break
            if m.visible_at > now or (q.fifo and m.group_id in blocked_groups):
                continue
            if policy and m.receive_count >= int(policy["maxReceiveCount"]):
                self._move_to_dlq(q, m, policy["deadLetterTargetArn"], now)
                continue
            m.receive_count += 1
            m.first_receive = m.first_receive or now
            m.visible_at = now + visibility
            m.receipt_handle = uuid.uuid4().hex + uuid.uuid4().hex
            if q.fifo:
                blocked_groups.add(m.group_id)
            out.append(self._render(m, wanted_sys, wanted_msg))
        return out

    def _move_to_dlq(self, q: Queue, m: Message, dlq_arn: str, now: float) -> None:
        q.messages.remove(m)
        dlq = self.queues.get(dlq_arn.rsplit(":", 1)[-1])
        if dlq is None:
            return  # AWS と同様、DLQ が存在しなければメッセージは失われる
        m.visible_at = now
        m.receipt_handle = None
        m.source_arn = q.arn
        dlq.seq += 1
        m.sequence = dlq.seq
        dlq.messages.append(m)

    @staticmethod
    def _render(m: Message, wanted_sys: set[str], wanted_msg: list[str]) -> dict[str, Any]:
        sys_values = {
            "SenderId": ACCOUNT_ID,
            "SentTimestamp": str(int(m.sent * 1000)),
            "ApproximateReceiveCount": str(m.receive_count),
            "ApproximateFirstReceiveTimestamp": str(int((m.first_receive or m.sent) * 1000)),
            "MessageGroupId": m.group_id,
            "MessageDeduplicationId": m.dedup_id,
            "SequenceNumber": str(m.sequence).zfill(20) if m.group_id else None,
            "DeadLetterQueueSourceArn": m.source_arn,
        }
        out: dict[str, Any] = {
            "MessageId": m.id,
            "ReceiptHandle": m.receipt_handle,
            "MD5OfBody": md5_hex(m.body.encode()),
            "Body": m.body,
        }
        names = SYSTEM_ATTRIBUTES if "All" in wanted_sys else [n for n in SYSTEM_ATTRIBUTES if n in wanted_sys]
        attrs = {n: sys_values[n] for n in names if sys_values.get(n) is not None}
        if attrs:
            out["Attributes"] = attrs
        if wanted_msg and m.attributes:
            if "All" in wanted_msg or ".*" in wanted_msg:
                selected = dict(m.attributes)
            else:
                selected = {k: v for k, v in m.attributes.items()
                            if k in wanted_msg or any(w.endswith(".*") and k.startswith(w[:-1]) for w in wanted_msg)}
            if selected:
                out["MessageAttributes"] = selected
                out["MD5OfMessageAttributes"] = md5_of_attributes(selected)
        return out

    def op_DeleteMessage(self, p, req):
        self._require(p, "ReceiptHandle")
        with self.lock:
            q = self._queue(p)
            m = self._find_by_handle(q, p["ReceiptHandle"])
            if m is None:
                if len(p["ReceiptHandle"]) != 64:
                    raise AwsError("ReceiptHandleIsInvalid",
                                   f'The input receipt handle "{p["ReceiptHandle"]}" is not a valid receipt handle.')
                return  # 古い受信ハンドル: AWS は成功を返す
            q.messages.remove(m)
            stats = req.ctx.setdefault("sqs", {"queue": q.name, "deleted": 0})
            stats["deleted"] = stats.get("deleted", 0) + 1

    def op_DeleteMessageBatch(self, p, req):
        entries = p.get("Entries") or []
        self._check_batch(entries)
        ok, failed = [], []
        for e in entries:
            try:
                self.op_DeleteMessage({"QueueUrl": p.get("QueueUrl"), **e}, req)
                ok.append({"Id": e["Id"]})
            except AwsError as err:
                if err.code == "QueueDoesNotExist":
                    raise
                failed.append({"Id": e["Id"], "SenderFault": True, "Code": err.code, "Message": err.message})
        return {"Successful": ok, "Failed": failed}

    def op_ChangeMessageVisibility(self, p, req):
        self._require(p, "ReceiptHandle")
        timeout = int(p.get("VisibilityTimeout", -1))
        if not 0 <= timeout <= 43200:
            raise AwsError("InvalidParameterValue", "Value for parameter VisibilityTimeout is invalid.")
        with self.lock:
            q = self._queue(p)
            m = self._find_by_handle(q, p["ReceiptHandle"])
            now = self.clock.now()
            if m is None:
                raise AwsError("ReceiptHandleIsInvalid",
                               f'The input receipt handle "{p["ReceiptHandle"]}" is not a valid receipt handle.')
            if m.visible_at <= now:
                raise AwsError("MessageNotInflight", "Message does not exist or is not available for visibility timeout change.")
            m.visible_at = now + timeout

    def op_ChangeMessageVisibilityBatch(self, p, req):
        entries = p.get("Entries") or []
        self._check_batch(entries)
        ok, failed = [], []
        for e in entries:
            try:
                self.op_ChangeMessageVisibility({"QueueUrl": p.get("QueueUrl"), **e}, req)
                ok.append({"Id": e["Id"]})
            except AwsError as err:
                if err.code == "QueueDoesNotExist":
                    raise
                failed.append({"Id": e["Id"], "SenderFault": True, "Code": err.code, "Message": err.message})
        return {"Successful": ok, "Failed": failed}

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        with self.lock:
            self.queues.clear()

    def state(self) -> dict[str, Any]:
        with self.lock:
            now = self.clock.now()
            out = {}
            for name, q in sorted(self.queues.items()):
                self._expire(q, now)
                out[name] = {
                    "arn": q.arn,
                    "attributes": {k: v for k, v in q.attributes.items() if not k.startswith("_")},
                    "tags": q.tags,
                    "messages": [
                        {
                            "message_id": m.id,
                            "body": m.body,
                            "message_attributes": m.attributes,
                            "state": "visible" if m.visible_at <= now else
                                     ("in_flight" if m.receive_count else "delayed"),
                            "visible_in_seconds": max(0.0, round(m.visible_at - now, 3)),
                            "receive_count": m.receive_count,
                            "sent_age_seconds": round(now - m.sent, 3),
                            "group_id": m.group_id,
                            "dead_letter_source": m.source_arn,
                        }
                        for m in q.messages
                    ],
                }
            return out

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {
                name: {
                    "created": q.created, "attributes": q.attributes, "tags": q.tags, "seq": q.seq,
                    "messages": [m.__dict__ for m in q.messages],
                }
                for name, q in self.queues.items()
            }

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.queues = {}
            for name, d in data.items():
                q = Queue(name, d["created"], d["attributes"], d["tags"], seq=d.get("seq", 0),
                          last_modified=d["created"])
                q.messages = [Message(**m) for m in d["messages"]]
                self.queues[name] = q

