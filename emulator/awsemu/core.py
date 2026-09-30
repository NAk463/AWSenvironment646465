"""エミュレータ共通の仕組み: リクエスト/レスポンス、エラー、時計、イベントログ、障害注入。"""
from __future__ import annotations

import itertools
import random
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from email.message import Message
from typing import Any
from urllib.parse import parse_qs, urlsplit

ACCOUNT_ID = "000000000000"
DEFAULT_REGION = "ap-northeast-1"


class AwsError(Exception):
    """AWS API のエラー。各サービスがプロトコルに合わせてシリアライズする。"""

    def __init__(self, code: str, message: str = "", status: int = 400, sender_fault: bool = True,
                 extra: dict[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.extra = extra or {}
        self.message = message or code
        self.status = status
        self.sender_fault = sender_fault


@dataclass
class Request:
    method: str
    raw_path: str
    headers: Message
    body: bytes
    region: str = DEFAULT_REGION
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        parts = urlsplit(self.raw_path)
        self.path = parts.path
        self.query_string = parts.query
        self.query = {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


class Clock:
    """オフセット可能な時計。可視性タイムアウトや保持期間の検証で時間を進めるのに使う。"""

    def __init__(self) -> None:
        self.offset = 0.0

    def now(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


class EventLog:
    """全 API 呼び出しの記録 (CloudTrail 風)。障害解析時の時系列追跡用。"""

    def __init__(self, maxlen: int = 5000) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._seq = itertools.count(1)
        self._lock = threading.Lock()

    def add(self, event: dict[str, Any]) -> None:
        with self._lock:
            event["seq"] = next(self._seq)
            self._events.append(event)

    def query(self, service: str | None = None, operation: str | None = None,
              errors_only: bool = False, since: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        out = [
            e for e in events
            if e["seq"] > since
            and (not service or e["service"] == service)
            and (not operation or e["operation"] == operation)
            and (not errors_only or e.get("error"))
        ]
        return out[-limit:] if limit else out

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


@dataclass
class FaultRule:
    """障害注入ルール。一致した呼び出しに遅延やエラーを発生させる。"""

    service: str = "*"
    operation: str = "*"
    resource: str | None = None      # バケット名/キュー名/テーブル名などの部分一致
    error_code: str | None = None
    error_message: str | None = None
    status: int = 500
    probability: float = 1.0
    latency_ms: int = 0
    count: int | None = None         # 残り発動回数。None は無制限
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    hits: int = 0

    def matches(self, service: str, operation: str, resource: str) -> bool:
        return (
            self.service in ("*", service)
            and self.operation in ("*", operation)
            and (not self.resource or self.resource in resource)
            and (self.count is None or self.count > 0)
        )


class FaultInjector:
    def __init__(self) -> None:
        self.rules: list[FaultRule] = []
        self._lock = threading.Lock()

    def add(self, spec: dict[str, Any]) -> FaultRule:
        allowed = FaultRule.__dataclass_fields__.keys() - {"id", "hits"}
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"unknown fault fields: {sorted(unknown)}")
        rule = FaultRule(**spec)
        with self._lock:
            self.rules.append(rule)
        return rule

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.id != rule_id]
            return len(self.rules) != before

    def clear(self) -> None:
        with self._lock:
            self.rules.clear()

    def check(self, service: str, operation: str, resource: str) -> FaultRule | None:
        with self._lock:
            for rule in self.rules:
                if rule.matches(service, operation, resource) and random.random() < rule.probability:
                    rule.hits += 1
                    if rule.count is not None:
                        rule.count -= 1
                    return rule
        return None


class Service:
    """サービス実装の基底クラス。"""

    name = ""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.lock = threading.RLock()

    # --- プロトコル ---
    def operation(self, req: Request) -> str:
        raise NotImplementedError

    def resource(self, req: Request, op: str) -> str:
        return ""

    def handle(self, req: Request, op: str) -> Response:
        raise NotImplementedError

    def error_response(self, req: Request, err: AwsError) -> Response:
        raise NotImplementedError

    def params_for_log(self, req: Request, op: str) -> Any:
        return None

    # --- 状態 ---
    def reset(self) -> None:
        raise NotImplementedError

    def state(self) -> dict[str, Any]:
        """人が読むための内部状態。"""
        raise NotImplementedError

    def dump(self) -> dict[str, Any]:
        """スナップショット用の完全な状態。"""
        return self.state()

    def load(self, data: dict[str, Any]) -> None:
        raise NotImplementedError
