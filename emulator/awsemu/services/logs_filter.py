"""CloudWatch Logs のフィルタパターン (FilterLogEvents / メトリクスフィルタ / サブスクリプションフィルタで共通)。

対応する構文:
  - 用語:            ERROR "exact phrase" -DEBUG ?WARN ?ERROR
  - JSON:            { $.level = "ERROR" && $.latency > 1000 }, { $.user IS NULL }, { $.x NOT EXISTS }
  - スペース区切り:   [ip, user, ..., status = 5*, bytes > 1000]
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from ..core import AwsError

Matcher = Callable[[str], "tuple[bool, dict[str, Any]]"]


def bad_pattern() -> AwsError:
    return AwsError("InvalidParameterException", "Invalid filter pattern")


def _wildcard(pattern: str, value: str) -> bool:
    regex = "".join(".*" if c == "*" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, value, re.S) is not None


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if actual is None:
        return op == "!="
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            a = float(actual)
        except (TypeError, ValueError):
            return op == "!="
        return {"=": a == expected, "!=": a != expected, "<": a < expected, "<=": a <= expected,
                ">": a > expected, ">=": a >= expected}[op]
    a = json.dumps(actual) if isinstance(actual, (dict, list)) else str(actual).lower() if isinstance(actual, bool) else str(actual)
    if op == "=":
        return _wildcard(str(expected), a)
    if op == "!=":
        return not _wildcard(str(expected), a)
    return False


def compile_pattern(pattern: str | None) -> Matcher:
    text = (pattern or "").strip()
    if not text:
        return lambda message: (True, {})
    if text.startswith("{"):
        if not text.endswith("}"):
            raise bad_pattern()
        return _compile_json(text[1:-1])
    if text.startswith("["):
        if not text.endswith("]"):
            raise bad_pattern()
        return _compile_delimited(text[1:-1])
    return _compile_terms(text)


# ============================================================================ terms
def _compile_terms(text: str) -> Matcher:
    tokens = re.findall(r'[-?]?"(?:[^"\\]|\\.)*"|\S+', text)
    required, excluded, optional = [], [], []
    for tok in tokens:
        prefix = tok[0] if tok[0] in "-?" else ""
        body = tok[len(prefix):]
        if body.startswith('"') and body.endswith('"') and len(body) >= 2:
            body = body[1:-1].replace('\\"', '"')
        {"-": excluded, "?": optional}.get(prefix, required).append(body)

    def match(message: str) -> tuple[bool, dict[str, Any]]:
        if any(t not in message for t in required):
            return False, {}
        if any(t in message for t in excluded):
            return False, {}
        if optional and not any(t in message for t in optional):
            return False, {}
        return True, {}
    return match


# ============================================================================ JSON
JSON_TOKEN = re.compile(r'\s*(\$(?:\.[A-Za-z0-9_\-@]+|\[\d+\])*|&&|\|\||!=|<=|>=|=|<|>|\(|\)|"(?:[^"\\]|\\.)*"|'
                        r'-?\d+(?:\.\d+)?(?![\w*])|[A-Za-z0-9_\-*.:/@]+)')


def _json_path(obj: Any, path: str) -> tuple[bool, Any]:
    cur = obj
    for part in re.findall(r"\.([A-Za-z0-9_\-@]+)|\[(\d+)\]", path[1:]):
        key, idx = part
        if key:
            if not isinstance(cur, dict) or key not in cur:
                return False, None
            cur = cur[key]
        else:
            if not isinstance(cur, list) or int(idx) >= len(cur):
                return False, None
            cur = cur[int(idx)]
    return True, cur


def _compile_json(body: str) -> Matcher:
    tokens, pos = [], 0
    body = body.strip()
    while pos < len(body):
        m = JSON_TOKEN.match(body, pos)
        if not m or m.end() == pos:
            raise bad_pattern()
        tokens.append(m.group(1))
        pos = m.end()
    i = 0

    def peek() -> str | None:
        return tokens[i] if i < len(tokens) else None

    def take() -> str:
        nonlocal i
        if i >= len(tokens):
            raise bad_pattern()
        i += 1
        return tokens[i - 1]

    def parse_or():
        node = parse_and()
        while peek() == "||":
            take()
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_term()
        while peek() == "&&":
            take()
            node = ("and", node, parse_term())
        return node

    def parse_term():
        if peek() == "(":
            take()
            node = parse_or()
            if take() != ")":
                raise bad_pattern()
            return node
        sel = take()
        if not sel.startswith("$"):
            raise bad_pattern()
        nxt = take()
        if nxt.upper() == "IS":
            val = take().upper()
            if val not in ("TRUE", "FALSE", "NULL"):
                raise bad_pattern()
            return ("is", sel, val)
        if nxt.upper() == "NOT":
            if take().upper() != "EXISTS":
                raise bad_pattern()
            return ("notexists", sel)
        if nxt not in ("=", "!=", "<", "<=", ">", ">="):
            raise bad_pattern()
        raw = take()
        if raw.startswith('"'):
            value: Any = json.loads(raw)
        else:
            try:
                value = float(raw)
            except ValueError:
                value = raw
        return ("cmp", nxt, sel, value)

    tree = parse_or()
    if i != len(tokens):
        raise bad_pattern()

    def ev(node, obj) -> bool:
        kind = node[0]
        if kind == "and":
            return ev(node[1], obj) and ev(node[2], obj)
        if kind == "or":
            return ev(node[1], obj) or ev(node[2], obj)
        if kind == "notexists":
            return not _json_path(obj, node[1])[0]
        if kind == "is":
            found, v = _json_path(obj, node[1])
            return found and {"TRUE": v is True, "FALSE": v is False, "NULL": v is None}[node[2]]
        _, op, sel, value = node
        found, v = _json_path(obj, sel)
        if not found:
            return False
        return _compare(op, v, value)

    def match(message: str) -> tuple[bool, dict[str, Any]]:
        try:
            obj = json.loads(message)
        except ValueError:
            return False, {}
        if not isinstance(obj, (dict, list)):
            return False, {}
        if not ev(tree, obj):
            return False, {}
        return True, {"$json": obj}
    return match


# ============================================================================ space-delimited
def _split_fields(message: str) -> list[str]:
    return [t[1:-1] if len(t) >= 2 and t[0] + t[-1] in ('""', "[]") else t
            for t in re.findall(r'"[^"]*"|\[[^\]]*\]|\S+', message)]


def _compile_delimited(body: str) -> Matcher:
    specs: list[tuple[str, list[tuple[str, Any]]]] = []
    for raw in [p.strip() for p in body.split(",")] if body.strip() else []:
        if raw == "...":
            specs.append(("...", []))
            continue
        m = re.fullmatch(r"([A-Za-z0-9_]+)\s*(.*)", raw)
        if not m:
            raise bad_pattern()
        name, rest = m.group(1), m.group(2).strip()
        conds: list[tuple[str, Any]] = []
        for part in re.split(r"\s*&&\s*", rest) if rest else []:
            cm = re.fullmatch(r"(!=|<=|>=|=|<|>)\s*(.+)", part)
            if not cm:
                raise bad_pattern()
            raw_value = cm.group(2).strip()
            if raw_value.startswith('"'):
                value: Any = raw_value.strip('"')
            else:
                try:
                    value = float(raw_value)
                except ValueError:
                    value = raw_value
            conds.append((cm.group(1), value))
        specs.append((name, conds))

    def match(message: str) -> tuple[bool, dict[str, Any]]:
        fields = _split_fields(message)

        def rec(si: int, fi: int, bound: dict[str, str]) -> dict[str, str] | None:
            if si == len(specs):
                return bound if fi == len(fields) else None
            name, conds = specs[si]
            if name == "...":
                for k in range(fi, len(fields) + 1):
                    r = rec(si + 1, k, bound)
                    if r is not None:
                        return r
                return None
            if fi >= len(fields):
                return None
            value = fields[fi]
            if not all(_compare(op, value, v) for op, v in conds):
                return None
            return rec(si + 1, fi + 1, {**bound, name: value})

        bound = rec(0, 0, {})
        return (bound is not None), (bound or {})
    return match


def extract_value(expr: str, extracted: dict[str, Any]) -> Any:
    """メトリクスフィルタの metricValue ("1", "$.latency", "$bytes") を解決する。"""
    if not expr.startswith("$"):
        return expr
    if expr.startswith("$.") or expr.startswith("$["):
        found, v = _json_path(extracted.get("$json"), expr)
        return v if found else None
    return extracted.get(expr[1:])
