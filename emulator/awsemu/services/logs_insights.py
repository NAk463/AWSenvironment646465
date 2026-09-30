"""CloudWatch Logs Insights のクエリエンジン (主要コマンドのサブセット)。

コマンド: fields / display / filter / parse / stats ... by / sort / limit / dedup
関数:     count, sum, avg, min, max, pct, count_distinct, earliest, latest, stddev,
          bin, ispresent, isempty, isblank, strlen, toupper, tolower, concat, abs, ceil, floor
JSON 形式のログはフィールドを自動検出する (ネストは a.b、配列は a.0)。
"""
from __future__ import annotations

import base64
import json
import math
import re
import statistics
from datetime import datetime, timezone
from typing import Any

from ..core import AwsError

TOKEN_RE = re.compile(
    r"\s*(?:(?P<string>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')|(?P<number>\d+(?:\.\d+)?[smhdw]?(?![\w@]))"
    r"|(?P<backtick>`[^`]+`)|(?P<op>=~|!=|<=|>=|==|=|<|>|\(|\)|\[|\]|,|\*|\+|-|/|%)"
    r"|(?P<ident>[@A-Za-z_][\w.@\-]*))")
REGEX_RE = re.compile(r"\s*/((?:[^/\\]|\\.)+)/(i?)")
AGGREGATES = {"count", "sum", "avg", "min", "max", "pct", "count_distinct", "earliest", "latest", "stddev"}
DURATION = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def malformed(msg: str) -> AwsError:
    return AwsError("MalformedQueryException", msg)


def flatten(obj: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}{k}.", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, f"{prefix}{i}.", out)
    elif prefix:
        out[prefix[:-1]] = obj
    return out


def fmt_ts(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def fmt_value(v: Any) -> str:
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(round(v, 6))
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)


# ============================================================================ tokenizer / parser
class Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def error(self) -> AwsError:
        near = self.text[self.pos:self.pos + 15].strip() or "<EOF>"
        return malformed(f"unexpected symbol found {near} at line 1 and position {self.pos + 1}")

    def peek(self, regex_ok: bool = False) -> tuple[str, str] | None:
        if regex_ok:
            m = REGEX_RE.match(self.text, self.pos)
            if m:
                return ("regex", m.group(0))
        m = TOKEN_RE.match(self.text, self.pos)
        if not m or m.end() == self.pos:
            return None
        return (m.lastgroup, m.group(m.lastgroup))

    def next(self, regex_ok: bool = False) -> tuple[str, str]:
        if regex_ok:
            m = REGEX_RE.match(self.text, self.pos)
            if m:
                self.pos = m.end()
                return ("regex", m.group(0))
        m = TOKEN_RE.match(self.text, self.pos)
        if not m or m.end() == self.pos:
            raise self.error()
        self.pos = m.end()
        return (m.lastgroup, m.group(m.lastgroup))

    def at(self, *values: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[1].lower() in values

    def expect(self, value: str) -> None:
        tok = self.next()
        if tok[1].lower() != value:
            self.pos -= len(tok[1])
            raise self.error()

    def done(self) -> bool:
        return not self.text[self.pos:].strip()

    # --- expressions
    def expr(self) -> Any:
        node = self._and()
        while self.at("or"):
            self.next()
            node = ("or", node, self._and())
        return node

    def _and(self) -> Any:
        node = self._not()
        while self.at("and"):
            self.next()
            node = ("and", node, self._not())
        return node

    def _not(self) -> Any:
        if self.at("not"):
            self.next()
            return ("not", self._not())
        return self._cmp()

    def _cmp(self) -> Any:
        left = self._add()
        negate = False
        if self.at("not") and re.match(r"\s*not\s+(like|in)\b", self.text[self.pos:], re.I):
            self.next()
            negate = True
        tok = self.peek()
        if tok is None:
            return left
        word = tok[1].lower()
        if word in ("like", "=~"):
            self.next()
            kind, raw = self.next(regex_ok=True)
            if kind == "regex":
                m = REGEX_RE.match(raw)
                pattern = re.compile(m.group(1), re.I if m.group(2) else 0)
            elif kind == "string":
                pattern = re.compile(re.escape(_unquote(raw)))
            else:
                raise self.error()
            node = ("like", left, pattern)
            return ("not", node) if negate else node
        if word == "in":
            self.next()
            self.expect("[")
            items = [self._add()]
            while self.at(","):
                self.next()
                items.append(self._add())
            self.expect("]")
            node = ("in", left, items)
            return ("not", node) if negate else node
        if word in ("=", "==", "!=", "<", "<=", ">", ">="):
            self.next()
            return ("cmp", "=" if word == "==" else word, left, self._add())
        return left

    def _add(self) -> Any:
        node = self._mul()
        while self.at("+", "-"):
            op = self.next()[1]
            node = ("arith", op, node, self._mul())
        return node

    def _mul(self) -> Any:
        node = self._unary()
        while self.at("*", "/", "%"):
            op = self.next()[1]
            node = ("arith", op, node, self._unary())
        return node

    def _unary(self) -> Any:
        if self.at("-"):
            self.next()
            return ("arith", "-", ("lit", 0.0), self._unary())
        return self._primary()

    def _primary(self) -> Any:
        kind, raw = self.next()
        if kind == "number":
            if raw[-1] in DURATION:
                return ("lit", float(raw[:-1]) * DURATION[raw[-1]] * 1000)
            return ("lit", float(raw))
        if kind == "string":
            return ("lit", _unquote(raw))
        if kind == "backtick":
            return ("field", raw[1:-1])
        if raw == "(":
            node = self.expr()
            self.expect(")")
            return node
        if raw == "*":
            return ("star",)
        if kind == "ident":
            if self.at("("):
                self.next()
                args = []
                if not self.at(")"):
                    args.append(self.expr())
                    while self.at(","):
                        self.next()
                        args.append(self.expr())
                self.expect(")")
                return ("call", raw.lower(), args)
            low = raw.lower()
            if low in ("true", "false"):
                return ("lit", low == "true")
            return ("field", raw)
        self.pos -= len(raw)
        raise self.error()

    def expr_list(self, allow_alias: bool = True) -> list[tuple[Any, str]]:
        items = []
        while True:
            start = self.pos
            node = self.expr()
            name = self.text[start:self.pos].strip()
            if allow_alias and self.at("as"):
                self.next()
                name = self.next()[1].strip("`")
            items.append((node, name))
            if not self.at(","):
                return items
            self.next()


def _unquote(raw: str) -> str:
    return raw[1:-1].replace('\\"', '"').replace("\\'", "'")


# ============================================================================ evaluation
def evaluate(node: Any, rec: dict[str, Any]) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "field":
        return rec.get(node[1])
    if kind == "star":
        return True
    if kind == "and":
        return bool(evaluate(node[1], rec)) and bool(evaluate(node[2], rec))
    if kind == "or":
        return bool(evaluate(node[1], rec)) or bool(evaluate(node[2], rec))
    if kind == "not":
        return not evaluate(node[1], rec)
    if kind == "like":
        v = evaluate(node[1], rec)
        return v is not None and node[2].search(fmt_value(v)) is not None
    if kind == "in":
        v = evaluate(node[1], rec)
        return any(_equal(v, evaluate(x, rec)) for x in node[2])
    if kind == "cmp":
        a, b = evaluate(node[2], rec), evaluate(node[3], rec)
        op = node[1]
        if op == "=":
            return _equal(a, b)
        if op == "!=":
            return not _equal(a, b)
        na, nb = _num(a), _num(b)
        if na is None or nb is None:
            if a is None or b is None:
                return False
            na, nb = str(a), str(b)
        return {"<": na < nb, "<=": na <= nb, ">": na > nb, ">=": na >= nb}[op]
    if kind == "arith":
        a, b = _num(evaluate(node[2], rec)), _num(evaluate(node[3], rec))
        if a is None or b is None:
            return None
        op = node[1]
        if op in ("/", "%") and b == 0:
            return None
        return {"+": a + b, "-": a - b, "*": a * b, "/": a / b if b else None, "%": a % b if b else None}[op]
    if kind == "call":
        return _call(node[1], node[2], rec)
    raise AssertionError(kind)


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _equal(a: Any, b: Any) -> bool:
    na, nb = _num(a), _num(b)
    if na is not None and nb is not None:
        return na == nb
    return a is not None and b is not None and fmt_value(a) == fmt_value(b)


def _call(name: str, args: list[Any], rec: dict[str, Any]) -> Any:
    if name in AGGREGATES:
        raise malformed(f"Aggregate function {name} can only be used in stats")
    vals = [evaluate(a, rec) for a in args]
    if name == "ispresent":
        return vals[0] is not None
    if name == "isempty":
        return vals[0] is None or vals[0] == ""
    if name == "isblank":
        return vals[0] is None or str(vals[0]).strip() == ""
    if name == "strlen":
        return float(len(fmt_value(vals[0]))) if vals[0] is not None else None
    if name == "toupper":
        return fmt_value(vals[0]).upper() if vals[0] is not None else None
    if name == "tolower":
        return fmt_value(vals[0]).lower() if vals[0] is not None else None
    if name == "concat":
        return "".join(fmt_value(v) for v in vals if v is not None)
    if name in ("abs", "ceil", "floor"):
        n = _num(vals[0])
        return None if n is None else float({"abs": abs, "ceil": math.ceil, "floor": math.floor}[name](n))
    if name in ("bin", "datefloor"):
        size = _num(vals[-1])
        ts = _num(rec.get("@timestamp")) if name == "bin" else _num(vals[0])
        if not size or ts is None:
            return None
        return fmt_ts(math.floor(ts / size) * size)
    if name == "frommillis":
        n = _num(vals[0])
        return fmt_ts(n) if n is not None else None
    raise malformed(f"Unknown function {name}")


def _aggregate(name: str, args: list[Any], group: list[dict[str, Any]]) -> Any:
    if name == "count":
        if not args or args[0][0] == "star":
            return float(len(group))
        return float(sum(1 for r in group if evaluate(args[0], r) is not None))
    values = [evaluate(args[0], r) for r in group] if args else []
    present = [v for v in values if v is not None]
    if name == "count_distinct":
        return float(len({fmt_value(v) for v in present}))
    if name in ("earliest", "latest"):
        ordered = sorted(((r.get("@timestamp", 0), evaluate(args[0], r)) for r in group), key=lambda x: x[0])
        ordered = [v for _, v in ordered if v is not None]
        return (ordered[0] if name == "earliest" else ordered[-1]) if ordered else None
    nums = [n for n in (_num(v) for v in present) if n is not None]
    if not nums:
        return None
    if name == "sum":
        return sum(nums)
    if name == "avg":
        return sum(nums) / len(nums)
    if name == "min":
        return min(nums)
    if name == "max":
        return max(nums)
    if name == "stddev":
        return statistics.pstdev(nums)
    if name == "pct":
        pct = _num(evaluate(args[1], {})) if len(args) > 1 else 50.0
        ordered = sorted(nums)
        rank = max(0, math.ceil((pct or 0) / 100 * len(ordered)) - 1)
        return ordered[min(rank, len(ordered) - 1)]
    raise malformed(f"Unknown aggregate {name}")


# ============================================================================ commands
def _split_commands(query: str) -> list[str]:
    parts, buf, quote, depth, i = [], "", "", 0, 0
    while i < len(query):
        c = query[i]
        if quote:
            buf += c
            if c == "\\" and i + 1 < len(query):
                buf += query[i + 1]
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
            buf += c
        elif c == "/" and re.search(r"(like|=~|parse\s+\S+)\s*$", buf, re.I):
            end = query.find("/", i + 1)
            while end > 0 and query[end - 1] == "\\":
                end = query.find("/", end + 1)
            if end < 0:
                raise malformed("unterminated regex")
            buf += query[i:end + 1]
            i = end
        elif c in "([":
            depth += 1
            buf += c
        elif c in ")]":
            depth -= 1
            buf += c
        elif c == "|" and depth == 0:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += c
        i += 1
    if buf.strip():
        parts.append(buf.strip())
    return [p for p in parts if p]


def run_query(query: str, records: list[dict[str, Any]], limit: int | None) -> tuple[list[list[dict[str, str]]], int]:
    """クエリを実行し (結果行, recordsMatched) を返す。"""
    rows = sorted(records, key=lambda r: r.get("@timestamp", 0), reverse=True)
    display: list[str] | None = None
    aggregated = False
    row_limit = limit
    for command in _split_commands(query):
        word, _, rest = command.partition(" ")
        word = word.lower()
        p = Parser(rest)
        if word in ("fields", "display"):
            items = p.expr_list()
            if not p.done():
                raise p.error()
            for node, name in items:
                if node[0] != "field" or node[1] != name:
                    for r in rows:
                        r[name] = evaluate(node, r)
            names = [n for _, n in items]
            display = names if word == "display" else (display or []) + [n for n in names if n not in (display or [])]
        elif word == "filter":
            node = p.expr()
            if not p.done():
                raise p.error()
            rows = [r for r in rows if evaluate(node, r)]
        elif word == "parse":
            _parse_command(rest, rows)
        elif word == "stats":
            rows, names = _stats(rest, rows)
            display, aggregated = names, True
        elif word == "sort":
            keys = []
            for part in rest.split(","):
                bits = part.split()
                if not bits:
                    raise malformed("sort requires a field")
                keys.append((bits[0].strip("`"), len(bits) > 1 and bits[1].lower() == "desc"))
            for name, desc in reversed(keys):
                rows.sort(key=lambda r: _sort_key(r.get(name)), reverse=desc)
        elif word == "limit":
            try:
                row_limit = int(rest.strip())
            except ValueError:
                raise malformed(f"unexpected symbol found {rest.strip()} at line 1")
        elif word == "dedup":
            names = [n.strip().strip("`") for n in rest.split(",")]
            seen, kept = set(), []
            for r in rows:
                k = tuple(fmt_value(r.get(n)) for n in names)
                if k not in seen:
                    seen.add(k)
                    kept.append(r)
            rows = kept
        else:
            raise malformed(f"unexpected symbol found {word} at line 1 and position 1")
    matched = len(rows)
    if row_limit:
        rows = rows[:row_limit]
    fields = display or ["@timestamp", "@message"]
    out = []
    for r in rows:
        row = [{"field": f, "value": fmt_ts(r[f]) if f in ("@timestamp", "@ingestionTime") and isinstance(r.get(f), (int, float))
                else fmt_value(r[f])} for f in fields if r.get(f) is not None]
        if not aggregated and "@ptr" in r:
            row.append({"field": "@ptr", "value": r["@ptr"]})
        out.append(row)
    return out, matched


def _sort_key(v: Any) -> tuple[int, Any]:
    n = _num(v)
    if n is not None:
        return (1, n)
    return (0, "") if v is None else (2, fmt_value(v))


def _parse_command(rest: str, rows: list[dict[str, Any]]) -> None:
    m = re.fullmatch(r"\s*(\S+)\s+(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')\s+as\s+(.+)", rest, re.S)
    if m:
        source, glob, names = m.group(1).strip("`"), _unquote(m.group(2)), [n.strip() for n in m.group(3).split(",")]
        pieces = glob.split("*")
        if len(pieces) - 1 != len(names):
            raise malformed("parse: the number of * does not match the number of fields")
        regex = re.compile("".join(re.escape(pc) + (f"(?P<g{i}>.*?)" if i < len(names) - 1 else
                                                     (f"(?P<g{i}>.*)" if i == len(names) - 1 else ""))
                                   for i, pc in enumerate(pieces)), re.S)
        for r in rows:
            hit = regex.search(fmt_value(r.get(source, "")))
            if hit:
                for i, n in enumerate(names):
                    r[n] = hit.group(f"g{i}")
        return
    m = re.fullmatch(r"\s*(\S+)\s+/((?:[^/\\]|\\.)+)/(i?)\s*", rest, re.S)
    if m:
        source = m.group(1).strip("`")
        pattern = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", m.group(2))
        regex = re.compile(pattern, re.I if m.group(3) else 0)
        for r in rows:
            hit = regex.search(fmt_value(r.get(source, "")))
            if hit:
                r.update({k: v for k, v in hit.groupdict().items() if v is not None})
        return
    raise malformed("parse requires: parse <field> \"<glob>\" as <fields> or parse <field> /<regex>/")


def _stats(rest: str, rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    by_idx = None
    for m in re.finditer(r"\bby\b", rest, re.I):
        before = rest[:m.start()]
        if before.count("(") == before.count(")") and before.count('"') % 2 == 0:
            by_idx = m
    agg_text = rest[:by_idx.start()] if by_idx else rest
    p = Parser(agg_text)
    aggs = p.expr_list()
    if not p.done():
        raise p.error()
    groups_spec: list[tuple[Any, str]] = []
    if by_idx:
        bp = Parser(rest[by_idx.end():])
        groups_spec = bp.expr_list()
        if not bp.done():
            raise bp.error()
    for node, _ in aggs:
        if node[0] != "call" or node[1] not in AGGREGATES:
            raise malformed("stats requires aggregate functions such as count(*), avg(field)")
    grouped: dict[tuple, list[dict[str, Any]]] = {}
    for r in rows:
        key = tuple(fmt_value(evaluate(n, r)) if evaluate(n, r) is not None else None for n, _ in groups_spec)
        grouped.setdefault(key, []).append(r)
    out = []
    for key, members in grouped.items():
        row: dict[str, Any] = {name: k for (_, name), k in zip(groups_spec, key)}
        for node, name in aggs:
            row[name] = _aggregate(node[1], node[2], members)
        out.append(row)
    if groups_spec and any("bin(" in n.replace(" ", "") for _, n in groups_spec):
        name = next(n for _, n in groups_spec if "bin(" in n.replace(" ", ""))
        out.sort(key=lambda r: r.get(name) or "", reverse=True)
    return out, [n for _, n in groups_spec] + [n for _, n in aggs]


def build_record(ts: int, message: str, ingestion: int, stream: str, group: str, ptr: str) -> dict[str, Any]:
    rec: dict[str, Any] = {"@timestamp": ts, "@message": message, "@ingestionTime": ingestion,
                           "@logStream": stream, "@log": group, "@ptr": base64.b64encode(ptr.encode()).decode()}
    text = message.strip()
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            for k, v in flatten(parsed).items():
                rec.setdefault(k, v)
    return rec
