"""DynamoDB 式 (Condition / Filter / KeyCondition / Update / Projection) のパーサと評価器。"""
from __future__ import annotations

import base64
import copy
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from ..core import AwsError
from .ddb_reserved import RESERVED_WORDS

AV = dict[str, Any]          # AttributeValue 例: {"S": "abc"}
Path = list[Any]             # ["a", "b", 0] = a.b[0]

TOKEN_RE = re.compile(
    r"\s*(?:(?P<name>#[A-Za-z0-9_]+)|(?P<value>:[A-Za-z0-9_]+)|(?P<cmp><>|<=|>=|=|<|>)"
    r"|(?P<punct>[()\[\],.+\-])|(?P<num>[0-9]+)|(?P<ident>[A-Za-z_][A-Za-z0-9_]*))"
)
FUNCTIONS = {"attribute_exists", "attribute_not_exists", "attribute_type", "begins_with", "contains"}


def invalid(msg: str) -> AwsError:
    return AwsError("ValidationException", msg)


# ============================================================================ values
def num(av: AV) -> Decimal:
    try:
        return Decimal(av["N"])
    except (InvalidOperation, KeyError, TypeError):
        raise invalid("A value provided cannot be converted into a number")


def fmt_num(d: Decimal) -> str:
    s = format(d.normalize(), "f")
    return "0" if s in ("-0", "") else s


def av_type(av: AV) -> str:
    return next(iter(av))


def sort_value(av: AV) -> Any:
    t = av_type(av)
    if t == "N":
        return num(av)
    if t == "B":
        return base64.b64decode(av["B"])
    return av[t]


def canonical(av: AV | None) -> Any:
    """等価比較用の正規化 (数値の表記ゆれ・集合の順序を吸収)。"""
    if av is None:
        return None
    t = av_type(av)
    v = av[t]
    if t == "N":
        return ("N", num(av))
    if t in ("SS", "BS"):
        return (t, frozenset(v))
    if t == "NS":
        return (t, frozenset(Decimal(x) for x in v))
    if t == "L":
        return ("L", tuple(canonical(x) for x in v))
    if t == "M":
        return ("M", tuple(sorted((k, canonical(x)) for k, x in v.items())))
    return (t, v)


def equal(a: AV | None, b: AV | None) -> bool:
    return canonical(a) == canonical(b)


def item_size(item: dict[str, AV]) -> int:
    def size(av: AV) -> int:
        t = av_type(av)
        v = av[t]
        if t == "S":
            return len(v.encode())
        if t == "N":
            return len(v)
        if t == "B":
            return len(base64.b64decode(v))
        if t in ("SS", "NS"):
            return sum(len(x.encode()) for x in v)
        if t == "BS":
            return sum(len(base64.b64decode(x)) for x in v)
        if t == "L":
            return 3 + sum(size(x) + 1 for x in v)
        if t == "M":
            return 3 + sum(len(k.encode()) + size(x) + 1 for k, x in v.items())
        return 1
    return sum(len(k.encode()) + size(v) for k, v in item.items())


# ============================================================================ paths
def get_path(item: dict[str, AV], path: Path) -> AV | None:
    cur: AV | None = {"M": item}
    for el in path:
        if cur is None:
            return None
        if isinstance(el, int):
            lst = cur.get("L")
            cur = lst[el] if lst is not None and el < len(lst) else None
        else:
            m = cur.get("M")
            cur = m.get(el) if m is not None else None
    return cur


def _parent(item: dict[str, AV], path: Path) -> AV:
    parent = get_path(item, path[:-1]) if len(path) > 1 else {"M": item}
    last = path[-1]
    if parent is None or (isinstance(last, int) and "L" not in parent) or (isinstance(last, str) and "M" not in parent):
        raise invalid("The document path provided in the update expression is invalid for update")
    return parent


def set_path(item: dict[str, AV], path: Path, value: AV) -> None:
    parent = _parent(item, path)
    last = path[-1]
    if isinstance(last, int):
        lst = parent["L"]
        if last < len(lst):
            lst[last] = value
        else:
            lst.append(value)
    else:
        parent["M"][last] = value


def remove_path(item: dict[str, AV], path: Path) -> None:
    try:
        parent = _parent(item, path)
    except AwsError:
        return
    last = path[-1]
    if isinstance(last, int):
        if last < len(parent["L"]):
            del parent["L"][last]
    else:
        parent["M"].pop(last, None)


def path_str(path: Path) -> str:
    out = ""
    for el in path:
        out += f"[{el}]" if isinstance(el, int) else (("." if out else "") + el)
    return out


# ============================================================================ parser
class Parser:
    def __init__(self, text: str, names: dict[str, str] | None, values: dict[str, AV] | None, kind: str):
        self.text = text
        self.names = names or {}
        self.values = values or {}
        self.kind = kind
        self.used_names: set[str] = set()
        self.used_values: set[str] = set()
        self.tokens = self._tokenize(text)
        self.pos = 0

    def _tokenize(self, text: str) -> list[tuple[str, str]]:
        tokens, pos = [], 0
        text = text.rstrip()
        while pos < len(text):
            m = TOKEN_RE.match(text, pos)
            if not m or m.end() == pos:
                bad = text[pos:].strip()[:1]
                raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{bad}\", near: \"{text[max(0, pos-5):pos+5].strip()}\"")
            kind = m.lastgroup
            tokens.append((kind, m.group(kind)))
            pos = m.end()
        return tokens

    # --- token helpers
    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        i = self.pos + offset
        return self.tokens[i] if i < len(self.tokens) else None

    def next(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise invalid(f"Invalid {self.kind}: Syntax error; token: \"<EOF>\", near: \"{self.text[-10:]}\"")
        self.pos += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.next()
        if tok[1].upper() != value.upper():
            raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{tok[1]}\", near: \"{self.text}\"")

    def at_keyword(self, *words: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] == "ident" and tok[1].upper() in words

    def done(self) -> None:
        if self.peek() is not None:
            tok = self.peek()
            raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{tok[1]}\", near: \"{self.text}\"")

    def check_unused(self) -> None:
        unused_v = set(self.values) - self.used_values
        if unused_v:
            raise invalid(f"Value provided in ExpressionAttributeValues unused in expressions: keys: {{{', '.join(sorted(unused_v))}}}")
        unused_n = set(self.names) - self.used_names
        if unused_n:
            raise invalid(f"Value provided in ExpressionAttributeNames unused in expressions: keys: {{{', '.join(sorted(unused_n))}}}")

    # --- operands
    def path(self) -> Path:
        path: Path = [self._name(self.next())]
        while self.peek() and self.peek()[1] in (".", "["):
            if self.next()[1] == ".":
                path.append(self._name(self.next()))
            else:
                tok = self.next()
                if tok[0] != "num":
                    raise invalid(f"Invalid {self.kind}: List index is not an integer")
                path.append(int(tok[1]))
                self.expect("]")
        return path

    def _name(self, tok: tuple[str, str]) -> str:
        kind, text = tok
        if kind == "name":
            if text not in self.names:
                raise invalid(f"Invalid {self.kind}: An expression attribute name used in the document path is not defined; attribute name: {text}")
            self.used_names.add(text)
            return self.names[text]
        if kind == "ident":
            if text.upper() in RESERVED_WORDS:
                raise invalid(f"Invalid {self.kind}: Attribute name is a reserved keyword; reserved keyword: {text}")
            return text
        raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{text}\", near: \"{self.text}\"")

    def value_ref(self) -> AV:
        kind, text = self.next()
        if kind != "value":
            raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{text}\", near: \"{self.text}\"")
        if text not in self.values:
            raise invalid(f"Invalid {self.kind}: An expression attribute value used in expression is not defined; attribute value: {text}")
        self.used_values.add(text)
        return self.values[text]

    def operand(self) -> tuple:
        tok = self.peek()
        if tok is None:
            self.next()
        if tok[0] == "value":
            return ("value", self.value_ref())
        if tok[0] == "ident" and tok[1] == "size" and self.peek(1) and self.peek(1)[1] == "(":
            self.pos += 2
            p = self.path()
            self.expect(")")
            return ("size", p)
        return ("path", self.path())

    # --- conditions
    def condition(self) -> tuple:
        node = self._and()
        while self.at_keyword("OR"):
            self.next()
            node = ("or", node, self._and())
        return node

    def _and(self) -> tuple:
        node = self._not()
        while self.at_keyword("AND"):
            self.next()
            node = ("and", node, self._not())
        return node

    def _not(self) -> tuple:
        if self.at_keyword("NOT"):
            self.next()
            return ("not", self._not())
        return self._primary()

    def _primary(self) -> tuple:
        tok = self.peek()
        if tok and tok[1] == "(":
            self.next()
            node = self.condition()
            self.expect(")")
            return node
        if tok and tok[0] == "ident" and tok[1] in FUNCTIONS and self.peek(1) and self.peek(1)[1] == "(":
            name = self.next()[1]
            self.next()
            args = [("path", self.path())]
            while self.peek() and self.peek()[1] == ",":
                self.next()
                args.append(self.operand())
            self.expect(")")
            expected = 1 if name in ("attribute_exists", "attribute_not_exists") else 2
            if len(args) != expected:
                raise invalid(f"Invalid {self.kind}: Incorrect number of operands for operator or function; operator or function: {name}, number of operands: {len(args)}")
            return ("func", name, args)
        left = self.operand()
        if self.at_keyword("BETWEEN"):
            self.next()
            lo = self.operand()
            self.expect("AND")
            return ("between", left, lo, self.operand())
        if self.at_keyword("IN"):
            self.next()
            self.expect("(")
            items = [self.operand()]
            while self.peek() and self.peek()[1] == ",":
                self.next()
                items.append(self.operand())
            self.expect(")")
            return ("in", left, items)
        tok = self.next()
        if tok[0] != "cmp":
            raise invalid(f"Invalid {self.kind}: Syntax error; token: \"{tok[1]}\", near: \"{self.text}\"")
        return ("cmp", tok[1], left, self.operand())

    # --- update
    def update(self) -> list[tuple]:
        actions: list[tuple] = []
        seen: set[str] = set()
        while self.peek():
            clause = self.next()[1].upper()
            if clause in seen or clause not in ("SET", "REMOVE", "ADD", "DELETE"):
                raise invalid(f"Invalid {self.kind}: " + (
                    f"The \"{clause}\" section can only be used once in an update expression;"
                    if clause in seen else f"Syntax error; token: \"{clause}\", near: \"{self.text}\""))
            seen.add(clause)
            while True:
                p = self.path()
                if clause == "SET":
                    self.expect("=")
                    actions.append(("SET", p, self._set_value()))
                elif clause == "REMOVE":
                    actions.append(("REMOVE", p, None))
                else:
                    actions.append((clause, p, self.value_ref()))
                if self.peek() and self.peek()[1] == ",":
                    self.next()
                    continue
                break
        if not actions:
            raise invalid(f"Invalid {self.kind}: The expression can not be empty;")
        paths = [a[1] for a in actions]
        for i, a in enumerate(paths):
            for b in paths[i + 1:]:
                n = min(len(a), len(b))
                if a[:n] == b[:n]:
                    raise invalid(f"Invalid {self.kind}: Two document paths overlap with each other; must remove or "
                                  f"rewrite one of these paths; path one: [{path_str(a)}], path two: [{path_str(b)}]")
        return actions

    def _set_value(self) -> tuple:
        left = self._set_operand()
        tok = self.peek()
        if tok and tok[1] in ("+", "-"):
            self.next()
            return ("arith", tok[1], left, self._set_operand())
        return left

    def _set_operand(self) -> tuple:
        tok = self.peek()
        if tok and tok[0] == "ident" and tok[1] in ("if_not_exists", "list_append") and self.peek(1) and self.peek(1)[1] == "(":
            fn = self.next()[1]
            self.next()
            a = ("path", self.path()) if fn == "if_not_exists" else self._set_operand()
            self.expect(",")
            b = self._set_operand()
            self.expect(")")
            return (fn, a, b)
        return self.operand()

    # --- projection
    def projection(self) -> list[Path]:
        paths = [self.path()]
        while self.peek() and self.peek()[1] == ",":
            self.next()
            paths.append(self.path())
        return paths


# ============================================================================ evaluation
def eval_operand(node: tuple, item: dict[str, AV]) -> AV | None:
    kind = node[0]
    if kind == "value":
        return node[1]
    if kind == "path":
        return get_path(item, node[1])
    if kind == "size":
        v = get_path(item, node[1])
        if v is None:
            return None
        t = av_type(v)
        if t == "B":
            n = len(base64.b64decode(v["B"]))
        elif t in ("S", "SS", "NS", "BS", "L", "M"):
            n = len(v[t])
        else:
            raise invalid("Invalid ConditionExpression: Incorrect operand type for operator or function; operator or function: size, operand type: " + t)
        return {"N": str(n)}
    raise AssertionError(kind)


def _ordered(op: str, a: AV | None, b: AV | None) -> bool:
    if a is None or b is None:
        return False
    ta, tb = av_type(a), av_type(b)
    if ta != tb or ta not in ("S", "N", "B"):
        return False
    x, y = sort_value(a), sort_value(b)
    return {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]


def evaluate(node: tuple, item: dict[str, AV]) -> bool:
    kind = node[0]
    if kind == "and":
        return evaluate(node[1], item) and evaluate(node[2], item)
    if kind == "or":
        return evaluate(node[1], item) or evaluate(node[2], item)
    if kind == "not":
        return not evaluate(node[1], item)
    if kind == "cmp":
        op, a, b = node[1], eval_operand(node[2], item), eval_operand(node[3], item)
        if op == "=":
            return a is not None and equal(a, b)
        if op == "<>":
            return not equal(a, b)
        return _ordered(op, a, b)
    if kind == "between":
        v, lo, hi = (eval_operand(n, item) for n in node[1:])
        return _ordered(">=", v, lo) and _ordered("<=", v, hi)
    if kind == "in":
        v = eval_operand(node[1], item)
        return v is not None and any(equal(v, eval_operand(n, item)) for n in node[2])
    if kind == "func":
        name, args = node[1], node[2]
        target = eval_operand(args[0], item)
        if name == "attribute_exists":
            return target is not None
        if name == "attribute_not_exists":
            return target is None
        arg = eval_operand(args[1], item)
        if target is None or arg is None:
            return False
        if name == "attribute_type":
            return av_type(target) == arg.get("S")
        if name == "begins_with":
            t = av_type(target)
            return t in ("S", "B") and av_type(arg) == t and (
                target["S"].startswith(arg["S"]) if t == "S"
                else base64.b64decode(target["B"]).startswith(base64.b64decode(arg["B"])))
        if name == "contains":
            t = av_type(target)
            if t == "S":
                return av_type(arg) == "S" and arg["S"] in target["S"]
            if t in ("SS", "NS", "BS"):
                return canonical(arg)[1] in {canonical({t[0]: x})[1] for x in target[t]}
            if t == "L":
                return any(equal(arg, x) for x in target["L"])
            return False
    raise AssertionError(kind)


def _update_value(node: tuple, item: dict[str, AV]) -> AV:
    kind = node[0]
    if kind == "arith":
        a, b = _update_value(node[2], item), _update_value(node[3], item)
        if "N" not in a or "N" not in b:
            raise invalid("An operand in the update expression has an incorrect data type")
        return {"N": fmt_num(num(a) + num(b) if node[1] == "+" else num(a) - num(b))}
    if kind == "if_not_exists":
        existing = get_path(item, node[1][1])
        return existing if existing is not None else _update_value(node[2], item)
    if kind == "list_append":
        a, b = _update_value(node[1], item), _update_value(node[2], item)
        if "L" not in a or "L" not in b:
            raise invalid("An operand in the update expression has an incorrect data type")
        return {"L": a["L"] + b["L"]}
    v = eval_operand(node, item)
    if v is None:
        raise invalid("The provided expression refers to an attribute that does not exist in the item")
    return copy.deepcopy(v)


def apply_update(actions: list[tuple], item: dict[str, AV]) -> dict[str, AV]:
    """更新後のアイテムを返す (元のアイテムは変更しない)。"""
    old = item
    new = copy.deepcopy(item)
    # SET の右辺はすべて更新前のアイテムを基に評価される
    computed = [(a, _update_value(a[2], old) if a[0] == "SET" else None) for a in actions]
    for (clause, path, operand), value in computed:
        if clause == "SET":
            set_path(new, path, value)
        elif clause == "REMOVE":
            remove_path(new, path)
        elif clause == "ADD":
            cur = get_path(new, path)
            t = av_type(operand)
            if t not in ("N", "SS", "NS", "BS"):
                raise invalid("Invalid UpdateExpression: Incorrect operand type for operator or function; operator: ADD, operand type: " + t)
            if cur is None:
                set_path(new, path, copy.deepcopy(operand))
            elif av_type(cur) != t:
                raise invalid("An operand in the update expression has an incorrect data type")
            elif t == "N":
                set_path(new, path, {"N": fmt_num(num(cur) + num(operand))})
            else:
                merged = list(cur[t]) + [x for x in operand[t] if x not in cur[t]]
                set_path(new, path, {t: merged})
        elif clause == "DELETE":
            cur = get_path(new, path)
            t = av_type(operand)
            if t not in ("SS", "NS", "BS"):
                raise invalid("Invalid UpdateExpression: Incorrect operand type for operator or function; operator: DELETE, operand type: " + t)
            if cur is None:
                continue
            if av_type(cur) != t:
                raise invalid("An operand in the update expression has an incorrect data type")
            remaining = [x for x in cur[t] if x not in operand[t]]
            if remaining:
                set_path(new, path, {t: remaining})
            else:
                remove_path(new, path)
    return new


def project(item: dict[str, AV], paths: list[Path]) -> dict[str, AV]:
    """ProjectionExpression を適用する。ネストしたパスは親構造ごと取り出す。"""
    out: dict[str, AV] = {}
    for path in paths:
        value = get_path(item, path)
        if value is None:
            continue
        container: AV = {"M": out}
        for el, nxt in zip(path, path[1:]):
            kind = "L" if isinstance(nxt, int) else "M"
            if isinstance(el, int):
                node: AV = {kind: [] if kind == "L" else {}}
                container["L"].append(node)
            else:
                node = container["M"].setdefault(el, {kind: [] if kind == "L" else {}})
            container = node
        last = path[-1]
        if isinstance(last, int):
            container["L"].append(copy.deepcopy(value))
        else:
            container["M"][last] = copy.deepcopy(value)
    return out


# ============================================================================ public helpers
def parse_condition(expr: str, names, values, kind: str = "ConditionExpression") -> tuple[tuple, Parser]:
    p = Parser(expr, names, values, kind)
    node = p.condition()
    p.done()
    return node, p


def parse_update(expr: str, names, values) -> tuple[list[tuple], Parser]:
    p = Parser(expr, names, values, "UpdateExpression")
    actions = p.update()
    p.done()
    return actions, p


def parse_projection(expr: str, names) -> tuple[list[Path], Parser]:
    p = Parser(expr, names, None, "ProjectionExpression")
    paths = p.projection()
    p.done()
    return paths, p
