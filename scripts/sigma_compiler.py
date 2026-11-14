#!/usr/bin/env python3
"""Compile imported Sigma rules into the engine's ``match_when`` language.

The imported Sigma corpus is the largest body of detection content in the
repository and none of it executes: there is no Sigma evaluator anywhere in the
tree, so every one of those rules is metadata. This module translates a Sigma
rule into the dialect :mod:`app.services.detection_matcher` already evaluates,
or **refuses it with a reason**.

Refusing is the point. A translation that is merely close changes what a rule
means, and a corpus of rules that load but fire on the wrong events is worse
than a smaller corpus that is right — that is the failure this repository has
spent a long time removing, and re-introducing it at scale through a compiler
would be the most expensive version of it.

Two properties make refusal the default rather than the exception:

**Case sensitivity.** Sigma compares strings case-insensitively. Several
matcher operators do not: ``eq``, ``in``, ``startswith``, ``endswith`` and
their ``_any`` forms are all exact. Compiling ``Image|endswith: \\svchost.exe``
to ``Image_endswith_any`` would silently stop matching ``\\SvcHost.exe``. So
equality and affix tests compile to ``pattern_match_any`` — anchored, escaped,
and evaluated with ``re.IGNORECASE`` — which reproduces Sigma's comparison
exactly. ``contains``/``contains_all`` already lower-case both sides, so those
map across directly.

**Absence.** Sigma's ``not filter`` is true when the filtered field is missing,
because a filter that cannot be evaluated does not exclude anything. Of the
matcher's negative operators only ``not_in`` and ``not_contains_any`` behave
that way; ``neq``, ``not_startswith`` and ``not_endswith_any`` all return False
on a missing field, which would silently narrow the rule. Those compile to a
refusal rather than to something that looks equivalent.

The compiler never decides that a rule works. It proposes one, and
``scripts/compile_sigma_ruleset.py`` replays a vendor-shaped event through the
real connector and the real engine to decide whether it actually fires.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------
# Refusal reasons. Kept as constants so the report aggregates cleanly and a
# reader can see the taxonomy without reading the code.
# --------------------------------------------------------------------------
R_NO_EMITTER = "no connector emits this log source"
R_NESTED_FIELD = "field is a dotted path and the matcher has no path traversal"
R_MOD_RE = "|re is case-sensitive upstream and the matcher forces IGNORECASE"
R_MOD_CIDR = "|cidr has no matcher operator"
R_MOD_BASE64 = "|base64/|base64offset has no matcher operator"
R_MOD_FIELDREF = "|fieldref compares two fields and has no matcher operator"
R_MOD_UNKNOWN = "unsupported Sigma modifier"
R_KEYWORDS = "bare keywords search the whole event; the matcher is field-scoped"
R_COND_PARSE = "condition expression could not be parsed"
R_COND_UNKNOWN_REF = "condition references a detection key that does not exist"
R_NEGATION = "negation is not faithfully expressible (missing field would flip)"
R_ALL_MOD = "|all on a non-contains modifier has no matcher operator"
R_EMPTY = "compiled to an empty clause, which would match every event"
R_VALUE_TYPE = "unsupported value type in a selection"

#: Sigma log sources mapped to the connector whose ``normalize()`` output the
#: compiled rule will be replayed against. A log source absent from this map is
#: refused rather than guessed at: emitting a rule for telemetry no connector
#: produces is exactly the "loads but cannot fire" failure being removed.
#:
#: Keys are matched most-specific-first as ``product/category/service``.
EMITTERS: dict[str, str] = {
    "windows/*/*": "windows_event",
    "aws/*/cloudtrail": "aws_cloudtrail",
    "okta/*/okta": "okta",
    "azure/*/activitylogs": "azure_activity",
    "azure/*/auditlogs": "azure_activity",
    "azure/*/signinlogs": "azure_activity",
}


def emitter_for(logsource: dict[str, Any]) -> str | None:
    product = str(logsource.get("product") or "").lower()
    category = str(logsource.get("category") or "").lower()
    service = str(logsource.get("service") or "").lower()
    for key in (
        f"{product}/{category}/{service}",
        f"{product}/*/{service}",
        f"{product}/{category}/*",
        f"{product}/*/*",
    ):
        if key in EMITTERS:
            return EMITTERS[key]
    return None


# --------------------------------------------------------------------------
# Value translation
# --------------------------------------------------------------------------

_WILDCARD = re.compile(r"[*?]")


def _has_wildcard(value: str) -> bool:
    """True when the value carries an unescaped Sigma wildcard."""
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            i += 2
            continue
        out.append(ch)
        i += 1
    return bool(_WILDCARD.search("".join(out)))


def sigma_value_to_regex(value: str) -> str:
    """Translate a Sigma string (with ``*``/``?`` wildcards) to a regex body.

    Sigma escapes a literal wildcard with a backslash. Everything that is not a
    wildcard is escaped, so a value containing regex metacharacters — Windows
    paths are full of backslashes, and ``(``/``)``/``+`` show up in command
    lines — cannot turn into an accidental pattern.
    """
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


@dataclass
class Refusal(Exception):
    reason: str
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - diagnostics only
        return f"{self.reason}{f' ({self.detail})' if self.detail else ''}"


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def _scalar(value: Any) -> str | None:
    """Sigma scalars are strings, ints, bools or null."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float | str):
        return str(value)
    raise Refusal(R_VALUE_TYPE, type(value).__name__)


_SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "windash"}
_REFUSED_MODS = {
    "re": R_MOD_RE,
    "cidr": R_MOD_CIDR,
    "base64": R_MOD_BASE64,
    "base64offset": R_MOD_BASE64,
    "fieldref": R_MOD_FIELDREF,
    "expand": R_MOD_UNKNOWN,
    "utf16": R_MOD_BASE64,
    "utf16le": R_MOD_BASE64,
    "utf16be": R_MOD_BASE64,
    "wide": R_MOD_BASE64,
}

#: ``|windash`` matches a command-line switch written with any of the dash
#: characters Windows accepts. It is a value expansion, not a new comparison,
#: so it translates by expanding the alternatives into the same list the
#: ``_any`` operators already take.
_WINDASH = ("-", "/", "\u2013", "\u2014", "\u2015")


def _windash_variants(value: str) -> list[str]:
    if not value or value[0] not in _WINDASH:
        return [value]
    return [d + value[1:] for d in _WINDASH]


@dataclass
class Leaf:
    """One compiled ``field: value`` test, plus what negating it would need."""

    key: str
    value: Any
    field_name: str
    #: True when the operator treats a missing field as "no match" and its
    #: negation therefore treats a missing field as True — the only shape whose
    #: negation matches Sigma's.
    faithfully_negatable: bool
    negated_key: str | None = None


def compile_field(raw_key: str, value: Any) -> Leaf:
    """Compile one ``Field|mod: value`` entry into a matcher clause."""
    parts = raw_key.split("|")
    name = parts[0]
    mods = [m.lower() for m in parts[1:]]

    if "." in name:
        # The matcher does a plain event.get(); `properties.message` would be
        # read as a field whose name contains a dot, which nothing emits.
        raise Refusal(R_NESTED_FIELD, name)

    for mod in mods:
        if mod in _REFUSED_MODS:
            raise Refusal(_REFUSED_MODS[mod], f"{name}|{mod}")
        if mod not in _SUPPORTED_MODS:
            raise Refusal(R_MOD_UNKNOWN, f"{name}|{mod}")

    want_all = "all" in mods
    values = _as_list(value)

    # `field: null` is Sigma's "field is absent", which is the matcher's bare
    # equality against None.
    if len(values) == 1 and values[0] is None and not mods:
        return Leaf(key=name, value=None, field_name=name, faithfully_negatable=False)

    strings: list[str] = []
    for item in values:
        s = _scalar(item)
        if s is None:
            raise Refusal(R_VALUE_TYPE, "null mixed into a value list")
        strings.extend(_windash_variants(s) if "windash" in mods else [s])

    if "contains" in mods:
        if any(_has_wildcard(s) for s in strings):
            # A wildcard inside a contains is a regex, not a substring.
            pats = [sigma_value_to_regex(s) for s in strings]
            if want_all:
                raise Refusal(R_ALL_MOD, f"{name}|contains|all with wildcards")
            return Leaf(f"{name}_pattern_match_any", pats, name, faithfully_negatable=False)
        if want_all:
            return Leaf(f"{name}_contains_all", strings, name, faithfully_negatable=True)
        return Leaf(
            f"{name}_contains_any",
            strings,
            name,
            faithfully_negatable=True,
            negated_key=f"{name}_not_contains_any",
        )

    if want_all:
        # `|all` without `contains` asks one field to equal several values.
        raise Refusal(R_ALL_MOD, f"{name}|all")

    if "startswith" in mods:
        return Leaf(f"{name}_pattern_match_any", ["^" + sigma_value_to_regex(s) for s in strings], name, False)
    if "endswith" in mods:
        return Leaf(f"{name}_pattern_match_any", [sigma_value_to_regex(s) + "$" for s in strings], name, False)

    # Bare equality. Sigma compares case-insensitively and allows wildcards, so
    # this is an anchored case-insensitive regex rather than `eq`/`in`.
    return Leaf(f"{name}_pattern_match_any", ["^" + sigma_value_to_regex(s) + "$" for s in strings], name, False)


# --------------------------------------------------------------------------
# Condition parsing
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|\ball\b|\b1\b|\bany\b|\bof\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*\*?|\*)", re.I)


def tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            if condition[pos].isspace():
                pos += 1
                continue
            raise Refusal(R_COND_PARSE, f"unexpected {condition[pos]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


@dataclass
class Node:
    kind: str  # "ref" | "and" | "or" | "not" | "oneof" | "allof"
    value: Any = None
    children: list[Node] = field(default_factory=list)


class _Parser:
    """Recursive-descent parser for the Sigma condition grammar we support."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise Refusal(R_COND_PARSE, "unexpected end of condition")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise Refusal(R_COND_PARSE, f"trailing {self.peek()!r}")
        return node

    def parse_or(self) -> Node:
        children = [self.parse_and()]
        while (tok := self.peek()) and tok.lower() == "or":
            self.take()
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Node("or", children=children)

    def parse_and(self) -> Node:
        children = [self.parse_unary()]
        while (tok := self.peek()) and tok.lower() == "and":
            self.take()
            children.append(self.parse_unary())
        return children[0] if len(children) == 1 else Node("and", children=children)

    def parse_unary(self) -> Node:
        tok = self.peek()
        if tok and tok.lower() == "not":
            self.take()
            return Node("not", children=[self.parse_unary()])
        return self.parse_atom()

    def parse_atom(self) -> Node:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            inner = self.parse_or()
            if self.take() != ")":
                raise Refusal(R_COND_PARSE, "unbalanced parenthesis")
            return inner
        if low in {"all", "1", "any"}:
            nxt = self.peek()
            if nxt and nxt.lower() == "of":
                self.take()
                pattern = self.take()
                return Node("allof" if low == "all" else "oneof", value=pattern)
            raise Refusal(R_COND_PARSE, f"{tok!r} not followed by 'of'")
        if low in {"and", "or", "not", ")", "of"}:
            raise Refusal(R_COND_PARSE, f"unexpected {tok!r}")
        return Node("ref", value=tok)


def _resolve(pattern: str, keys: list[str]) -> list[str]:
    """Expand a Sigma selector (``selection*``, ``them``) to detection keys."""
    if pattern == "them":
        return list(keys)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return [k for k in keys if k.startswith(prefix)]
    return [k for k in keys if k == pattern]


# --------------------------------------------------------------------------
# Clause assembly
# --------------------------------------------------------------------------


def _merge_and(clauses: list[dict[str, Any]]) -> dict[str, Any]:
    """AND a list of clauses, flattening into one dict when keys allow it.

    A flat dict is already an AND, so merging keeps the common case readable.
    Two clauses constraining the same field would collide as dict keys, and
    silently dropping one would turn an AND of two tests into one test, so that
    case falls back to the matcher's explicit ``all_of``.
    """
    clauses = [c for c in clauses if c]
    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    merged: dict[str, Any] = {}
    for clause in clauses:
        if any(k in merged for k in clause) or "any_of" in clause or "all_of" in clause:
            return {"all_of": clauses}
        merged.update(clause)
    return merged


def _compile_selection(sel: Any) -> dict[str, Any]:
    """Compile one detection key's body into a clause.

    A Sigma map is an AND over its entries; a list of maps is an OR over them.
    """
    if isinstance(sel, list):
        if all(isinstance(item, dict) for item in sel):
            subs = [_compile_selection(item) for item in sel]
            return {"any_of": subs} if len(subs) > 1 else subs[0]
        # A bare list of strings under a detection key is a keyword search.
        raise Refusal(R_KEYWORDS, "list of literals")
    if not isinstance(sel, dict):
        raise Refusal(R_KEYWORDS, "non-map detection body")
    leaves = [compile_field(k, v) for k, v in sel.items()]
    return _merge_and([{leaf.key: leaf.value} for leaf in leaves])


def _negate_selection(sel: Any) -> dict[str, Any]:
    """Negate a detection key's body, or refuse.

    ``not (a AND b)`` is ``(not a) OR (not b)``, which the matcher expresses
    with ``any_of``. Each leaf must negate faithfully on its own — see the
    module docstring on absence — or the whole filter is refused.
    """
    if isinstance(sel, list):
        if all(isinstance(item, dict) for item in sel):
            # not (s1 OR s2) == (not s1) AND (not s2)
            return _merge_and([_negate_selection(item) for item in sel])
        raise Refusal(R_KEYWORDS, "list of literals")
    if not isinstance(sel, dict):
        raise Refusal(R_KEYWORDS, "non-map detection body")

    negated: list[dict[str, Any]] = []
    for key, value in sel.items():
        leaf = compile_field(key, value)
        if not leaf.faithfully_negatable:
            raise Refusal(R_NEGATION, key)
        if leaf.negated_key:
            negated.append({leaf.negated_key: leaf.value})
            continue
        if leaf.key.endswith("_contains_all"):
            # not (x contains a AND x contains b) == (a absent) OR (b absent).
            # Both halves use not_contains_any, which reads a missing field as
            # "does not contain" — the same answer Sigma gives.
            misses = [{f"{leaf.field_name}_not_contains_any": [v]} for v in leaf.value]
            negated.append(misses[0] if len(misses) == 1 else {"any_of": misses})
            continue
        raise Refusal(R_NEGATION, key)
    if not negated:
        raise Refusal(R_NEGATION, "empty filter")
    return negated[0] if len(negated) == 1 else {"any_of": negated}


def _compile_node(node: Node, detection: dict[str, Any], negate: bool = False) -> dict[str, Any]:
    keys = [k for k in detection if k != "condition"]

    if node.kind == "ref":
        if node.value not in detection:
            raise Refusal(R_COND_UNKNOWN_REF, str(node.value))
        body = detection[node.value]
        return _negate_selection(body) if negate else _compile_selection(body)

    if node.kind in {"oneof", "allof"}:
        targets = _resolve(str(node.value), keys)
        if not targets:
            raise Refusal(R_COND_UNKNOWN_REF, str(node.value))
        if node.kind == "allof":
            # not (a AND b) == (not a) OR (not b)
            if negate:
                return {"any_of": [_negate_selection(detection[t]) for t in targets]}
            return _merge_and([_compile_selection(detection[t]) for t in targets])
        # oneof: not (a OR b) == (not a) AND (not b)
        if negate:
            return _merge_and([_negate_selection(detection[t]) for t in targets])
        subs = [_compile_selection(detection[t]) for t in targets]
        return {"any_of": subs} if len(subs) > 1 else subs[0]

    if node.kind == "not":
        return _compile_node(node.children[0], detection, negate=not negate)

    if node.kind == "and":
        if negate:
            return {"any_of": [_compile_node(c, detection, negate=True) for c in node.children]}
        return _merge_and([_compile_node(c, detection) for c in node.children])

    if node.kind == "or":
        if negate:
            return _merge_and([_compile_node(c, detection, negate=True) for c in node.children])
        subs = [_compile_node(c, detection) for c in node.children]
        return {"any_of": subs}

    raise Refusal(R_COND_PARSE, node.kind)


@dataclass
class Compiled:
    match_when: dict[str, Any]
    emitter: str
    fields: list[str]


def compile_rule(doc: dict[str, Any]) -> Compiled:
    """Compile one imported Sigma rule document. Raises :class:`Refusal`."""
    logsource = doc.get("logsource") or doc.get("log_source") or {}
    emitter = emitter_for(logsource)
    if emitter is None:
        raise Refusal(R_NO_EMITTER, f"{logsource.get('product')}/{logsource.get('service')}")

    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if isinstance(condition, list):
        # A list of conditions is an OR of independent rules upstream; keeping
        # them as one rule would change which one fired.
        raise Refusal(R_COND_PARSE, "list-valued condition")
    if not isinstance(condition, str) or not condition.strip():
        raise Refusal(R_COND_PARSE, "missing condition")

    if "keywords" in detection and not isinstance(detection.get("keywords"), dict):
        raise Refusal(R_KEYWORDS, "keywords block")

    ast = _Parser(tokenize(condition)).parse()
    match_when = _compile_node(ast, detection)
    if not match_when:
        raise Refusal(R_EMPTY, "no clauses")

    return Compiled(match_when=match_when, emitter=emitter, fields=sorted(_fields_of(match_when)))


def _fields_of(clause: Any, out: set[str] | None = None) -> set[str]:
    out = set() if out is None else out
    if isinstance(clause, dict):
        for key, value in clause.items():
            if key in {"any_of", "all_of"}:
                _fields_of(value, out)
                continue
            base = key
            for suffix in (
                "_pattern_match_any",
                "_not_contains_any",
                "_contains_any",
                "_contains_all",
            ):
                if key.endswith(suffix):
                    base = key[: -len(suffix)]
                    break
            out.add(base)
    elif isinstance(clause, list):
        for item in clause:
            _fields_of(item, out)
    return out
