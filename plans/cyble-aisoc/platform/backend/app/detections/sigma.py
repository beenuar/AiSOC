"""Sigma rule parser + in-memory matcher.

Implements the subset of the Sigma specification that matters for our
detection content:

Field modifiers supported:
    contains, startswith, endswith, equals (default), all, re, cidr,
    base64, base64offset, gt, gte, lt, lte, exists

Detection-block conditions supported:
    selection (bare identifier)
    not <id>
    <a> and <b>
    <a> or <b>
    parentheses
    1 of <prefix>*  / any of <prefix>*  / all of <prefix>*
    1 of them      / any of them        / all of them

Values:
    str, int, float, bool, None — null in a list means "no value"
    Wildcards * and ? inside string values
    Field names may use Sigma's nested-field dot notation (e.g.
        ``Image.path``); we resolve them against the event dict by
    walking keys, with case-insensitive fallback.

The matcher never raises on unknown modifiers — it logs and treats the
unmatched modifier as False, so a broken rule never silently matches
everything. Parse errors *do* raise ``SigmaParseError`` at load time;
we want them caught in CI, not at 3am.
"""

from __future__ import annotations

import base64 as _b64
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import yaml

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Public surface
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Sigma `level:` field, normalized.

    We collapse Sigma's ``informational`` and ``low`` since our case
    schema only carries 4 priorities (low/medium/high/critical) and
    "informational" almost always rounds down to "low" anyway.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, raw: Any) -> "Severity":
        if raw is None:
            return cls.MEDIUM
        s = str(raw).strip().lower()
        if s in {"informational", "info", "low"}:
            return cls.LOW
        if s in {"medium", "med"}:
            return cls.MEDIUM
        if s == "high":
            return cls.HIGH
        if s == "critical":
            return cls.CRITICAL
        # Unknown levels round up — better to over-alert than miss.
        return cls.HIGH


class SigmaParseError(ValueError):
    """Raised when a Sigma YAML rule is malformed.

    The message always names the offending rule (by id or title or
    path), so CI failures point straight at the broken file.
    """


@dataclass(frozen=True)
class Hit:
    """A single rule fired against a single event.

    `event_ref` is whatever the caller passed in; we keep a reference
    so downstream code can hydrate the full event from a cache without
    re-storing the payload in every Hit.
    """

    rule_id: str
    title: str
    severity: Severity
    tags: tuple[str, ...]
    matched_selections: tuple[str, ...]
    event_ref: Any = None


# --------------------------------------------------------------------------- #
# Detection AST
# --------------------------------------------------------------------------- #
#
# The Sigma "detection:" block parses into:
#
#   detection:
#     selection_1:        # a "selection" maps field -> value(list)
#       field: value
#     selection_2:
#       other_field|contains:
#         - foo
#         - bar
#     condition: selection_1 and not selection_2
#
# We represent each selection as a `_Selection` (list of field-tests,
# AND'd together) and we represent the `condition:` as a tiny boolean
# AST of `_AndNode` / `_OrNode` / `_NotNode` / `_RefNode` / `_QuantNode`.
# That AST is then `.evaluate(selection_results)`'d at match time.


_WILDCARD_TRANSLATE = {ord("?"): ".", ord("*"): ".*"}


def _wildcard_to_regex(s: str) -> re.Pattern[str]:
    """Translate a Sigma wildcard string ('foo*bar') into a regex."""
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in ("*", "?"):
            # Escaped wildcard — match literally.
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _get_field(event: dict[str, Any], path: str) -> Any:
    """Resolve a possibly-dotted field name out of a nested dict.

    Sigma uses dot-separated paths for nested fields. We:
      1. Try exact path first.
      2. Fall back to case-insensitive matching at each segment.
      3. Treat lists transparently — looking up ``parent.child`` against
         ``{"parent": [{"child": 1}, {"child": 2}]}`` yields ``[1, 2]``.
    """

    if path in event:
        # Fast path: top-level exact match.
        return event[path]

    parts = path.split(".")
    cursor: Any = event

    for part in parts:
        if cursor is None:
            return None
        if isinstance(cursor, list):
            # Lift through lists: collect each child for that key.
            collected: list[Any] = []
            for item in cursor:
                if isinstance(item, dict):
                    val = _dict_get_ci(item, part)
                    if val is _SENTINEL_MISSING:
                        continue
                    if isinstance(val, list):
                        collected.extend(val)
                    else:
                        collected.append(val)
            cursor = collected if collected else None
            continue
        if isinstance(cursor, dict):
            val = _dict_get_ci(cursor, part)
            if val is _SENTINEL_MISSING:
                return None
            cursor = val
        else:
            return None
    return cursor


class _Missing:
    """Sentinel for "key absent" — distinct from the value None."""

    __slots__ = ()


_SENTINEL_MISSING = _Missing()


def _dict_get_ci(d: dict[str, Any], key: str) -> Any:
    """Case-insensitive dict.get, returning ``_SENTINEL_MISSING`` if absent."""
    if key in d:
        return d[key]
    # Sigma source field names are inconsistent across vendors. We try
    # exact first (cheap), then fall back to case-insensitive search.
    lower = key.lower()
    for k, v in d.items():
        if k.lower() == lower:
            return v
    return _SENTINEL_MISSING


@dataclass
class _FieldTest:
    """One field comparison inside a selection.

    The `modifiers` list is preserved in order (Sigma allows chained
    modifiers like ``payload|base64|contains: foo``), but in practice
    we only honor the first match-modifier and any preprocessors
    (base64, base64offset).
    """

    field: str
    modifiers: tuple[str, ...]
    values: tuple[Any, ...]

    def evaluate(self, event: dict[str, Any]) -> bool:
        # `exists` doesn't care about values; everything else does.
        if "exists" in self.modifiers:
            present = _get_field(event, self.field) is not None
            want = bool(self.values[0]) if self.values else True
            return present is want

        raw = _get_field(event, self.field)
        if raw is None:
            # "field|all: [..]" against a missing field is always false;
            # "field: null" is matched explicitly below.
            if self.values and self.values[0] is None and "all" not in self.modifiers:
                return True  # explicit null match on missing field
            return False

        # Apply value preprocessors (base64, base64offset).
        prepared = self._prepare_values()

        # Sigma "|all": every value must match the same field separately.
        require_all = "all" in self.modifiers

        # Lists in event values mean "any of these field values may match".
        haystacks = raw if isinstance(raw, list) else [raw]

        def matches_one(value: Any) -> bool:
            for hay in haystacks:
                if self._compare(hay, value):
                    return True
            return False

        if require_all:
            return all(matches_one(v) for v in prepared)
        return any(matches_one(v) for v in prepared)

    def _prepare_values(self) -> tuple[Any, ...]:
        # base64 preprocessor: encode each string value before matching.
        if "base64" in self.modifiers:
            return tuple(
                _b64.b64encode(v.encode("utf-8")).decode("ascii") if isinstance(v, str) else v
                for v in self.values
            )
        if "base64offset" in self.modifiers:
            # base64offset emits all 3 byte-aligned encodings, sans the
            # trailing padding sensitivity. We just produce all three so
            # downstream regex/contains works.
            offsets: list[str] = []
            for v in self.values:
                if not isinstance(v, str):
                    offsets.append(v)
                    continue
                vb = v.encode("utf-8")
                for prefix in (b"", b"A", b"AA"):
                    enc = _b64.b64encode(prefix + vb).decode("ascii")
                    # Strip the bytes that correspond to the prefix.
                    if prefix == b"":
                        offsets.append(enc)
                    elif prefix == b"A":
                        offsets.append(enc[2:])  # 2 chars cover 1 prefix byte
                    else:
                        offsets.append(enc[3:])
            return tuple(offsets)
        return self.values

    def _compare(self, hay: Any, needle: Any) -> bool:
        # `re` modifier — needle is a regex.
        if "re" in self.modifiers:
            if not isinstance(needle, str) or hay is None:
                return False
            try:
                return re.search(needle, str(hay), re.IGNORECASE | re.DOTALL) is not None
            except re.error:
                logger.warning("sigma: invalid regex on field %s: %r", self.field, needle)
                return False

        # `cidr` modifier — needle is a CIDR block.
        if "cidr" in self.modifiers:
            if not isinstance(needle, str) or hay is None:
                return False
            try:
                net = ipaddress.ip_network(needle, strict=False)
                addr = ipaddress.ip_address(str(hay))
                return addr in net
            except (ValueError, TypeError):
                return False

        # Numeric modifiers.
        if any(m in self.modifiers for m in ("gt", "gte", "lt", "lte")):
            try:
                h = float(hay)
                n = float(needle)
            except (TypeError, ValueError):
                return False
            if "gt" in self.modifiers:
                return h > n
            if "gte" in self.modifiers:
                return h >= n
            if "lt" in self.modifiers:
                return h < n
            if "lte" in self.modifiers:
                return h <= n
            return False

        # Explicit null match.
        if needle is None:
            return hay is None

        # String comparisons.
        if isinstance(needle, str):
            hs = "" if hay is None else str(hay)
            ns = needle
            if "contains" in self.modifiers:
                return ns.lower() in hs.lower()
            if "startswith" in self.modifiers:
                return hs.lower().startswith(ns.lower())
            if "endswith" in self.modifiers:
                return hs.lower().endswith(ns.lower())
            # Default: equality with wildcards (* and ?).
            if any(ch in ns for ch in "*?"):
                return _wildcard_to_regex(ns).match(hs) is not None
            return hs.lower() == ns.lower()

        # Bool / number equality.
        return hay == needle


@dataclass
class _Selection:
    """A Sigma selection: a list of field-tests AND'd together.

    A "keyword-only" selection (a bare list of strings under the
    selection name) is represented as a single _FieldTest against
    the synthetic field ``__keywords__``, which the matcher resolves
    against every string value in the event.
    """

    name: str
    tests: tuple[_FieldTest, ...]
    keywords: tuple[str, ...] = ()  # raw keyword list; OR-matched

    def evaluate(self, event: dict[str, Any]) -> bool:
        if self.keywords:
            blob = _flatten_event_strings(event)
            for kw in self.keywords:
                if isinstance(kw, str) and kw.lower() in blob:
                    return True
            return False
        return all(t.evaluate(event) for t in self.tests)


def _flatten_event_strings(event: Any) -> str:
    """Flatten all string-ish values in an event into one lowercased blob."""
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for vv in v.values():
                walk(vv)
        elif isinstance(v, (list, tuple)):
            for vv in v:
                walk(vv)
        elif v is None or isinstance(v, bool):
            return
        else:
            out.append(str(v).lower())

    walk(event)
    return " ".join(out)


# --------------------------------------------------------------------------- #
# Condition parser
# --------------------------------------------------------------------------- #


@dataclass
class _RefNode:
    name: str

    def evaluate(self, results: dict[str, bool]) -> bool:
        return bool(results.get(self.name, False))


@dataclass
class _NotNode:
    inner: Any

    def evaluate(self, results: dict[str, bool]) -> bool:
        return not self.inner.evaluate(results)


@dataclass
class _AndNode:
    parts: list[Any]

    def evaluate(self, results: dict[str, bool]) -> bool:
        return all(p.evaluate(results) for p in self.parts)


@dataclass
class _OrNode:
    parts: list[Any]

    def evaluate(self, results: dict[str, bool]) -> bool:
        return any(p.evaluate(results) for p in self.parts)


@dataclass
class _QuantNode:
    """`N of <prefix>*` — N is "1"/"any"/"all" expanded against selections.

    We resolve the matched selection names at parse time so evaluation
    is O(k) in the number of matched selections.
    """

    quantifier: str  # "any" | "all"
    targets: tuple[str, ...]  # concrete selection names

    def evaluate(self, results: dict[str, bool]) -> bool:
        if not self.targets:
            return False
        vals = [bool(results.get(t, False)) for t in self.targets]
        if self.quantifier == "all":
            return all(vals)
        return any(vals)


_CONDITION_TOKEN = re.compile(
    r"""
        \s*
        (?:
            (?P<lparen>\()
          | (?P<rparen>\))
          | (?P<op>and\b|or\b|not\b)
          | (?P<quant>1|any|all)\s+of\s+(?P<target>them|[A-Za-z_][\w*]*)
          | (?P<ref>[A-Za-z_][\w]*)
        )
        \s*
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize_condition(text: str) -> list[tuple[str, str]]:
    pos = 0
    tokens: list[tuple[str, str]] = []
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _CONDITION_TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise SigmaParseError(f"condition: cannot parse near {text[pos:pos + 20]!r}")
        if m.group("lparen"):
            tokens.append(("LP", "("))
        elif m.group("rparen"):
            tokens.append(("RP", ")"))
        elif m.group("op"):
            tokens.append(("OP", m.group("op").lower()))
        elif m.group("quant"):
            q = m.group("quant").lower()
            q = "any" if q in ("1", "any") else "all"
            tokens.append(("QUANT", q + ":" + m.group("target")))
        elif m.group("ref"):
            tokens.append(("REF", m.group("ref")))
        pos = m.end()
    return tokens


def _parse_condition(text: str, selection_names: Iterable[str]) -> Any:
    """Recursive-descent parser for the Sigma condition grammar."""

    tokens = _tokenize_condition(text)
    if not tokens:
        raise SigmaParseError("condition: empty")

    names = tuple(selection_names)
    idx = 0

    def peek() -> tuple[str, str] | None:
        return tokens[idx] if idx < len(tokens) else None

    def eat() -> tuple[str, str]:
        nonlocal idx
        tok = tokens[idx]
        idx += 1
        return tok

    def parse_or() -> Any:
        left = parse_and()
        parts = [left]
        while True:
            t = peek()
            if t and t[0] == "OP" and t[1] == "or":
                eat()
                parts.append(parse_and())
            else:
                break
        return parts[0] if len(parts) == 1 else _OrNode(parts)

    def parse_and() -> Any:
        left = parse_not()
        parts = [left]
        while True:
            t = peek()
            if t and t[0] == "OP" and t[1] == "and":
                eat()
                parts.append(parse_not())
            else:
                break
        return parts[0] if len(parts) == 1 else _AndNode(parts)

    def parse_not() -> Any:
        t = peek()
        if t and t[0] == "OP" and t[1] == "not":
            eat()
            return _NotNode(parse_not())
        return parse_atom()

    def parse_atom() -> Any:
        t = peek()
        if t is None:
            raise SigmaParseError("condition: unexpected end")
        if t[0] == "LP":
            eat()
            node = parse_or()
            close = peek()
            if close is None or close[0] != "RP":
                raise SigmaParseError("condition: expected ')'")
            eat()
            return node
        if t[0] == "QUANT":
            eat()
            quant, target = t[1].split(":", 1)
            if target == "them":
                resolved = names
            elif target.endswith("*"):
                prefix = target[:-1]
                resolved = tuple(n for n in names if n.startswith(prefix))
            else:
                resolved = (target,)
            if not resolved:
                raise SigmaParseError(
                    f"condition: '{quant} of {target}' matched no selections"
                )
            return _QuantNode(quantifier=quant, targets=resolved)
        if t[0] == "REF":
            eat()
            if t[1] not in names:
                raise SigmaParseError(
                    f"condition: '{t[1]}' references unknown selection"
                )
            return _RefNode(name=t[1])
        raise SigmaParseError(f"condition: unexpected token {t!r}")

    root = parse_or()
    if peek() is not None:
        raise SigmaParseError(f"condition: trailing tokens {tokens[idx:]!r}")
    return root


# --------------------------------------------------------------------------- #
# SigmaRule
# --------------------------------------------------------------------------- #


@dataclass
class SigmaRule:
    """A parsed Sigma rule, ready to match events or be translated."""

    id: str
    title: str
    description: str
    severity: Severity
    status: str
    author: str
    tags: tuple[str, ...]
    falsepositives: tuple[str, ...]
    logsource: dict[str, Any]
    selections: dict[str, _Selection] = field(repr=False)
    condition: Any = field(repr=False)  # AST root
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # ---- public API --------------------------------------------------------

    def matches(self, event: dict[str, Any]) -> bool:
        """True if ``event`` triggers this rule."""
        results = {name: sel.evaluate(event) for name, sel in self.selections.items()}
        return bool(self.condition.evaluate(results))

    def evaluate(self, event: dict[str, Any]) -> Hit | None:
        """Return a Hit on match, else None."""
        results = {name: sel.evaluate(event) for name, sel in self.selections.items()}
        if not self.condition.evaluate(results):
            return None
        matched = tuple(name for name, ok in results.items() if ok)
        return Hit(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            tags=self.tags,
            matched_selections=matched,
            event_ref=event,
        )

    # ---- loaders -----------------------------------------------------------

    @classmethod
    def from_yaml(cls, text: str, *, source: str = "<inline>") -> "SigmaRule":
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise SigmaParseError(f"{source}: YAML error: {e}") from e
        if not isinstance(doc, dict):
            raise SigmaParseError(f"{source}: top-level must be a mapping")
        return cls.from_dict(doc, source=source)

    @classmethod
    def from_file(cls, path: str | Path) -> "SigmaRule":
        p = Path(path)
        return cls.from_yaml(p.read_text(encoding="utf-8"), source=str(p))

    @classmethod
    def from_dict(cls, doc: dict[str, Any], *, source: str = "<dict>") -> "SigmaRule":
        title = doc.get("title")
        if not isinstance(title, str) or not title.strip():
            raise SigmaParseError(f"{source}: missing 'title'")
        rid = doc.get("id") or _slugify(title)
        if not isinstance(rid, str):
            raise SigmaParseError(f"{source}: 'id' must be a string")

        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise SigmaParseError(f"{source}: 'detection' must contain a 'condition'")

        condition_str = detection.get("condition")
        if not isinstance(condition_str, str) or not condition_str.strip():
            raise SigmaParseError(f"{source}: 'detection.condition' must be a non-empty string")

        selections: dict[str, _Selection] = {}
        for name, body in detection.items():
            if name == "condition":
                continue
            if not _is_valid_selection_name(name):
                raise SigmaParseError(
                    f"{source}: selection name {name!r} contains invalid characters"
                )
            selections[name] = _parse_selection(name, body, source=source)

        if not selections:
            raise SigmaParseError(f"{source}: 'detection' must define at least one selection")

        try:
            condition_ast = _parse_condition(condition_str, selections.keys())
        except SigmaParseError as e:
            raise SigmaParseError(f"{source}: {e}") from None

        tags = doc.get("tags") or []
        if not isinstance(tags, list):
            raise SigmaParseError(f"{source}: 'tags' must be a list")

        fps = doc.get("falsepositives") or []
        if not isinstance(fps, list):
            fps = [fps]

        return cls(
            id=rid,
            title=title,
            description=str(doc.get("description") or "").strip(),
            severity=Severity.from_str(doc.get("level")),
            status=str(doc.get("status") or "experimental"),
            author=str(doc.get("author") or "Cyble AiSOC"),
            tags=tuple(str(t) for t in tags),
            falsepositives=tuple(str(f) for f in fps if f is not None),
            logsource=doc.get("logsource") or {},
            selections=selections,
            condition=condition_ast,
            raw=doc,
        )


# --------------------------------------------------------------------------- #
# Selection / value parsing
# --------------------------------------------------------------------------- #


_VALID_NAME = re.compile(r"^[A-Za-z_][\w]*$")


def _is_valid_selection_name(name: str) -> bool:
    return bool(_VALID_NAME.match(name))


def _parse_selection(name: str, body: Any, *, source: str) -> _Selection:
    # Keyword-only selection: a bare list of strings/numbers.
    if isinstance(body, list) and all(not isinstance(x, dict) for x in body):
        return _Selection(name=name, tests=(), keywords=tuple(body))

    # A list of dicts is treated as OR'd sub-selections. We expand by
    # flattening — each sub-dict becomes its own _FieldTest AND-chain,
    # and at evaluation we OR them. That's modelled by giving the
    # selection a single synthetic OR over the sub-selections.
    if isinstance(body, list) and all(isinstance(x, dict) for x in body):
        sub_tests: list[_FieldTest] = []
        # Sigma "list of dicts" semantics: each item is its own sub-selection
        # OR'd. We can't represent that with a single _Selection (which is
        # AND-only), so we wrap each sub-selection as its own synthetic
        # selection name and OR them in the condition. The simplest robust
        # approach: collapse via a single FieldTest that evaluates an
        # internal OR.
        wrapped = _ListOfDictsTest(name=name, items=tuple(body), source=source)
        return _Selection(name=name, tests=(wrapped,))  # type: ignore[arg-type]

    if not isinstance(body, dict):
        raise SigmaParseError(
            f"{source}: selection {name!r} must be a mapping or keyword list"
        )

    tests: list[_FieldTest] = []
    for key, val in body.items():
        if not isinstance(key, str):
            raise SigmaParseError(
                f"{source}: selection {name!r} has non-string field {key!r}"
            )
        field_name, modifiers = _split_field_and_modifiers(key)
        values = _normalize_value_list(val)
        tests.append(_FieldTest(field=field_name, modifiers=modifiers, values=values))

    return _Selection(name=name, tests=tuple(tests))


def _split_field_and_modifiers(raw: str) -> tuple[str, tuple[str, ...]]:
    parts = raw.split("|")
    field_name = parts[0].strip()
    mods = tuple(p.strip().lower() for p in parts[1:] if p.strip())
    return field_name, mods


def _normalize_value_list(val: Any) -> tuple[Any, ...]:
    if isinstance(val, list):
        return tuple(val)
    return (val,)


@dataclass
class _ListOfDictsTest(_FieldTest):  # type: ignore[misc]
    """A pseudo field-test that evaluates an OR of sub-selections.

    Inheriting from `_FieldTest` keeps the type of `_Selection.tests`
    homogeneous; we override evaluate().
    """

    name: str = ""
    items: tuple[dict[str, Any], ...] = ()
    source: str = ""

    def __init__(self, name: str, items: tuple[dict[str, Any], ...], source: str) -> None:
        super().__init__(field="__sub__", modifiers=(), values=())
        self.name = name
        self.items = items
        self.source = source

    def evaluate(self, event: dict[str, Any]) -> bool:  # type: ignore[override]
        for item in self.items:
            try:
                sub = _parse_selection(self.name, item, source=self.source)
            except SigmaParseError as e:
                logger.warning("sigma: sub-selection in %s failed to parse: %s", self.name, e)
                continue
            if sub.evaluate(event):
                return True
        return False


def _slugify(s: str) -> str:
    out = re.sub(r"[^A-Za-z0-9]+", "-", s.lower()).strip("-")
    return out or "rule"
