#!/usr/bin/env python3
"""Render AiSOC native rules out to SPL, KQL, EQL and AQL (WS1.5).

The mirror of :mod:`inbound`, bound by one contract that decides every
design choice here: **outbound then inbound must reproduce the same rule.**
A rendering the inbound half cannot read back identically is not a
translation, it is a one-way export wearing a translation's name — the
almost-right class inbound's own docstring refuses.

That contract pins the carryable subset to what inbound parses:

* operators ``eq`` (bare), ``neq``, ``gt``, ``gte``, ``lt``, ``lte``;
* scalar values (strings, numbers, booleans).

Everything else **refuses with its reason**, including operators the
target dialect could technically express: SPL can say ``contains`` as
``field=*value*``, but inbound reads a wildcard back as the literal
string ``*value*``, so the roundtrip would silently change the rule's
meaning — exactly the defect the refusal exists to prevent. When the
inbound parser grows an operator, the subset here widens with it, and the
roundtrip suite is what proves the pair stays a pair.

AQL is render-only: inbound does not parse AQL, so AQL output carries a
note saying the roundtrip proof does not cover it — stated rather than
implied, because "translated" and "translated and provable" are different
claims.

Threshold/windowed native rules refuse entirely: inbound deliberately
marks aggregation down to PARTIAL on the way in, so a rendered
``stats``/``summarize`` could never roundtrip clean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["OUTBOUND_DIALECTS", "Rendering", "render"]

OUTBOUND_DIALECTS = ("spl", "kql", "eql", "aql")

#: The operator subset the roundtrip contract can prove. Key: the native
#: matcher suffix (empty string = bare equality). Value: per-dialect
#: rendering, or None where that dialect cannot carry it parseably.
_CARRYABLE: dict[str, dict[str, str | None]] = {
    "": {"spl": "{f}={v}", "kql": "{f} == {v}", "eql": "{f} == {v}", "aql": "{f} = {v}"},
    "_neq": {"spl": "{f}!={v}", "kql": "{f} != {v}", "eql": "{f} != {v}", "aql": "{f} != {v}"},
    "_gt": {"spl": "{f}>{v}", "kql": "{f} > {v}", "eql": "{f} > {v}", "aql": "{f} > {v}"},
    "_gte": {"spl": "{f}>={v}", "kql": "{f} >= {v}", "eql": "{f} >= {v}", "aql": "{f} >= {v}"},
    "_lt": {"spl": "{f}<{v}", "kql": "{f} < {v}", "eql": "{f} < {v}", "aql": "{f} < {v}"},
    "_lte": {"spl": "{f}<={v}", "kql": "{f} <= {v}", "eql": "{f} <= {v}", "aql": "{f} <= {v}"},
}

#: Native operator suffixes outbound recognises but refuses, each with the
#: roundtrip reason. Longest-first so `_not_contains_any` is not eaten by
#: `_contains`.
_REFUSED_SUFFIXES: tuple[tuple[str, str], ...] = tuple(
    sorted(
        {
            "_pattern_match_any": "regex alternation does not read back as itself through the inbound field parser",
            "_not_startswith_any": "negated wildcard lists read back as literals",
            "_not_endswith_any": "negated wildcard lists read back as literals",
            "_not_contains_any": "negated wildcard lists read back as literals",
            "_pattern_match": "a regex does not read back as itself through the inbound field parser",
            "_not_startswith": "a negated wildcard reads back as a literal",
            "_not_endswith": "a negated wildcard reads back as a literal",
            "_startswith_any": "wildcard lists read back as literals",
            "_endswith_any": "wildcard lists read back as literals",
            "_contains_any": "wildcard lists read back as literals",
            "_contains_all": "wildcard lists read back as literals",
            "_startswith": (
                "SPL/KQL can say it as a wildcard or prefix call, but inbound reads that "
                "back as a literal string — the roundtrip would change the rule's meaning"
            ),
            "_match_any": "value lists need IN, which inbound does not parse back",
            "_endswith": "a wildcard reads back as a literal",
            "_contains": (
                "SPL can say it as field=*value*, but inbound reads a wildcard back as "
                "the literal *value* — the roundtrip would change the rule's meaning"
            ),
            "_has_any": "list-membership has no scalar rendering",
            "_not_in": "value lists need NOT IN, which inbound does not parse back",
            "_match": "a regex does not read back as itself",
            "_in": "value lists need IN, which inbound does not parse back",
        }.items(),
        key=lambda item: -len(item[0]),
    )
)

_SAFE_FIELD = re.compile(r"^[A-Za-z_][\w.]*$")

#: SPL routing fields inbound DROPS on the way back in; a rule naming one
#: outbound would silently lose that clause on the roundtrip.
_SPL_ROUTING = {"index", "sourcetype", "source", "host"}


@dataclass
class Rendering:
    dialect: str
    rule_id: str
    confidence: str = "none"  # none | roundtrip | render_only
    query: str = ""
    unsupported: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return bool(self.query) and self.confidence != "none"

    def as_dict(self) -> dict[str, Any]:
        return {
            "dialect": self.dialect,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "usable": self.usable,
            "query": self.query,
            "unsupported": self.unsupported,
            "notes": self.notes,
        }


def _split(key: str) -> tuple[str, str] | tuple[None, str]:
    """(field, suffix) for a carryable key, (None, reason) for a refused one."""
    for suffix, reason in _REFUSED_SUFFIXES:
        if key.endswith(suffix):
            return None, f"`{key}` — {reason}"
    for suffix in sorted((s for s in _CARRYABLE if s), key=len, reverse=True):
        if key.endswith(suffix):
            return key[: -len(suffix)], suffix
    return key, ""


def _value(value: Any, dialect: str) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if any(ch in value for ch in "*?\"'\\"):
            return None  # a wildcard or quote would not read back as itself
        return f'"{value}"'
    return None


def render(rule: dict[str, Any], dialect: str) -> Rendering:
    """Render one native rule, or refuse and say exactly what stopped it."""
    dialect = str(dialect or "").strip().lower()
    out = Rendering(dialect=dialect, rule_id=str(rule.get("id") or ""))
    if dialect not in OUTBOUND_DIALECTS:
        out.notes.append(f"unknown dialect {dialect!r}; expected one of {list(OUTBOUND_DIALECTS)}")
        return out

    if rule.get("threshold") or rule.get("window_seconds") or rule.get("sequence"):
        out.unsupported.append(
            "threshold/window/sequence — inbound marks aggregation down to PARTIAL on the way "
            "in, so a rendered stats/summarize could never roundtrip clean; translate the "
            "windowed form by hand against the target engine's own windowing"
        )
        return out

    match_when = rule.get("match_when")
    if not isinstance(match_when, dict) or not match_when:
        out.notes.append("the rule carries no match_when; nothing to render")
        return out

    clauses: list[str] = []
    for key, value in match_when.items():
        split_field, suffix_or_reason = _split(str(key))
        if split_field is None:
            out.unsupported.append(suffix_or_reason)
            continue
        if not _SAFE_FIELD.match(split_field):
            out.unsupported.append(f"`{key}` — field name does not render safely")
            continue
        if dialect == "spl" and split_field.lower() in _SPL_ROUTING:
            out.unsupported.append(
                f"`{split_field}` — a Splunk routing field; inbound drops it on the way back, "
                "so the roundtrip would silently lose this clause"
            )
            continue
        template = _CARRYABLE[suffix_or_reason][dialect]
        if template is None:  # pragma: no cover — every current subset op renders in all four
            out.unsupported.append(f"`{key}` — {dialect} cannot carry this operator parseably")
            continue
        rendered_value = _value(value, dialect)
        if rendered_value is None:
            out.unsupported.append(
                f"`{key}` — the value {value!r} contains wildcard or quote characters that would not read back as themselves"
            )
            continue
        clauses.append(template.format(f=split_field, v=rendered_value))

    if out.unsupported:
        # One refused clause refuses the rule: a rendering missing a clause
        # matches MORE than the original, which is the almost-right failure.
        out.query = ""
        out.notes.append("refused rather than approximated: a rendering missing a clause matches more than the original rule")
        return out
    if not clauses:
        out.notes.append("no clauses survived rendering")
        return out

    joiner = {"spl": " ", "kql": " and ", "eql": " and ", "aql": " AND "}[dialect]
    body = joiner.join(clauses)
    if dialect == "spl":
        out.query = f"search {body}"
    elif dialect == "kql":
        out.query = body
    elif dialect == "eql":
        out.query = f"any where {body}"
    else:  # aql
        out.query = f"SELECT * FROM events WHERE {body}"

    if dialect == "aql":
        out.confidence = "render_only"
        out.notes.append(
            "AQL is render-only: inbound does not parse AQL, so the roundtrip proof does not "
            "cover this dialect — 'translated' and 'translated and provable' are different claims"
        )
    else:
        out.confidence = "roundtrip"
    return out
