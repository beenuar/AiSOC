#!/usr/bin/env python3
"""Compile Sigma correlation rules into the windowed engine's form.

Specification: https://github.com/SigmaHQ/sigma-specification — "Sigma
Correlations", the ``correlation:`` document type. Read before writing this;
every field name and correlation type below is taken from it rather than
guessed.

What the engine can and cannot express
--------------------------------------
The windowed engine counts events or distinct values for one entity over a
sliding window, and stages ordered or unordered sets of events for one entity
over a sliding window. That covers four of Sigma's correlation types:

``event_count``       → a counting rule.
``value_count``       → a counting rule with ``distinct_by``.
``temporal``          → an unordered staged rule.
``temporal_ordered``  → an ordered staged rule.

It does not cover the rest, and the rule here is **refuse rather than
approximate**. A correlation that is translated with one of its constraints
dropped is a different detection shipping under the original's name and
severity, which is the specific failure the windowed translation work in
depth plan 3.1 existed to stop. Every refusal carries a reason, and the
refusals are counted and published the same way the Sigma compiler's are.

The two refusals worth knowing about in advance, because they look like
oversights:

* **A ``lt`` / ``lte`` condition is a rarity signal.** "Fewer than five in an
  hour" fires when nothing much happened, so it needs a store of what is
  normal rather than a counter. The engine fires when a count is high.
* **A multi-field ``group-by`` has no single entity.** The engine accumulates
  against one field. Picking the first would group by something the rule
  author did not ask for and silently widen or narrow every count.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

__all__ = [
    "CORRELATION_TYPES",
    "CorrelationRefusal",
    "compile_correlation",
    "parse_timespan",
]

#: Correlation types this compiler accepts, mapped to the shape they become.
CORRELATION_TYPES: dict[str, str] = {
    "event_count": "counting",
    "value_count": "counting",
    "temporal": "staged",
    "temporal_ordered": "staged",
}

R_UNKNOWN_TYPE = "correlation type is not one this engine can express"
R_CONDITION_SHAPE = "the condition is not a single comparison the engine can threshold"
R_RARITY = "a `lt`/`lte` condition fires when a count is low, which needs a baseline rather than a counter"
R_EQ = "an `eq` condition fires on an exact count, and a sliding window cannot hold a count still"
R_MULTI_GROUP = "`group-by` names more than one field and the engine accumulates against one entity"
R_NO_GROUP = "`group-by` is absent, so the count has no entity and would be global"
R_TIMESPAN = "`timespan` is missing or not a Sigma duration"
R_NO_RULES = "`rules` names no referenced rule"
R_UNRESOLVED = "a referenced rule is not in the corpus or did not compile"
R_ONE_STAGE = "a temporal correlation over a single rule is a plain count, not a sequence"
R_VALUE_FIELD = "`value_count` needs a `field` naming what to count distinctly"
R_ALIASES = "`aliases` map different field names across referenced rules and the engine has no aliasing"
R_GENERATE = "`generate: true` also emits the referenced rules, which this path does not model"
R_CHAINED = "the correlation references another correlation, which the engine cannot stage"

#: Sigma duration suffixes, from the specification.
_UNITS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class CorrelationRefusal(Exception):
    """This correlation cannot be expressed without changing what it detects."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}{f' ({detail})' if detail else ''}")
        self.reason = reason
        self.detail = detail


def parse_timespan(raw: Any) -> int:
    """Sigma duration (``5m``, ``1h``, ``30s``) to seconds."""
    text = str(raw or "").strip()
    if len(text) < 2 or text[-1] not in _UNITS or not text[:-1].isdigit():
        raise CorrelationRefusal(R_TIMESPAN, text or "absent")
    seconds = int(text[:-1]) * _UNITS[text[-1]]
    if seconds < 1:
        raise CorrelationRefusal(R_TIMESPAN, text)
    return seconds


@dataclass(frozen=True)
class _Condition:
    operator: str
    value: int


def _parse_condition(block: Any, correlation_type: str) -> _Condition:
    """The ``condition:`` mapping, which Sigma writes as one comparison."""
    if not isinstance(block, dict) or len(block) != 1:
        raise CorrelationRefusal(R_CONDITION_SHAPE, repr(block))
    ((operator, value),) = block.items()
    operator = str(operator).lower()
    if operator in {"lt", "lte"}:
        raise CorrelationRefusal(R_RARITY, f"{operator}: {value}")
    if operator == "eq":
        raise CorrelationRefusal(R_EQ, f"eq: {value}")
    if operator not in {"gt", "gte"}:
        raise CorrelationRefusal(R_CONDITION_SHAPE, operator)
    try:
        bound = int(value)
    except (TypeError, ValueError) as exc:
        raise CorrelationRefusal(R_CONDITION_SHAPE, f"{operator}: {value!r}") from exc
    if bound < 0:
        raise CorrelationRefusal(R_CONDITION_SHAPE, f"{operator}: {bound}")
    # `correlation_type` is carried so a later type with different threshold
    # semantics cannot silently reuse this.
    del correlation_type
    return _Condition(operator=operator, value=bound)


def _group_by(block: Any) -> str:
    fields = block if isinstance(block, list) else [block] if block else []
    names = [str(f) for f in fields if str(f or "").strip()]
    if not names:
        raise CorrelationRefusal(R_NO_GROUP)
    if len(names) > 1:
        raise CorrelationRefusal(R_MULTI_GROUP, ", ".join(names))
    return names[0]


def _referenced(block: dict[str, Any]) -> list[str]:
    """`rules:` lives inside the correlation block, per the specification."""
    raw = block.get("rules")
    names = [str(r) for r in (raw if isinstance(raw, list) else [raw] if raw else []) if str(r or "").strip()]
    if not names:
        raise CorrelationRefusal(R_NO_RULES)
    return names


def compile_correlation(
    doc: dict[str, Any],
    *,
    selectors: dict[str, dict[str, Any]],
    correlations: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """One Sigma correlation document to one windowed rule.

    ``selectors`` maps a referenced rule's name (or id) to the ``match_when``
    it compiled to. A correlation whose referenced rule is missing is refused
    rather than compiled against an empty selector — an empty selector
    matches every event, so that refusal is the difference between a rule and
    an outage.
    """
    block = doc.get("correlation")
    if not isinstance(block, dict):
        raise CorrelationRefusal(R_UNKNOWN_TYPE, "no correlation block")

    correlation_type = str(block.get("type") or "").strip().lower()
    if correlation_type not in CORRELATION_TYPES:
        raise CorrelationRefusal(R_UNKNOWN_TYPE, correlation_type or "absent")
    if block.get("aliases"):
        raise CorrelationRefusal(R_ALIASES)
    if block.get("generate"):
        raise CorrelationRefusal(R_GENERATE)

    window_seconds = parse_timespan(block.get("timespan"))
    group_by = _group_by(block.get("group-by"))
    names = _referenced(block)
    if any(name in correlations for name in names):
        raise CorrelationRefusal(R_CHAINED, ", ".join(n for n in names if n in correlations))
    missing = [name for name in names if name not in selectors]
    if missing:
        raise CorrelationRefusal(R_UNRESOLVED, ", ".join(missing))

    common = {
        "id": str(doc.get("id") or "").strip(),
        "name": str(doc.get("title") or doc.get("name") or "").strip(),
        "severity": str(doc.get("level") or doc.get("severity") or "medium").strip().lower(),
        "category": str(doc.get("category") or "identity").strip().lower(),
        "mitre": sorted({str(t).upper().removeprefix("ATTACK.") for t in doc.get("tags") or [] if str(t).lower().startswith("attack.t")}),
        "group_by": group_by,
        "window_seconds": window_seconds,
        "correlation_type": correlation_type,
        "correlates": names,
    }
    if not common["id"] or not common["name"]:
        raise CorrelationRefusal(R_CONDITION_SHAPE, "the document has no id or title")

    if CORRELATION_TYPES[correlation_type] == "counting":
        if len(names) != 1:
            # Sigma allows several, meaning "events matching any of them".
            # The engine's `match_when` is one clause set, and an `any_of`
            # over compiled selectors is a faithful translation only when the
            # selectors are disjoint, which nothing here can establish.
            raise CorrelationRefusal(R_CONDITION_SHAPE, f"{correlation_type} over {len(names)} rules")
        condition = _parse_condition(block.get("condition"), correlation_type)
        rule: dict[str, Any] = {
            **common,
            "match_when": dict(selectors[names[0]]),
            # `gt: N` crosses at N+1; `gte: N` crosses at N.
            "threshold": condition.value + 1 if condition.operator == "gt" else condition.value,
        }
        if correlation_type == "value_count":
            field = str(block.get("field") or "").strip()
            if not field:
                raise CorrelationRefusal(R_VALUE_FIELD)
            rule["distinct_by"] = field
        if rule["threshold"] < 1:
            raise CorrelationRefusal(R_CONDITION_SHAPE, "threshold below one fires on the first event")
        return rule

    if len(names) < 2:
        raise CorrelationRefusal(R_ONE_STAGE, names[0])
    return {
        **common,
        "sequence": [dict(selectors[name]) for name in names],
        "ordered": correlation_type == "temporal_ordered",
    }
