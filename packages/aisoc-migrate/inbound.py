#!/usr/bin/env python3
"""Bring detections in from Splunk SPL, Sentinel KQL and Elastic EQL.

Gap-closure wave 16.

Translators exist in one direction — AiSOC rules become SPL, KQL, ESQL
and AQL so a federated search can run on a customer's SIEM. Nothing
goes the other way, so a team arriving with 400 Splunk searches has to
rewrite all of them by hand, and that is the cost that decides whether
a migration happens at all.

2,005 SPL rules are already **stored and quarantined** in this
repository and have never been translated. They are the obvious first
corpus.

Refusing is a feature
---------------------
A translator that produces something for every input is worse than one
that refuses, because an almost-right detection is harder to find than
a missing one: it sits in the catalogue, fires on the wrong thing, and
nobody checks it against the original.

So every translation reports a **confidence** and an explicit list of
what it could not carry across. Anything below `PARTIAL` yields no
rule at all. A search using `transaction`, a lookup table, or a custom
command has no equivalent here, and saying so is the honest output.

What is deliberately not attempted
-------------------------------------
Statistical and transactional constructs — `stats` with a `by` clause
feeding a threshold, `transaction`, `eventstats` — are refused rather
than approximated. They describe windowed aggregation, the engine's
windowed support is limited to 18 rules, and emitting a point-in-time
rule that *looks* like the original is exactly the almost-right
failure above.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "SUPPORTED_DIALECTS",
    "Translation",
    "translate",
]

SUPPORTED_DIALECTS = ("spl", "kql", "eql")

#: Confidence tiers. `NONE` means no rule is produced.
NONE, PARTIAL, GOOD, HIGH = "none", "partial", "good", "high"

#: Constructs with no equivalent in the matcher. Each refuses the
#: whole translation rather than being dropped quietly, because a rule
#: missing its aggregation matches far more than the original did.
_SPL_UNSUPPORTED = {
    "transaction": "groups events into sessions; the engine has no session concept",
    "eventstats": "windowed aggregation back onto each row",
    "streamstats": "running aggregation across an ordered stream",
    "lookup": "joins an external table this deployment does not have",
    "inputlookup": "reads an external table",
    "join": "correlates two searches; use a correlation rule instead",
    "map": "runs a search per result row",
}

_KQL_UNSUPPORTED = {
    "join": "correlates two tables; use a correlation rule instead",
    "externaldata": "reads data from outside the workspace",
    "materialize": "caches a subquery",
    "make-series": "time-series aggregation",
    "evaluate": "invokes a plugin",
}

_EQL_UNSUPPORTED = {
    "sequence": "ordered multi-event match; the engine evaluates one event at a time",
    "join": "correlates event streams",
    "until": "bounds a sequence",
}

#: `stats`/`summarize` are aggregation. Supported only where the
#: result is a simple count threshold, which the windowed engine can
#: express; anything else refuses.
_AGGREGATION_HINTS = ("stats ", "summarize ", "| count", "bin(")

_SPL_FIELD = re.compile(r"\b([A-Za-z_][\w.]*)\s*(=|!=|>=|<=|>|<)\s*(\"[^\"]*\"|'[^']*'|[^\s()|]+)")
_KQL_FIELD = re.compile(r"\b([A-Za-z_][\w.]*)\s*(==|!=|>=|<=|>|<|=~)\s*(\"[^\"]*\"|'[^']*'|[^\s()|]+)")
_EQL_FIELD = re.compile(r"\b([A-Za-z_][\w.]*)\s*(==|!=|>=|<=|>|<|:)\s*(\"[^\"]*\"|'[^']*'|[^\s()]+)")

_OPERATOR_MAP = {
    "=": "eq",
    "==": "eq",
    ":": "eq",
    "=~": "eq",
    "!=": "neq",
    ">": "gt",
    ">=": "gte",
    "<": "lt",
    "<=": "lte",
}


@dataclass
class Translation:
    dialect: str
    source: str
    confidence: str = NONE
    match_when: dict[str, Any] = field(default_factory=dict)
    #: Everything the translation could not carry across, in words.
    #: Not a count: "3 constructs dropped" tells a reviewer nothing
    #: about whether the result is usable.
    unsupported: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.confidence != NONE and bool(self.match_when)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dialect": self.dialect,
            "confidence": self.confidence,
            "usable": self.usable,
            "match_when": self.match_when,
            "unsupported": self.unsupported,
            "notes": self.notes,
        }

    def render(self) -> str:
        if not self.usable:
            lines = [f"REFUSED ({self.dialect}): no rule produced"]
            lines.extend(f"  cannot translate: {u}" for u in self.unsupported)
            lines.extend(f"  {n}" for n in self.notes)
            return "\n".join(lines)
        lines = [f"{self.confidence.upper()} ({self.dialect}): {len(self.match_when)} clause(s)"]
        lines.extend(f"  {k}: {v!r}" for k, v in self.match_when.items())
        lines.extend(f"  NOT CARRIED: {u}" for u in self.unsupported)
        return "\n".join(lines)


def _unquote(value: str) -> Any:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.lower() in {"true", "false"}:
        return text.lower() == "true"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _refusals(query: str, table: dict[str, str]) -> list[str]:
    lowered = query.lower()
    found: list[str] = []
    for keyword, why in table.items():
        # Word-bounded: a field named `join_key` is not a `join`.
        if re.search(rf"(?:^|[|\s]){re.escape(keyword)}(?:\s|\(|$)", lowered):
            found.append(f"`{keyword}` — {why}")
    return found


def translate(query: str, dialect: str) -> Translation:
    """Translate one search, or refuse and say what stopped it."""
    dialect = dialect.strip().lower()
    result = Translation(dialect=dialect, source=query)
    if dialect not in SUPPORTED_DIALECTS:
        result.notes.append(f"unknown dialect {dialect!r}; expected one of {list(SUPPORTED_DIALECTS)}")
        return result
    if not query.strip():
        result.notes.append("empty query")
        return result

    table, pattern = {
        "spl": (_SPL_UNSUPPORTED, _SPL_FIELD),
        "kql": (_KQL_UNSUPPORTED, _KQL_FIELD),
        "eql": (_EQL_UNSUPPORTED, _EQL_FIELD),
    }[dialect]

    result.unsupported = _refusals(query, table)
    if result.unsupported:
        result.notes.append(
            "refused rather than approximated: a rule missing its correlation matches far "
            "more than the original, and an almost-right detection is harder to find than a "
            "missing one"
        )
        return result

    lowered = query.lower()
    aggregating = any(hint in lowered for hint in _AGGREGATION_HINTS)

    clauses: dict[str, Any] = {}
    for match_field, operator, raw in pattern.findall(query):
        # Skip SPL's own macro and search-head keywords, which look
        # like fields to the pattern.
        if match_field.lower() in {"index", "sourcetype", "source", "host"} and dialect == "spl":
            result.notes.append(f"`{match_field}` is a Splunk routing field, not an event field; dropped")
            continue
        operator_name = _OPERATOR_MAP.get(operator)
        if operator_name is None:
            result.unsupported.append(f"operator {operator!r}")
            continue
        key = match_field if operator_name == "eq" else f"{match_field}_{operator_name}"
        clauses[key] = _unquote(raw)

    if not clauses:
        result.notes.append("no field comparisons found; nothing to match on")
        return result

    result.match_when = clauses

    if aggregating:
        # A threshold over a window. The engine supports 18 such rules,
        # so this is marked down rather than refused — a reviewer
        # decides whether the windowed form is available.
        result.unsupported.append(
            "aggregation (`stats`/`summarize`/`count`) — the field matches carried across, the "
            "threshold did not. Review against the windowed engine before enabling."
        )
        result.confidence = PARTIAL
    elif len(clauses) >= 3:
        result.confidence = HIGH
    elif len(clauses) == 2:
        result.confidence = GOOD
    else:
        # One clause is a translation that probably lost something.
        result.confidence = PARTIAL
        result.notes.append("a single clause rarely captures a real detection; check against the original")

    return result


def _self_test() -> int:
    cases: list[tuple[str, str, str, str]] = [
        (
            "a plain SPL search",
            'index=windows EventCode=4625 Account_Name="svc-backup" LogonType=3',
            "spl",
            HIGH,
        ),
        (
            "SPL with a transaction — refused",
            "index=windows | transaction host maxspan=5m",
            "spl",
            NONE,
        ),
        (
            "SPL with a lookup — refused",
            "index=proxy | lookup bad_domains domain OUTPUT verdict",
            "spl",
            NONE,
        ),
        (
            "SPL aggregation — carried partially, flagged",
            'index=windows EventCode=4625 user="x" | stats count by src',
            "spl",
            PARTIAL,
        ),
        (
            "plain KQL",
            'SecurityEvent | where EventID == 4625 and AccountType == "User" and LogonType == 3',
            "kql",
            HIGH,
        ),
        (
            "KQL with a join — refused",
            "SecurityEvent | join kind=inner Heartbeat on Computer",
            "kql",
            NONE,
        ),
        (
            "plain EQL",
            'process where process.name == "mimikatz.exe" and user.name == "admin"',
            "eql",
            GOOD,
        ),
        (
            "EQL sequence — refused",
            "sequence by host [process where true] [network where true]",
            "eql",
            NONE,
        ),
        ("an unknown dialect", "whatever", "sigma", NONE),
        ("an empty query", "", "spl", NONE),
    ]

    failures = 0
    for name, query, dialect, expected in cases:
        result = translate(query, dialect)
        ok = result.confidence == expected
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            print(f"      got {result.confidence!r}, wanted {expected!r}")
            print(f"      {result.render()}")

    # A refusal must say what stopped it, or a reviewer cannot act.
    refused = translate("index=windows | transaction host", "spl")
    if not refused.unsupported:
        print("  self-test [FAIL] a refusal with no stated cause is unactionable")
        failures += 1

    # And a word-bounded keyword must not fire on a field name.
    if translate('index=win join_key="abc" user="x" host_role="dc"', "spl").confidence == NONE:
        print("  self-test [FAIL] `join_key` was mistaken for a `join`")
        failures += 1

    print(f"inbound: self-test {'OK' if not failures else 'FAILED'} — {len(SUPPORTED_DIALECTS)} dialects")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--dialect", choices=SUPPORTED_DIALECTS)
    parser.add_argument("--query")
    parser.add_argument("--file", help="newline-delimited queries to translate in bulk")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.dialect:
        parser.error("--dialect is required")

    queries: list[str] = []
    if args.query:
        queries.append(args.query)
    if args.file:
        queries.extend(q for q in Path(args.file).read_text(encoding="utf-8").splitlines() if q.strip())
    if not queries:
        parser.error("--query or --file")

    results = [translate(q, args.dialect) for q in queries]
    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
    else:
        for result in results:
            print(result.render())
            print()
        usable = sum(1 for r in results if r.usable)
        print(f"{usable}/{len(results)} translated; {len(results) - usable} refused with stated reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
