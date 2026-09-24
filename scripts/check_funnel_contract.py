#!/usr/bin/env python3
"""Gate: every field the funnel endpoint returns is documented.

Eight fields shipped across v7.7 and v8.0 without reaching
`apps/docs/docs/console/funnel-kpis.md`. That matters more than a
documentation gap usually does, because of *which* eight: repeat-alert
suppression, abstention rate, ungrounded demotions and mean groundedness are
the fields that say whether the automation is working honestly. A number
nobody documents is a number nobody checks — and `repeat_alerts_suppressed`
reported a flat zero for an entire release without anyone noticing, because
the fingerprint bug meant no two alerts ever matched.

Parsed from the source rather than by importing the endpoint: the API
package pulls in SQLAlchemy, asyncpg, Neo4j and ClickHouse drivers, and a
documentation gate that needs a database container is a gate that gets
disabled.

Run:  python3 scripts/check_funnel_contract.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
METRICS = REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "metrics.py"
DOC = REPO_ROOT / "apps" / "docs" / "docs" / "console" / "funnel-kpis.md"

#: Functions whose returned dict keys form the funnel response. Named rather
#: than discovered, because the module has other endpoints whose fields do
#: not belong on this page.
CONTRIBUTING_FUNCTIONS = ("_funnel_window", "_triage_quality")

#: Keys that are internal plumbing rather than response fields: SQL bind
#: parameters and the like. Listed so the exemption is reviewable.
NOT_RESPONSE_FIELDS = frozenset(
    {
        "tid",
        "start",
        "end",
        "data",
        "count",
        "timestamp",
        "covered",
        "total",
        "ratio",
    }
)


def _function_body(source: str, name: str) -> str:
    """The text of one top-level function, up to the next one."""
    match = re.search(rf"^(?:async )?def {re.escape(name)}\(", source, re.M)
    if not match:
        return ""
    start = match.start()
    nxt = re.search(r"^(?:async )?def ", source[match.end() :], re.M)
    return source[start : match.end() + nxt.start()] if nxt else source[start:]


def response_fields() -> set[str]:
    source = METRICS.read_text(encoding="utf-8")
    fields: set[str] = set()
    for name in CONTRIBUTING_FUNCTIONS:
        body = _function_body(source, name)
        if not body:
            print(
                f"  warning: {name} not found in metrics.py; the contract may be " f"checked against an incomplete field list",
                file=sys.stderr,
            )
            continue
        # Keys of the returned dict literal.
        fields |= set(re.findall(r'^\s+"([a-z_]+)":', body, re.M))
    return fields - NOT_RESPONSE_FIELDS


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    if not METRICS.exists() or not DOC.exists():
        print("funnel-contract: metrics.py or funnel-kpis.md not found", file=sys.stderr)
        return 2

    fields = response_fields()
    if not fields:
        print(
            "funnel-contract: parsed zero response fields; the gate would pass " "vacuously",
            file=sys.stderr,
        )
        return 2

    doc = DOC.read_text(encoding="utf-8")
    undocumented = sorted(f for f in fields if f"`{f}`" not in doc and f'"{f}"' not in doc)

    if undocumented:
        print("FUNNEL CONTRACT GATE FAILED:", file=sys.stderr)
        print(
            f"  {len(undocumented)} field(s) returned by /metrics/funnel are not " f"documented in apps/docs/docs/console/funnel-kpis.md:",
            file=sys.stderr,
        )
        for field in undocumented:
            print(f"    {field}", file=sys.stderr)
        print(
            "  These are the numbers operators use to tell whether the automation " "is working. An undocumented one is an unchecked one.",
            file=sys.stderr,
        )
        return 1

    print(f"funnel-contract: OK — all {len(fields)} response fields are documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
