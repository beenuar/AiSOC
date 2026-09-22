#!/usr/bin/env python3
"""Export windowed detection rules for `services/fusion` to load at startup.

The windowed engine shipped with three hardcoded rules and no way to add a
fourth without editing the module. That mattered beyond inconvenience: a large
share of the 2,005 quarantined Splunk rules are `| stats count ... by`
aggregations. They cannot be expressed in the stateless `match_when` at all,
because that matcher evaluates one event in isolation, and until now they had
nowhere else to go — which is most of why the quarantine has stayed at ~2,000
rules.

This mirrors `export_detection_ruleset.py` exactly: specs are the source of
truth, the JSON is a build artifact, and `--check` fails CI when the two drift
so the deployed engine cannot silently diverge from the committed corpus.

A windowed rule is deliberately a narrow shape — match, group by one entity,
count, threshold, window. It is not a general aggregation language. Anything
needing joins, subsearches or multi-field grouping is out of scope here and
should stay quarantined with an honest reason rather than be half-translated.

Usage:
    python3 scripts/export_windowed_ruleset.py           # write the JSON
    python3 scripts/export_windowed_ruleset.py --check   # fail on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"

#: Windowed rules, authored here rather than in the engine module.
#:
#: Thresholds are chosen to be defensible rather than impressive. A brute-force
#: rule that fires on three failures generates more work than it saves, and the
#: fastest way to have a detection corpus ignored is to ship it noisy.
#:
#: `group_by` names the entity the count accumulates against, and it must be a
#: field some connector actually emits — `scripts/check_detection_fields.py`
#: gates the stateless corpus for exactly this and the same discipline applies
#: here.
WINDOWED_RULES: list[dict] = [
    {
        "id": "wd-ai-agent-tool-denials",
        "name": "AI agent repeatedly denied a tool call",
        "severity": "high",
        "category": "application",
        "mitre": ["T1078"],
        "match_when": {"outcome": "denied"},
        "group_by": "agent_id",
        "threshold": 10,
        "window_seconds": 300,
        # A single denial is routine: agents retry, and tools go down. Ten in
        # five minutes from one agent is the shape that separates an agent
        # probing its boundaries — or being steered into doing so — from one
        # that is merely misconfigured. The stateless
        # `ai-agent-tool-call-failed-repeatedly` rule exists as the low-severity
        # building block for precisely this, and says so in its description.
    },
    {
        "id": "wd-ai-model-fanout",
        "name": "AI agent called an unusual number of distinct models",
        "severity": "medium",
        "category": "application",
        "mitre": ["T1078"],
        "match_when": {"tool_name_startswith": "model:"},
        "group_by": "agent_id",
        "threshold": 50,
        "window_seconds": 300,
        # Model-shopping at volume is either a runaway loop burning budget or
        # someone enumerating which providers a key can reach. Both are worth
        # a look, neither is worth a critical.
    },
    {
        "id": "wd-mfa-fatigue",
        "name": "MFA fatigue: repeated push denials for one account",
        "severity": "high",
        "category": "identity",
        "mitre": ["T1621"],
        "match_when": {"event_type": "authentication", "outcome": "denied"},
        "group_by": "user",
        "threshold": 8,
        "window_seconds": 600,
        # The attack works by wearing the user down, so the signal is
        # repetition against a single account rather than any one denial.
    },
    {
        "id": "wd-impossible-travel-volume",
        "name": "Many distinct source IPs authenticating one account",
        "severity": "medium",
        "category": "identity",
        "mitre": ["T1078"],
        "match_when": {"event_type": "authentication"},
        "group_by": "user",
        "threshold": 25,
        "window_seconds": 900,
        # Volume-based rather than geo-based on purpose: geo needs an enrichment
        # this pipeline does not compute, and inventing a `geo_distance_km`
        # field would produce a rule that can never fire — the exact defect
        # `check_detection_fields.py` was written to catch.
    },
    {
        "id": "wd-data-egress-burst",
        "name": "Burst of outbound transfers from one host",
        "severity": "high",
        "category": "data-exfil",
        "mitre": ["T1041"],
        "match_when": {"event_type": "network"},
        "group_by": "hostname",
        "threshold": 200,
        "window_seconds": 300,
    },
]


def build() -> dict:
    return {"count": len(WINDOWED_RULES), "rules": WINDOWED_RULES}


def _strip_count(payload: dict) -> list:
    return payload.get("rules") or []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed JSON is stale")
    args = parser.parse_args()

    payload = build()
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    ids = [r["id"] for r in WINDOWED_RULES]
    if len(ids) != len(set(ids)):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        print(f"ERROR: duplicate windowed rule ids: {duplicates}", file=sys.stderr)
        return 2

    if args.check:
        if not OUT.exists():
            print(f"ERROR: {OUT.relative_to(ROOT)} missing — run scripts/export_windowed_ruleset.py", file=sys.stderr)
            return 1
        if _strip_count(json.loads(OUT.read_text(encoding="utf-8"))) != _strip_count(payload):
            print(
                f"ERROR: {OUT.relative_to(ROOT)} is stale. Run: python3 scripts/export_windowed_ruleset.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: windowed ruleset current ({len(WINDOWED_RULES)} rules)")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(WINDOWED_RULES)} windowed rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
