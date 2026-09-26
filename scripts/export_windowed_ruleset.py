#!/usr/bin/env python3
"""Export windowed detection rules for `services/fusion` to load at startup.

The windowed engine shipped with three hardcoded rules and no way to add a
fourth without editing the module. That mattered beyond inconvenience: a large
share of the 2,005 quarantined Splunk rules are `| stats count ... by`
aggregations. They cannot be expressed in the stateless `match_when` at all,
because that matcher evaluates one event in isolation, and until now they had
nowhere else to go — which is most of why the quarantine has stayed at ~2,000
rules.

The JSON is a build artifact and `--check` fails CI when it drifts from this
file, so the deployed engine cannot silently diverge from the committed
corpus.

This used to claim it "mirrors `export_detection_ruleset.py` exactly: specs
are the source of truth". It does not, and the difference is worth stating
rather than papering over: the stateless exporter reads spec *modules*, while
the rules here are a literal list in this script. That is a deliberate
tradeoff at this corpus size — eight rules do not need a module per rule, and
a reader can see the whole windowed corpus on one screen — but it is a
different arrangement, and describing it as identical sent anyone looking for
`detections/windowed/` somewhere that does not exist.

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

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
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
    {
        # `events_per_minute_gt` is the single largest unreachable family —
        # sixteen `det-*` rules name it and none of them can fire, because
        # nothing computes a per-minute rate for a single event.
        "id": "wd-high-rate-activity-per-actor",
        "name": "Sustained high-rate activity from one actor",
        "severity": "medium",
        "category": "identity",
        "mitre": ["T1078"],
        "match_when": {},
        "group_by": "user",
        "threshold": 120,
        "window_seconds": 60,
    },
    {
        "id": "wd-high-rate-activity-per-source",
        "name": "Sustained high-rate activity from one source address",
        "severity": "medium",
        "category": "network",
        "mitre": ["T1071"],
        "match_when": {},
        "group_by": "src_ip",
        "threshold": 300,
        "window_seconds": 60,
    },
    {
        # Distinct, not count. "Fifty reads by one principal" is a script
        # retrying; "fifty *different* secrets read by one principal" is a
        # vault being walked. Counting events cannot tell those apart.
        "id": "wd-secret-enumeration",
        "name": "Many distinct secrets read by one principal",
        "severity": "high",
        "category": "identity",
        "mitre": ["T1552.007"],
        "match_when": {"event_type": "secret_access"},
        "group_by": "user",
        "distinct_by": "secret_name",
        "threshold": 15,
        "window_seconds": 300,
    },
    {
        "id": "wd-horizontal-scan",
        "name": "One source touching many distinct destinations",
        "severity": "medium",
        "category": "network",
        "mitre": ["T1046"],
        "match_when": {"event_type": "network"},
        "group_by": "src_ip",
        "distinct_by": "dst_ip",
        "threshold": 40,
        "window_seconds": 120,
    },
    {
        "id": "wd-bulk-object-deletion",
        "name": "Bulk object deletion by one principal",
        "severity": "high",
        "category": "cloud",
        "mitre": ["T1485"],
        "match_when": {"event_type": "delete"},
        "group_by": "user",
        "threshold": 50,
        "window_seconds": 300,
    },
    # ---------------------------------------------------------------------
    # Windows aggregations.
    #
    # These could not be written before, for a reason that had nothing to do
    # with the windowed engine: a Windows event nests its payload under
    # `EventData` and its header under `System`, one level deeper than either
    # engine flattens, so `EventID` and `Computer` read as absent and any rule
    # naming them would have counted nothing forever. The `windows_event`
    # connector now lifts both containers, which is what makes the group_by
    # fields below real.
    #
    # `EventID` is matched as an anchored pattern rather than with equality
    # because collectors disagree about whether it arrives as `4625` or
    # `"4625"`, and `pattern_match_any` compares the string form of whatever
    # turned up. An `EventID: 4625` equality clause would match one collector
    # and silently not the other.
    # ---------------------------------------------------------------------
    {
        "id": "wd-windows-failed-logons-per-host",
        "name": "Repeated failed Windows logons against one host",
        "severity": "high",
        "category": "identity",
        "mitre": ["T1110"],
        "match_when": {"EventID_pattern_match_any": ["^4625$"]},
        "group_by": "Computer",
        "threshold": 15,
        "window_seconds": 600,
        # Higher than the generic `wd-bruteforce-auth` threshold of five on
        # purpose: a Windows host aggregates failures from every account and
        # every service on it, so five is background noise there in a way it
        # is not for a single identity.
    },
    {
        "id": "wd-windows-password-spray",
        "name": "Windows logon failures across many accounts from one source",
        "severity": "high",
        "category": "identity",
        "mitre": ["T1110.003"],
        "match_when": {"EventID_pattern_match_any": ["^4625$"]},
        "group_by": "IpAddress",
        "distinct_by": "TargetUserName",
        "threshold": 10,
        "window_seconds": 900,
        # Distinct accounts, not attempts. One account failing repeatedly is a
        # forgotten password; ten different accounts failing once each from one
        # address is someone working through a user list.
    },
    {
        "id": "wd-windows-service-install-burst",
        "name": "Several new Windows services installed on one host",
        "severity": "high",
        "category": "endpoint",
        "mitre": ["T1543.003"],
        "match_when": {"EventID_pattern_match_any": ["^7045$"]},
        "group_by": "Computer",
        "threshold": 4,
        "window_seconds": 600,
        # Service installation is rare outside patching, so the threshold is
        # low. Patch windows are the expected false positive and are better
        # handled by a maintenance-window suppression than by a number nobody
        # can justify.
    },
    {
        "id": "wd-windows-account-creation-burst",
        "name": "One actor created several Windows accounts",
        "severity": "high",
        "category": "identity",
        "mitre": ["T1136.002"],
        "match_when": {"EventID_pattern_match_any": ["^4720$"]},
        "group_by": "SubjectUserName",
        "distinct_by": "TargetUserName",
        "threshold": 5,
        "window_seconds": 900,
    },
    {
        "id": "wd-windows-scheduled-task-burst",
        "name": "Several scheduled tasks registered on one host",
        "severity": "medium",
        "category": "endpoint",
        "mitre": ["T1053.005"],
        "match_when": {"EventID_pattern_match_any": ["^4698$"]},
        "group_by": "Computer",
        "threshold": 5,
        "window_seconds": 600,
    },
    {
        "id": "wd-sysmon-remote-thread-fanout",
        "name": "One process created remote threads in many others",
        "severity": "high",
        "category": "endpoint",
        "mitre": ["T1055"],
        "match_when": {"EventID_pattern_match_any": ["^8$"]},
        "group_by": "SourceImage",
        "distinct_by": "TargetImage",
        "threshold": 5,
        "window_seconds": 300,
        # Injecting into one process has a long list of benign explanations.
        # Injecting into five different ones inside five minutes has very few.
    },
    {
        "id": "wd-sysmon-dns-query-fanout",
        "name": "One process resolved an unusual number of distinct domains",
        "severity": "medium",
        "category": "network",
        "mitre": ["T1071.004"],
        "match_when": {"EventID_pattern_match_any": ["^22$"]},
        "group_by": "Image",
        "distinct_by": "QueryName",
        "threshold": 150,
        "window_seconds": 300,
        # Aimed at DNS tunnelling and at domain-generation algorithms, both of
        # which show up as one binary resolving far more names than it has any
        # reason to. Browsers legitimately clear this bar, which is why the
        # grouping is per-image rather than per-host.
    },
    {
        "id": "wd-sysmon-process-spawn-burst",
        "name": "One parent process spawned an unusual number of children",
        "severity": "medium",
        "category": "endpoint",
        "mitre": ["T1059"],
        "match_when": {"EventID_pattern_match_any": ["^1$"]},
        "group_by": "ParentImage",
        "threshold": 100,
        "window_seconds": 120,
        # Script-driven enumeration and mass encryption both look like this.
        # Build agents and installers do too, so this is deliberately medium.
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
