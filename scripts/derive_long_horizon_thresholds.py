#!/usr/bin/env python3
"""Derive the item 2.2 long-horizon thresholds from a corpus, or refuse to.

The plan asks for thresholds "derived from the corpus and published". This
script is the derivation, and its most important behaviour is the one it
performs today: it **refuses**. No corpus in this repository carries what
the derivation needs — an authentication event with an account, a source
network and a stated outcome — so there is nothing to measure, and a number
emitted anyway would be a rationale dressed as a measurement.

What it looks for, per event: an account (`actor_email`, `user_name`, ...),
a source network (`src_asn`, `src_country`, `src_ip`) and an outcome the
connectors state (`outcome`, `is_success`, `result_status`). An event
missing any of the three cannot contribute to a breadth distribution.

Output is `docs/detections/long-horizon-thresholds.json`, carrying
`measured: false` and the reason when the corpus cannot support a
derivation, so every reader of the published threshold sees the state of
the evidence rather than only the number. The shipped defaults are a
*rationale*, recorded as such:

* `lh_distinct_failed_asn >= 8` — a password-spray against one account
  from eight distinct autonomous systems is not a person; a traveller
  authenticating badly from eight networks in a month is implausible
  because a failure does not repeat across networks for a human who
  knows their password.
* `lh_failed_to_success_asn_ratio >= 4.0` — four times as many networks
  failing as succeeding. A traveller's two sides move together; an attack
  widens only the failing side.

Return to measured when a corpus of authentication events with those three
fields exists — the replay recording under `services/agents/tests/eval_data`
would qualify if it carried outcomes and source networks, which it does not.

Usage:
    python3 scripts/derive_long_horizon_thresholds.py
    python3 scripts/derive_long_horizon_thresholds.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
OUT = ROOT / "docs" / "detections" / "long-horizon-thresholds.json"

CORPORA = (
    ROOT / "services" / "agents" / "tests" / "eval_data" / "synthetic_telemetry.jsonl",
    ROOT / "services" / "agents" / "tests" / "eval_data" / "synthetic_hunt_telemetry.jsonl",
)

ACCOUNT_FIELDS = ("target_user", "target_user_email", "actor_email", "user_principal_name", "actor", "user_name", "username")
NETWORK_FIELDS = ("src_asn", "src_asn_org", "src_country", "src_ip", "ip_address", "client_ip")
OUTCOME_FIELDS = ("is_success", "outcome", "outcome_result", "result", "result_status", "status")

#: Thresholds the rules use when the corpus cannot support a derivation.
#: Rationale is in the module docstring; `measured` records which they are.
RATIONALE_THRESHOLDS: dict[str, float] = {
    "lh_distinct_failed_asn": 8,
    "lh_distinct_failed_country": 5,
    "lh_failed_to_success_asn_ratio": 4.0,
}


def _usable(event: dict[str, Any]) -> bool:
    return (
        any(event.get(f) for f in ACCOUNT_FIELDS) and any(event.get(f) for f in NETWORK_FIELDS) and any(f in event for f in OUTCOME_FIELDS)
    )


def survey() -> dict[str, Any]:
    scanned = 0
    usable = 0
    present: list[str] = []
    for path in CORPORA:
        if not path.is_file():
            continue
        present.append(str(path.relative_to(ROOT)))
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            scanned += 1
            if _usable(event):
                usable += 1
    return {"corpora": present, "events_scanned": scanned, "events_usable": usable}


def build() -> dict[str, Any]:
    stats = survey()
    if stats["events_usable"] == 0:
        return {
            "measured": False,
            "reason": (
                "UNMEASURED — no corpus in this repository carries an authentication event with an "
                "account, a source network and a stated outcome together, so no breadth distribution "
                f"exists to derive a threshold from. {stats['events_scanned']} events scanned across "
                f"{len(stats['corpora'])} corpora, 0 usable. The thresholds below are a recorded "
                "rationale, not a measurement, and the rules that read them say so."
            ),
            "thresholds": RATIONALE_THRESHOLDS,
            "survey": stats,
            "return_to_measured": (
                "A corpus of authentication events carrying account, source ASN or country, and outcome. "
                "Re-run scripts/derive_long_horizon_thresholds.py; it will publish percentiles and set "
                "measured to true."
            ),
        }
    # No path reaches here yet. When a usable corpus lands, the percentile
    # derivation goes here and `measured` becomes true — deliberately not
    # written in advance, because untested derivation code that has never
    # seen data is a worse artefact than an honest refusal.
    raise SystemExit(
        f"{stats['events_usable']} usable events found but no derivation is implemented. "
        "Implement the percentile derivation in build() rather than publishing the rationale "
        "defaults over real data."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the published artefact is stale")
    args = parser.parse_args()

    payload = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.is_file():
            print(f"ERROR: {OUT.relative_to(ROOT)} missing — run scripts/derive_long_horizon_thresholds.py", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != payload:
            print(f"ERROR: {OUT.relative_to(ROOT)} is stale — run scripts/derive_long_horizon_thresholds.py", file=sys.stderr)
            return 1
        print("long-horizon thresholds: OK — published artefact matches the corpus survey")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(payload, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
