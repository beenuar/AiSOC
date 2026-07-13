#!/usr/bin/env python3
"""Gate the public benchmark scoreboard against a real live-agent run (Phase E1).

This closes the last `NO GATE` row in the claim-to-gate matrix — "the weekly
benchmark scoreboard runs live against main". Before this, `apps/docs/static/
data/scoreboard.json` was hand-maintained and the only automation
(`wet-eval.yml`) no-ops without a funded LLM key, so nothing in per-PR CI proved
the published headline number matched what the agent actually scores.

This checker makes the scoreboard **backed by a failing test**:

1. **Schema** — validates the scoreboard against `scoreboard.schema.json`.
2. **Honesty invariants** — every row carries `substrate` (bool) + `eval_mode`;
   `substrate:true` rows must use a substrate `eval_mode` and are never allowed
   to omit the marker (so a deterministic number can't be quoted as live-LLM).
3. **Freshness** — runs the deterministic live-agent MITRE-accuracy eval (the
   real LangGraph tactic prediction over the 200-incident corpus, no LLM key
   required) and asserts the newest `substrate:true` row's `mitre_accuracy`
   matches the freshly-computed value within tolerance. If the agent's accuracy
   changes and the scoreboard isn't refreshed, CI fails.

The LLM-tier (`substrate:false`) rows remain the province of the weekly funded
`wet-eval.yml` job; this gate governs the per-PR deterministic tier + the
scoreboard's structural + honesty contract.

Usage:
    python3 scripts/check_scoreboard.py --check      # CI gate (default)
    python3 scripts/check_scoreboard.py --refresh     # rewrite the newest
                                                       # substrate row in place
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCOREBOARD = ROOT / "apps" / "docs" / "static" / "data" / "scoreboard.json"
SCHEMA = ROOT / "apps" / "docs" / "static" / "data" / "scoreboard.schema.json"
_AGENTS = ROOT / "services" / "agents"

# The newest substrate row must be within this of a fresh CI run, else the
# published number has drifted from reality.
_TOLERANCE = 0.02


def _live_accuracy() -> float:
    """Run the deterministic live-agent MITRE-accuracy eval and return it."""
    if str(_AGENTS) not in sys.path:
        sys.path.insert(0, str(_AGENTS))
    from tests.test_mitre_accuracy import evaluate_mitre_accuracy  # noqa: PLC0415

    return round(float(evaluate_mitre_accuracy(threshold=0.0).accuracy), 4)


def _load() -> dict:
    return json.loads(SCOREBOARD.read_text(encoding="utf-8"))


def _newest_substrate_row(data: dict) -> dict | None:
    for row in data.get("rows", []):
        if row.get("substrate") is True:
            return row
    return None


def _validate_schema(data: dict) -> list[str]:
    errors: list[str] = []
    try:
        import jsonschema  # noqa: PLC0415

        jsonschema.validate(data, json.loads(SCHEMA.read_text(encoding="utf-8")))
    except ImportError:
        errors.append("jsonschema not installed — cannot validate scoreboard schema")
    except Exception as exc:  # noqa: BLE001 — surface the validation error
        errors.append(f"schema validation failed: {exc}")
    return errors


def _validate_honesty(data: dict) -> list[str]:
    errors: list[str] = []
    for i, row in enumerate(data.get("rows", [])):
        if "substrate" not in row or not isinstance(row["substrate"], bool):
            errors.append(f"row[{i}] missing boolean `substrate` marker")
            continue
        mode = row.get("eval_mode", "")
        if row["substrate"] and mode != "substrate-only":
            errors.append(f"row[{i}] substrate:true but eval_mode={mode!r} (must be 'substrate-only')")
        if not row["substrate"] and mode == "substrate-only":
            errors.append(f"row[{i}] substrate:false but eval_mode='substrate-only' (contradiction)")
    return errors


def check() -> int:
    if not SCOREBOARD.exists():
        print(f"ERROR: {SCOREBOARD.relative_to(ROOT)} missing", file=sys.stderr)
        return 1
    data = _load()
    errors = _validate_schema(data) + _validate_honesty(data)

    row = _newest_substrate_row(data)
    if row is None:
        errors.append("no substrate row present — the per-PR deterministic gate has nothing to pin against")
    else:
        live = _live_accuracy()
        published = float(row.get("mitre_accuracy", -1))
        if abs(live - published) > _TOLERANCE:
            errors.append(
                f"scoreboard drift: newest substrate mitre_accuracy={published} but a fresh live-agent run "
                f"scores {live} (tolerance {_TOLERANCE}). Run: python3 scripts/check_scoreboard.py --refresh"
            )
        else:
            print(f"OK: scoreboard mitre_accuracy={published} matches fresh live-agent run={live} (±{_TOLERANCE})")

    if errors:
        print("SCOREBOARD GATE FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: scoreboard valid ({len(data.get('rows', []))} rows, schema + honesty + freshness).")
    return 0


def refresh() -> int:
    data = _load()
    row = _newest_substrate_row(data)
    if row is None:
        print("ERROR: no substrate row to refresh", file=sys.stderr)
        return 1
    live = _live_accuracy()
    row["mitre_accuracy"] = live
    SCOREBOARD.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"refreshed newest substrate row mitre_accuracy -> {live}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="rewrite the newest substrate row's mitre_accuracy")
    parser.add_argument("--check", action="store_true", help="validate + freshness-gate (default action)")
    args = parser.parse_args()
    return refresh() if args.refresh else check()


if __name__ == "__main__":
    raise SystemExit(main())
