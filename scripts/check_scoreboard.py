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
from datetime import date
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


#: How stale the published scoreboard may be before this gate fails.
#:
#: The page above the table says rows are appended weekly. It sat frozen at
#: 2026-07-13 / v7.5.0 for ten weeks across three releases and **every check
#: in the repository passed throughout**, because "freshness" here meant the
#: accuracy *value* was current and nothing ever read the row's date.
#:
#: 45 days rather than 7: the weekly job needs a funded provider key it does
#: not have, so a 7-day ceiling would red `main` permanently for a reason no
#: contributor can fix, and a gate people route around is worse than none.
#: This catches the failure that actually happened — a scoreboard going stale
#: for a season while claiming to be weekly.
MAX_SCOREBOARD_AGE_DAYS = 45


def _newest_substrate_row(data: dict) -> dict | None:
    """The newest substrate row *by date*, not by position in the file.

    This used to return the first row with ``substrate: true`` and the file
    is only conventionally newest-first, so a row appended in the wrong place
    would have silently become the one every check measured.
    """
    substrate = [row for row in data.get("rows", []) if row.get("substrate") is True]
    if not substrate:
        return None
    return max(substrate, key=lambda row: str(row.get("date", "")))


def _newest_row(data: dict) -> dict | None:
    rows = data.get("rows", [])
    return max(rows, key=lambda row: str(row.get("date", ""))) if rows else None


def _staleness_errors(data: dict, today: date | None = None) -> list[str]:
    """Fail when the published table has gone quiet while promising weekly rows."""
    newest = _newest_row(data)
    if newest is None:
        return ["scoreboard has no rows at all"]

    raw = str(newest.get("date", ""))
    try:
        newest_date = date.fromisoformat(raw)
    except ValueError:
        return [f"newest row has an unparseable date: {raw!r}"]

    age = ((today or date.today()) - newest_date).days
    if age <= MAX_SCOREBOARD_AGE_DAYS:
        return []
    return [
        f"the newest scoreboard row is {age} days old ({raw}), over the "
        f"{MAX_SCOREBOARD_AGE_DAYS}-day ceiling. The benchmark page says rows are "
        "appended weekly. Either append a run, or change what the page claims — "
        "a table that has gone quiet for a season must not keep advertising a cadence."
    ]


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
    errors = _validate_schema(data) + _validate_honesty(data) + _staleness_errors(data)

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
    # Re-stamp the row. --refresh rewrote only the accuracy, so a refreshed
    # row kept a months-old date and commit_sha: the number described today's
    # code and the row said it was measured in July. That is a worse claim
    # than a stale number, because it looks current.
    row["date"] = date.today().isoformat()
    row["commit_sha"] = _head_sha() or row.get("commit_sha", "")
    row["agent_version"] = _tree_version() or row.get("agent_version", "")
    SCOREBOARD.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"refreshed newest substrate row -> accuracy {live}, dated {row['date']}, {row['commit_sha']}")
    return 0


def _head_sha() -> str:
    """Short HEAD sha, or empty when git is unavailable."""
    import subprocess  # noqa: PLC0415 — only needed on the refresh path

    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return out.stdout.strip()


def _tree_version() -> str:
    """The version in the working tree, not a remembered one."""
    version_file = ROOT / "VERSION"
    if not version_file.exists():
        return ""
    return "v" + version_file.read_text(encoding="utf-8").strip()


def append() -> int:
    """Append one substrate row from a fresh deterministic run.

    The scoreboard had no writer at all. `wet-eval.yml` rewrites
    `benchmark.md` and a snapshot file and never touches `scoreboard.json`;
    `live-agent-eval.yml` runs a real Ollama-hosted agent and has
    `permissions: contents: read`, so it could not have written one if it
    tried. The docs promise an auto-PR appending a row, and nothing
    implements it. That is why the table sat frozen for ten weeks across
    three releases with every check passing.

    This is the substrate half only, and it is labelled as such — the row
    carries `substrate: true` and `eval_mode: substrate-only`, and the
    honesty check refuses any other combination. Appending a substrate row
    does not and must not look like live-agent performance.
    """
    data = _load()
    rows = data.setdefault("rows", [])
    today = date.today().isoformat()
    sha = _head_sha()

    # (date, commit_sha) is the row key. Re-running on the same commit on the
    # same day is a no-op rather than a duplicate.
    if any(r.get("date") == today and r.get("commit_sha") == sha for r in rows):
        print(f"OK: a row for {today} @ {sha} already exists; nothing appended")
        return 0

    template = _newest_substrate_row(data)
    if template is None:
        print("ERROR: no existing substrate row to take a shape from", file=sys.stderr)
        return 1

    row = dict(template)
    row["date"] = today
    row["commit_sha"] = sha
    row["agent_version"] = _tree_version() or row.get("agent_version", "")
    row["mitre_accuracy"] = _live_accuracy()
    row["substrate"] = True
    row["eval_mode"] = "substrate-only"

    rows.insert(0, row)
    SCOREBOARD.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"appended substrate row {today} @ {sha}: mitre_accuracy={row['mitre_accuracy']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--append", action="store_true", help="append a substrate row from a fresh run")
    parser.add_argument("--refresh", action="store_true", help="rewrite the newest substrate row's mitre_accuracy")
    parser.add_argument("--check", action="store_true", help="validate + freshness-gate (default action)")
    args = parser.parse_args()
    if args.append:
        return append()
    return refresh() if args.refresh else check()


if __name__ == "__main__":
    raise SystemExit(main())
