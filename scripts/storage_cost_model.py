#!/usr/bin/env python3
"""Storage $/TB cost model (Phase 6 — cost).

AiSOC stores security telemetry in tiers: a hot ClickHouse tier on block
storage for recent, queryable events; a warm object tier; and a cold/archive
object tier for compliance retention. This model turns that tiering into a
defensible $/TB number so the storage-consolidation decision
(`docs/decisions/0005-storage-consolidation.md`) rests on arithmetic, not vibes.

**The value here is the methodology, not the exact prices.** The rate card
below is *reference list pricing* (2026, single representative region) and MUST
be verified against your provider, region, and negotiated rates. The model is
deterministic, so `--check` gates the committed worked example
(`docs/decisions/storage-cost-model.json`) — if the rate card or scenario
changes, the JSON must be regenerated, and the ADR cites that file.

Usage:
    python3 scripts/storage_cost_model.py            # print the worked example
    python3 scripts/storage_cost_model.py --json      # JSON to stdout
    python3 scripts/storage_cost_model.py --check      # fail on drift vs committed JSON
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import json
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
COMMITTED = ROOT / "docs" / "decisions" / "storage-cost-model.json"

# Reference list prices, USD per GB-month. VERIFY against your provider/region.
RATE_CARD_USD_PER_GB_MONTH = {
    "hot_block": 0.080,  # gp3-class block storage backing ClickHouse hot tier
    "warm_object": 0.023,  # standard object storage
    "cold_archive": 0.0125,  # infrequent-access / archive object storage
}

# Canonical worked example. Security telemetry compresses well under ClickHouse
# ZSTD; 8x is a conservative documented assumption for JSON-shaped logs.
SCENARIO = {
    "raw_tb_per_day": 1.0,
    "compression_ratio": 8.0,
    "retention_days": {"hot_block": 30, "warm_object": 60, "cold_archive": 275},  # 365 total
}

_GB_PER_TB = 1000


def compute(scenario: dict, rate_card: dict) -> dict:
    raw_gb_per_day = scenario["raw_tb_per_day"] * _GB_PER_TB
    ratio = scenario["compression_ratio"]
    stored_gb_per_day = raw_gb_per_day / ratio

    tiers: dict[str, dict] = {}
    total_monthly = 0.0
    for tier, days in scenario["retention_days"].items():
        # Steady-state stored volume for this tier = days of retention worth of
        # compressed data resident in the tier at any moment.
        resident_gb = stored_gb_per_day * days
        monthly = resident_gb * rate_card[tier]
        total_monthly += monthly
        tiers[tier] = {
            "retention_days": days,
            "resident_gb": round(resident_gb, 2),
            "rate_usd_per_gb_month": rate_card[tier],
            "monthly_usd": round(monthly, 2),
        }

    raw_tb_ingested_per_month = scenario["raw_tb_per_day"] * 30
    usd_per_raw_tb = total_monthly / raw_tb_ingested_per_month if raw_tb_ingested_per_month else 0.0

    return {
        "scenario": scenario,
        "rate_card_usd_per_gb_month": rate_card,
        "tiers": tiers,
        "total_monthly_usd": round(total_monthly, 2),
        "raw_tb_ingested_per_month": round(raw_tb_ingested_per_month, 2),
        "usd_per_raw_tb_ingested": round(usd_per_raw_tb, 2),
        "disclaimer": "reference list prices; verify against your provider/region and negotiated rates",
    }


def _print_table(result: dict) -> None:
    s = result["scenario"]
    print("Storage cost model — worked example")
    print(f"  raw ingest:        {s['raw_tb_per_day']} TB/day")
    print(f"  compression:       {s['compression_ratio']}x")
    print()
    print(f"  {'tier':<14}{'days':>6}{'resident_GB':>14}{'$/GB-mo':>10}{'$/mo':>12}")
    for tier, t in result["tiers"].items():
        print(f"  {tier:<14}{t['retention_days']:>6}{t['resident_gb']:>14}{t['rate_usd_per_gb_month']:>10}{t['monthly_usd']:>12}")
    print()
    print(f"  total monthly:     ${result['total_monthly_usd']}")
    print(f"  $ / raw TB ingested: ${result['usd_per_raw_tb_ingested']}")
    print(f"  ({result['disclaimer']})")


#: The API service's copy of this model. It cannot import this module — the
#: container has neither ``scripts/`` nor a git checkout, and ``repo_root()``
#: above shells out to git at import — so the constants are mirrored there,
#: the same constraint that put a second LLM price table in
#: ``cost_dashboard._PUBLIC_PRICING``. A second copy of a number is a second
#: place for it to drift, so ``--check`` reads it back. Without this, 6b would
#: have closed "the model has no consumer" by creating a consumer that could
#: silently start quoting different prices.
CONSUMER = "services/api/app/services/storage_cost.py"

_CONSUMER_CONSTANTS = {
    "RATE_CARD_USD_PER_GB_MONTH": lambda: RATE_CARD_USD_PER_GB_MONTH,
    "RETENTION_DAYS": lambda: SCENARIO["retention_days"],
    "COMPRESSION_RATIO": lambda: SCENARIO["compression_ratio"],
}


def check_consumer() -> list[str]:
    """Read the API's mirrored constants back and report any disagreement.

    Parsed rather than imported, for the same reason the API cannot import
    this file: the gate runs in a dep-light lint job and must not pull in
    FastAPI, pydantic and the ClickHouse driver to compare three literals.
    """
    path = ROOT / CONSUMER
    if not path.exists():
        return [f"{CONSUMER} is missing — the model's only consumer is gone, so this gate now checks a constant nothing reads"]

    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: dict[str, object] = {}
    for node in tree.body:
        target: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        if target in _CONSUMER_CONSTANTS and value is not None:
            with contextlib.suppress(ValueError):
                found[target] = ast.literal_eval(value)

    problems: list[str] = []
    for name, expected in _CONSUMER_CONSTANTS.items():
        if name not in found:
            problems.append(f"{CONSUMER} no longer declares {name}; the mirror cannot be checked, so it is not a mirror")
        elif found[name] != expected():
            problems.append(
                f"{CONSUMER}:{name} is {found[name]!r}, this model says {expected()!r} — "
                "the console would quote a price this model does not"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument("--check", action="store_true", help="fail if committed JSON or the API's mirrored constants are stale")
    args = parser.parse_args()

    result = compute(SCENARIO, RATE_CARD_USD_PER_GB_MONTH)

    if args.check:
        if not COMMITTED.exists():
            print(f"ERROR: {COMMITTED.relative_to(ROOT)} missing — run scripts/storage_cost_model.py --write", file=sys.stderr)
            return 1
        committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
        if committed != result:
            print(
                f"ERROR: {COMMITTED.relative_to(ROOT)} is stale. The rate card or scenario changed but the "
                "committed worked example was not regenerated. Run: python3 scripts/storage_cost_model.py --write",
                file=sys.stderr,
            )
            return 1
        drift = check_consumer()
        if drift:
            print(f"ERROR: the model and {CONSUMER} disagree:", file=sys.stderr)
            for problem in drift:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(f"OK: storage cost model current — ${result['usd_per_raw_tb_ingested']}/raw-TB, and {CONSUMER} mirrors it")
        return 0

    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    _print_table(result)
    return 0


if __name__ == "__main__":
    # Hidden --write to regenerate the committed JSON (used by maintainers).
    if "--write" in sys.argv:
        payload = compute(SCENARIO, RATE_CARD_USD_PER_GB_MONTH)
        COMMITTED.parent.mkdir(parents=True, exist_ok=True)
        COMMITTED.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {COMMITTED.relative_to(ROOT)}")
        raise SystemExit(0)
    raise SystemExit(main())
