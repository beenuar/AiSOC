"""Offline benchmark reproduction CLI (t5-benchmark).

Anyone with a clone of this repo and the runtime dependencies can
exercise the benchmark suite end-to-end and produce a leaderboard
row identical to what the platform would produce.

Usage::

    python -m scripts.run_benchmark --print-manifest
    python -m scripts.run_benchmark --run --notes "claude-3.5"
    python -m scripts.run_benchmark --run --scenario cl0p-moveit-exfil

The ``--print-manifest`` mode is the falsifiability anchor: it
prints the canonical scenario JSON and its SHA-256 to stdout. A
partner can run the same command on their checkout and confirm
the hash matches the one published in our leaderboard.

This script is intentionally thin — it delegates to the existing
:class:`BenchmarkRunner` and :func:`bench_manifest` helpers so the
CLI and the live API agree exactly on what "running the benchmark"
means.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Make ``app`` importable when invoked as a script from the repo root.
_REPO_BACKEND = Path(__file__).resolve().parent.parent
if str(_REPO_BACKEND) not in sys.path:
    sys.path.insert(0, str(_REPO_BACKEND))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the AiSOC public benchmark suite offline.",
    )
    parser.add_argument(
        "--print-manifest",
        action="store_true",
        help="Print the canonical scenario manifest + SHA-256 and exit.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the benchmark suite end-to-end and print the leaderboard row.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help=(
            "Restrict the run to a single scenario id. Can be passed "
            "multiple times. Default: run the full suite."
        ),
    )
    parser.add_argument(
        "--notes",
        default=None,
        help="Free-form notes recorded on the persisted leaderboard row.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write the JSON outcome to. Default: stdout.",
    )
    return parser


def _print_manifest() -> int:
    # Local import keeps the CLI startup fast for ``--help``.
    from app.benchmark import bench_manifest
    from app.marketplace.scenarios import builtin_scenarios_raw

    manifest = bench_manifest()
    payload = {
        "manifest": manifest.to_dict(),
        "scenarios": builtin_scenarios_raw(),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


async def _run(scenario_ids: list[str], notes: str | None) -> dict:
    from app.db import init_db
    from app.marketplace import benchmark_runner

    # The runner persists to the configured DB. Initialise it here so
    # the script works against the local SQLite file by default.
    init_db()

    outcome = await benchmark_runner.run(
        notes=notes,
        scenario_ids=scenario_ids or None,
    )
    return outcome.to_dict()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.print_manifest and not args.run:
        parser.print_help()
        return 2

    if args.print_manifest:
        return _print_manifest()

    # ``--run`` was supplied. Run the suite synchronously.
    os.environ.setdefault("AISOC_AUTH_DISABLED", "1")
    outcome = asyncio.run(_run(args.scenario, args.notes))
    serialised = json.dumps(outcome, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(serialised)
        print(f"wrote {args.output}")
    else:
        print(serialised)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
