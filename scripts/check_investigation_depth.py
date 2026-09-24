#!/usr/bin/env python3
"""Gate: investigations must actually investigate.

Pillar 2's failure mode is not that the code is absent — ``run_with_tools``
existed and worked for months with no production caller. It is that depth
silently disappears. A refactor drops the tool binding, a prompt change makes
the model answer in one turn, an exception handler swallows the loop, and
what ships is alert-enrich-summarise with an investigation's vocabulary. Every
narrative still reads plausibly, so nothing catches it.

This grades the structure of an investigation rather than its prose:

  1. Every strategy's ``expected_pivots`` must name a real tool. A strategy
     that asks for a tool nobody implements is guidance the model cannot
     follow.
  2. Every backed tool must be reachable from at least one strategy,
     otherwise it is dead weight the model pays context for.
  3. The loop must be wired into a production path. This is the specific
     regression that already happened once.
  4. Replayed investigations (when a corpus is supplied) must reach their
     strategy's pivot floor, with real distinct tools, inside budget.

Run:  python3 scripts/check_investigation_depth.py [--corpus path.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
AGENTS = REPO_ROOT / "services" / "agents"

sys.path.insert(0, str(AGENTS))


def _fail(errors: list[str], message: str) -> None:
    errors.append(message)


def check_strategies(errors: list[str]) -> None:
    """Strategies and tools must agree on what exists."""
    from app.investigator.strategies import KNOWN_PIVOTS, STRATEGIES

    if len(STRATEGIES) < 5:
        _fail(
            errors,
            f"only {len(STRATEGIES)} strategies defined; the library is meant to " f"cover the kill chains the corpus fires on",
        )

    seen_pivots: set[str] = set()
    for strategy in STRATEGIES:
        if not strategy.expected_pivots:
            _fail(errors, f"strategy {strategy.id!r} declares no expected pivots")
        if not strategy.rationale.strip():
            _fail(errors, f"strategy {strategy.id!r} has no rationale")
        if strategy.min_pivots < 2:
            _fail(
                errors,
                f"strategy {strategy.id!r} has min_pivots={strategy.min_pivots}; "
                f"a single tool call is enrichment, not an investigation",
            )
        if strategy.min_pivots > len(strategy.expected_pivots):
            _fail(
                errors,
                f"strategy {strategy.id!r} requires {strategy.min_pivots} pivots but "
                f"only names {len(strategy.expected_pivots)}; it can never pass",
            )
        for pivot in strategy.expected_pivots:
            seen_pivots.add(pivot)
            if pivot not in KNOWN_PIVOTS:
                _fail(
                    errors,
                    f"strategy {strategy.id!r} expects unknown pivot {pivot!r}",
                )

    return None


def check_tool_coverage(errors: list[str]) -> None:
    """Every tool the model is offered must be worth its context cost."""
    from app.investigator.strategies import STRATEGIES
    from app.tools.investigation import investigation_tools

    tool_names = {t.name for t in investigation_tools("test-tenant")}
    expected = {p for s in STRATEGIES for p in s.expected_pivots}

    orphaned = tool_names - expected
    if orphaned:
        _fail(
            errors,
            f"tools offered to the model but named by no strategy: "
            f"{', '.join(sorted(orphaned))} — the model pays context for these "
            f"with no guidance on when to use them",
        )

    missing = expected - tool_names
    if missing:
        _fail(
            errors,
            f"strategies expect tools that do not exist: {', '.join(sorted(missing))}",
        )

    for tool in investigation_tools("test-tenant"):
        if len(tool.description) < 40:
            _fail(
                errors,
                f"tool {tool.name!r} has a {len(tool.description)}-character " f"description; the model selects on this",
            )


def check_loop_is_wired(errors: list[str]) -> None:
    """The regression that already happened: a loop with no production caller.

    Checked by reading the source rather than by importing, so the gate does
    not need an LLM, a lake or a running service.
    """
    driver = AGENTS / "app" / "investigator" / "deep_investigation.py"
    if not driver.exists():
        _fail(errors, "app/investigator/deep_investigation.py is missing")
        return
    if "run_with_tools(" not in driver.read_text(encoding="utf-8"):
        _fail(errors, "deep_investigation.py no longer calls run_with_tools")

    agent = AGENTS / "app" / "agents" / "investigation_agent.py"
    if not agent.exists():
        _fail(errors, "app/agents/investigation_agent.py is missing")
        return
    agent_source = agent.read_text(encoding="utf-8")
    if "run_deep_investigation" not in agent_source:
        _fail(
            errors,
            "investigation_agent.py does not call run_deep_investigation — the "
            "tool loop has no production caller again, which is exactly the "
            "state this gate exists to prevent",
        )
    if "investigation_depth" not in agent_source:
        _fail(
            errors,
            "investigation_agent.py does not record investigation_depth; without "
            "it a shallow run is indistinguishable from a deep one after the fact",
        )

    # The toolset must actually be bound, not merely imported.
    driver_source = driver.read_text(encoding="utf-8")
    if not re.search(r"registry\.register\(", driver_source):
        _fail(
            errors,
            "deep_investigation.py does not register the investigation tools onto "
            "the registry; the loop would run with enrichment tools only",
        )


def check_selection(errors: list[str]) -> None:
    """Strategy selection must discriminate, not always return the fallback."""
    from app.investigator.strategies import FALLBACK, select_strategy

    cases = [
        ("suspicious powershell process spawned on WS-42", ["T1059.001"], "endpoint-suspicious-process"),
        ("impossible travel detected for user j.doe", ["T1078"], "identity-account-takeover"),
        ("user clicked phishing url in email", ["T1566.002"], "phishing-payload"),
        ("periodic outbound beacon to 203.0.113.9", ["T1071.001"], "c2-beaconing"),
        ("psexec lateral movement to FS-01", ["T1021.002"], "lateral-movement"),
    ]
    for summary, techniques, expected in cases:
        chosen = select_strategy(summary=summary, techniques=techniques)
        if chosen.id != expected:
            _fail(
                errors,
                f"selection: {summary!r} chose {chosen.id!r}, expected {expected!r}",
            )

    unmatched = select_strategy(summary="something entirely unrelated", techniques=[])
    if unmatched.id != FALLBACK.id:
        _fail(errors, f"an unmatched alert chose {unmatched.id!r} rather than the fallback")


def check_corpus(errors: list[str], corpus_path: Path) -> None:
    """Grade recorded investigation runs against their strategy's floor.

    The corpus is produced by the eval harness; this gate only reads it, so a
    PR that has not re-run the harness is checked on structure alone rather
    than being blocked.
    """
    from app.investigator.strategies import get_strategy

    try:
        runs = json.loads(corpus_path.read_text(encoding="utf-8"))
    except Exception as exc:
        _fail(errors, f"could not read corpus {corpus_path}: {exc}")
        return

    if not isinstance(runs, list) or not runs:
        _fail(errors, f"corpus {corpus_path} is empty")
        return

    shallow: list[str] = []
    for run in runs:
        strategy_id = run.get("strategy_id", "")
        strategy = get_strategy(strategy_id)
        floor = strategy.min_pivots if strategy else 2
        distinct = int(run.get("distinct_pivots", 0))
        if distinct < floor:
            shallow.append(f"{run.get('incident_id', '?')} ({strategy_id}): {distinct} pivots, floor {floor}")

    if shallow:
        _fail(
            errors,
            f"{len(shallow)}/{len(runs)} investigations did not reach their "
            f"strategy's pivot floor:\n    " + "\n    ".join(shallow[:10]),
        )

    over = [r for r in runs if r.get("over_budget")]
    if len(over) > len(runs) * 0.1:
        _fail(
            errors,
            f"{len(over)}/{len(runs)} investigations exceeded their time budget; " f"the pivot chain is too slow to run on the hot path",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        help="Optional JSON array of recorded investigation_depth payloads to grade.",
    )
    args = parser.parse_args(argv)

    errors: list[str] = []
    try:
        check_strategies(errors)
        check_tool_coverage(errors)
        check_loop_is_wired(errors)
        check_selection(errors)
    except ImportError as exc:
        print(f"investigation-depth: cannot import the agents package: {exc}", file=sys.stderr)
        return 2

    if args.corpus:
        check_corpus(errors, args.corpus)

    if errors:
        print("INVESTIGATION DEPTH GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    from app.investigator.strategies import STRATEGIES
    from app.tools.investigation import investigation_tools

    print(
        f"investigation-depth: OK — {len(STRATEGIES)} strategies, "
        f"{len(investigation_tools('t'))} tools, loop wired into the production path"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
