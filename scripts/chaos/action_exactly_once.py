#!/usr/bin/env python3
"""Does a response action survive a restart exactly once?

Gap-closure wave 5.

`fusion_restart.py` grades exactly-once delivery for *events* and does
it well. Nothing grades it for **actions**, and the two failure modes
are not comparable:

* A lost event is a gap in a timeline. Bad, recoverable, and usually
  visible later.
* A lost action is a host that was never isolated while the console
  says it was.
* A **duplicated** action is the same host isolated twice, a user
  disabled twice, or — the case that actually hurts — a ticket raised
  twice and a firewall rule added twice, which an operator then has to
  find and unpick by hand.

So the grading is asymmetric on purpose. A duplicate is worse than a
delay, and both are worse than a refusal, because a refusal is visible.

What is graded
--------------
A batch of actions is dispatched with stable idempotency keys. The
executor is interrupted mid-batch. On recovery, every action must have
exactly one *terminal* record: `executed`, `failed` or `blocked`. Two
terminal records for one key is a duplicate; zero is a loss.

An action still `pending_approval` or `awaiting_completion` after
recovery is **neither** — it is in flight, which is a correct state to
be in. Counting it as a loss would make an approval queue look like
data corruption, and this harness would then be unusable on the default
posture, which is exactly the posture the product ships.

Why idempotency keys rather than counting
--------------------------------------------
Counting rows cannot distinguish "ran twice" from "two different
actions that happen to look alike" — and two isolate requests for one
host from two analysts is legitimate. The key is what makes the
question answerable.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

#: Outcomes that mean the action is finished and will not change.
TERMINAL = frozenset({"executed", "failed", "blocked", "refused", "unsupported", "no_integration"})

#: Outcomes that mean it is legitimately still in flight. Not a loss.
IN_FLIGHT = frozenset({"pending_approval", "awaiting_completion", "queued", "dry_run", "simulated"})

#: The one that must never appear twice for a single key.
EXECUTED = "executed"


@dataclass
class Verdict:
    dispatched: int = 0
    terminal: int = 0
    in_flight: int = 0
    lost: list[str] = field(default_factory=list)
    duplicated: list[str] = field(default_factory=list)
    #: Keys that reached a vendor more than once. The subset of
    #: `duplicated` that actually did something to the estate.
    double_executed: list[str] = field(default_factory=list)
    unknown_outcomes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not (self.lost or self.duplicated or self.unknown_outcomes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dispatched": self.dispatched,
            "terminal": self.terminal,
            "in_flight": self.in_flight,
            "lost": sorted(self.lost),
            "duplicated": sorted(self.duplicated),
            "double_executed": sorted(self.double_executed),
            "unknown_outcomes": sorted(self.unknown_outcomes),
            "passed": self.passed,
        }

    def render(self) -> str:
        lines = [
            f"dispatched      {self.dispatched}",
            f"terminal        {self.terminal}",
            f"still in flight {self.in_flight}  (approval queue; not a loss)",
        ]
        if self.lost:
            lines.append(f"LOST            {len(self.lost)}  {', '.join(sorted(self.lost)[:5])}")
        if self.double_executed:
            lines.append(
                f"DOUBLE-EXECUTED {len(self.double_executed)}  {', '.join(sorted(self.double_executed)[:5])}"
                "  — these reached a vendor twice"
            )
        elif self.duplicated:
            lines.append(f"DUPLICATED      {len(self.duplicated)}  {', '.join(sorted(self.duplicated)[:5])}")
        if self.unknown_outcomes:
            lines.append(f"UNKNOWN OUTCOME {len(self.unknown_outcomes)}  {', '.join(sorted(self.unknown_outcomes)[:5])}")
        if self.passed:
            lines.append("OK — every dispatched action has exactly one terminal record, or is in flight.")
        return "\n".join(lines)


def grade(dispatched_keys: list[str], records: list[dict[str, Any]]) -> Verdict:
    """Compare what was asked for against what the store holds.

    `records` is `[{"idempotency_key": ..., "outcome": ...}, ...]` as
    read back after recovery.
    """
    verdict = Verdict(dispatched=len(dispatched_keys))

    by_key: dict[str, list[str]] = {}
    for record in records:
        key = str(record.get("idempotency_key") or "")
        outcome = str(record.get("outcome") or "")
        if not key:
            continue
        by_key.setdefault(key, []).append(outcome)

    for key in dispatched_keys:
        outcomes = by_key.get(key, [])
        unrecognised = [o for o in outcomes if o not in TERMINAL and o not in IN_FLIGHT]
        if unrecognised:
            # An outcome the harness does not know is not graded as a
            # pass. A vocabulary that drifted silently is how a lost
            # action gets counted as an in-flight one.
            verdict.unknown_outcomes.append(f"{key}={unrecognised[0]}")
            continue

        terminal = [o for o in outcomes if o in TERMINAL]
        in_flight = [o for o in outcomes if o in IN_FLIGHT]

        if len(terminal) > 1:
            verdict.duplicated.append(key)
            if Counter(terminal)[EXECUTED] > 1:
                verdict.double_executed.append(key)
            verdict.terminal += 1
        elif terminal:
            verdict.terminal += 1
        elif in_flight:
            verdict.in_flight += 1
        else:
            verdict.lost.append(key)

    return verdict


def _self_test() -> int:
    """Prove the grader separates the four outcomes.

    Run in CI unconditionally, because the live harness needs a stack
    and a grader nobody exercised is a grader nobody can trust.
    """
    cases: list[tuple[str, list[str], list[dict[str, Any]], str]] = [
        (
            "clean run",
            ["k1", "k2"],
            [{"idempotency_key": "k1", "outcome": "executed"}, {"idempotency_key": "k2", "outcome": "executed"}],
            "pass",
        ),
        (
            "one action lost in the restart",
            ["k1", "k2"],
            [{"idempotency_key": "k1", "outcome": "executed"}],
            "lost",
        ),
        (
            "one action executed twice — the worst case",
            ["k1"],
            [{"idempotency_key": "k1", "outcome": "executed"}, {"idempotency_key": "k1", "outcome": "executed"}],
            "double",
        ),
        (
            "two terminal records that are not both executions",
            ["k1"],
            [{"idempotency_key": "k1", "outcome": "executed"}, {"idempotency_key": "k1", "outcome": "failed"}],
            "duplicate-not-double",
        ),
        (
            "awaiting approval is in flight, not lost",
            ["k1"],
            [{"idempotency_key": "k1", "outcome": "pending_approval"}],
            "pass",
        ),
        (
            "an outcome the grader does not recognise is not a pass",
            ["k1"],
            [{"idempotency_key": "k1", "outcome": "probably_fine"}],
            "unknown",
        ),
    ]

    failures = 0
    for name, keys, records, expectation in cases:
        verdict = grade(keys, records)
        ok = {
            "pass": verdict.passed,
            "lost": bool(verdict.lost) and not verdict.duplicated,
            "double": bool(verdict.double_executed),
            "duplicate-not-double": bool(verdict.duplicated) and not verdict.double_executed,
            "unknown": bool(verdict.unknown_outcomes),
        }[expectation]
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1

    print(f"action_exactly_once: self-test {'OK' if not failures else 'FAILED'}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the grader separates the four outcomes")
    parser.add_argument("--dispatched", help="JSON file: the idempotency keys that were dispatched")
    parser.add_argument("--records", help="JSON file: the action records read back after recovery")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not (args.dispatched and args.records):
        parser.error("--dispatched and --records are required unless --self-test")

    with open(args.dispatched, encoding="utf-8") as handle:
        keys = json.load(handle)
    with open(args.records, encoding="utf-8") as handle:
        records = json.load(handle)

    verdict = grade(list(keys), list(records))
    print(verdict.render())
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
