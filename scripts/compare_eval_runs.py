#!/usr/bin/env python3
"""Publish the delta between two eval runs, and refuse the ones that lie.

Parity 3.4, which defers to gap-closure 6.4: *"replay before and after
... and publish the delta."*

Why a delta needs its own tool
-------------------------------
Subtracting two numbers is easy. Subtracting them *honestly* is where
this goes wrong, and three of the four ways it goes wrong produce a
plausible figure rather than an error.

**"Not measured" is not zero, and a delta involving it is not a delta.**
If the before run measured malicious recall and the after run did not,
the arithmetic says `0.62 - 0 = -0.62` and the report says the agent got
much worse. It did not; nobody asked it. Every axis here reports one of
four states — improved, regressed, unchanged, or *not comparable* — and
the fourth exists because the first three would otherwise absorb it.

**A mean without its denominator is not comparable.** A precision of
1.00 over two predictions and a precision of 1.00 over two hundred are
the same number and different facts. When the support behind an axis
changes materially, the delta is reported with both counts rather than
as a bare difference.

**Two runs on different corpora are not a before and after.** A delta
between a run over 200 incidents and one over 10 measures the corpus,
not the change. The dataset identity is compared first and a mismatch is
refused outright.

**A wall-clock number is not a property of the change.** Latency differs
between two runs on one host, let alone two hosts, so it is excluded
from the verdict and reported separately, labelled as measuring the
machine.

What "regressed" means
----------------------
Any axis moving down by more than :data:`NOISE_FLOOR`. The floor is not
a tolerance for sloppiness — it exists because a bootstrap CI and a
sampled corpus both move slightly between runs, and a tool that called
every 0.001 drift a regression would be ignored within a week.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

#: Below this, a move is reported as unchanged. See the module docstring.
NOISE_FLOOR = 0.005

#: Axes whose *higher is better*. Everything else is reported without a
#: direction rather than guessed at, because a tool that assumed the
#: wrong direction would call an improvement a regression.
HIGHER_IS_BETTER = (
    "accuracy",
    "malicious_recall",
    "groundedness",
    "mitre_accuracy",
    "alert_reduction",
    "investigation_completeness",
    "response_quality",
)

#: Measures the host, not the agent. Reported, never graded.
HOST_AXES = ("mean_latency_ms", "p95_latency_ms")

#: Fields that identify the run rather than measure it. Excluded so the
#: dataset name does not become an axis with no delta.
_IDENTITY_KEYS = frozenset({"dataset", "corpus", "dataset_id", "model", "commit", "date", "mode"})

VERDICT_IMPROVED = "improved"
VERDICT_REGRESSED = "regressed"
VERDICT_UNCHANGED = "unchanged"
VERDICT_NOT_COMPARABLE = "not comparable"


class ComparisonRefused(RuntimeError):
    """The two runs cannot honestly be compared. Carries why."""


@dataclass(frozen=True)
class AxisDelta:
    axis: str
    before: float | None
    after: float | None
    delta: float | None
    verdict: str
    note: str = ""
    before_n: int | None = None
    after_n: int | None = None


def _number(value: Any) -> float | None:
    """A float, or None for anything that is not a measurement.

    `None`, `"not measured"` and a missing key all mean the same thing
    and all become `None`. A string that happens to parse is still a
    number; a bool is not, because `True` would silently become 1.0.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _axis_values(report: dict[str, Any]) -> dict[str, tuple[float | None, int | None]]:
    """Flatten a report into axis -> (value, support).

    Handles both shapes this tree produces: a flat `{"accuracy": 0.9}`
    and the nested `{"groundedness": {"mean": 0.8, "scored_incidents": 20}}`
    the live-agent harness writes.
    """
    out: dict[str, tuple[float | None, int | None]] = {}
    for key, value in (report or {}).items():
        if isinstance(value, dict):
            number = _number(value.get("mean", value.get("value", value.get("score"))))
            support = value.get("scored_incidents", value.get("count", value.get("support")))
            out[key] = (number, support if isinstance(support, int) else None)
        elif key not in _IDENTITY_KEYS:
            # Recorded even when it is not a number, so a key that
            # stopped being a measurement shows up as "not comparable"
            # rather than vanishing. Dropping it is how a report loses an
            # axis without anyone noticing which one went quiet.
            out[key] = (_number(value), None)
    return out


def _dataset_identity(report: dict[str, Any]) -> str | None:
    for key in ("dataset", "corpus", "dataset_id"):
        value = report.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def compare(before: dict[str, Any], after: dict[str, Any]) -> list[AxisDelta]:
    """Every axis in either run, with a verdict that can say "no".

    Axes present in only one run are reported as not comparable rather
    than dropped: an axis that stopped being measured is a change worth
    seeing, and silently omitting it is how a report shrinks without
    anyone noticing.
    """
    before_id, after_id = _dataset_identity(before), _dataset_identity(after)
    if before_id and after_id and before_id != after_id:
        raise ComparisonRefused(
            f"these runs used different datasets ({before_id!r} and {after_id!r}), so a delta "
            "between them measures the corpus rather than the change"
        )

    left, right = _axis_values(before), _axis_values(after)
    deltas: list[AxisDelta] = []

    for axis in sorted(set(left) | set(right)):
        before_value, before_n = left.get(axis, (None, None))
        after_value, after_n = right.get(axis, (None, None))

        if axis in HOST_AXES:
            deltas.append(
                AxisDelta(
                    axis=axis,
                    before=before_value,
                    after=after_value,
                    delta=None,
                    verdict=VERDICT_NOT_COMPARABLE,
                    note="measures the machine the run happened on, not the agent",
                    before_n=before_n,
                    after_n=after_n,
                )
            )
            continue

        if before_value is None or after_value is None:
            # The case the arithmetic gets wrong. Saying "not measured"
            # minus 0.62 is a regression would be a confident lie.
            which = (
                "the before run did not measure it"
                if before_value is None and after_value is not None
                else "the after run did not measure it"
                if after_value is None and before_value is not None
                else "neither run measured it"
            )
            deltas.append(
                AxisDelta(
                    axis=axis,
                    before=before_value,
                    after=after_value,
                    delta=None,
                    verdict=VERDICT_NOT_COMPARABLE,
                    note=f"{which}; absent is not zero, so there is no delta to report",
                    before_n=before_n,
                    after_n=after_n,
                )
            )
            continue

        raw = after_value - before_value
        if abs(raw) <= NOISE_FLOOR:
            verdict = VERDICT_UNCHANGED
        elif axis in HIGHER_IS_BETTER:
            verdict = VERDICT_IMPROVED if raw > 0 else VERDICT_REGRESSED
        else:
            verdict = VERDICT_NOT_COMPARABLE

        note = ""
        if axis not in HIGHER_IS_BETTER and verdict == VERDICT_NOT_COMPARABLE:
            note = "no known direction for this axis, so the move is reported without a verdict"
        elif before_n is not None and after_n is not None and before_n and after_n:
            ratio = after_n / before_n
            if ratio < 0.5 or ratio > 2.0:
                note = (
                    f"support changed from {before_n} to {after_n}; a mean over a materially "
                    "different number of cases is a different fact, not only a different number"
                )

        deltas.append(
            AxisDelta(
                axis=axis,
                before=before_value,
                after=after_value,
                delta=round(raw, 6),
                verdict=verdict,
                note=note,
                before_n=before_n,
                after_n=after_n,
            )
        )

    return deltas


def _fmt(value: float | None) -> str:
    return "not measured" if value is None else f"{value:.4f}"


def format_delta_report(deltas: list[AxisDelta], *, before_label: str, after_label: str) -> str:
    """Markdown, deterministic, with "not measured" spelled out.

    No timestamps and no host names: a report that has to reproduce for
    a reviewer cannot carry either.
    """
    lines = [
        "# Before and after",
        "",
        f"- Before: `{before_label}`",
        f"- After: `{after_label}`",
        "",
        "| Axis | Before | After | Delta | Verdict |",
        "|---|---|---|---|---|",
    ]
    for d in deltas:
        delta = "—" if d.delta is None else f"{d.delta:+.4f}"
        lines.append(f"| `{d.axis}` | {_fmt(d.before)} | {_fmt(d.after)} | {delta} | {d.verdict} |")

    notes = [d for d in deltas if d.note]
    if notes:
        lines += ["", "## Why some axes have no delta", ""]
        lines += [f"- **`{d.axis}`** — {d.note}" for d in notes]

    regressed = [d.axis for d in deltas if d.verdict == VERDICT_REGRESSED]
    lines += ["", f"**Regressions: {len(regressed)}**" + (f" — {', '.join(regressed)}" if regressed else "")]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--out", type=Path, help="write the Markdown report here")
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="exit non-zero when any graded axis moved down past the noise floor",
    )
    args = parser.parse_args()

    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))

    try:
        deltas = compare(before, after)
    except ComparisonRefused as exc:
        print(f"compare_eval_runs: REFUSED — {exc}", file=sys.stderr)
        return 2

    report = format_delta_report(deltas, before_label=args.before.name, after_label=args.after.name)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    print(report)

    regressed = [d for d in deltas if d.verdict == VERDICT_REGRESSED]
    if regressed and args.fail_on_regression:
        print(
            f"compare_eval_runs: {len(regressed)} axis/axes regressed: " + ", ".join(d.axis for d in regressed),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
