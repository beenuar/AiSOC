#!/usr/bin/env python3
"""Load shapes the harness could not produce, and a saturation verdict.

Gap-closure wave 6.

The published figures — 176.9 alerts/s on Compose, 214.0 on a
three-node kind cluster — come from one laptop session on 2026-09-27
that nothing re-measures, and the nightly floor is `--assert-eps-floor
5`, two orders of magnitude below them. The harness can only send a
fixed number of events as fast as it can, which answers exactly one
question: how fast is a burst of N.

It cannot answer the three that decide whether a deployment survives a
week:

**Does it hold?** No `--duration` flag exists anywhere, so there has
never been a soak. Throughput at minute one and at hour twenty-four
differ for reasons that only show up over hours — a queue that grows
slightly faster than it drains, a connection pool that leaks one
handle per error, a partition that compacts.

**What happens at the edge?** A burst is the normal shape of security
telemetry: a scan, a deployment, an incident. A system that sustains
200/s and collapses at a 2,000/s spike is not a 200/s system.

**Does it recover?** Backpressure is only a feature if the queue
drains afterwards. One that sheds load and never catches up has
converted a spike into permanent loss.

Saturation, stated as a cause
--------------------------------
`saturation_verdict` reports the rate at which the system stopped
keeping up **and which signal gave way first** — acceptance latency,
queue depth, or loss. "It saturates at 340/s" is a number; "it
saturates at 340/s because consumer lag grows monotonically past there
while acceptance latency stays flat" is something to act on.

Nothing here claims a measurement. These are the shapes; the figures
come from running them, and a profile that has not been run says so.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "PROFILES",
    "LoadProfile",
    "SaturationVerdict",
    "Sample",
    "saturation_verdict",
    "steps_for",
]


@dataclass(frozen=True)
class LoadProfile:
    """A shape to drive the ingest path with."""

    name: str
    description: str
    #: Events per second at each step. A single entry is a flat run.
    rates: tuple[int, ...]
    #: Seconds to hold each rate.
    hold_seconds: int
    #: Whether the run is expected to push the system past its limit.
    #: A profile that never saturates cannot locate a saturation point,
    #: and one that always does cannot measure a sustainable rate.
    expects_saturation: bool
    why: str


PROFILES: dict[str, LoadProfile] = {
    "smoke": LoadProfile(
        name="smoke",
        description="Thirty seconds at a low fixed rate.",
        rates=(50,),
        hold_seconds=30,
        expects_saturation=False,
        why="Proves the harness and the stack are both wired before a long run commits an hour.",
    ),
    "ramp": LoadProfile(
        name="ramp",
        description="Step up until something gives.",
        rates=(50, 100, 200, 400, 800, 1600, 3200),
        hold_seconds=120,
        expects_saturation=True,
        why=(
            "Locates the saturation point and names the signal that gave way first. Two "
            "minutes per step because a queue that is slowly losing ground looks healthy "
            "for the first thirty seconds."
        ),
    ),
    "burst": LoadProfile(
        name="burst",
        description="Baseline, a ten-fold spike, then baseline again.",
        rates=(100, 1000, 100),
        hold_seconds=180,
        expects_saturation=True,
        why=(
            "The normal shape of security telemetry — a scan, a deployment, an incident. "
            "The third leg is the measurement that matters: a system that sheds load and "
            "never catches up turned a spike into permanent loss."
        ),
    ),
    "soak-24h": LoadProfile(
        name="soak-24h",
        description="Twenty-four hours at a rate the ramp showed is sustainable.",
        rates=(150,),
        hold_seconds=86_400,
        expects_saturation=False,
        why=(
            "Throughput at minute one and at hour twenty-four differ for reasons only "
            "hours reveal: a queue growing slightly faster than it drains, a pool leaking "
            "one handle per error, a partition compacting."
        ),
    ),
    "soak-72h": LoadProfile(
        name="soak-72h",
        description="Three days at the same rate.",
        rates=(150,),
        hold_seconds=259_200,
        expects_saturation=False,
        why=("Catches what a day does not: log rotation, certificate refresh, a weekly compaction, and the slowest leaks."),
    ),
    "backpressure": LoadProfile(
        name="backpressure",
        description="Well past saturation, then silence, then baseline.",
        rates=(5000, 0, 100),
        hold_seconds=300,
        expects_saturation=True,
        why=(
            "Backpressure is only a feature if the queue drains. The zero leg measures "
            "drain rate with nothing arriving, which is the cleanest reading of it."
        ),
    ),
}


@dataclass
class Sample:
    """One observation during a run."""

    at_second: int
    offered_eps: int
    accepted_eps: float
    p95_accept_ms: float
    #: Consumer lag, in events. The signal that usually gives way first
    #: and the one a throughput-only harness cannot see at all.
    queue_depth: int = 0
    errors: int = 0


@dataclass
class SaturationVerdict:
    saturated: bool = False
    #: The highest offered rate the system kept up with.
    sustainable_eps: int | None = None
    #: The rate at which it stopped.
    saturation_eps: int | None = None
    #: Which signal gave way first. The actionable half.
    first_signal: str | None = None
    recovered: bool | None = None
    recovery_seconds: int | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        if not self.saturated:
            top = self.sustainable_eps
            return (
                f"No saturation observed up to {top} eps. That is a floor, not a ceiling — "
                "the profile did not push hard enough to find one."
            )
        lines = [
            f"Sustainable        {self.sustainable_eps} eps",
            f"Saturates at       {self.saturation_eps} eps",
            f"First signal       {self.first_signal}",
        ]
        if self.recovered is not None:
            lines.append(
                f"Recovery           {'yes' if self.recovered else 'NO'}"
                + (f" in {self.recovery_seconds}s" if self.recovery_seconds else "")
            )
        lines.extend(f"  {note}" for note in self.notes)
        return "\n".join(lines)


#: Acceptance below this fraction of what was offered means the system
#: is not keeping up. 95% rather than 100% because a sampling window
#: that ends mid-batch always under-counts slightly.
_KEEPING_UP = 0.95

#: Queue depth growing across three consecutive samples at one rate is
#: losing ground even if acceptance looks fine — which is precisely the
#: case a throughput-only harness calls healthy.
_GROWTH_SAMPLES = 3


def steps_for(profile: LoadProfile) -> list[tuple[int, int]]:
    """`(rate, seconds)` pairs for a runner to execute."""
    return [(rate, profile.hold_seconds) for rate in profile.rates]


def saturation_verdict(samples: list[Sample], *, latency_ceiling_ms: float = 1000.0) -> SaturationVerdict:
    """Find where it stopped keeping up, and say which signal gave way.

    Pure, so every branch is exercisable without a stack.
    """
    verdict = SaturationVerdict()
    if not samples:
        verdict.notes.append("no samples — nothing was measured, which is not the same as no saturation")
        return verdict

    by_rate: dict[int, list[Sample]] = {}
    for sample in samples:
        by_rate.setdefault(sample.offered_eps, []).append(sample)

    for rate in sorted(by_rate):
        if rate <= 0:
            continue
        window = sorted(by_rate[rate], key=lambda s: s.at_second)
        accepted = sum(s.accepted_eps for s in window) / len(window)
        worst_latency = max(s.p95_accept_ms for s in window)
        depths = [s.queue_depth for s in window]
        growing = len(depths) >= _GROWTH_SAMPLES and all(
            b > a for a, b in zip(depths[-_GROWTH_SAMPLES:], depths[-_GROWTH_SAMPLES + 1 :], strict=False)
        )
        lost = any(s.errors for s in window)

        signal: str | None = None
        if accepted < rate * _KEEPING_UP:
            signal = f"acceptance fell to {accepted:.0f}/s against {rate}/s offered"
        elif growing:
            signal = f"queue depth grew across {_GROWTH_SAMPLES} samples while acceptance held"
        elif worst_latency > latency_ceiling_ms:
            signal = f"p95 acceptance latency reached {worst_latency:.0f} ms"
        elif lost:
            signal = "the ingest endpoint returned errors"

        if signal is None:
            verdict.sustainable_eps = rate
            continue

        verdict.saturated = True
        verdict.saturation_eps = rate
        verdict.first_signal = signal
        if verdict.sustainable_eps is None:
            verdict.notes.append("saturated at the first rate offered, so no sustainable rate was established")
        break

    if not verdict.saturated:
        verdict.notes.append(
            "every offered rate was sustained; the published figure is a floor and the real ceiling is above the top of this profile"
        )

    # Recovery, read off a trailing low-rate leg if the profile had one.
    tail = [s for s in samples if s.offered_eps and s.offered_eps <= (verdict.sustainable_eps or math.inf)]
    if verdict.saturated and tail:
        last = sorted(tail, key=lambda s: s.at_second)[-1]
        verdict.recovered = last.accepted_eps >= last.offered_eps * _KEEPING_UP and last.queue_depth == 0
        if verdict.recovered:
            verdict.recovery_seconds = last.at_second
        else:
            verdict.notes.append(
                "the queue had not drained by the end of the run — backpressure that never catches up turns a spike into permanent loss"
            )
    return verdict


def _self_test() -> int:
    """Every branch, without a stack."""
    cases: list[tuple[str, list[Sample], bool, str | None]] = [
        (
            "well inside capacity",
            [Sample(at_second=s, offered_eps=100, accepted_eps=100, p95_accept_ms=20, queue_depth=0) for s in range(5)],
            False,
            None,
        ),
        (
            "acceptance falls away",
            [Sample(at_second=s, offered_eps=100, accepted_eps=40, p95_accept_ms=30, queue_depth=0) for s in range(5)],
            True,
            "acceptance",
        ),
        (
            "acceptance holds while the queue grows — the invisible case",
            [Sample(at_second=s, offered_eps=100, accepted_eps=100, p95_accept_ms=30, queue_depth=100 * s) for s in range(5)],
            True,
            "queue depth",
        ),
        (
            "latency blows past the ceiling",
            [Sample(at_second=s, offered_eps=100, accepted_eps=100, p95_accept_ms=5000, queue_depth=0) for s in range(5)],
            True,
            "latency",
        ),
        (
            "errors at the endpoint",
            [Sample(at_second=s, offered_eps=100, accepted_eps=100, p95_accept_ms=20, queue_depth=0, errors=3) for s in range(5)],
            True,
            "errors",
        ),
        ("no samples at all", [], False, None),
    ]

    failures = 0
    for name, samples, should_saturate, expect_signal in cases:
        verdict = saturation_verdict(samples)
        ok = verdict.saturated is should_saturate
        if ok and expect_signal:
            ok = expect_signal in (verdict.first_signal or "")
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            print(f"      saturated={verdict.saturated} signal={verdict.first_signal!r}")

    # A profile set with no saturating profile cannot locate a limit,
    # and one with no sustained profile cannot establish a safe rate.
    if not any(p.expects_saturation for p in PROFILES.values()):
        print("  self-test [FAIL] no profile pushes to saturation, so no limit can be found")
        failures += 1
    if not any(not p.expects_saturation for p in PROFILES.values()):
        print("  self-test [FAIL] every profile saturates, so no sustainable rate can be established")
        failures += 1

    print(f"load_profiles: self-test {'OK' if not failures else 'FAILED'} — {len(PROFILES)} profiles")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="print the steps for a profile")
    parser.add_argument("--list", action="store_true", help="list the profiles and what each is for")
    parser.add_argument("--samples", help="JSON file of samples to grade")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.list:
        for profile in PROFILES.values():
            total = profile.hold_seconds * len(profile.rates)
            print(f"{profile.name:14s} {total // 60:>6d} min  {profile.description}")
            print(f"{'':14s}        {profile.why}")
        return 0

    if args.profile:
        print(json.dumps({"profile": args.profile, "steps": steps_for(PROFILES[args.profile])}, indent=2))
        return 0

    if args.samples:
        with open(args.samples, encoding="utf-8") as handle:
            raw = json.load(handle)
        verdict = saturation_verdict([Sample(**row) for row in raw])
        print(verdict.render())
        return 0

    parser.error("one of --self-test, --list, --profile or --samples")
    return 2


if __name__ == "__main__":
    sys.exit(main())
