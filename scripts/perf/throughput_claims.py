#!/usr/bin/env python3
"""Three throughput claims, each measured and labelled separately.

Gap-closure wave 8.

The repository has published one number — "176.9 alerts/s" — and a
reader cannot tell which pipeline it describes. That matters because
the three stages differ by two orders of magnitude, and quoting the
slowest as *the* throughput understates the product while quoting the
fastest misrepresents it.

    ingest      accept an event and hand it to Kafka durably
    lake        archive it to ClickHouse
    alert_path  normalise, correlate, fuse, score and write an alert

Only the last involves correlation state and a Postgres write per
output, which is why it is slowest and why it is the number that
decides whether a deployment keeps up during an incident.

Detection on a subset, stated as such
----------------------------------------
Running the full executable corpus against every event at six figures
a second is not something this product does, and a claim that implied
otherwise would be false. The honest claim is that **ingest and lake
sustain the headline rate while detection runs over a defined subset**
— windowed, sampled, or filtered by log source — and the subset has to
be published with the rate. A detection coverage of "12% of events,
sampled uniformly" is a usable fact. "100K EPS with detection" without
that qualifier is not.

Nothing here invents a figure. `ClaimSet.render` prints **not
measured** for every claim with no run behind it, and a claim whose
measurement is older than its staleness budget is reported as stale
rather than quietly reused.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = ["CLAIMS", "Claim", "ClaimSet", "Measurement", "load_claims"]

#: A measurement older than this is reported stale. Thirty days because
#: the tree changes faster than that, and a figure nobody re-measured
#: across a release is describing a different product.
STALENESS_DAYS = 30


@dataclass(frozen=True)
class Claim:
    """One thing that can be measured, and what it would mean."""

    key: str
    stage: str
    unit: str
    description: str
    #: What must travel with the number for it to mean anything.
    required_context: tuple[str, ...]
    why_separate: str


CLAIMS: dict[str, Claim] = {
    "ingest_eps": Claim(
        key="ingest_eps",
        stage="ingest",
        unit="events/s",
        description="Events accepted at /v1/ingest/batch and durably handed to Kafka.",
        required_context=("hosts", "batch_size", "payload_bytes", "commit_sha"),
        why_separate=(
            "No correlation state and no per-event database write. This is the fastest "
            "stage by a wide margin, so quoting it as the platform's throughput "
            "misrepresents what the alert path can do."
        ),
    ),
    "lake_eps": Claim(
        key="lake_eps",
        stage="lake",
        unit="events/s",
        description="Events archived to ClickHouse from the Kafka spine.",
        required_context=("hosts", "batch_size", "commit_sha"),
        why_separate=(
            "Columnar bulk insert, which behaves nothing like the alert path's row-at-a-time "
            "write. A lake figure says nothing about how fast alerts appear."
        ),
    ),
    "alert_path_aps": Claim(
        key="alert_path_aps",
        stage="alert_path",
        unit="alerts/s",
        description="Fused alerts written to Postgres, end to end from ingest.",
        required_context=("hosts", "fusion_replicas", "kafka_partitions", "commit_sha"),
        why_separate=(
            "The number that decides whether a deployment keeps up during an incident. "
            "Correlation state and a write per output make it the slowest stage, and it is "
            "the one the published 176.9 figure actually described."
        ),
    ),
    "detection_coverage_pct": Claim(
        key="detection_coverage_pct",
        stage="detection",
        unit="% of events",
        description="Share of ingested events the detection engine evaluated.",
        required_context=("selection_method", "rules_loaded", "commit_sha"),
        why_separate=(
            "The qualifier that makes a six-figure ingest claim honest. Running the full "
            "corpus against every event at that rate is not what this product does, and a "
            "rate published without the coverage implies it did."
        ),
    ),
}


@dataclass
class Measurement:
    claim: str
    value: float
    measured_at: str
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def missing_context(self) -> list[str]:
        required = CLAIMS[self.claim].required_context if self.claim in CLAIMS else ()
        return [k for k in required if not self.context.get(k)]

    @property
    def age_days(self) -> float | None:
        try:
            when = datetime.fromisoformat(self.measured_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (datetime.now(UTC) - when).total_seconds() / 86_400

    @property
    def stale(self) -> bool:
        age = self.age_days
        return age is None or age > STALENESS_DAYS


@dataclass
class ClaimSet:
    measurements: dict[str, Measurement] = field(default_factory=dict)

    def problems(self) -> list[str]:
        """Everything that would make a published table misleading."""
        found: list[str] = []
        for key, measurement in self.measurements.items():
            if key not in CLAIMS:
                found.append(f"[unknown-claim] {key!r} is measured and declared nowhere")
                continue
            for missing in measurement.missing_context:
                found.append(
                    f"[missing-context] {key} reports {measurement.value} without {missing!r}; "
                    f"{CLAIMS[key].why_separate.split('.')[0].lower()}"
                )
            if measurement.stale:
                age = measurement.age_days
                found.append(
                    f"[stale] {key} was measured "
                    + (f"{age:.0f} days ago" if age is not None else "at an unparseable time")
                    + f", past the {STALENESS_DAYS}-day budget — the tree has moved since"
                )
        if "ingest_eps" in self.measurements and "detection_coverage_pct" not in self.measurements:
            found.append(
                "[unqualified-throughput] an ingest rate is published with no detection "
                "coverage beside it, which reads as 'every event was evaluated'"
            )
        return found

    def render(self) -> str:
        lines = ["| Claim | Stage | Value | Measured | Context |", "|---|---|---|---|---|"]
        for key, claim in CLAIMS.items():
            measurement = self.measurements.get(key)
            if measurement is None:
                lines.append(f"| {key} | {claim.stage} | **not measured** | — | — |")
                continue
            flag = " *(stale)*" if measurement.stale else ""
            context = ", ".join(f"{k}={v}" for k, v in sorted(measurement.context.items())) or "—"
            lines.append(f"| {key} | {claim.stage} | {measurement.value:g} {claim.unit}{flag} | {measurement.measured_at} | {context} |")
        return "\n".join(lines)


#: What `load_harness.py` calls a metric, against what this file calls a claim.
#:
#: The two shipped speaking different languages and this file had no caller at
#: all (fix-pass item 5.8), so the split it exists to publish was never
#: computed from a real run. Only the claims the harness actually measures are
#: mapped: `lake_eps` is absent because the harness does not time the
#: ClickHouse archive separately, and inventing a value for it -- or quietly
#: reusing the ingest figure -- would be the exact misattribution this file was
#: written to prevent.
HARNESS_METRIC_BY_CLAIM: dict[str, str] = {
    "ingest_eps": "ingest_accepted_eps",
    "alert_path_aps": "pipeline_eps",
}


def claims_from_harness(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a `load_harness.py` result into this file's claim shape.

    A metric the harness reports as unmeasured, or does not report at all, is
    left out entirely rather than carried through as zero -- the harness emits
    measured-with-a-value or unmeasured-with-a-reason and never both, and that
    property has to survive the translation or a reader sees `0.00` where the
    truth is "not measured".
    """
    metrics = payload.get("metrics") or {}
    measured_at = str(payload.get("measured_at", ""))

    # `run.shape` is what the harness recorded about the load it applied:
    # batch size, workers, the commit, and the host count where it can know
    # it. Carried through verbatim, because the whole point of the required
    # context is that a reader can reproduce the number -- a context key
    # invented here would defeat that more quietly than omitting it.
    shape = dict((payload.get("run") or {}).get("shape") or {})
    hardware = payload.get("hardware") or {}
    context: dict[str, Any] = {
        "deployment": str(payload.get("deployment", "")),
        **shape,
    }
    if hardware.get("cpu"):
        context["hardware"] = f"{hardware.get('cpu')} / {hardware.get('runtime_cpus', '?')} runtime CPUs"

    out: dict[str, Any] = {}
    for claim, metric_name in HARNESS_METRIC_BY_CLAIM.items():
        metric = metrics.get(metric_name)
        if not isinstance(metric, dict) or not metric.get("measured") or "value" not in metric:
            continue
        out[claim] = {
            "value": float(metric["value"]),
            "measured_at": measured_at,
            # `0` is a legitimate context value, so filter on None rather
            # than on falsiness.
            "context": {k: v for k, v in context.items() if v is not None and v != ""},
        }
    return {"measurements": out}


def load_claims(payload: dict[str, Any]) -> ClaimSet:
    out = ClaimSet()
    for key, raw in (payload.get("measurements") or {}).items():
        out.measurements[key] = Measurement(
            claim=key,
            value=float(raw.get("value", 0.0)),
            measured_at=str(raw.get("measured_at", "")),
            context=dict(raw.get("context") or {}),
        )
    return out


def _self_test() -> int:
    now = datetime.now(UTC).isoformat()
    old = (datetime.now(UTC) - timedelta(days=STALENESS_DAYS + 5)).isoformat()

    cases: list[tuple[str, dict[str, Any], str]] = [
        (
            "nothing measured renders as not measured, never as zero",
            {},
            "clean",
        ),
        (
            "a complete, fresh ingest claim with its coverage",
            {
                "measurements": {
                    "ingest_eps": {
                        "value": 100_000,
                        "measured_at": now,
                        "context": {"hosts": 3, "batch_size": 500, "payload_bytes": 900, "commit_sha": "abc1234"},
                    },
                    "detection_coverage_pct": {
                        "value": 12.0,
                        "measured_at": now,
                        "context": {"selection_method": "uniform sample", "rules_loaded": 2603, "commit_sha": "abc1234"},
                    },
                }
            },
            "clean",
        ),
        (
            "an ingest rate with no coverage beside it",
            {
                "measurements": {
                    "ingest_eps": {
                        "value": 100_000,
                        "measured_at": now,
                        "context": {"hosts": 3, "batch_size": 500, "payload_bytes": 900, "commit_sha": "abc1234"},
                    }
                }
            },
            "unqualified-throughput",
        ),
        (
            "a number with no host count — unreproducible",
            {"measurements": {"alert_path_aps": {"value": 214, "measured_at": now, "context": {"commit_sha": "abc1234"}}}},
            "missing-context",
        ),
        (
            "a figure older than the staleness budget",
            {
                "measurements": {
                    "alert_path_aps": {
                        "value": 176.9,
                        "measured_at": old,
                        "context": {
                            "hosts": 1,
                            "fusion_replicas": 1,
                            "kafka_partitions": 1,
                            "commit_sha": "abc1234",
                        },
                    }
                }
            },
            "stale",
        ),
        (
            "a claim nobody declared",
            {"measurements": {"magic_number": {"value": 9001, "measured_at": now}}},
            "unknown-claim",
        ),
    ]

    failures = 0
    for name, payload, expectation in cases:
        problems = load_claims(payload).problems()
        ok = not problems if expectation == "clean" else any(p.startswith(f"[{expectation}]") for p in problems)
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            for problem in problems:
                print(f"      {problem}")

    rendered = ClaimSet().render()
    if "not measured" not in rendered:
        print("  self-test [FAIL] an unmeasured claim must render as 'not measured'")
        failures += 1

    print(f"throughput_claims: self-test {'OK' if not failures else 'FAILED'} — {len(CLAIMS)} claims declared")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--claims", help="JSON file of measurements to validate and render")
    parser.add_argument(
        "--from-harness",
        help=(
            "A scripts/perf/load_harness.py result to translate and grade. The harness and "
            "this file name the same quantities differently, which is why this file had no "
            "caller: there was no way to point it at a real run."
        ),
    )
    parser.add_argument("--check", action="store_true", help="exit non-zero on any problem")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="KIND",
        help=(
            "A problem kind to tolerate under --check, e.g. `unqualified-throughput`. "
            "Every use needs a reason in the caller, and the tolerated problems are still "
            "printed: the point is that a known gap stays visible rather than being "
            "silently absorbed, which is how a gate stops meaning anything."
        ),
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.claims and not args.from_harness:
        print(ClaimSet().render())
        return 0

    if args.from_harness:
        with open(args.from_harness, encoding="utf-8") as handle:
            claims = load_claims(claims_from_harness(json.load(handle)))
    else:
        with open(args.claims, encoding="utf-8") as handle:
            claims = load_claims(json.load(handle))
    print(claims.render())
    problems = claims.problems()
    if problems:
        print("\nProblems:")
        for problem in problems:
            print(f"  {problem}")

    allowed = set(args.allow or [])
    blocking = [p for p in problems if not any(f"[{kind}]" in p for kind in allowed)]
    if allowed:
        tolerated = len(problems) - len(blocking)
        print(f"\nTolerated by --allow {sorted(allowed)}: {tolerated} of {len(problems)}")
    return 1 if (blocking and args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
