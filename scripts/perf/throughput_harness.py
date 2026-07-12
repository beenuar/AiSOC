#!/usr/bin/env python3
"""Fusion hot-path throughput harness (Phase 6 — performance).

Measures how fast the promotion hot path — the deterministic per-event work that
turns an ingest-normalized OCSF event into a fusion RawAlert — processes events.
This is the CPU-bound stage that sits on the critical ingest→alert path, so a
regression here (e.g. someone slips an I/O call into `promote_normalized_event`)
directly widens time-to-alert.

The harness runs the **real** `services/fusion` promoter over a deterministic
synthetic corpus and reports events/sec plus per-event p50/p95/p99 latency. It
is deliberately **not** a production SLO — CI runners are noisy shared hardware.
`--assert-floor` sets a *generous* regression floor (order of magnitude below
the real number) so the gate fires only on a catastrophic regression, never on
runner jitter. The measured number is published for trend visibility.

Usage:
    python3 scripts/perf/throughput_harness.py                 # measure + print
    python3 scripts/perf/throughput_harness.py --json          # JSON to stdout
    python3 scripts/perf/throughput_harness.py --events 20000 --assert-floor 1000
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The promoter lives in the fusion service; import it directly so we benchmark
# the code that actually runs in production, not a copy.
sys.path.insert(0, str(ROOT / "services" / "fusion"))

from app.services.promoter import promote_normalized_event  # noqa: E402

_TENANT = "00000000-0000-0000-0000-000000000001"


def _synthetic_event(i: int) -> dict:
    """A deterministic OCSF-ish event. Every 3rd is a promotable finding; the
    rest are lower-severity telemetry (exercises both promoter branches)."""
    is_finding = i % 3 == 0
    severity_id = 5 if is_finding else (4 if i % 3 == 1 else 2)
    return {
        "tenant_id": _TENANT,
        "ocsf_event": {
            "class_uid": 2001 if is_finding else 4001,
            "category_uid": 2 if is_finding else 4,
            "severity_id": severity_id,
            "message": f"synthetic event {i}: suspicious process activity",
            "time": "2026-07-12T08:00:00Z",
            "metadata": {"uid": f"ev-{i}", "product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
            "device": {"name": f"HOST-{i % 500}"},
            "actor": {"user": {"name": f"user{i % 200}"}},
            "src_endpoint": {"ip": f"10.0.{i % 255}.{(i * 7) % 255}"},
            "file": {"fingerprints": [{"value": f"{i:064x}"}]},
            "mitre_attck": [
                {"technique_id": "T1003", "technique_name": "OS Credential Dumping", "tactic_names": ["Credential Access"]}
            ],
        },
    }


def run(n_events: int) -> dict:
    corpus = [_synthetic_event(i) for i in range(n_events)]

    latencies_us: list[float] = []
    promoted = 0
    started = time.perf_counter()
    for event in corpus:
        t0 = time.perf_counter()
        alert = promote_normalized_event(event)
        latencies_us.append((time.perf_counter() - t0) * 1e6)
        if alert is not None:
            promoted += 1
    elapsed = time.perf_counter() - started

    latencies_us.sort()

    def _pct(p: float) -> float:
        if not latencies_us:
            return 0.0
        idx = min(len(latencies_us) - 1, int(p / 100 * len(latencies_us)))
        return round(latencies_us[idx], 2)

    eps = round(n_events / elapsed, 1) if elapsed > 0 else float("inf")
    return {
        "events": n_events,
        "promoted": promoted,
        "elapsed_seconds": round(elapsed, 4),
        "events_per_second": eps,
        "latency_us": {"p50": _pct(50), "p95": _pct(95), "p99": _pct(99)},
        "stage": "fusion.promote_normalized_event",
        "note": "regression floor, not a production SLO (CI runners are shared hardware)",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument(
        "--assert-floor",
        type=float,
        default=None,
        help="fail (exit 1) if events/sec falls below this generous regression floor",
    )
    args = parser.parse_args()

    result = run(args.events)

    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"stage:            {result['stage']}")
        print(f"events:           {result['events']} ({result['promoted']} promoted)")
        print(f"elapsed:          {result['elapsed_seconds']}s")
        print(f"throughput:       {result['events_per_second']} events/sec")
        print(f"latency (us):     p50={result['latency_us']['p50']} p95={result['latency_us']['p95']} p99={result['latency_us']['p99']}")

    if args.assert_floor is not None:
        if result["events_per_second"] < args.assert_floor:
            print(
                f"::error::throughput {result['events_per_second']} eps below regression floor "
                f"{args.assert_floor} eps — a catastrophic regression (likely I/O on the hot path)",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {result['events_per_second']} eps >= floor {args.assert_floor} eps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
