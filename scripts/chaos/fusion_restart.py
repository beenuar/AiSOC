#!/usr/bin/env python3
"""Chaos test: kill fusion mid-stream, assert no loss and no duplicates.

The claim
---------
A fusion replica can be destroyed while events are flowing and every event
that ingest accepted still becomes exactly one alert row. Not "roughly all of
them", and not "at least one row each".

Why the assertion is made against Postgres and nothing else
-----------------------------------------------------------
It would be easier to ask the replacement pod whether it thinks it recovered,
or to read a counter out of the process. Both would be a service grading its
own homework, and this repository has the scar: a UEBA consumer whose handler
raised had no ``except`` at all, so the ``async for`` exited, the ``finally``
stopped the consumer, and the container sat at ``Running`` with restarts 0 and
``/health`` answering 200, permanently, with the exception never logged. Every
in-process signal said healthy.

So the only evidence this test accepts is rows in the alert store. The producer
stamps a sequence number into every event's title; after the run, each accepted
sequence number must appear in ``alerts`` exactly once. A missing one is loss.
A repeated one is a duplicate. Both are counted and both fail.

What makes the property true, so a failure is diagnosable
---------------------------------------------------------
Two independent mechanisms, and the test is really asking whether they still
hold together:

* ``services/fusion/app/workers/consumer.py`` runs with
  ``enable_auto_commit=False`` and commits only after a message is fully
  processed. A kill between processing and commit re-delivers on restart,
  which is at-least-once: it cannot lose, and it can duplicate.
* ``services/fusion/app/services/alert_sink.py`` inserts under
  ``WHERE NOT EXISTS (… tenant_id = $2 AND dedup_hash = $11)``, so the
  re-delivery does not become a second row. That converts at-least-once into
  effectively-once at the store.

Remove either and this test fails in a distinguishable direction: losing the
commit discipline shows up as missing rows, losing the dedup guard as
duplicates.

Usage
-----
::

    # kubernetes (the shape the plan names: kill a pod)
    python3 scripts/chaos/fusion_restart.py --target kubernetes \\
        --namespace aisoc --token "$AISOC_INGEST_TOKEN" \\
        --ingest-url http://127.0.0.1:30081/v1/ingest/batch

    # docker compose (kill the container)
    python3 scripts/chaos/fusion_restart.py --target compose \\
        --token "$AISOC_INGEST_TOKEN"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "perf"))

from gate_toolkit import repo_root, self_test_main  # noqa: E402
from load_harness import (  # noqa: E402
    MARKER_PREFIX,
    Target,
    collect_alerts,
    compose_target,
    kubernetes_target,
)

_FUSION_COMPOSE_SERVICE = "fusion"
_FUSION_K8S_SELECTOR = "app.kubernetes.io/component=alert-fusion"


@dataclass
class Verdict:
    """What the alert store says happened, independent of what any pod says."""

    accepted: int
    alert_rows: int
    distinct_seqs: int
    missing: list[int]
    duplicated: list[int]

    @property
    def ok(self) -> bool:
        return self.accepted > 0 and not self.missing and not self.duplicated

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted_events": self.accepted,
            "alert_rows": self.alert_rows,
            "distinct_events_alerted": self.distinct_seqs,
            "missing_count": len(self.missing),
            "duplicate_count": len(self.duplicated),
            # Bounded so a total failure does not write a hundred-thousand-line
            # report, but never summarised to a bare count: the ids are what
            # makes a failure reproducible.
            "missing_sample": self.missing[:25],
            "duplicated_sample": self.duplicated[:25],
            "verdict": "no loss, no duplicates" if self.ok else "FAILED",
        }


def grade(accepted: int, seq_counts: dict[int, int]) -> Verdict:
    """Compare what ingest accepted against what the alert store holds.

    Sequence numbers are contiguous from 0 by construction (the producer hands
    them out from one atomic counter), so "which ones are missing" is a set
    difference rather than a guess.
    """
    expected = range(accepted)
    missing = sorted(seq for seq in expected if seq not in seq_counts)
    duplicated = sorted(seq for seq, count in seq_counts.items() if count > 1)
    return Verdict(
        accepted=accepted,
        alert_rows=sum(seq_counts.values()),
        distinct_seqs=len(seq_counts),
        missing=missing,
        duplicated=duplicated,
    )


def fusion_victims(target: Target, namespace: str) -> list[str]:
    if target.name == "kubernetes":
        out = subprocess.run(  # noqa: S603
            [
                "kubectl",
                "-n",
                namespace,
                "get",
                "pods",
                "-l",
                _FUSION_K8S_SELECTOR,
                "--field-selector=status.phase=Running",
                "-o",
                "jsonpath={.items[*].metadata.name}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return out.stdout.split()
    out = subprocess.run(  # noqa: S603
        ["docker", "ps", "--filter", "name=aisoc-fusion", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [name for name in out.stdout.split() if name]


def kill_fusion(target: Target, namespace: str, victim: str) -> tuple[bool, str]:
    """Destroy the replica without letting it shut down cleanly.

    ``--grace-period=0 --force`` and ``docker kill -s KILL`` are both
    deliberate: a graceful stop runs fusion's ``stop()``, which stops the
    consumer in an orderly way and would test the shutdown path rather than
    the crash path. The failure worth proving survivable is the one where the
    process never gets to run any code at all.
    """
    if target.name == "kubernetes":
        argv = ["kubectl", "-n", namespace, "delete", "pod", victim, "--grace-period=0", "--force", "--wait=false"]
    else:
        argv = ["docker", "kill", "-s", "KILL", victim]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    return done.returncode == 0, (done.stderr or done.stdout).strip()[:300]


def count_marked(target: Target, run_id: str) -> int:
    raw = target.sql(f"select count(*) from alerts where title like '{MARKER_PREFIX} {run_id} %'")
    return int(raw or 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=("compose", "kubernetes"), default="kubernetes")
    parser.add_argument("--namespace", default="aisoc")
    parser.add_argument("--events", type=int, default=6000)
    parser.add_argument("--target-eps", type=int, default=100, help="paced so the kill lands mid-stream, not after it")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--batch", type=int, default=20)
    parser.add_argument("--kill-at", type=float, default=0.4, help="fraction of the push elapsed before the kill")
    parser.add_argument("--token", default=os.environ.get("AISOC_INGEST_TOKEN", ""))
    parser.add_argument("--tenant", default=os.environ.get("AISOC_TENANT_ID", "00000000-0000-0000-0000-000000000001"))
    parser.add_argument("--ingest-url", default=os.environ.get("AISOC_INGEST_URL", "http://localhost:8081/v1/ingest/batch"))
    parser.add_argument("--compose-file", action="append", default=[])
    parser.add_argument("--postgres-ref", default="statefulset/postgres")
    parser.add_argument("--kafka-ref", default="statefulset/aisoc-kafka")
    parser.add_argument("--producer-bin", default=os.environ.get("AISOC_PRODUCER_BIN", ""))
    parser.add_argument("--drain-timeout", type=int, default=420)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    root = repo_root()
    if not (root / "services" / "fusion").is_dir() or not (root / "services" / "demo-producer").is_dir():
        print(
            "fusion_restart: services/fusion and services/demo-producer are not in this tree; "
            "there is nothing to kill and nothing to drive it with",
            file=sys.stderr,
        )
        return 2
    if not args.token:
        print("fusion_restart: no ingest credential. Pass --token or set AISOC_INGEST_TOKEN (`make ingest-token`).", file=sys.stderr)
        return 2

    target = (
        compose_target(root, args.compose_file or ["docker-compose.yml"], args.ingest_url)
        if args.target == "compose"
        else kubernetes_target(args.namespace, "aisoc", args.ingest_url, args.postgres_ref, args.kafka_ref)
    )

    before = fusion_victims(target, args.namespace)
    if len(before) < 2:
        print(
            f"fusion_restart: found {len(before)} running fusion replica(s): {before or 'none'}. "
            "This test needs at least two, because with one there is nothing for the surviving "
            "consumer to take over and the result would only measure restart time.",
            file=sys.stderr,
        )
        return 2

    run_id = f"c{int(time.time()) % 100000000:08d}"
    summary_path = Path(os.environ.get("TMPDIR", "/tmp")) / f"aisoc-chaos-{run_id}.json"
    producer = [args.producer_bin] if args.producer_bin else ["go", "run", "./services/demo-producer"]
    producer += [
        "--load",
        "--ingest-url",
        args.ingest_url,
        "--token",
        args.token,
        "--tenant",
        args.tenant,
        "--total",
        str(args.events),
        "--workers",
        str(args.workers),
        "--batch",
        str(args.batch),
        "--target-eps",
        str(args.target_eps),
        "--run-id",
        run_id,
        "--summary",
        str(summary_path),
    ]

    expected_seconds = args.events / max(1, args.target_eps)
    print(
        f"chaos: run={run_id} events={args.events} paced at {args.target_eps}/s "
        f"(about {expected_seconds:.0f}s of stream); killing a replica at {args.kill_at:.0%}"
    )

    started = time.time()
    proc = subprocess.Popen(producer, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)  # noqa: S603

    # The kill has to land while events are still arriving. Waiting on the
    # clock alone would fire early on a stack that never started, so the
    # alert store is checked first: rows for this run mean the stream is live.
    deadline = started + expected_seconds * args.kill_at
    while time.time() < deadline:
        time.sleep(1)
        if proc.poll() is not None:
            break
    in_flight = count_marked(target, run_id)
    victim = before[0]
    killed_ok, detail = kill_fusion(target, args.namespace, victim)
    killed_at = time.time()
    print(
        f"chaos: killed {victim} at t+{killed_at - started:.0f}s with {in_flight:,} alerts already stored "
        f"({'ok' if killed_ok else 'FAILED: ' + detail})"
    )
    if not killed_ok:
        proc.kill()
        return 2
    if in_flight == 0:
        print(
            "chaos: no alerts had been stored when the kill landed, so the replica was destroyed "
            "before the stream reached it. That tests nothing; re-run with a lower --target-eps "
            "or a later --kill-at.",
            file=sys.stderr,
        )
        proc.kill()
        return 2

    _, producer_err = proc.communicate(timeout=max(300, expected_seconds * 4))
    if proc.returncode != 0:
        print(f"chaos: producer failed ({proc.returncode}): {producer_err[-400:]}", file=sys.stderr)
        return 2
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    accepted = int(summary["accepted_events"])

    drain_started = time.time()
    stable_reads = 0
    last = -1
    while time.time() - drain_started < args.drain_timeout:
        count = count_marked(target, run_id)
        if count >= accepted:
            break
        # Three identical reads is the stopping rule when rows are still
        # missing: one could be the gap between two batches.
        stable_reads = stable_reads + 1 if count == last else 0
        if stable_reads >= 3:
            break
        last = count
        time.sleep(5)

    seq_counts: dict[int, int] = {}
    for row in collect_alerts(target, run_id):
        seq_counts[row.seq] = seq_counts.get(row.seq, 0) + 1
    verdict = grade(accepted, seq_counts)

    after = fusion_victims(target, args.namespace)
    replaced = args.target == "compose" or (victim not in after and len(after) >= len(before))

    report = {
        "schema": "aisoc.chaos_fusion_restart/v1",
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "deployment": target.name,
        "run_id": run_id,
        "replica_killed": victim,
        "replicas_before": before,
        "replicas_after": after,
        "replica_replaced": replaced,
        "killed_at_offset_seconds": round(killed_at - started, 1),
        "alerts_stored_when_killed": in_flight,
        "drain_seconds": round(time.time() - drain_started, 1),
        **verdict.as_dict(),
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    if not verdict.ok:
        print(
            f"\nFAIL: {len(verdict.missing)} event(s) produced no alert and {len(verdict.duplicated)} produced more than one.",
            file=sys.stderr,
        )
        return 1
    if not replaced:
        print(
            "\nFAIL: the killed replica was not replaced, so the run survived by running at reduced capacity rather than by recovering.",
            file=sys.stderr,
        )
        return 1
    print(
        f"\nPASS: {accepted:,} accepted events produced {accepted:,} alert rows across a replica kill "
        f"at t+{report['killed_at_offset_seconds']}s. No loss, no duplicates."
    )
    return 0


def _self_test() -> int:
    """Prove the verdict fails in both directions it is supposed to catch."""
    checks = [
        (
            "a clean run passes",
            grade(5, {0: 1, 1: 1, 2: 1, 3: 1, 4: 1}).ok,
        ),
        (
            "a lost event fails and is named, rather than being absorbed into a rate",
            (lambda v: not v.ok and v.missing == [2] and v.as_dict()["missing_sample"] == [2])(grade(5, {0: 1, 1: 1, 3: 1, 4: 1})),
        ),
        (
            "a duplicated event fails even though every event is present",
            (lambda v: not v.ok and v.duplicated == [1] and not v.missing)(grade(5, {0: 1, 1: 2, 2: 1, 3: 1, 4: 1})),
        ),
        (
            "a loss and a duplicate that cancel out in the row count still fail",
            (lambda v: not v.ok and v.alert_rows == 5 and v.missing == [4] and v.duplicated == [1])(grade(5, {0: 1, 1: 2, 2: 1, 3: 1})),
        ),
        (
            "a run where nothing was accepted is not a pass",
            not grade(0, {}).ok,
        ),
    ]
    ok = True
    for description, passed in checks:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    print()
    print("fusion_restart.py: self-test " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test() or self_test_main("chaos/fusion_restart.py", []))
    sys.exit(main())
