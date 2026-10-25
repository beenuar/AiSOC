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

_FUSION_K8S_SELECTOR = "app.kubernetes.io/component=alert-fusion"

#: Named so the self-test can assert the relation between them rather than
#: either value: a stall rule shorter than a Kafka consumer-group rejoin
#: cannot tell loss from an unfinished drain, and one longer than the drain
#: budget can never fire.
_DEFAULT_DRAIN_TIMEOUT_SECONDS = 420
_DEFAULT_DRAIN_STALL_SECONDS = 90.0


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


def _inspect(victim: str, template: str) -> str | None:
    done = subprocess.run(  # noqa: S603
        ["docker", "inspect", "-f", template, victim],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    value = (done.stdout or "").strip()
    return value if done.returncode == 0 and value else None


def crash_rungs(pid: str, image: str, *, host_pid_is_ours: bool) -> list[tuple[str, list[str]]]:
    """Every way this harness is allowed to make a container's PID 1 die.

    Pure, and public, so the self-test can assert the one property that
    matters and cannot be read off a passing live run: **none of these is
    ``docker kill``**. Each rung delivers SIGKILL to the same process; they
    differ only in the privilege the host makes available.

    ``host_pid_is_ours`` gates the two rungs that signal a bare pid. On a
    Docker Desktop host the daemon reports a pid from inside its VM, which on
    the host is either absent or -- the reason this gate exists -- some
    unrelated local process. Signalling it would kill a bystander on a
    developer's laptop, so the bare-pid rungs are offered only when ``/proc``
    confirms that pid belongs to this container, and the ``--pid=host``
    container handles every other host.
    """
    rungs: list[tuple[str, list[str]]] = []
    if host_pid_is_ours:
        # Already privileged: root in a CI container, or a rootless daemon.
        rungs.append(("direct kill", ["kill", "-9", pid]))
        # The GitHub runner shape: an unprivileged job user with passwordless sudo.
        rungs.append(("sudo kill", ["sudo", "-n", "kill", "-9", pid]))
    # Works wherever a Docker daemon does, including Docker Desktop. Uses the
    # victim's own image so nothing has to be pulled while the stream is in
    # flight.
    rungs.append(
        (
            "privileged --pid=host container",
            ["docker", "run", "--rm", "--privileged", "--pid=host", "--entrypoint", "sh", image, "-c", f"kill -9 {pid}"],
        )
    )
    return rungs


def host_pid_is_container(container: str, pid: str) -> bool:
    """Whether host pid *pid* really is this container's own process.

    ``/proc`` is the only authority that can answer, and the question has to
    be asked before any bare ``kill``: a pid number that is valid inside a
    Docker Desktop VM is meaningless on the macOS host and may well name
    something else. No ``/proc``, no match, no bare kill.
    """
    full_id = _inspect(container, "{{.Id}}")
    if not full_id:
        return False
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    except OSError:
        return False
    # Both cgroup drivers put the container id in the path:
    # systemd `…/docker-<id>.scope`, cgroupfs `/docker/<id>`.
    return full_id in cgroup or full_id[:12] in cgroup


def _compose_crash(victim: str) -> tuple[bool, str]:
    """Make the container's main process die the way a crash kills it.

    ``docker kill`` is not a crash, and the difference is the whole of the
    "1650 of 3000 events lost" measurement this harness used to produce.
    The daemon records a killed container as *manually stopped*, and
    ``restartmanager.ShouldRestart`` then declines to restart it. Measured on
    Docker 29.5.2, 60 s after the signal:

    ===========================================  ==========================
    action                                       result
    ===========================================  ==========================
    ``docker kill -s KILL``, ``unless-stopped``  ``running=false``, ``restartCount=0``
    ``docker kill -s KILL``, ``always``          ``running=false``, ``restartCount=0``
    SIGKILL of the main process, host PID ns     ``running=true``, ``restartCount=1`` (~4 s)
    ===========================================  ==========================

    So ``restart: unless-stopped`` in ``docker-compose.yml`` was never the
    problem -- ``always`` behaves identically -- and fusion staying dead was
    the harness asking the daemon for an administrative stop and then
    reporting the absence of a consumer as event loss. Under Kubernetes the
    equivalent is genuine: ``kubectl delete pod --force`` is replaced by the
    Deployment controller, so only the compose leg was wrong.

    Signalling the container's PID 1 from the *host* namespace is the shape a
    real crash has: the daemon sees an unexpected exit 137 it did not ask
    for, and applies the restart policy. That also makes the policy itself
    part of what is graded, which nothing else in CI checks.

    ``docker exec <c> kill -9 1`` is not an alternative: PID 1 is
    signal-protected inside its own PID namespace and survives (measured).

    The three rungs exist because the privilege needed differs by host, not
    because any of them is a weaker test -- they all deliver the same signal
    to the same process. If none of them lands the caller is told, and the
    run is refused rather than silently falling back to ``docker kill``,
    which is the fallback that produced a number nobody could interpret.
    """
    pid = _inspect(victim, "{{.State.Pid}}")
    if not pid or pid == "0":
        return False, f"could not read a host PID for {victim}: docker reported {pid!r}"
    image = _inspect(victim, "{{.Config.Image}}") or "busybox:1.36"
    restarts_before = int(_inspect(victim, "{{.RestartCount}}") or 0)

    attempted: list[str] = []
    for label, argv in crash_rungs(pid, image, host_pid_is_ours=host_pid_is_container(victim, pid)):
        done = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
        detail = (done.stderr or done.stdout or "").strip()[:160]
        attempted.append(f"{label}: rc={done.returncode} {detail}".strip())
        # The exit code of `kill` is not the measurement -- whether the
        # process died is. Watch the daemon's own view instead: either the
        # container is down, or the restart policy has already replaced it.
        deadline = time.time() + 20
        while time.time() < deadline:
            running = _inspect(victim, "{{.State.Running}}")
            restarts = int(_inspect(victim, "{{.RestartCount}}") or restarts_before)
            if running == "false" or restarts > restarts_before:
                return True, f"{label} (restartCount {restarts_before} -> {restarts})"
            time.sleep(0.5)

    return False, (
        f"the main process of {victim} (host pid {pid}) could not be signalled. "
        "Refusing to fall back to `docker kill`, which the daemon treats as an administrative "
        "stop and never restarts, so the run would measure a missing consumer as event loss. "
        "Tried -- " + "; ".join(attempted)
    )


def kill_fusion(target: Target, namespace: str, victim: str) -> tuple[bool, str]:
    """Destroy the replica without letting it shut down cleanly.

    ``--grace-period=0 --force`` and the host-namespace SIGKILL are both
    deliberate: a graceful stop runs fusion's ``stop()``, which stops the
    consumer in an orderly way and would test the shutdown path rather than
    the crash path. The failure worth proving survivable is the one where the
    process never gets to run any code at all.
    """
    if target.name != "kubernetes":
        return _compose_crash(victim)
    argv = ["kubectl", "-n", namespace, "delete", "pod", victim, "--grace-period=0", "--force", "--wait=false"]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    return done.returncode == 0, (done.stderr or done.stdout).strip()[:300]


def count_marked(target: Target, run_id: str) -> int:
    raw = target.sql(f"select count(*) from alerts where title like '{MARKER_PREFIX} {run_id} %'")
    return int(raw or 0)


def _is_compose(target_name: str) -> bool:
    """Whether a target name is the compose adapter's.

    The CLI spells its choice ``compose`` and ``load_harness.compose_target``
    names the adapter ``docker-compose``. Reading only the CLI spelling made
    the self-test pass while ``main`` refused a single-replica stack: the guard
    is handed ``Target.name``, which is the adapter's spelling.
    """
    return target_name in ("compose", "docker-compose")


def minimum_replicas(target_name: str) -> int:
    """How many fusion replicas the harness needs before it can prove anything.

    Compose in CI runs one replica. Deleting it does not reduce capacity for a
    survivor to absorb — the container is restarted and Kafka re-delivers from
    the last committed offset — so a single-replica restart is a valid test of
    the durability property. Kubernetes keeps the two-replica requirement: the
    interesting claim there is takeover, not restart latency.
    """
    return 1 if _is_compose(target_name) else 2


def wait_for_replacement(
    target: Target,
    namespace: str,
    *,
    victim: str,
    replicas_before: list[str],
    timeout_seconds: float,
) -> list[str]:
    """Poll until the killed replica is running again (or the timeout expires).

    Compose restarts the same container name; Kubernetes creates a new pod.
    Both count as replacement. Returning the last observation lets the caller
    report what it actually saw rather than assuming recovery from ``docker
    kill`` returning 0.
    """
    deadline = time.time() + max(1.0, timeout_seconds)
    after = fusion_victims(target, namespace)
    while time.time() < deadline:
        after = fusion_victims(target, namespace)
        if _is_compose(target.name):
            if after and len(after) >= len(replicas_before):
                return after
        elif victim not in after and len(after) >= len(replicas_before):
            return after
        time.sleep(2)
    return after


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
    parser.add_argument("--drain-timeout", type=int, default=_DEFAULT_DRAIN_TIMEOUT_SECONDS)
    parser.add_argument(
        "--drain-stall-seconds",
        type=float,
        default=_DEFAULT_DRAIN_STALL_SECONDS,
        help=(
            "how long the alert count may stand still before the drain is called finished. "
            "Must exceed the time a replacement consumer takes to be evicted from its group, "
            "restart and get an assignment, or the stopping rule fires before recovery can show"
        ),
    )
    parser.add_argument("--restart-timeout", type=int, default=180)
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
    required = minimum_replicas(target.name)
    if len(before) < required:
        detail = (
            "compose restarts the same container, so the offset/loss property is still testable"
            if _is_compose(target.name)
            else "the surviving replica must take over while the killed pod is absent"
        )
        print(
            f"fusion_restart: found {len(before)} running fusion replica(s): {before or 'none'}. "
            f"This target needs at least {required}: {detail}.",
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
    if proc.poll() is not None:
        # The producer finished before the kill landed. Killing a replica now
        # would measure restart time against an already-drained stream: the
        # verdict would pass without ever testing an in-flight event. That is a
        # vacuous PASS, so refuse to grade it.
        print(
            "chaos: the producer finished before the kill landed, so no event was in flight. "
            "That tests nothing; raise --events, lower --target-eps, or lower --kill-at.",
            file=sys.stderr,
        )
        return 2

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

    # Wait for the replacement BEFORE grading, not after.
    #
    # This ran last, which meant the loss figure was computed over a window
    # in which nothing was consuming by construction: the drain stopped
    # ~20 s after the last row and the replacement was polled for afterwards,
    # so even a replica that came back in 30 s and caught up in a minute
    # would have been published as total loss. The measurement has to begin
    # once there is something to measure.
    replacement_started = time.time()
    after = wait_for_replacement(
        target,
        args.namespace,
        victim=victim,
        replicas_before=before,
        timeout_seconds=args.restart_timeout,
    )
    if _is_compose(args.target):
        replaced = bool(after) and len(after) >= len(before)
    else:
        replaced = victim not in after and len(after) >= len(before)
    replacement_seconds = round(time.time() - replacement_started, 1)
    print(
        f"chaos: replacement {'observed' if replaced else 'NOT observed'} after {replacement_seconds}s "
        f"(replicas now: {', '.join(after) or 'none'})"
    )

    drain_started = time.time()
    last = -1
    last_progress = time.time()
    while time.time() - drain_started < args.drain_timeout:
        count = count_marked(target, run_id)
        if count >= accepted:
            break
        if count != last:
            last = count
            last_progress = time.time()
        # A stall window, not a read count. The old rule -- three identical
        # reads five seconds apart -- gave up ~20 s after the last row, which
        # is shorter than a hard-killed consumer takes to be evicted from its
        # group and replaced (the coordinator alone waits out
        # `session.timeout.ms`). A stopping rule shorter than the recovery it
        # is watching for cannot tell "lost" from "not finished yet".
        #
        # This is a stopping rule, not a threshold: `--drain-timeout` is
        # unchanged, so rows that genuinely never arrive still fail.
        if time.time() - last_progress >= args.drain_stall_seconds:
            break
        time.sleep(5)

    seq_counts: dict[int, int] = {}
    for row in collect_alerts(target, run_id):
        seq_counts[row.seq] = seq_counts.get(row.seq, 0) + 1
    verdict = grade(accepted, seq_counts)

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
        "replacement_seconds": replacement_seconds,
        "drain_seconds": round(time.time() - drain_started, 1),
        **verdict.as_dict(),
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    # Replacement is reported first when it failed, because it is the fact
    # that makes the other number meaningless. A run with no consumer loses
    # everything that arrives after the kill *by construction*, so leading
    # with the loss count invites a reader to diagnose the durability path
    # for a defect that is not there -- which is exactly what happened to
    # "1650 of 3000 events lost" before the kill primitive was fixed.
    if not replaced:
        print(
            f"\nFAIL: the killed replica was not replaced within {args.restart_timeout}s "
            f"({len(verdict.missing)} event(s) also produced no alert, which this explains: with no "
            "consumer, every event accepted after the kill is lost by construction and the figure "
            "says nothing about durability).",
            file=sys.stderr,
        )
        return 1
    if not verdict.ok:
        print(
            f"\nFAIL: {len(verdict.missing)} event(s) produced no alert and {len(verdict.duplicated)} produced more than one, "
            f"across a replacement that was back in {replacement_seconds}s.",
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
    # The adapter's name, not the CLI's spelling: `main` reads `Target.name`,
    # and those two disagreed once already.
    compose_name = compose_target(Path("."), ["docker-compose.yml"], "").name
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
        (
            "a single-replica compose stack is runnable (CI boots one fusion container)",
            minimum_replicas(compose_name) == 1,
        ),
        (
            "a single-replica kubernetes stack is still refused",
            minimum_replicas("kubernetes") == 2,
        ),
        (
            "the compose branch is chosen for the adapter's target name, not the CLI's spelling",
            _is_compose(compose_name) and not _is_compose("kubernetes"),
        ),
        (
            "no crash rung is `docker kill` — the daemon treats that as an administrative stop and never restarts",
            all(
                argv[:2] != ["docker", "kill"]
                for _label, argv in crash_rungs("4242", "ghcr.io/beenuar/aisoc-fusion:latest", host_pid_is_ours=True)
            ),
        ),
        (
            "every crash rung delivers SIGKILL to the pid it was handed",
            all("4242" in " ".join(argv) and "-9" in " ".join(argv) for _label, argv in crash_rungs("4242", "img", host_pid_is_ours=True)),
        ),
        (
            "a pid that /proc cannot attribute to the container is never signalled directly — it may be a bystander",
            [label for label, _argv in crash_rungs("4242", "img", host_pid_is_ours=False)] == ["privileged --pid=host container"],
        ),
        (
            "the --pid=host rung reuses the victim's own image, so nothing is pulled mid-stream",
            any(
                "ghcr.io/beenuar/aisoc-fusion:latest" in argv
                for _label, argv in crash_rungs("1", "ghcr.io/beenuar/aisoc-fusion:latest", host_pid_is_ours=False)
            ),
        ),
        (
            "the drain stall window is long enough to outlast a consumer-group rejoin and short enough to fire inside the drain budget",
            # Asserted as a relation rather than a value: the numbers may move,
            # but a stall rule shorter than a Kafka session timeout cannot tell
            # "lost" from "not finished yet", and one longer than the drain
            # budget can never fire at all.
            30.0 < _DEFAULT_DRAIN_STALL_SECONDS < _DEFAULT_DRAIN_TIMEOUT_SECONDS,
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
