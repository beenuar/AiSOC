#!/usr/bin/env python3
"""End-to-end load harness: ingest -> Kafka -> fusion -> Postgres.

What this measures, and what the existing harness next to it does not
---------------------------------------------------------------------
``throughput_harness.py`` times one function, ``promote_normalized_event``,
in one process. That is the right shape for a regression floor on the CPU-bound
stage, and it is not production evidence: it never opens a socket, never
serialises to Kafka, never writes a row, and never competes for a runner's
page cache with a broker.

This harness drives the deployed stack. It pushes attributable events through
the real ingest endpoint with the real credential, waits for them to arrive in
the real ``alerts`` table, and reports:

* **sustained events per second**, twice. ``ingest_accepted_eps`` is what the
  front door took. ``pipeline_eps`` is how fast alerts actually landed, which
  is the number that degrades first when fusion falls behind, and the two
  diverge exactly when the queue is absorbing the difference.
* **event-to-alert latency** p50/p95/p99, per event rather than averaged over
  a batch, and corrected for the measured offset between this process's clock
  and the database's rather than assuming they agree.
* **consumer lag** on the fusion group, sampled while the run is in flight and
  again once it has drained. A lag figure taken only at the end says nothing:
  a drained queue reads zero however far behind it got.
* **dead-letter rate**, as rows that appeared in ``aisoc_dead_letters``
  during the window over events attempted.
* **resource use**, sampled from the container runtime during the run.
* **delivery**: how many of the accepted events became exactly one alert, how
  many are missing, and how many produced more than one row.

Two things this deliberately refuses to do
------------------------------------------
It never renders a figure it did not measure as ``0``. Every metric is a
``Measurement`` that is either measured with a value and a sample count, or
unmeasured with the reason why, and the JSON carries no ``value`` key in the
second case. A p99 over zero correlated alerts is not "0 ms".

And it never publishes a number without the hardware it was taken on and the
date. ``scripts/check_perf_results.py`` enforces that on everything committed
under ``docs/perf/results/``, including the label saying this is not a
production service-level objective. CI runners are shared, throttled and
noisy; a floor here fires on a catastrophic regression, not on jitter.

Usage
-----
::

    # against a local `make up` stack
    python3 scripts/perf/load_harness.py \
        --token "$AISOC_INGEST_TOKEN" --events 20000 --workers 8

    # against a kind/k3d deployment of the Helm chart
    python3 scripts/perf/load_harness.py --target kubernetes \
        --namespace aisoc --token "$AISOC_INGEST_TOKEN" --events 5000

    # regression floor, for perf.yml
    python3 scripts/perf/load_harness.py --token ... --assert-eps-floor 50 \
        --assert-p95-ceiling-ms 60000
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: Must equal ``MarkerPrefix`` in services/demo-producer/main.go. The producer
#: stamps it into every title; this harness matches alert rows on it. A test
#: pins the two together, because a silent disagreement would look like a
#: pipeline that lost every event.
MARKER_PREFIX = "aisoc-load"

#: ``aisoc-load <run-id> seq=<n> t=<unix-nanoseconds>``
_TITLE_RE = re.compile(rf"^{re.escape(MARKER_PREFIX)} (?P<run>[A-Za-z0-9_-]+) seq=(?P<seq>\d+) t=(?P<sent>\d+)$")

_FUSION_GROUP = "aisoc-fusion-consumer"
_DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"

#: The containers whose CPU and memory are worth publishing beside a
#: throughput figure. A number without them describes a machine, not a stack.
_RESOURCE_SERVICES = ("ingest", "fusion", "kafka", "postgres", "api", "agents")


# ── measurement ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Measurement:
    """A number and what it is over, or the reason there is no number.

    The repository's standing rule is that a figure that was not measured
    reads "not measured", never ``0``. Encoding that as a type rather than a
    convention is what stops a formatter rounding an unrun metric into a
    confident zero: :meth:`as_dict` emits no ``value`` key at all when the
    measurement did not happen.
    """

    name: str
    unit: str
    value: float | None = None
    samples: int = 0
    reason: str | None = None

    @property
    def measured(self) -> bool:
        return self.value is not None

    def render(self) -> str:
        if not self.measured:
            return f"not measured ({self.reason or 'no reason recorded'})"
        return f"{self.value:,.2f} {self.unit} (n={self.samples:,})"

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"unit": self.unit, "measured": self.measured, "samples": self.samples}
        if self.measured:
            out["value"] = self.value
        else:
            out["reason"] = self.reason or "no reason recorded"
        return out


def measured(name: str, unit: str, value: float, samples: int) -> Measurement:
    return Measurement(name=name, unit=unit, value=value, samples=samples)


def unmeasured(name: str, unit: str, reason: str) -> Measurement:
    return Measurement(name=name, unit=unit, reason=reason)


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile. Caller sorts; caller guarantees non-empty."""
    if not sorted_values:
        raise ValueError("percentile of an empty sample")
    rank = max(1, min(len(sorted_values), int(round(fraction * len(sorted_values) + 0.5))))
    return sorted_values[rank - 1]


# ── target adapters ─────────────────────────────────────────────────────────


@dataclass
class Target:
    """How to reach the datastores and the runtime, for one deployment shape.

    ``compose`` and ``kubernetes`` differ only in the command prefixes, so the
    measurement code below is identical for both. That matters: if the two
    paths measured differently, publishing a compose number beside a kind
    number would be comparing two harnesses rather than two deployments.
    """

    name: str
    psql: list[str]
    kafka: list[str]
    stats: list[str] | None
    ingest_url: str

    def sql(self, query: str, *, timeout: int = 120) -> str:
        done = subprocess.run(  # noqa: S603 - fixed argv built from operator-supplied prefix
            [*self.psql, "-tAc", query],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if done.returncode != 0:
            raise RuntimeError(f"psql failed ({done.returncode}): {(done.stderr or done.stdout).strip()[:400]}")
        return done.stdout.strip()

    def kafka_lag(self, group: str, *, timeout: int = 60) -> tuple[int | None, str]:
        """Total lag across the group's partitions, or None and why not."""
        if not self.kafka:
            return None, "no kafka command configured for this target"
        try:
            done = subprocess.run(  # noqa: S603
                [*self.kafka, "--bootstrap-server", "localhost:9092", "--describe", "--group", group],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, f"kafka-consumer-groups did not answer: {exc}"
        if done.returncode != 0:
            return None, f"kafka-consumer-groups failed: {(done.stderr or done.stdout).strip()[:200]}"
        total = 0
        rows = 0
        for line in done.stdout.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] != group:
                continue
            try:
                total += int(fields[5])
            except ValueError:
                continue
            rows += 1
        if rows == 0:
            return None, f"consumer group {group} reported no partitions"
        return total, ""


def compose_target(project_dir: Path, compose_files: list[str], ingest_url: str) -> Target:
    base = ["docker", "compose"]
    for spec in compose_files:
        base += ["-f", spec]
    return Target(
        name="docker-compose",
        psql=[*base, "exec", "-T", "postgres", "psql", "-U", "aisoc", "-d", "aisoc"],
        kafka=[*base, "exec", "-T", "kafka", "kafka-consumer-groups"],
        stats=["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
        ingest_url=ingest_url,
    )


def kubernetes_target(namespace: str, release: str, ingest_url: str, postgres_ref: str, kafka_ref: str) -> Target:
    kubectl = ["kubectl", "-n", namespace]
    return Target(
        name="kubernetes",
        psql=[*kubectl, "exec", "-i", postgres_ref, "--", "psql", "-U", "aisoc", "-d", "aisoc"],
        kafka=[*kubectl, "exec", "-i", kafka_ref, "--", "/opt/kafka/bin/kafka-consumer-groups.sh"],
        # `kubectl top` needs metrics-server, which kind does not ship. Absent
        # is reported as absent rather than as zero usage.
        stats=[*kubectl, "top", "pods", "--no-headers"],
        ingest_url=ingest_url,
    )


# ── the run ─────────────────────────────────────────────────────────────────


@dataclass
class ProducerSummary:
    raw: dict[str, Any]

    @property
    def run_id(self) -> str:
        return str(self.raw["run_id"])

    @property
    def accepted(self) -> int:
        return int(self.raw["accepted_events"])

    @property
    def attempted(self) -> int:
        return int(self.raw["attempted_events"])

    @property
    def wall_seconds(self) -> float:
        return float(self.raw["wall_seconds"])

    @property
    def accepted_eps(self) -> float:
        return float(self.raw["accepted_eps"])


@dataclass
class AlertRow:
    seq: int
    sent_epoch: float
    created_epoch: float


@dataclass
class ResourceSample:
    at: float
    rows: dict[str, dict[str, str]] = field(default_factory=dict)


def hardware_fingerprint() -> dict[str, Any]:
    """Where the number came from. Published beside every figure, always."""
    info: dict[str, Any] = {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    if platform.system() == "Darwin":
        for key, label in (("machdep.cpu.brand_string", "cpu"), ("hw.memsize", "memory_bytes")):
            out = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, check=False)  # noqa: S603
            if out.returncode == 0 and out.stdout.strip():
                info[label] = out.stdout.strip()
    elif platform.system() == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal"):
                    info["memory_bytes"] = str(int(line.split()[1]) * 1024)
                    break
        except OSError:
            pass
    if shutil.which("docker"):
        out = subprocess.run(  # noqa: S603
            ["docker", "info", "--format", "{{.ServerVersion}}|{{.NCPU}}|{{.MemTotal}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode == 0 and "|" in out.stdout:
            version, ncpu, memtotal = out.stdout.strip().split("|", 2)
            info["container_runtime"] = f"docker {version}"
            info["runtime_cpus"] = ncpu
            info["runtime_memory_bytes"] = memtotal
    if os.environ.get("GITHUB_ACTIONS") == "true":
        info["ci_runner"] = os.environ.get("RUNNER_NAME") or "github-actions"
        info["ci_os"] = os.environ.get("ImageOS") or os.environ.get("RUNNER_OS", "")
    return info


def measure_clock_offset(target: Target, rounds: int = 5) -> tuple[float, float]:
    """Seconds to add to a database timestamp to express it in this clock.

    The producer stamps its own clock into every title and the database stamps
    ``created_at`` with its own. Subtracting one from the other without this
    correction publishes the offset between two machines as pipeline latency.
    Measured by bracketing each query with local reads and taking the midpoint,
    so the round trip itself does not enter the estimate. Returns the median
    offset and the spread, and the spread is published: a wide one means the
    latency figures carry that much uncertainty.
    """
    offsets: list[float] = []
    for _ in range(rounds):
        before = time.time()
        db_epoch = float(target.sql("select extract(epoch from clock_timestamp())"))
        after = time.time()
        offsets.append(((before + after) / 2.0) - db_epoch)
    offsets.sort()
    spread = offsets[-1] - offsets[0]
    return statistics.median(offsets), spread


def run_producer(
    *,
    producer_bin: str | None,
    root: Path,
    ingest_url: str,
    token: str,
    tenant: str,
    events: int,
    workers: int,
    batch: int,
    target_eps: int,
    run_id: str,
    summary_path: Path,
) -> ProducerSummary:
    if producer_bin:
        argv = [producer_bin]
    else:
        if not shutil.which("go"):
            raise RuntimeError("no --producer-bin given and `go` is not on PATH to build services/demo-producer")
        argv = ["go", "run", "./services/demo-producer"]
    argv += [
        "--load",
        "--ingest-url",
        ingest_url,
        "--token",
        token,
        "--tenant",
        tenant,
        "--total",
        str(events),
        "--workers",
        str(workers),
        "--batch",
        str(batch),
        "--target-eps",
        str(target_eps),
        "--run-id",
        run_id,
        "--summary",
        str(summary_path),
    ]
    done = subprocess.run(argv, cwd=root, capture_output=True, text=True, check=False)  # noqa: S603
    if done.returncode != 0:
        raise RuntimeError(f"producer failed ({done.returncode}): {(done.stderr or done.stdout).strip()[-600:]}")
    return ProducerSummary(json.loads(summary_path.read_text(encoding="utf-8")))


def collect_alerts(target: Target, run_id: str) -> list[AlertRow]:
    query = f"select title, extract(epoch from created_at) from alerts where title like '{MARKER_PREFIX} {run_id} %'"
    rows: list[AlertRow] = []
    for line in target.sql(query, timeout=300).splitlines():
        if "|" not in line:
            continue
        title, created = line.rsplit("|", 1)
        match = _TITLE_RE.match(title.strip())
        if not match or match.group("run") != run_id:
            continue
        rows.append(
            AlertRow(
                seq=int(match.group("seq")),
                sent_epoch=int(match.group("sent")) / 1e9,
                created_epoch=float(created),
            )
        )
    return rows


def sample_resources(target: Target) -> ResourceSample:
    sample = ResourceSample(at=time.time())
    if not target.stats:
        return sample
    try:
        done = subprocess.run(target.stats, capture_output=True, text=True, timeout=45, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return sample
    if done.returncode != 0:
        return sample
    for line in done.stdout.splitlines():
        fields = line.split("\t") if "\t" in line else line.split()
        if len(fields) < 3:
            continue
        name = fields[0]
        short = name.replace("aisoc-", "").split("-")[0]
        if short not in _RESOURCE_SERVICES:
            continue
        sample.rows[short] = {"cpu": fields[1], "memory": " ".join(fields[2:])}
    return sample


def build_report(
    *,
    target: Target,
    summary: ProducerSummary,
    alerts: list[AlertRow],
    clock_offset: float,
    clock_spread: float,
    lag_in_flight: tuple[int | None, str],
    lag_drained: tuple[int | None, str],
    dead_letters: int | None,
    dead_letter_reason: str,
    resources: list[ResourceSample],
    drain_seconds: float,
    settled: bool,
) -> dict[str, Any]:
    accepted = summary.accepted
    seen: dict[int, int] = {}
    for row in alerts:
        seen[row.seq] = seen.get(row.seq, 0) + 1
    duplicates = sum(count - 1 for count in seen.values() if count > 1)
    missing = accepted - len(seen)

    latencies_ms: list[float] = sorted(((row.created_epoch + clock_offset) - row.sent_epoch) * 1000.0 for row in alerts)

    metrics: dict[str, Measurement] = {}
    if latencies_ms:
        metrics["latency_p50_ms"] = measured("latency_p50_ms", "ms", percentile(latencies_ms, 0.50), len(latencies_ms))
        metrics["latency_p95_ms"] = measured("latency_p95_ms", "ms", percentile(latencies_ms, 0.95), len(latencies_ms))
        metrics["latency_p99_ms"] = measured("latency_p99_ms", "ms", percentile(latencies_ms, 0.99), len(latencies_ms))
        metrics["latency_max_ms"] = measured("latency_max_ms", "ms", latencies_ms[-1], len(latencies_ms))
    else:
        why = "no alert rows carried this run's marker"
        for name in ("latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "latency_max_ms"):
            metrics[name] = unmeasured(name, "ms", why)

    metrics["ingest_accepted_eps"] = (
        measured("ingest_accepted_eps", "events/s", summary.accepted_eps, accepted)
        if accepted > 0
        else unmeasured("ingest_accepted_eps", "events/s", "ingest accepted no events")
    )

    if len(alerts) >= 2:
        span = max(r.created_epoch for r in alerts) - min(r.created_epoch for r in alerts)
        metrics["pipeline_eps"] = (
            measured("pipeline_eps", "alerts/s", len(alerts) / span, len(alerts))
            if span > 0
            else unmeasured("pipeline_eps", "alerts/s", "every alert carried the same timestamp; span too short to divide")
        )
    else:
        metrics["pipeline_eps"] = unmeasured("pipeline_eps", "alerts/s", "fewer than two alerts landed")

    metrics["delivery_ratio"] = (
        measured("delivery_ratio", "fraction", len(seen) / accepted, accepted)
        if accepted > 0
        else unmeasured("delivery_ratio", "fraction", "ingest accepted no events")
    )

    for key, (value, reason) in (("consumer_lag_in_flight", lag_in_flight), ("consumer_lag_drained", lag_drained)):
        metrics[key] = measured(key, "messages", float(value), 1) if value is not None else unmeasured(key, "messages", reason)

    if dead_letters is not None and summary.attempted > 0:
        metrics["dead_letter_rate"] = measured("dead_letter_rate", "fraction", dead_letters / summary.attempted, summary.attempted)
    else:
        metrics["dead_letter_rate"] = unmeasured("dead_letter_rate", "fraction", dead_letter_reason or "no attempted events")

    return {
        "schema": "aisoc.load_harness/v1",
        # Every published figure carries these two. check_perf_results.py
        # fails a committed result that drops either, because a throughput
        # number without the machine and the date is not a measurement.
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "hardware": hardware_fingerprint(),
        "deployment": target.name,
        "not_a_production_slo": True,
        "slo_disclaimer": (
            "These are measurements of one deployment on the hardware named above, on the date named "
            "above. They are not a service-level objective and no support commitment is derived from "
            "them. Sustained throughput on other hardware, other storage and other event mixes will "
            "differ. The regression floors in perf.yml are set well below the measured values so they "
            "fire on a catastrophic regression rather than on runner jitter."
        ),
        "run": {
            "run_id": summary.run_id,
            "attempted_events": summary.attempted,
            "accepted_events": accepted,
            "alerts_observed": len(alerts),
            "distinct_events_alerted": len(seen),
            "missing_events": missing,
            "duplicate_alert_rows": duplicates,
            "push_wall_seconds": summary.wall_seconds,
            "drain_wall_seconds": drain_seconds,
            "drain_settled": settled,
            "clock_offset_seconds": clock_offset,
            "clock_offset_spread_seconds": clock_spread,
            "producer": summary.raw,
        },
        "metrics": {name: m.as_dict() for name, m in sorted(metrics.items())},
        "resources": [{"at": datetime.fromtimestamp(s.at, tz=UTC).isoformat(timespec="seconds"), "containers": s.rows} for s in resources],
    }


def render_text(report: dict[str, Any]) -> str:
    hw = report["hardware"]
    lines = [
        f"AiSOC load harness · {report['deployment']} · {report['measured_at']}",
        f"  hardware: {hw.get('cpu', hw.get('arch'))} · {hw.get('cpu_count')} cpu · runtime {hw.get('container_runtime', 'n/a')}",
        "  NOT A PRODUCTION SLO. One deployment, this hardware, this date.",
        "",
    ]
    run = report["run"]
    lines.append(
        f"  events: {run['accepted_events']:,} accepted of {run['attempted_events']:,} attempted; "
        f"{run['distinct_events_alerted']:,} alerted, {run['missing_events']:,} missing, "
        f"{run['duplicate_alert_rows']:,} duplicate rows"
    )
    lines.append("")
    for name, body in report["metrics"].items():
        if body["measured"]:
            lines.append(f"  {name:<26} {body['value']:>14,.2f} {body['unit']}  (n={body['samples']:,})")
        else:
            lines.append(f"  {name:<26} {'not measured':>14}          ({body['reason']})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=("compose", "kubernetes"), default="compose")
    parser.add_argument("--events", type=int, default=20000, help="events to push")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--batch", type=int, default=50)
    parser.add_argument("--target-eps", type=int, default=0, help="0 saturates; otherwise pace to this rate")
    parser.add_argument("--token", default=os.environ.get("AISOC_INGEST_TOKEN", ""))
    parser.add_argument("--tenant", default=os.environ.get("AISOC_TENANT_ID", _DEFAULT_TENANT))
    parser.add_argument("--ingest-url", default=os.environ.get("AISOC_INGEST_URL", "http://localhost:8081/v1/ingest/batch"))
    parser.add_argument("--compose-file", action="append", default=[], help="repeatable; passed to docker compose -f")
    parser.add_argument("--namespace", default="aisoc")
    parser.add_argument("--release", default="aisoc")
    parser.add_argument("--postgres-ref", default="statefulset/postgres", help="kubernetes: what to `kubectl exec` psql in")
    parser.add_argument("--kafka-ref", default="statefulset/aisoc-kafka", help="kubernetes: what to `kubectl exec` kafka tools in")
    parser.add_argument(
        "--producer-bin", default=os.environ.get("AISOC_PRODUCER_BIN", ""), help="prebuilt demo-producer; otherwise `go run`"
    )
    parser.add_argument("--drain-timeout", type=int, default=300, help="seconds to wait for alerts to stop arriving")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--out", type=Path, help="write the JSON report here")
    parser.add_argument("--assert-eps-floor", type=float, help="fail if pipeline throughput is below this")
    parser.add_argument("--assert-p95-ceiling-ms", type=float, help="fail if p95 event-to-alert latency exceeds this")
    parser.add_argument("--assert-no-loss", action="store_true", help="fail if any accepted event produced no alert")
    args = parser.parse_args(argv)

    root = repo_root()
    if not (root / "services" / "demo-producer").is_dir():
        print("load_harness: services/demo-producer is not in this tree; nothing to drive", file=sys.stderr)
        return 2
    if not args.token:
        print(
            "load_harness: no ingest credential. Pass --token or set AISOC_INGEST_TOKEN "
            "(`make ingest-token`). /v1/ingest/batch refuses an unauthenticated push.",
            file=sys.stderr,
        )
        return 2

    compose_files = args.compose_file or ["docker-compose.yml"]
    target = (
        compose_target(root, compose_files, args.ingest_url)
        if args.target == "compose"
        else kubernetes_target(args.namespace, args.release, args.ingest_url, args.postgres_ref, args.kafka_ref)
    )

    try:
        clock_offset, clock_spread = measure_clock_offset(target)
    except (RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"load_harness: cannot reach the alert store, so nothing can be measured: {exc}", file=sys.stderr)
        return 2

    run_id = f"p{int(time.time()) % 100000000:08d}"
    baseline_dl = target.sql("select count(*) from aisoc_dead_letters")
    summary_path = Path(os.environ.get("TMPDIR", "/tmp")) / f"aisoc-load-{run_id}.json"

    resources: list[ResourceSample] = []
    push_started = time.time()
    summary = run_producer(
        producer_bin=args.producer_bin or None,
        root=root,
        ingest_url=args.ingest_url,
        token=args.token,
        tenant=args.tenant,
        events=args.events,
        workers=args.workers,
        batch=args.batch,
        target_eps=args.target_eps,
        run_id=run_id,
        summary_path=summary_path,
    )
    # Sampled immediately after the push rather than after the drain: the
    # queue is at its deepest here, and a lag read once the pipeline has caught
    # up is zero however far behind it got.
    lag_in_flight = target.kafka_lag(_FUSION_GROUP)
    resources.append(sample_resources(target))

    drain_started = time.time()
    previous = -1
    settled = False
    while time.time() - drain_started < args.drain_timeout:
        count = int(target.sql(f"select count(*) from alerts where title like '{MARKER_PREFIX} {run_id} %'") or 0)
        if count >= summary.accepted:
            settled = True
            break
        if count == previous and count > 0:
            # Two identical reads five seconds apart with events still missing.
            # Stop waiting and report the shortfall rather than burning the
            # timeout: a stalled consumer is the finding.
            settled = True
            break
        previous = count
        if len(resources) < 12:
            resources.append(sample_resources(target))
        time.sleep(5)
    drain_seconds = time.time() - drain_started

    alerts = collect_alerts(target, run_id)
    lag_drained = target.kafka_lag(_FUSION_GROUP)
    try:
        after_dl = int(target.sql("select count(*) from aisoc_dead_letters") or 0)
        dead_letters: int | None = max(0, after_dl - int(baseline_dl or 0))
        dl_reason = ""
    except (RuntimeError, ValueError) as exc:
        dead_letters, dl_reason = None, f"dead-letter table unreadable: {exc}"

    report = build_report(
        target=target,
        summary=summary,
        alerts=alerts,
        clock_offset=clock_offset,
        clock_spread=clock_spread,
        lag_in_flight=lag_in_flight,
        lag_drained=lag_drained,
        dead_letters=dead_letters,
        dead_letter_reason=dl_reason,
        resources=resources,
        drain_seconds=drain_seconds,
        settled=settled,
    )
    report["run"]["total_wall_seconds"] = time.time() - push_started

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2) if args.json else render_text(report))

    failures: list[str] = []
    metrics = report["metrics"]
    if args.assert_eps_floor is not None:
        body = metrics["pipeline_eps"]
        if not body["measured"]:
            failures.append(f"pipeline throughput was not measured ({body['reason']}), so the floor cannot be met")
        elif body["value"] < args.assert_eps_floor:
            failures.append(f"pipeline throughput {body['value']:.1f}/s is below the floor {args.assert_eps_floor:.1f}/s")
    if args.assert_p95_ceiling_ms is not None:
        body = metrics["latency_p95_ms"]
        if not body["measured"]:
            failures.append(f"p95 latency was not measured ({body['reason']}), so the ceiling cannot be met")
        elif body["value"] > args.assert_p95_ceiling_ms:
            failures.append(f"p95 latency {body['value']:.0f}ms exceeds the ceiling {args.assert_p95_ceiling_ms:.0f}ms")
    if args.assert_no_loss and report["run"]["missing_events"] > 0:
        failures.append(f"{report['run']['missing_events']} accepted events produced no alert")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


def _self_test() -> int:
    """Prove the two properties a reader has to trust before believing a number."""
    checks: list[tuple[str, bool]] = []

    empty = build_report(
        target=Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
        summary=ProducerSummary(
            {
                "run_id": "x",
                "attempted_events": 10,
                "accepted_events": 0,
                "wall_seconds": 1.0,
                "accepted_eps": 0.0,
            }
        ),
        alerts=[],
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(None, "broker unreachable"),
        lag_drained=(None, "broker unreachable"),
        dead_letters=None,
        dead_letter_reason="table unreadable",
        resources=[],
        drain_seconds=0.0,
        settled=False,
    )
    unmeasured_bodies = [body for body in empty["metrics"].values() if not body["measured"]]
    checks.append(
        (
            "a run that measured nothing emits no `value` key anywhere, so no formatter can render it as 0",
            len(unmeasured_bodies) == len(empty["metrics"]) and all("value" not in b for b in unmeasured_bodies),
        )
    )
    checks.append(
        (
            "every unmeasured metric carries the reason it was not measured",
            all(b.get("reason") for b in unmeasured_bodies),
        )
    )

    real = build_report(
        target=Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
        summary=ProducerSummary({"run_id": "x", "attempted_events": 3, "accepted_events": 3, "wall_seconds": 1.0, "accepted_eps": 3.0}),
        alerts=[AlertRow(seq=i, sent_epoch=100.0, created_epoch=100.0 + (i + 1) / 10) for i in range(3)],
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(7, ""),
        lag_drained=(0, ""),
        dead_letters=0,
        dead_letter_reason="",
        resources=[],
        drain_seconds=1.0,
        settled=True,
    )
    checks.append(
        (
            "a real zero stays a zero: 0 dead letters and 0 drained lag are measured values, not absences",
            real["metrics"]["dead_letter_rate"] == {"unit": "fraction", "measured": True, "samples": 3, "value": 0.0}
            and real["metrics"]["consumer_lag_drained"]["value"] == 0.0,
        )
    )
    checks.append(
        (
            "latency is corrected for the clock offset rather than assuming the two clocks agree",
            build_report(
                target=Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
                summary=ProducerSummary(
                    {"run_id": "x", "attempted_events": 1, "accepted_events": 1, "wall_seconds": 1.0, "accepted_eps": 1.0}
                ),
                alerts=[AlertRow(seq=0, sent_epoch=100.0, created_epoch=105.0)],
                clock_offset=-4.0,
                clock_spread=0.0,
                lag_in_flight=(0, ""),
                lag_drained=(0, ""),
                dead_letters=0,
                dead_letter_reason="",
                resources=[],
                drain_seconds=0.0,
                settled=True,
            )["metrics"]["latency_p50_ms"]["value"]
            == 1000.0,
        )
    )
    # Two accepted events, but both alert rows carry seq=0: one event was
    # duplicated and one never arrived. Both have to be visible, because a
    # count of rows alone reads as full delivery.
    doubled = build_report(
        target=Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
        summary=ProducerSummary({"run_id": "x", "attempted_events": 2, "accepted_events": 2, "wall_seconds": 1.0, "accepted_eps": 2.0}),
        alerts=[AlertRow(seq=0, sent_epoch=1.0, created_epoch=1.1), AlertRow(seq=0, sent_epoch=1.0, created_epoch=1.2)],
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(0, ""),
        lag_drained=(0, ""),
        dead_letters=0,
        dead_letter_reason="",
        resources=[],
        drain_seconds=0.0,
        settled=True,
    )
    checks.append(
        (
            "two rows for one sequence number report one duplicate and one loss, not two deliveries",
            doubled["run"]["duplicate_alert_rows"] == 1
            and doubled["run"]["missing_events"] == 1
            and doubled["run"]["alerts_observed"] == 2,
        )
    )

    title = f"{MARKER_PREFIX} run1 seq=12 t=1700000000123456789"
    match = _TITLE_RE.match(title)
    checks.append(("the marker this harness matches is the marker the producer writes", bool(match) and match.group("seq") == "12"))

    ok = True
    for description, passed in checks:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    print()
    print("load_harness.py: self-test " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        # The shared empty-tree refusal, plus the properties only this file can
        # express. Both have to hold: a harness that cannot tell "measured 0"
        # from "did not measure" is worse than no harness.
        #
        # The path is passed relative to ``scripts/`` rather than through
        # ``self_test_if_requested``, which takes a basename: this file lives
        # in ``scripts/perf/`` and the probe would have launched
        # ``scripts/load_harness.py``, which does not exist. A missing file
        # exits non-zero, so the refusal would have passed while proving
        # nothing at all about this harness.
        sys.exit(_self_test() or self_test_main("perf/load_harness.py", []))
    sys.exit(main())
