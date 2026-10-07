---
id: performance
title: Measured performance
sidebar_label: Performance
---

# Measured performance

**These figures are not a service-level objective.** They are what one
deployment did on one machine on one day, and they are published so you have a
starting point for capacity planning rather than a promise. Your storage, your
event mix, your detection corpus and your network will move every number here.
Nothing in the project's support arrangements is derived from this page.

Every figure below was produced by `scripts/perf/load_harness.py` against a
running stack: real events through the real ingest endpoint with a real
credential, through Kafka, through fusion, into the `alerts` table in
PostgreSQL. Nothing is simulated and nothing is extrapolated. The raw JSON for
each run is committed under `docs/perf/results/` in the repository, and `scripts/check_perf_results.py` fails the build if a published figure loses
its hardware, its date or this disclaimer.

## The machine

| | |
|---|---|
| Host | Apple M5 Max, 18 cores, macOS 25.5.0 (arm64) |
| Container runtime | Docker Engine 29.5.2, 8 CPUs and 15.6 GiB allocated to the VM |
| Date | 2026-09-27 |

A laptop is not a server. The absolute numbers would be different on a
dedicated host with NVMe storage and a real broker cluster; what generalises is
the *shape*, in particular that the ceiling is fusion's per-event work and not
ingest.

## How to read the two rows for each deployment

Each deployment was measured twice, because one number cannot answer both
questions people ask.

**Saturation** pushes as fast as the producer can and reports what drained.
This is the throughput ceiling. Latency in this row is mostly queue wait: the
front door accepts faster than fusion consumes, the difference accumulates in
Kafka, and an event's age is dominated by how long it sat there. That is the
correct behaviour under overload and it is a bad way to quote latency.

**Steady state** paces the producer below the measured drain rate. Lag stays at
zero and the latency figures describe the pipeline rather than the backlog.
This is the row to plan against.

## Single host, Docker Compose (CORE profile), 2026-09-27

| | Saturation | Steady state |
|---|---|---|
| Events pushed | 20,000 | 12,000 |
| Ingest accepted | 397.3 events/s | 79.7 events/s |
| Pipeline drain rate | **176.9 alerts/s** | 80.1 alerts/s |
| Event-to-alert p50 | 30,415 ms | **976 ms** |
| Event-to-alert p95 | 60,707 ms | **1,091 ms** |
| Event-to-alert p99 | 63,776 ms | **1,156 ms** |
| Event-to-alert max | 64,713 ms | 1,273 ms |
| Peak consumer lag | 10,759 messages | 0 messages |
| Lag after drain | 0 messages | 0 messages |
| Dead-letter rate | 0.00 | 0.00 |
| Events that produced no alert | 0 | 0 |
| Events that produced more than one alert | 0 | 0 |

Container usage at saturation, sampled from the runtime during the run: fusion
held one core at 60 to 100% on 74 MiB, Kafka spiked to 82% CPU on 454 MiB of
its 1.5 GiB limit, PostgreSQL sat near 7% CPU on 97 MiB, and ingest never
exceeded 29 MiB. Fusion is the bottleneck, which is why the drain rate is
roughly 45% of what ingest accepts.

## Single host, Docker Compose (CORE profile), 2026-10-07

The depth plan's Phase 0 baseline, taken so every later change to ingest,
fusion or detection has a "before" on the same harness. Saturation only --
no steady-state pacing was run, so there is no row to plan latency against
here; use the 2026-09-27 steady-state column for that.

A different host from the run above, which is most of the difference in the
drain rate: a 6-CPU, 15.6 GiB Linux VM on Apple silicon, against the
18-core host the September run used. Quoting the two drain rates against
each other would be comparing machines, not releases.

| | Saturation |
|---|---|
| Events pushed | 20,000 |
| Ingest accepted | 397.6 events/s |
| Pipeline drain rate | **130.3 alerts/s** |
| Event-to-alert p50 | 54,903 ms |
| Event-to-alert p95 | 100,248 ms |
| Event-to-alert p99 | 103,933 ms |
| Event-to-alert max | 105,194 ms |
| Peak consumer lag | 13,952 messages |
| Lag after drain | 0 messages |
| Dead-letter rate | 0.00 |
| Events that produced no alert | 0 |
| Events that produced more than one alert | 0 |

Fusion again held one core at roughly 77% while ingest never exceeded 29 MiB,
so the bottleneck is where the September run found it. Artefact:
`docs/perf/results/2026-10-07-compose-depth-baseline.json`.

**The harness could not run from a clean checkout before this run.** It
invoked `go run ./services/demo-producer` from the repository root, where
there is no `go.mod` -- the producer is its own module -- so the subprocess
failed before starting. Earlier published figures must have come from a
prebuilt `--producer-bin`, which needs no module context.

## Three-node Kubernetes (kind), 2026-09-27

Installed from `infra/helm/aisoc` with `values-ha.yaml` and
`ci/kind-values.yaml`: three Kafka brokers in KRaft mode with replication
factor 3 and `min.insync.replicas=2`, two ingest replicas, two fusion replicas
and one API replica, on three kind nodes, against an external PostgreSQL and
Redis. Topics carry three partitions so both fusion replicas consume.

| | Saturation | Steady state |
|---|---|---|
| Events pushed | 10,000 | 9,000 |
| Ingest accepted | 397.2 events/s | 79.1 events/s |
| Pipeline drain rate | **214.0 alerts/s** | 79.8 alerts/s |
| Event-to-alert p50 | 4,579 ms | **982 ms** |
| Event-to-alert p95 | 20,034 ms | **1,317 ms** |
| Event-to-alert p99 | 22,988 ms | **1,437 ms** |
| Event-to-alert max | 23,571 ms | 1,638 ms |
| Peak consumer lag | 3,059 messages | 0 messages |
| Lag after drain | 0 messages | 0 messages |
| Dead-letter rate | 0.00 | 0.00 |
| Events that produced no alert | 0 | 0 |
| Events that produced more than one alert | 0 | 0 |

**Per-pod CPU and memory were not measured on this deployment.** `kubectl top`
needs metrics-server and kind does not ship one, so the harness recorded the
absence rather than a zero. The committed JSON carries empty `containers`
objects for exactly that reason.

Two fusion replicas across three partitions drained 214 alerts/s against
compose's 177 on the same laptop, sharing it with three brokers and a
three-node control plane. The comparison is indicative, not a scaling law:
kind nodes are containers on the same kernel, so this is not two machines'
worth of hardware.

## Failure injection: killing a fusion replica mid-stream

`scripts/chaos/fusion_restart.py`, run against the Kubernetes deployment above
on 2026-09-27. 6,000 events paced at 100/s; one fusion pod destroyed with
`--grace-period=0 --force` 24.3 seconds in, with 1,840 alerts already written.

| | |
|---|---|
| Events accepted by ingest | 6,000 |
| Alert rows after recovery | 6,000 |
| Events that produced no alert | 0 |
| Events that produced more than one alert | 0 |
| Time for the backlog to clear after the kill | 5.4 s |

The assertion is made against PostgreSQL, not against anything the replacement
pod reports about itself. Two mechanisms make it hold, and a regression in
either shows up in a different column: the consumer commits offsets only after
a message is fully processed, so a kill re-delivers rather than losing
(missing count), and the alert sink inserts under a per-tenant dedup-hash
guard, so the re-delivery does not become a second row (duplicate count).

## Running it yourself

```bash
make up
make ingest-token                       # mint a credential

AISOC_INGEST_TOKEN=<token> python3 scripts/perf/load_harness.py \
    --target compose --events 20000 --workers 8

AISOC_INGEST_TOKEN=<token> python3 scripts/perf/load_harness.py \
    --target compose --events 12000 --target-eps 120   # steady state
```

For Kubernetes, see [Reference HA deployment](./ha-deployment.md).

## What CI enforces, and what it does not

`.github/workflows/perf.yml` runs three things:

1. the in-process fusion hot-path harness with a generous regression floor;
2. the storage cost model drift check;
3. this end-to-end harness against a Compose stack, nightly and on demand,
   with a floor far below the figures above.

The floors exist to catch a catastrophic regression, such as an I/O call
appearing on the promotion hot path. They are deliberately not set near the
measured values: GitHub runners are shared, throttled and noisy, and a gate
that fires on runner jitter gets disabled within a week. **A passing perf job
is not evidence that any number on this page still holds on your hardware.**
