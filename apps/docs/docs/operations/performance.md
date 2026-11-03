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

## Single host, Docker Compose, realistic mix, 2026-10-11

Every run above pushes one event shape, and every instance of it becomes
an alert. No estate looks like that. In a real deployment almost all
telemetry is routine, and the work fusion does is evaluating the detection
corpus against traffic that matches nothing — so an all-alerting harness
over-measures the alert path and under-measures detection.

This run is **one alerting event in every hundred** (`--alert-every 100`).
The other ninety-nine are routine authentication telemetry: successful
sign-ins, satisfied MFA challenges, read-only console views.

| | Saturation, 1-in-100 mix |
|---|---|
| Events pushed | 6,000 (60 alerting, 5,940 routine) |
| Ingest accepted | 122.6 events/s |
| Event-to-alert p50 | 946 ms |
| Event-to-alert p95 | **1,195 ms** |
| Event-to-alert p99 | 1,503 ms |
| Event-to-alert max | 1,503 ms |
| Peak consumer lag | 15 messages |
| Lag after drain | 0 messages |
| Routine events that raised an alert | **0 of 5,940 (0.00)** |
| Alerting events that raised no alert | 0 of 60 |
| Alerting events that raised more than one | 0 |
| Dead-letter rate | 0.00 |

Artefact: `docs/perf/results/2026-10-11-compose-realistic-mix.json`.
**Not an SLO.** One deployment, the machine named at the top of this page,
that date.

### What the first attempt at this measured, and why it is worth knowing

The first run of this mix reported a routine-event alert rate of **1.00**:
every one of the 3,960 "benign" events became an alert. Not because the
detection corpus fired on them — because of where they entered.

The load path sends an undeclared connector type. The ingest normalizer's
generic fallback files an undeclared connector as class 2001, Security
Finding, and the promoter promotes OCSF category 2 unconditionally.
**Eight of the twelve declared connector profiles are category 2**, so on
those connectors no event can be routine whatever it contains.

The routine population is therefore sent as `okta_system_log`, class 3002
(Authentication), where promotion needs `severity_id >= 4` — a property of
the event rather than of the connector. That is what the 0.00 above is
measuring.

### Two things this run is not

**It is not a measure of the rule index.** The stack it ran against is the
published image set, not a build of the branch that added the index to
fusion. The index is measured separately and in process: 2,511 rules,
797 candidates for a routine cloud event (a 68.3% reduction), and
2.760 ms/event down to 1.066 ms/event over 2,000 iterations — a 2.6x
improvement on detection evaluation alone.

**It is not a cloud-hardware run.** See the note at the end of this page.

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

## Fusion hot path, in process, 2026-11-01

The deterministic per-event work that turns an ingest-normalized OCSF event
into a fusion `RawAlert`. This is the CPU-bound stage on the critical
ingest-to-alert path, measured by `scripts/perf/throughput_harness.py` driving
the real `promote_normalized_event` over a synthetic corpus — no broker, no
database, no network.

Published here because the pull-request gate asserts a floor against it, and
until this section existed that floor related to nothing: `perf.yml` passed
`--assert-floor 1000` under a comment claiming "a >200x margin below the
measured number", where the measured number appeared nowhere a reader could
check. A threshold has to be derived from a published figure or it is not a
gate.

| | |
|---|---|
| Events | 20,000 |
| Promoted | 13,334 |
| Promote rate | **140,692 events/s** |
| Per-event p50 | 8.67 µs |
| Per-event p95 | 9.37 µs |
| Per-event p99 | 15.17 µs |
| Machine | Apple M5 Max, 18 cores, macOS 25.5.0 (arm64) |
| Commit | `4e6c79305` |

**This is not a pipeline figure and must not be quoted as one.** It is two to
three orders of magnitude above the end-to-end numbers above, because it
measures one function rather than ingest, a broker, a consumer and a database.
The figure it bounds is a regression in that function — an I/O call slipping
onto the promote hot path is the canonical case — and nothing else.

**Not an SLO,** on the same terms as every other row on this page.

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

1. the in-process fusion hot-path harness, with a floor **20x below** the
   promote rate published above;
2. the storage cost model drift check;
3. this end-to-end harness against a Compose stack, nightly and on demand,
   with a floor 7.3x below the published drain rate and a latency ceiling
   19.2x above the published p95.

Only the first two run on a pull request. The end-to-end job boots Kafka,
Postgres, ingest and fusion and is too slow for that, so it is nightly and on
demand — which makes the in-process floor the only throughput assertion most
changes are graded against.

The floors exist to catch a catastrophic regression, such as an I/O call
appearing on the promotion hot path. They are deliberately not set near the
measured values: GitHub runners are shared, throttled and noisy, and a gate
that fires on runner jitter gets disabled within a week. They are also not
arbitrary constants, which is the other way to get this wrong and the way
this page got it wrong for longer: every floor above is a stated multiple of
a figure published on this page, and `tests/test_perf_gate_is_related_to_the_claims.py`
parses both the workflow and this page and fails if either ratio drifts.
**A passing perf job is not evidence that any number on this page still holds
on your hardware.**

## Scaling on lag

`GET /scale-hint` on the fusion service publishes the consumer backlog
and a suggested replica count. AiSOC does not scale itself — an
autoscaler belongs to the cluster, would need write access to the
orchestrator, and would fight whatever scaler you already run. ADR-0012
records that decision.

```json
{
  "status": "ok",
  "lag_messages": 31204,
  "lag_measured": true,
  "replica_eps": 122.56,
  "drain_target_seconds": 120.0,
  "suggested_replicas": 3,
  "basis": "31204 message(s) backlog, cleared in 120s at 122.6 events/s per replica"
}
```

`replica_eps` defaults to the ingest rate measured in the realistic-mix
run above, which is a laptop's figure. Set `AISOC_FUSION_REPLICA_EPS` to
your own and the hint is derived from that instead;
`AISOC_FUSION_DRAIN_TARGET_SECONDS` changes how fast you want a backlog
cleared.

`lag_measured: false` means the backlog could not be read — no partition
assignment yet, or a broker that did not answer. It is **not** zero
backlog, and a scaler should treat it as no signal rather than as an
all-clear.

A KEDA `ScaledObject` consuming it:

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: aisoc-fusion
spec:
  scaleTargetRef:
    name: aisoc-fusion
  minReplicaCount: 1
  maxReplicaCount: 20
  triggers:
    - type: metrics-api
      metadata:
        targetValue: "1"
        url: "http://aisoc-fusion:8000/scale-hint"
        valueLocation: "suggested_replicas"
```

## Neither a cloud-hardware run nor a managed-cluster run exists yet, and both are gaps

Two separate things are missing and they are easy to read as one, because the
page carries a Kubernetes table that is neither of them.

The depth plan asks for a run on stated cloud hardware, aiming at a
sustained 5,000 events/s through detection at p95 under 2 seconds on one
documented instance size. It separately asks for one run on a **managed**
Kubernetes cluster — EKS, GKE or AKS.

**No managed-cluster run exists.** The three-node Kubernetes table above is
`kind`, and that section already says what `kind` is not: three containers on
one kernel on the same laptop. A managed cluster differs in every dimension
that would make the run worth having — real nodes, a control plane somebody
else operates, a CNI, real inter-node network, and storage classes backed by
cloud volumes. What is needed to close it is a cluster, not code: the Helm
chart installs all of CORE and `helm.yml` proves it on `kind` on every pull
request, so the same `values-ha.yaml` plus a kubeconfig produces the row.

**Not measured.** Every figure on this page comes from a laptop — one
18-core Apple-silicon host and one 6-CPU Linux VM on it — or from a kind
cluster on the same machine. No cloud instance has been provisioned for
this project, so there is no row here for one, and no number on this page
should be read as describing one. A laptop VM's disk, network and CPU
scheduling are not an instance type's, and extrapolating from one to the
other is how a figure becomes a promise nobody can keep.

What is needed to close it is an account and an instance, not code: the
harness already records the hardware fingerprint, the load shape and the
commit into every result file, and `scripts/check_perf_results.py` already
refuses a result that drops any of them. Running

```bash
python3 scripts/perf/load_harness.py \
    --target compose --events 500000 --workers 32 --batch 100 \
    --alert-every 100 --target-eps 5000 --drain-timeout 1800 \
    --assert-benign-alert-rate-max 0.001 \
    --out docs/perf/results/<date>-<instance-type>-realistic-mix.json
```

on a named instance type produces the row, and the result file carries the
machine it came off so it cannot later be quoted as something else.

Until then the honest statement is the one at the top of this page: these
are measurements of specific deployments on specific hardware on specific
dates, they are not a service-level objective, and the 5,000 events/s
target remains an aim rather than a result.
