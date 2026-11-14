# ADR-0011: behavioural baselines in CORE are a fusion module; the UEBA service stays in `full`

- **Status:** accepted
- **Date:** 2026-10-11
- **Related:** [ADR-0010](./0010-entity-and-session-context-in-core.md), which made the same shape of decision for entity and session context; [ADR-0007](./0007-connectors-and-actions-in-core.md), which established that a capability configured and pointed at nothing is the failure to avoid; [ADR-0006](./0006-llm-gateway-in-core.md), which established the measurement method
- **Implements:** depth plan 3.4

## Context

Depth plan 3.4 states the problem and names both options:

> Behavioural scoring needs the `full`-profile UEBA service today. Move its
> scoring core into fusion as a module, or add UEBA to CORE behind an ADR
> that measures it.

The reason it has to move at all is the plan's own "Done when" for Phase 3:

> a CORE install fires a threat-and-anomaly rule on a replayed fixture with
> no `full` service running.

Depth plan 3.5 pairs anomaly signals with threat conditions into ordinary
rules. If the anomaly half of every such rule is only computable in `full`,
then on the profile `make up` starts — the one every quickstart, every
install script and every evaluator uses — those rules read `None` on their
baseline clause and can never fire. That is precisely the shape ADR-0007
closed: content that exists, is counted, and is pointed at nothing.

## What was measured, rather than assumed

Same method as ADR-0006, ADR-0007 and ADR-0010: image size from
`docker image inspect`, resident memory from `docker stats --no-stream`.

Host: macOS, Docker Engine 29.5.2, 15.58 GiB available to the engine.
Date 2026-10-11, `arm64`.

### Option B — add the UEBA service to CORE

| Measure | Value | How |
|---|---|---|
| Image on disk | **145.4 MB** | `docker image inspect ghcr.io/beenuar/aisoc-ueba:latest` |
| Resident at import | **63.3 MiB** | container running `import app.main`, then `docker stats --no-stream` |

The resident figure is a **floor, not an idle cost**. It is the footprint of
importing the application; a running instance adds a SQLAlchemy pool, an
`aiokafka` consumer and its buffers on top. It is recorded as a floor rather
than extrapolated, because the honest version of "we did not run the full
service against live dependencies" is to say so.

The service also brings a second cost that is not memory: UEBA owns its own
Alembic chain and its own tables. CORE would gain a migration chain whose
failure mode is already documented in this repository — four Alembic chains
once shared one `alembic_version` table and two services came up healthy
with zero tables while every command reported success.

### Option A — the scoring core as a fusion module

Zero new containers and zero new images. Fusion already runs a Redis for the
windowed engine's sliding windows and for the Phase 3.3 first-seen store, so
the counting state has a home that costs no new process.

What it does cost is Redis memory, measured directly rather than estimated —
`used_memory` before and after driving `BaselineStore.derived_fields` against
a real Redis 7 container:

| Measure | Value |
|---|---|
| Workload | 200 principals × 50 events = 10,000 events, six attributes each |
| Redis keys created | 1,020 |
| `used_memory` delta | **471 KiB** |
| Per principal | **2,412 bytes** |

At 10,000 principals — larger than most tenants a CORE install serves — that
projects to roughly **24 MB of Redis**, against the 63.3 MiB floor plus an
image, a migration chain and a Kafka consumer group for the alternative.

## Decision

**Take option A.** The behavioural scoring core moves into fusion as
`services/fusion/app/services/baselines.py`. The UEBA service stays in the
`full` profile, unchanged.

The scoring itself is three lines of Welford arithmetic. What makes UEBA a
`full`-profile service is the table, the Alembic chain and the Kafka consumer
around that arithmetic — not the statistics. Moving the statistics is cheap;
moving the scaffolding is what the measurement above prices.

### What CORE gets, and what it does not

CORE gets the three signal families depth plan 3.4 names: per-principal
rarity of actions, resources, client families and locations; peer-group
deviation; and volume anomalies per principal and per OAuth application.
Each is a typed signal that rules read, never an alert on its own.

CORE does **not** get UEBA's per-entity history, its API surface, or its
`ueba.anomalies` topic. A deployment that wants an entity's full behavioural
record over time still runs `full`. Fusion's existing `ueba_signal.py`
consumer is untouched, so a `full` deployment keeps folding the service's
richer score into alert confidence exactly as before — the two coexist
rather than compete.

## Consequences

**The arithmetic now exists twice**, in `services/ueba/app/services/baseline.py`
and in the fusion module. That is a real cost and it is accepted deliberately:
the alternative is a shared package that both services depend on, which makes
CORE's detection path depend on a `full`-profile service's release cadence for
three lines of maths. The fusion copy is pure and has no SQLAlchemy in it,
which is what lets it carry the one correctness property the UEBA copy had to
learn the hard way — see below.

**One bug class is designed out rather than copied.** `_welford_update` in the
UEBA service once edited its argument in place; its caller passed the object
SQLAlchemy had loaded, SQLAlchemy compares loaded-against-new to decide
whether a JSONB column is dirty, found them equal, and omitted the column from
every `UPDATE`. No baseline in that service advanced past its first event, and
the symptom was `features_unscoreable`, which reads as "this entity is too
quiet to score" rather than as a bug. The fusion `welford_add` returns a new
dict and mutates nothing, and a test asserts exactly that.

**`None` means unknown and never normal.** Carried across from the UEBA copy,
which already draws this distinction, because it is the property that decides
whether the module is useful: service accounts and batch jobs converge on a
constant stream, their standard deviation collapses to zero, and every
subsequent value then sits exactly zero deviations from the mean. A `0.0`
there would make the most automated account in the estate the least
suspicious one it is possible to be.

**A short history produces no key at all**, for the same reason the first-seen
store reports nothing during a Redis outage. The first event a principal ever
produces is 100% of their history, so on a fresh install every value is novel;
publishing that would fire every novelty rule on every event until the
baselines warmed.

**The value set per principal is bounded.** A resource name is
attacker-chosen, so an unbounded hash is a memory-exhaustion primitive aimed
at the detection path. Past `MAX_DISTINCT_VALUES` the hash stops admitting new
members while the total still advances, so the baseline degrades into
"stopped learning new values for this principal" rather than into a wrong
denominator or an outage.

**Every subject chain is held against the emitted-field namespace.** A
baseline over a field nothing emits is a signal that cannot be computed, and
the field name reads as working, so it is worse than a missing feature. The
first draft of this module got that wrong: `baseline_client_family_rarity`
resolved its subject from `client_family`, `user_agent_family` or
`client_app`, and **no connector emits any of the three**. A test now asserts
each chain intersects the namespace `scripts/check_detection_fields.py`
builds, and was proved by reinstating the broken chain and watching it fail.

**Peer groups are only as good as the group key.** The plan names the Phase
2.5 posture snapshot as the source. Until that lands, the group is taken from
whatever the identity provider already puts on the event — `department`,
`group`, `job_title` — which is what Workspace, Entra and Okta all emit. An
event naming no group yields no peer signal rather than a group of one, and a
group below `MIN_PEER_MEMBERS` distinct principals yields none either: a group
of one is that principal's own baseline wearing a group's name, and comparing
them reports every event as perfectly typical.
