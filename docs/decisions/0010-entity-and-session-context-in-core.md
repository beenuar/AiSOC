# ADR-0010: entity and session context in CORE is a Postgres store; Neo4j stays in `full`

- **Status:** accepted
- **Date:** 2026-10-11
- **Related:** [ADR-0007](./0007-connectors-and-actions-in-core.md), which moved `connectors` and `actions` into CORE and explicitly left this decision open; [ADR-0006](./0006-llm-gateway-in-core.md), which established the measurement method both use
- **Implements:** depth plan 2.7

## Context

ADR-0007 moved two services into CORE and closed with a sentence that named
this ADR's subject and refused to decide it:

> **The lake and the graph stay in `full`.** […] ClickHouse and Neo4j are
> stateful stores with their own memory floors, not network front ends, so
> they are a different decision needing its own measurement.

Depth plan 2.4 now builds sessions per principal and 2.6 puts an actor kind
and a privilege tier on every alert. Both have to land somewhere. If they land
only in the graph and the lake, they land only in `full`, and the profile
`make up` starts — the one every quickstart, every install script and every
evaluator uses — gets alerts with none of it. That is the same shape as the
problem ADR-0007 fixed: a capability configured and pointed at nothing.

The plan asks for a measurement of two options against CORE's 8 GB budget:
Neo4j in CORE, or a Postgres-backed entity and session store for CORE with
Neo4j kept for `full`.

## What was measured, rather than assumed

Same method as ADR-0006 and ADR-0007: resident memory read with
`docker stats --no-stream`, image size from `docker image inspect`.

Host: macOS, Docker Engine 29.5.2, 15.58 GiB available to the engine.
Date 2026-10-11.

### What CORE costs today

Read off a running CORE stack, all 16 services, idle:

| Service | Resident | | Service | Resident |
|---|---|---|---|---|
| `kafka` | 1,078.3 MiB | | `realtime` | 101.6 MiB |
| `litellm` | 638.0 MiB | | `qdrant` | 97.0 MiB |
| `threatintel` | 310.1 MiB | | `fusion` | 84.8 MiB |
| `zookeeper` | 262.6 MiB | | `connectors` | 75.8 MiB |
| `api` | 227.6 MiB | | `actions` | 49.9 MiB |
| `agents` | 210.0 MiB | | `redis` | 38.8 MiB |
| `postgres` | 202.7 MiB | | `ingest` | 20.0 MiB |
| `ollama` | 140.6 MiB | | | |
| `web` | 112.1 MiB | | **total, idle** | **3,649.8 MiB** |

The idle total is not the number that matters, for the reason ADR-0006 found
the hard way: `ollama` idles at 140.6 MiB and measures **2.96 GiB** running
inference. CORE triages every fused alert through the local model, so the
working peak is the idle total with that substitution:

**CORE at its working peak is ≈ 6,540 MiB, leaving ≈ 1,652 MiB of an
8 GiB budget.** Every figure below is spent out of that 1,652 MiB, not out of
8 GiB.

### Option A — Neo4j in CORE

`neo4j:5.15-community` with the `full` profile's own settings (APOC loaded,
heap 256m initial / 512m max), then loaded with 20,000 sessions, 500 users and
20,000 `OPENED_SESSION` edges, then read with the originating-human
aggregation that 2.4 needs:

| | Measured |
|---|---|
| Image on disk | **289 MB** |
| Empty, 45 s after boot | **527.0 MiB** |
| 20,000 sessions + 500 users + 20,000 edges | **680.0 MiB** |
| After the aggregation read | **696.8 MiB** |
| Store on disk at that volume | **516 MB** |

### Option B — a Postgres-backed store in CORE

`postgres:16-alpine`, the identical 20,000 sessions in a tenant-scoped table
with the three indexes the store needs (unique on
`(tenant_id, source, session_key)`, plus `(tenant_id, originating_human)` and
`(tenant_id, last_seen_at DESC)`), then the same aggregation:

| | Measured |
|---|---|
| New containers | **0** — Postgres is already in CORE |
| Resident, before the table exists | 21.95 MiB |
| Resident, 20,000 sessions written and read | 32.84 MiB |
| **Marginal resident cost** | **+10.9 MiB** |
| Total relation size | **8,288 kB** (5,600 kB heap, 2,656 kB indexes) |
| The aggregation read | **5.148 ms** |

### The comparison in one line

| | Resident | Image | Store on disk | Share of CORE's 1,652 MiB headroom |
|---|---|---|---|---|
| Neo4j in CORE | 696.8 MiB | 289 MB | 516 MB | **42.2%** |
| Postgres store | 10.9 MiB | 0 | 8.1 MB | **0.7%** |

Neo4j costs **64×** the resident memory of the Postgres store for the same
20,000 sessions, and it takes almost half of what CORE has left at the moment
it is triaging an alert — which is exactly the moment a user is watching.

Two further properties were checked rather than assumed, because the previous
two ADRs were each caught out by one:

- **The loaded figure, not the idle one.** Neo4j's idle 527 MiB would have
  understated it by 32%; the 696.8 MiB figure is after writing and reading.
  20,000 sessions is a small estate — the compose file's existing
  `mem_limit: 1g` on `neo4j` is 1.5× the measured figure at that volume, so a
  real estate would need that limit raised as well, which is a second cost
  this option carries and the Postgres option does not.
- **The query CORE actually needs is not a traversal.** What 2.6 puts on an
  alert is the session, the actor kind and the privilege tier for *one*
  principal. That is an indexed lookup, which is what the 5.148 ms above
  measures. Arbitrary-depth permission-path search is a different query and a
  genuinely graph-shaped one; see "What this ADR does not decide".

## Decision

**A Postgres-backed entity and session store in CORE. Neo4j stays in `full`.**

- Sessions (depth plan 2.4) and the identity privilege tier (2.6) are written
  to tenant-scoped Postgres tables under row-level security, by migrations
  `102_sessions.sql` and `103_posture_snapshots.sql`.
- Fusion attaches the session id, the actor kind and the privilege tier to
  every alert on **every** profile, reading that store.
- The `Session` node and its edges are still written to Neo4j when the graph
  is enabled, from the same projection, so a `full` deployment keeps one
  traversable graph. The graph is a second consumer, never the only one.

## Consequences

- **CORE stays at 16 services and the README's ~8 GB and 20 GB figures stay
  as they are.** +10.9 MiB and 8.1 MB do not move a figure published to one
  significant figure, and the same reasoning ADR-0007 used applies: inflating
  it would imply a precision the other rows do not have.
- **A CORE alert carries session, actor-kind and privilege context**, which is
  the "Done when" of 2.7 and the precondition for 2.6.
- **Two writers for one projection is a drift risk, and it is accepted with a
  gate rather than with a comment.** The ingest-side projection
  (`services/ingest/internal/activity/session.go`) is the single source of
  the key and its kind; both the Postgres store and the graph writer consume
  it and neither re-derives it. A repository that has paid several times for a
  second copy of a producer should not add one silently.
- **Blast radius over effective permissions remains a `full` capability.** It
  must say so on CORE rather than rendering an empty graph, which is the
  behaviour ADR-0007 required of the lake pivots for the same reason.

## Alternatives considered

### Neo4j in CORE

Rejected on the measurement above: 42.2% of the headroom CORE has at its
working peak, for a query shape that is an indexed lookup. The precedent
cuts the same way — Qdrant was taken into CORE at 79 MiB and ADR-0007's two
services at 124.8 MiB *together*. 696.8 MiB is 5.6× the entire ADR-0007
budget, and it would be the single largest thing in CORE after Kafka and the
LLM gateway.

There is also a correctness reason that is independent of the budget. The Go
graph writer `MERGE`s on `natural_key` with `tenant_id` as a property, so
shared entities are last-writer-wins across tenants and the read filter has to
fail closed to compensate. Making that the only home for a value that
*prioritises alerts* would put a known-incomplete read on the path that
decides what an analyst sees first. The Postgres store is tenant-scoped by a
unique key and by row-level security, which is the stronger of the two for
this use.

### The lake as the session store

Rejected: ClickHouse is in `full` too, so it does not answer the question, and
`ReplacingMergeTree` collapses on merge rather than on write — a session's
`event_count` and `last_seen_at` change on every event, which is an update
pattern the lake is the wrong engine for. The lake still gets a `sessions`
table for hunting at `full`, written from the same projection; what it does
not get is ownership.

### Keep it all in `full` and tell CORE users to switch profiles

Rejected for the reason ADR-0007 gives at length: it relocates the manual step
rather than removing it, and it leaves the default profile advertising a
capability it cannot perform. The measured price of not making that trade is
0.7% of the remaining budget.

## What this ADR does not decide

**ClickHouse stays in `full`.** It is the other half of ADR-0007's sentence
and it is not in scope here. The consequence is stated plainly so nobody reads
this ADR as having closed the whole gap: on CORE there is still no event lake,
the eleven lake pivots still report that their data class is not available,
and a hunt over historical sessions is a `full` capability. What changes is
that the *context on an alert* no longer depends on either store.
