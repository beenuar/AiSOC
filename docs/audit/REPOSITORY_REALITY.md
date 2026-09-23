# Repository reality

**What actually works today**, established by reading the implementations and
by running the stack — not by reading filenames or documentation.

Audit date: 2026-09-23 · against `v8.1.0`

Everything marked WORKING below was either exercised against a live stack or
traced to a caller on a real path. Where a claim could not be verified, it
says so. Nothing here is inferred from a file being present.

---

## How to read this

| Status | Meaning |
|---|---|
| **WORKING** | Exercised end to end, or traced to a production caller with a passing gate. |
| **PARTIAL** | Real implementation, but a named limitation stops it being the whole claim. |
| **BROKEN** | Present and wired, but does not function. |
| **DEMO-ONLY** | Runs only with synthetic data; produces nothing from real telemetry. |
| **EXPERIMENTAL** | Works, but interface or results are not stable. |
| **DEAD CODE** | No production caller. |
| **DOCS-ONLY** | Described somewhere; no implementation behind the description. |

---

## The headline

**The core pipeline works.** A single event posted to the ingest API traverses
Kafka, fusion, detection and promotion, lands in Postgres, and is retrievable
from the public API. Verified on 2026-09-23 against a clean `docker compose up`
on arm64:

```
[PASS] raw telemetry accepted by ingest
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
[PASS] severity survived normalization
[PASS] source attribution is not duplicated
[PASS] description is prose, not a serialized payload
```

That run is reproducible: `make up && make smoke`.

**What was not true before this audit** is that the *documented* quick start
exercised any of it. `./install.sh` handed off to a nine-service compose file
with **no ingest service, no fusion service, and `AISOC_DISABLE_KAFKA: true`**,
whose only content came from `seed_demo.py` writing 15 fabricated incidents
directly into Postgres. A new user followed the README, saw a populated
console, and concluded the platform worked — having never run the platform.
That single fact accounts for most of the recurring feedback about fabricated
data and unverifiable architecture.

---

## Component inventory

### The event spine — WORKING

| Component | Language | Entry point | Consumes | Produces | Status |
|---|---|---|---|---|---|
| `services/ingest` | Go | `main.go` → `:8080` | HTTP `POST /v1/ingest/batch` | Kafka `aisoc.raw_events` | **WORKING** |
| `services/fusion` | Python | `app/main.py` → `:8003` | Kafka `aisoc.raw_events` | Postgres `alerts`, Kafka `aisoc.alerts.fused` | **WORKING** |
| `services/api` | Python | `app/main.py` → `:8000` | Postgres | HTTP `GET /api/v1/alerts` | **WORKING** |
| `services/agents` | Python | `app/main.py` → `:8084` | Kafka `aisoc.alerts.fused` | triage verdicts | **PARTIAL** — needs a provider key; deterministic offline otherwise |
| `services/realtime` | TypeScript | `src/index.ts` → `:8086` | Kafka `aisoc.alerts.fused` | WebSocket | **WORKING** |
| `apps/web` | Next.js | `:3000` | API | console | **WORKING** |

Topic names match literally on both sides (`aisoc.raw_events`,
`aisoc.alerts.fused`), and compose supplies the env vars each config module
reads. This was checked rather than assumed, because a one-character topic
mismatch is invisible until nothing arrives.

### Storage — what each one is actually for

| Store | Profile | What lives here | Status |
|---|---|---|---|
| PostgreSQL | core | alerts, incidents, cases, users, tenants, detection rules, audit log | **WORKING** |
| Redis | core | correlation windows, dedup keys, investigation run state | **WORKING** |
| Kafka | core | the event spine: `aisoc.raw_events`, `aisoc.alerts.fused` | **WORKING** |
| ClickHouse | full | the event lake (`aisoc.raw_events` table) behind `/lake/sql` and hunt | **WORKING** when enabled |
| Neo4j | full | entity graph, blast radius | **WORKING** when enabled |
| Qdrant | full | IOC/actor embeddings for `services/threatintel` | **WORKING** when enabled |
| OpenSearch | full | IOC + threat-actor indices for `services/threatintel` | **WORKING** when enabled |

**Correction (v9.0).** This audit originally recorded OpenSearch as dead code
on the grounds that nothing read it. That was wrong, and wrong in the way this
document exists to prevent: the check was made against `services/api`, which
holds no OpenSearch client, and never against `services/threatintel`, which
holds one and uses it unconditionally. `OpenSearchStore.initialize()` runs in
the threatintel lifespan with no feature flag and no `try`, and every CISA KEV
poll bulk-indexes into `threatintel-iocs`.

Two real defects sat underneath the wrong verdict, both now fixed: compose set
`OPENSEARCH_URL` on the threatintel service, which its settings class has no
field for and `extra="ignore"` silently discards, so the connection worked
only because the defaults happened to match the compose service name; and
threatintel declared no `depends_on` for OpenSearch, so it could boot first,
die in the lifespan, and be restarted until the race resolved.

What *is* vestigial is on the API side. `AISOC_DISABLE_OPENSEARCH` had zero
readers while three deploy configs set it and the env-var reference documented
it — an operator could disable a subsystem this service never had — so the
setting is removed rather than left as a switch wired to nothing.
`OPENSEARCH_URL` stays in the API config because `esql_runner` reads it as an
SSRF allow-list entry, and is commented as such.

### Broken or disconnected

| Component | Status | What is wrong |
|---|---|---|
| `services/ueba` | **FIXED in v9.0** | Consumed the topic `security.events`, which nothing in the repository produces — ingest writes `aisoc.raw_events`. So UEBA never scored, never emitted `ueba.anomalies`, and fusion's UEBA confidence boost was permanently inert despite defaulting on. The default topic is now `aisoc.raw_events` and `app/services/feature_extraction.py` recovers the entity and features the scorer needs from the OCSF envelope. |
| Ingest inbox webhooks | **FIXED in v9.0** | Routes mounted only when `DATABASE_DSN` was set and compose never set it; the templates were also not copied into the runtime image, so even with a DSN every template resolved 503. Templates are now `go:embed`-ed into the binary — a directory cannot be missing from an image — and compose sets the DSN. The on-disk path remains as an operator override. |
| Fuse-time enrichment | **FIXED in v8.1.1** | Defaulted to `http://localhost:8082`, which inside the fusion container is fusion itself. Every enrichment call failed and the failure was swallowed at `DEBUG`. Now points at the `enrichment` service and is a declared `full`-profile capability. |
| Investigation → response | **PARTIAL, by design** | Nothing automatically dispatches to `services/actions`. Response is copilot-default and human-initiated. This is intentional, but it means the pipeline terminates at triage. |
| `aisoc.alerts.raw` | **EXTERNAL ENTRYPOINT** | Previously recorded as dead because no in-repo producer exists. That is what an entrypoint is: fusion subscribes, schema-validates against the pinned `v1` RawAlert envelope, and dead-letters poison, so an external system can push a vendor alert straight into fusion. Covered by `test_event_schema.py` and `test_consumer_dlq.py`, and documented in `docs/runbooks/kafka-consumer-lag.md`. |
| `aisoc.vulnerability_matches` | **OPT-IN EXPORT** | Ingest produced it by default and nothing consumed it — fusion gets vulnerability context by calling the enrichment service at fuse time. `VULN_CORREL_ENABLED` now defaults to `false`, so a stock deployment no longer downloads the CISA KEV catalogue at boot to publish into a topic with no reader. It stays available for an external consumer. |

### Detection

| Item | Count | Status |
|---|---|---|
| Rules the engine loads | **833** | **WORKING** — these can fire |
| YAML files under `detections/` | **7016** | mostly quarantined imports with **no evaluator**; the engine never reads them |

The gap matters and has been published both ways in the past. `make stats`
reports both numbers side by side so they cannot be conflated again.

### Known defects found by running it

These were not visible from the code alone:

1. **`connector_type` read `"crowdstrike crowdstrike"`** on every alert —
   vendor and product joined without dedup, in two separate copies of the
   same helper. Fixed; both now share one implementation.
2. **Alert `description` was the serialized event** — `str(raw_data)`, so the
   console showed `{"command_line": "powershell.exe -nop ...` where a sentence
   belonged, discarding the vendor's own description. Fixed.
3. **The Kafka healthcheck passes on a broker that cannot serve.** When the
   Docker VM ran out of disk, Kafka failed to write `meta.properties`, refused
   every request, and compose still reported it `healthy`. `make doctor`
   checks disk before anything else and probes the broker with an admin call
   rather than trusting the healthcheck.
4. **CrowdStrike alerts reached fusion with no actor.** Recorded here first as
   "has no normalizer profile", which was the wrong diagnosis: the connector
   emits a canonical envelope, so it takes the canonical path and gets OCSF
   2001 correctly. The actual faults were two, and both are fixed in v9.0.
   The connector never read `behaviors[].user_name`, where Falcon puts the
   acting identity, so the envelope carried none. And the canonical field map
   recognised only `actor` — of the 68 canonical-envelope connectors, 40 use
   that spelling and 11 use `username` or `user`, which mapped nowhere.
   Because the fusion correlation key is `{tenant}:{entity}:{tactic}`, a
   missing actor did not merely blank a column: every affected alert
   correlated into the same `unknown` bucket. Aliases now resolve in declared
   order rather than as extra map entries, because Go randomises map
   iteration and three entries pointing at one destination would pick a
   different winner per process.

---

## Data integrity

The project's rule is that fabricated security data must never render as a
tenant's real state. The audit found the rule was enforced in 22 console
components and violated in five places, three of them authenticated API
endpoints.

| Site | Was | Now |
|---|---|---|
| `GET /api/v1/mssp/{overview,tenants,incidents}` | Returned invented tenants ("Acme Corp, health 92.4") and incidents with named assignees to any authenticated caller | Demo-mode only; empty otherwise |
| `CopilotView.tsx` catch block | Any backend error produced an invented investigation with a named host, a named user and three fake alert citations | Demo-mode only; otherwise the error is shown as an error |
| `GET /api/v1/deployment/airgap/status` | Reported `passed: True` with invented detail ("487 rules loaded from offline bundle") for checks that measured nothing | Reports "not checked" with the reason |
| `SettingsView.tsx` | Showed `Sasha Lin <sasha.lin@example.com>` as the signed-in user's own profile | Empty fields |
| `InvestigationTimeline.tsx` | Rendered a fabricated investigation when no run was selected | Demo-mode only (fixed in v8.1.0) |

**Provenance is now a column, not a convention.** Migration
`054_alert_provenance.sql` adds `is_synthetic`, `synthetic_source` and
`synthetic_scenario` to `alerts`, defaulting to "not synthetic" so the real
pipeline can never be mislabelled. Before this, the only marker was a `"demo"`
string in a `tags` array that the most realistic-looking seed rows omitted.

`seed_demo.py` also had no guard of any kind — it ran against whatever
`DATABASE_URL` resolved to. It now refuses outside a development environment
unless `AISOC_ALLOW_SEED=1`.

---

## What is demo-only

| Component | Status |
|---|---|
| `services/demo-producer` | **DEMO-ONLY**. Emits randomised vendor events into the real ingest API. Not in any compose profile; invoked manually. |
| `seed_demo.py` | **DEMO-ONLY**. 15 hand-written incidents plus randomised alerts. |
| `services/agents/app/api/hunt_search.py` | **DEMO-ONLY** but honest — returns `source: "sample"` and a notice saying it does not query the lake. |
| `services/agents/app/api/copilot.py` | **PARTIAL** — real LLM path with a key; returns `source: "template"` and a notice without one. |
| `packages/aisoc-sandbox` | **WORKING** as an offline simulator. Deliberately not the production stack. |

---

## Unverified

Stated rather than guessed:

- **The live-agent LLM path** could not be exercised: no provider key was
  available. The deterministic offline path was exercised. Every published
  benchmark row is labelled `substrate: true` and must not be read as live
  agent accuracy.
- **Kubernetes/Helm deployment** was not exercised in this audit. The chart
  renders; whether it runs was not tested here.
- **Whether migrations 050–053 apply** on an existing volume was not traced.
  Compose mounts `services/api/migrations` as `docker-entrypoint-initdb.d`,
  which runs only on a *fresh* volume. On a clean install the schema is
  correct (92 tables observed).

---

## Reproducing this audit

```bash
make up          # CORE profile: 10 services
make doctor      # every dependency probed, not just "running"
make smoke       # one real event through the real pipeline
make stats       # recount every published figure from the tree
```

`make smoke` is the claim. If it fails, the pipeline is broken, and the
failure names the boundary that broke.
