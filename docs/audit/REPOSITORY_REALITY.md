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
| Knowledge base → triage | **FIXED in gap-closure 6.3** | `services/api/app/api/v1/endpoints/knowledge_base.py` has indexed runbooks, playbooks and SOPs since the knowledge base shipped, and nothing in `services/agents` read any of it: a tenant that wrote down how to handle an alert still got a verdict produced in ignorance of the document. Auto-triage now retrieves the matching chunks through `GET /kb/runbooks/for-triage`, fences them as untrusted evidence, and records a citation per chunk that resolves to a document id and chunk index. Point-in-time during a replay by a server-side `as_of` rather than by snapshot capture, and the number of chunks the cutoff refused is published, so a freeze that did nothing is distinguishable from one that did. |
| `aisoc.alerts.raw` | **EXTERNAL ENTRYPOINT** | Previously recorded as dead because no in-repo producer exists. That is what an entrypoint is: fusion subscribes, schema-validates against the pinned `v1` RawAlert envelope, and dead-letters poison, so an external system can push a vendor alert straight into fusion. Covered by `test_event_schema.py` and `test_consumer_dlq.py`, and documented in `docs/runbooks/kafka-consumer-lag.md`. |
| `aisoc.threat_intel` (`NEW_IOC`) | **FIXED in Phase 8.1** | `services/threatintel` published a `NEW_IOC` event for every newly-seen indicator and nothing subscribed, so an indicator the CISA KEV catalogue published was never checked against any customer's recorded history. `services/api`'s `retro_hunt_consumer` now consumes it and sweeps each opted-in tenant's lake and connected SIEMs. Two names had to be reconciled: the pipeline's constructor defaults the topic to `threat-intel-events`, which is unreachable because the service's lifespan overrides it with `KAFKA_TOPIC_THREAT_INTEL` (`aisoc.threat_intel`), so a consumer written against the signature would have read an empty topic and stayed healthy. `check_ioc_lake_mapping.py` now compares the producer's setting with the consumer's. Off by default at the deployment level and again per tenant. |
| `aisoc.vulnerability_matches` | **OPT-IN EXPORT** | Ingest produced it by default and nothing consumed it — fusion gets vulnerability context by calling the enrichment service at fuse time. `VULN_CORREL_ENABLED` now defaults to `false`, so a stock deployment no longer downloads the CISA KEV catalogue at boot to publish into a topic with no reader. It stays available for an external consumer. |

### Detection

| Item | Count | Status |
|---|---|---|
| Rules the engine loads | **2511** | **WORKING** — each was replayed through its real connector and the real engine and watched to fire |
| Detection rules on disk | **6991** | the rest are imports in languages with **no evaluator** here (Splunk SPL, Chronicle YARA-L, CAR pseudocode); the engine never reads them |
| YAML files under `detections/` | **7022** | 25 are response playbooks (`detections/playbooks/`) and 6 are Sigma correlation files (`detections/sigma-correlations/`); neither is a stateless rule |
| Hunts under `hunts/` | **68** | **WORKING** — each replayed against a synthetic scenario and observed to fire, and each graded in the other direction too. Not a claim a hunt fires on a given deployment's telemetry, which depends on whether its connectors emit the fields the hunt names. The negative half of that grading was satisfiable without testing anything until Phase 8.4: a negative drawn from a different log source never fires on any hunt, so `check_hunt_scenarios.py` now requires it to differ from its positive in exactly one indicator field. It found 8 violations on first run, 3 in the 5 hunts that predate the phase |

The gap matters and has been published both ways in the past. `make stats`
reports the first two numbers side by side so they cannot be conflated again.

833 of the executable set are native; 1,770 are imported Sigma rules the
compiler translated. The reason the figure was 833 for months was not a
missing feature: Windows events nest their payload under `System`/`EventData`,
one level below anything the engine flattened, so `CommandLine` and `Image` —
the two most-used fields in the public Sigma corpus — read `None` and no
Windows rule could fire however correctly it was written. Fixed in the
connector; the engine and matcher are byte-identical.

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
5. **A deactivated user's API keys kept authenticating.** Not visible from a
   session test, which is what anyone would have run: `get_current_user`
   re-reads `users.is_active` per request, so deactivating did stop sessions
   immediately. `_resolve_api_key` took a different path. It looked up the
   owning user with `is_active == True` and, when that returned nothing, fell
   through to a generic `api_service` role instead of refusing, so every key
   a departing principal had minted for themselves went on working
   indefinitely. Fixed in Phase 13.1, alongside a session-revocation
   timestamp checked against a new `iat` claim, because the `is_active` check
   is reversible: re-enabling an account resurrected any token minted before
   the deactivation that had not yet expired.

---

## Identity and provisioning

**SCIM 2.0 — WORKING, no external dependency to verify against in CI.**
`/scim/v2` on the API service serves Users, Groups, ServiceProviderConfig,
ResourceTypes and Schemas, authenticated by a per-tenant bearer token held as
a SHA-256 digest. What is proven in CI is that the handlers behave correctly
against request bodies transcribed from Okta and Microsoft Entra ID
provisioning, including the five shapes where the two providers disagree.

What that does **not** prove, and is worth stating plainly: no live identity
provider has been pointed at this build. The payloads are synthetic
reproductions of documented request shapes, not captures from a running
integration, so a provider quirk outside those five would not be caught here.
The honest claim is that the implementation handles both dialects as
documented, not that either vendor's connector has been run against it end to
end.

OIDC (`services/api/app/auth/oidc.py`, PKCE on by default) and SAML
(`services/api/app/auth/saml.py`) handle sign-in and predate this work.
Provisioning and sign-in are separate concerns: SCIM creates and removes the
principal, OIDC or SAML authenticates them.

---

## White-label and usage metering

**White-label — WORKING on four of five surfaces, and the fifth is out of
scope rather than pending.** The console, the executive digest in HTML and
PDF, the case close-out summary, the replay evaluation report, the
investigation summary PDF and the signed email approval all carry a
white-labelled organisation's product name, palette and — where the renderer
has somewhere to put one — its logo, each asserted in CI against an unbranded
negative control.

The earlier record here said email approvals and ChatOps "resolve the same
`sender_name` from the same resolver". That was not true of either:
`sender_name` had no reader anywhere in the tree outside the resolver that
produced it, and `send_approval_email` had no caller at all, so the signed
fallback the documentation names for "Slack and Teams are unreachable"
produced nothing. Both are closed; the sentence is recorded because a tracker
that credits a field for resolving is the failure this audit exists to catch,
and it had.

ChatOps stays unbranded on purpose. The prompt is posted by
`services/actions` and by the two bot services, none of which can read the
branding store, and a deployment-wide product name would be wrong for every
organisation on the deployment but one. The sign-in page is unbranded for a
different reason: branding resolves from the caller's credential, and there is
none yet. Both are stated as limits in
`apps/docs/docs/operations/white-label.md` rather than implied to be pending.

Brand assets are held as bytes in Postgres and served from this deployment.
Nothing is fetched from a third-party URL, in the console or in the
server-side PDF renderer. Uploaded SVGs are rewritten against an allowlist and
a document declaring a DTD or an entity is refused before parsing.

**Usage metering — WORKING, and it equals the rows by construction.** Ten
meters, each a query against the table holding the evidence, with no counter
table to drift. `events_ingested` is the one meter with no source on a CORE
deployment and reports "not measured" with its reason rather than zero.

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
| `services/demo-producer` | **DEMO-ONLY** in its default mode: randomised vendor events into the real ingest API, not in any compose profile, invoked manually. `--load` is **WORKING** and is not demo data: it is the generator `scripts/perf/load_harness.py` drives, and its events are attributable per event so the harness can time each one to the alert it became. |
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
- **Kubernetes/Helm deployment: partly exercised on 2026-09-27, and only on
  kind.** The chart was installed on a three-node kind cluster (Kubernetes
  v1.34.0) on an Apple M5 Max with 8 CPUs and 15.6 GiB allocated to the
  container runtime, using `values-ha.yaml` plus `ci/kind-values.yaml`. Three
  Kafka brokers formed a KRaft quorum, two ingest and two fusion replicas came
  up, the migration chain applied, 10,000 events pushed through the public
  ingest endpoint all became alert rows, and a fusion pod destroyed mid-stream
  cost neither a lost event nor a duplicated one. Figures:
  `apps/docs/docs/operations/performance.md`.

  **UNVERIFIED, in the same breath:** no managed Kubernetes service (EKS, GKE,
  AKS) and no bare-metal cluster has been tried; kind nodes are containers on
  one kernel, so this is not multi-machine evidence; no ingress controller or
  cloud load balancer was in front of the release; PersistentVolumeClaims were
  switched off for the run; NetworkPolicy enforcement needs a CNI that
  implements it and was not exercised; managed PostgreSQL and ClickHouse were
  not used, the run pointed at single ephemeral pods; and the longest run was
  a few minutes, so nothing is known about sustained operation, compaction,
  log growth or rolling upgrades. **"The chart installs and survives a pod
  kill on kind" is not "Kubernetes is production-ready."**

  Four defects were found by running it, none of which rendering could have
  shown: `KAFKA_BOOTSTRAP_SERVERS` was set on the UEBA deployment and nowhere
  else, so ingest and fusion defaulted to `localhost:9092` and the spine was
  installed but not connected; the first batch after an install was lost to
  Kafka auto-creation; readiness probes pointed at `/health`, which answers
  200 regardless of whether the consumer is attached, instead of `/readyz`,
  which reports the subscription; and `ueba.enabled` had no reader, so
  switching UEBA off still scheduled it. All four are fixed and gated by
  `helm.yml`.
- **Whether migrations 050–053 apply** on an existing volume was not traced.
  Compose mounts `services/api/migrations` as `docker-entrypoint-initdb.d`,
  which runs only on a *fresh* volume. On a clean install the schema is
  correct (92 tables observed).

---

## Reproducing this audit

```bash
make up          # CORE profile: 16 long-running services (+ a one-shot model pull)
make doctor      # every dependency probed, not just "running"
make smoke       # one real event through the real pipeline
make stats       # recount every published figure from the tree
```

`make smoke` is the claim. If it fails, the pipeline is broken, and the
failure names the boundary that broke.
