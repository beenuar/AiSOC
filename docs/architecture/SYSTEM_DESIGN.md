# AiSOC System Design

This document describes the end-to-end architecture of the AiSOC platform after the v2 enterprise upgrade. It covers data flow, the new knowledge graph, the detection rule engine, the threat intelligence pipeline, and the ML-augmented alert fusion pipeline.

---

## 1. High-level Topology

```
                       ┌──────────────────────────────────────────────┐
                       │              External Sources                │
                       │  EDR / SIEM / Cloud / Identity / Network     │
                       │  CrowdStrike · Splunk · AWS · Okta · Sentinel│
                       └─────────────────────┬────────────────────────┘
                                             │
                                       Webhooks / Pull
                                             │
                                             ▼
              ┌──────────────────────────────────────────────────────┐
              │                services/ingest (Go)                   │
              │  ─ OCSF normalizer                                     │
              │  ─ MITRE ATT&CK technique tagger (in-process index)    │
              │  ─ Shodan enrichment (TTL cache)                       │
              │  ─ CISA KEV correlator → VULNERABILITY_MATCH events    │
              └────────┬───────────────────────────┬─────────────────┘
                       │                           │
                ocsf.events                vulnerability.matches
                       │                           │
                       ▼                           ▼
              ┌────────────────────┐      ┌────────────────────┐
              │   Apache Kafka     │      │   Apache Kafka     │
              └────────┬───────────┘      └─────────┬──────────┘
                       │                            │
                       ▼                            ▼
              ┌──────────────────────────────────────────────────┐
              │         services/fusion (Python)                  │
              │  ─ Simhash dedup (Redis)                          │
              │  ─ Entity + ATT&CK correlation                    │
              │  ─ MLScorer: Isolation Forest + LightGBM ranker   │
              │  ─ Analyst feedback loop                          │
              └────────┬─────────────────────────────────────────┘
                       │
                fused.alerts
                       │
                       ▼
              ┌──────────────────────────────────────────────────┐
              │             services/api (FastAPI)                │
              │  ─ REST + WebSocket endpoints                     │
              │  ─ Detection rule engine (Sigma / YARA / KQL)     │
              │  ─ Neo4j graph_service (entity + attack-path)     │
              │  ─ Cases / RBAC / audit                           │
              └────┬───────────┬───────────────┬─────────────────┘
                   │           │               │
                   ▼           ▼               ▼
              ┌────────┐  ┌────────┐   ┌────────────────┐
              │PostgreSQL│ │Neo4j  │   │OpenSearch + QDR│
              │ (state)  │ │(graph)│   │ (search + RAG) │
              └──────────┘ └───────┘   └────────────────┘

                       ┌──────────────────────────────────┐
                       │     services/threatintel          │
                       │  TAXII 2.1 · MISP · OTX · KEV     │
                       │  → OpenSearch · Qdrant · Neo4j    │
                       └──────────────────────────────────┘

                       ┌──────────────────────────────────┐
                       │      services/agents              │
                       │  LangGraph + full ATT&CK + RAG    │
                       │  (Anthropic Claude 3.7 / GPT-4o)  │
                       └──────────────────────────────────┘
```

---

## 2. Service Responsibilities

| Service | Language | Hot path | Async path |
|---------|----------|----------|------------|
| `services/ingest` | Go 1.21 | Normalize raw events → OCSF, tag ATT&CK, enrich Shodan | Emit `vulnerability.matches` topic |
| `services/enrichment` | Go 1.21 | Per-IOC TTL-cached enrichment lookups | n/a |
| `services/fusion` | Python 3.11 | Simhash dedup → correlation → ML scoring → publish fused alerts | Background ML retrain on feedback |
| `services/api` | Python 3.11 | REST + WS, RBAC, case mgmt, rule engine, graph queries | Schema migrations on boot |
| `services/agents` | Python 3.11 | LangGraph multi-agent investigation runs | Loads full ATT&CK STIX bundle on boot, optional Qdrant embed |
| `services/actions` | Python 3.11 | SOAR action execution with blast-radius gating | Approval workflows |
| `services/threatintel` | Python 3.11 | IOC/actor search API | APScheduler poll loop for TAXII/MISP/OTX/KEV |
| `services/realtime` | Node 20 | WebSocket fan-out for the web console | n/a |
| `apps/web` | Next.js 14 | Server components + SWR | n/a |

---

## 3. Knowledge Graph (Neo4j)

The knowledge graph is the connective tissue between alerts, entities, and the MITRE ATT&CK matrix.

### 3.1 Node Labels

| Label | Key | Purpose |
|-------|-----|---------|
| `Host` | `id` (host UUID or hostname) | Endpoint context |
| `User` | `id` (sub or upn) | Identity context |
| `Alert` | `id` (alert UUID) | Detected event |
| `Case` | `id` (case UUID) | Triage container |
| `IOC` | `value` (sha256/ip/domain) | Atomic indicators |
| `Technique` | `id` (e.g. `T1059.001`) | MITRE ATT&CK |
| `Tactic` | `id` (e.g. `TA0002`) | MITRE ATT&CK |
| `ThreatActor` | `id` | Attribution |

### 3.2 Relationships

```
(Host)-[:LOGGED_IN]->(User)
(User)-[:OWNS]->(Host)
(Alert)-[:ON_HOST]->(Host)
(Alert)-[:AFFECTS]->(User)
(Alert)-[:USES]->(Technique)
(Technique)-[:PART_OF]->(Tactic)
(IOC)-[:OBSERVED_IN]->(Alert)
(ThreatActor)-[:USES]->(Technique)
(ThreatActor)-[:OBSERVED_AS]->(IOC)
(Case)-[:CONTAINS]->(Alert)
```

### 3.3 Critical Queries

* **Attack path** (`get_attack_path`): given a `Case`, traverse `(:Case)-[:CONTAINS]->(:Alert)-[:USES]->(:Technique)-[:PART_OF]->(:Tactic)` ordered by tactic kill-chain index.
* **Blast radius** (`get_blast_radius`): variable-length path query from any entity, capped at 3 hops, filtered by relationship type, used by the `actions` service's gating layer.
* **Entity neighbors**: 1-hop graph used by the SOC console "show context" panel.
* **MITRE coverage**: aggregated counts of distinct techniques observed per tenant per time window.

### 3.4 Bootstrapping

`services/api/app/db/neo4j.py` initializes a singleton `AsyncDriver`, verifies connectivity, and creates uniqueness constraints on `(Host.id)`, `(User.id)`, `(Alert.id)`, `(Case.id)`, `(IOC.value)`, `(Technique.id)` at startup.

---

## 4. Detection Rule Engine

`services/api/app/services/rule_engine.py` implements multi-language rule execution.

| Rule type | Backend | Notes |
|-----------|---------|-------|
| Sigma | `pySigma` → OpenSearch query | Most common path; supports field mappings |
| YARA | `yara-python` | Targets file/memory artifacts |
| KQL | Translated to ClickHouse SQL | For event analytics |
| Lucene / Regex | Direct OpenSearch | For full-text patterns |

### 4.1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET /v1/rules` | List rules with filtering | |
| `POST /v1/rules` | Create a new rule | |
| `POST /v1/rules/{id}/execute` | Execute single rule on demand | |
| `POST /v1/rules/hunt` | Multi-rule, time-bounded hunt | |
| `PATCH /v1/rules/{id}` | Update rule (validate, version) | |

### 4.2 Lifecycle

1. Rule authored in the web console IDE (Monaco editor with live test panel).
2. Validated against a sample event; on save, written to `detection_rules` table.
3. Scheduler service evaluates `enabled=true` rules at their cadence.
4. Hits emit fused alert candidates onto Kafka via the `fusion` pipeline.

---

## 5. Threat Intelligence Pipeline

`services/threatintel` runs an APScheduler-driven poll loop with per-feed handlers.

```
TAXII 2.1 ─┐
MISP ──────┤   ┌──────────────────────────┐   ┌────────────┐
OTX  ──────┼──▶│   ThreatIntelPipeline    │──▶│ OpenSearch │
CISA KEV ──┘   │  ─ STIX 2.1 parser       │   │  Qdrant    │
               │  ─ Redis bloom dedup     │   │  Neo4j     │
               └──────────────────────────┘   └────────────┘
```

### 5.1 Components

| Module | Role |
|--------|------|
| `clients/taxii.py` | Async TAXII 2.1 client |
| `clients/misp.py` | MISP REST client |
| `clients/otx.py` | AlienVault OTX client |
| `clients/cisa_kev.py` | KEV catalog fetcher |
| `parsers/stix.py` | Normalize STIX 2.1 SDO/SRO objects |
| `storage/bloom.py` | Redis-backed Bloom filter (configurable size + FP rate) |
| `storage/opensearch.py` | Index `iocs-*` and `actors-*` |
| `storage/qdrant.py` | Embed via `text-embedding-3-large` for semantic recall |
| `storage/neo4j.py` | Persist actor↔TTP and actor↔IOC graph |
| `feeds/scheduler.py` | APScheduler interval jobs |
| `feeds/pipeline.py` | Fan-out to all sinks with idempotency |

### 5.2 Configuration

All feeds toggle via env vars (see [`docs/runbooks/LOCAL_DEVELOPMENT.md`](../runbooks/LOCAL_DEVELOPMENT.md)).

---

## 6. ML-Augmented Fusion

`services/fusion/app/services/ml_scorer.py` adds two scoring dimensions to every fused alert.

| Score | Model | Trigger | Cold-start |
|-------|-------|---------|-----------|
| `anomaly_score` | Isolation Forest (sklearn) | Auto-train at ≥50 alerts | Heuristic on event rarity, hour-of-day, severity |
| `priority_score` | LightGBM `LambdaRank` | Trains when ≥100 analyst feedback rows | Heuristic blending severity, anomaly score, asset criticality |

### 6.1 Feature Vector (`_featurize`)

* Numerical: `severity` (1-5), `asset_criticality` (0-1), `hour_of_day` (cyclical), `dedup_count`, `anomaly_score` (when ranking)
* Categorical: top-N MITRE tactic, source product, alert kind (one-hot)

### 6.2 Feedback Loop

1. Analyst submits `POST /ml/feedback` with `is_true_positive` and `assigned_priority` 1-5.
2. Fusion buffers feedback; once buffer ≥100, schedules a background retrain.
3. New model is hot-swapped behind a `RWLock`; old model is retained until validation.
4. `GET /ml/status` exposes counts, last-trained timestamp, buffer size.

---

## 7. AI Agents (LangGraph)

`services/agents` boots with the **full** MITRE ATT&CK STIX bundle and (optionally) embeds it into Qdrant for semantic retrieval.

### 7.1 Agent DAG

```
PlannerAgent
   │
   ├─▶ EndpointAgent     (CrowdStrike, Velociraptor, GRR)
   ├─▶ IdentityAgent     (Okta, Azure AD, Sentinel)
   ├─▶ NetworkAgent      (Zeek, NetFlow, Darktrace)
   ├─▶ CloudAgent        (AWS, Azure, GCP)
   ├─▶ EmailAgent        (M365 Defender, Gmail)
   ├─▶ ThreatIntelAgent  (calls services/threatintel)
   └─▶ VulnerabilityAgent(reads VULNERABILITY_MATCH stream)
        │
        ▼
   SynthesisAgent ──▶ ActionAgent (with blast-radius gate)
```

Each agent emits chain-of-thought traces persisted in PostgreSQL for explainability.

### 7.2 RAG

* **Threat reports**: indexed by the threat intel service in Qdrant
* **MITRE corpus**: technique descriptions embedded on agent boot (toggle via `ATTCK_QDRANT_EMBED=true`)
* **Internal runbooks**: ingested via `POST /v1/agents/runbooks`

---

## 8. Multi-tenancy & Security

* **Tenant isolation** — All Postgres tables include `tenant_id` and are protected by RLS policies.
* **Neo4j scoping** — Every node carries `tenant_id` and queries use `WHERE n.tenant_id = $tid`.
* **Auth** — JWT + API keys; per-tenant scope checks live in `app/api/v1/deps.py`.
* **Audit log** — Every mutating endpoint emits an audit entry to `audit_log` (Postgres) and Kafka.
* **Action gating** — Blast-radius traversal in Neo4j must return ≤ configured cap before high-impact actions execute.

---

## 9. Observability

* **Metrics** — Prometheus `/metrics` on every service; Grafana dashboards under `infra/grafana/`.
* **Tracing** — OpenTelemetry SDK in Python services; Jaeger for visualization.
* **Logging** — `structlog` (Python) + `log/slog` (Go) in JSON for ELK ingestion.

---

## 10. Deployment Topologies

| Environment | Recommended |
|-------------|-------------|
| Dev / demo | `docker compose up` (this repo) |
| Single-cluster prod | Helm chart at `infra/helm/aisoc` |
| Multi-region | Terraform `infra/terraform` + EKS + cross-region MSK |
| Air-gapped | Swap LLM to Ollama-compatible endpoint (`OPENAI_BASE_URL`) |

---

## 11. References

* [API Reference](../api/API_REFERENCE.md)
* [Local Development](../runbooks/LOCAL_DEVELOPMENT.md)
* [PROGRESS.md](../../PROGRESS.md)
