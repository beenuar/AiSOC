# AiSOC Multi-Region Operations

> **Audience**: Platform / SRE teams running AiSOC in production across multiple cloud regions.
> **Last updated**: auto-generated (see `scripts/generate_runbook.py`)

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [Region topology](#2-region-topology)
3. [Data residency & replication strategy](#3-data-residency--replication-strategy)
4. [Traffic routing & failover](#4-traffic-routing--failover)
5. [Deployment procedures](#5-deployment-procedures)
6. [Observability & alerting](#6-observability--alerting)
7. [Runbooks](#7-runbooks)
8. [Recovery objectives (RTO / RPO)](#8-recovery-objectives-rto--rpo)
9. [Chaos engineering checklist](#9-chaos-engineering-checklist)
10. [Contact & escalation matrix](#10-contact--escalation-matrix)

---

## 1. Architecture overview

AiSOC is deployed as a set of independent microservices managed by Helm. In a multi-region setup each region runs a full replica of the control plane with:

- **Active–passive** PostgreSQL: one writer in the primary region; read replicas in secondary regions promoted on failover.
- **Active–active** ClickHouse: distributed cluster with per-shard replicas across regions; ZooKeeper or ClickHouse Keeper runs in every region.
- **Active–active** ingest pipeline: events are fan-out written to all region Kafka clusters; correlation happens locally.
- **Global load balancer** (e.g. Cloudflare, AWS Global Accelerator, or GCP Traffic Director) directing API traffic to the nearest healthy region.

```
                ┌──────────────────────────────────────────────────────┐
                │             Global Load Balancer / Anycast DNS       │
                └───────────┬──────────────────────┬───────────────────┘
                            │                      │
              ┌─────────────▼──────────┐  ┌────────▼──────────────┐
              │  Region: us-east-1      │  │  Region: eu-west-1    │
              │ ─────────────────────  │  │ ──────────────────── │
              │  Kubernetes cluster    │  │  Kubernetes cluster   │
              │  ├─ api (×2)           │  │  ├─ api (×2)          │
              │  ├─ ingest (×3)        │  │  ├─ ingest (×3)       │
              │  ├─ enrichment (×2)    │  │  ├─ enrichment (×2)   │
              │  ├─ alert-fusion (×2)  │  │  ├─ alert-fusion (×2) │
              │  └─ agents (×2)        │  │  └─ agents (×2)       │
              │                        │  │                        │
              │  PostgreSQL PRIMARY ─────────► PostgreSQL REPLICA  │
              │  ClickHouse shard 1    │  │  ClickHouse shard 2   │
              │  Redis (leader)  ────────►  Redis (replica)       │
              └────────────────────────┘  └───────────────────────┘
```

---

## 2. Region topology

| Region label | Cloud / zone | Role | Postgres | ClickHouse shards |
|---|---|---|---|---|
| `us-east-1` | AWS us-east-1a/b | Primary | Writer | Shard 1 (1 replica each) |
| `eu-west-1` | AWS eu-west-1a/b | Secondary | Async replica | Shard 2 (1 replica each) |
| `ap-southeast-1` | AWS ap-southeast-1a | DR-only | Async replica | — |

### Adding a new region

```bash
# 1. Provision cluster (Terraform / eksctl / etc.)
# 2. Install cert-manager, nginx-ingress, external-secrets
# 3. Deploy AiSOC chart pointing to existing secrets store
helm upgrade --install aisoc infra/helm/aisoc \
  --namespace aisoc \
  --create-namespace \
  --set global.environment=production \
  --set ingress.hosts[0].host=aisoc-eu.example.com \
  -f infra/helm/aisoc/values-eu-west-1.yaml

# 4. Register region in Global LB (health-check /api/health)
# 5. Stream Postgres WAL to new replica (pg_basebackup)
# 6. Extend ClickHouse cluster config to include new shard
```

---

## 3. Data residency & replication strategy

### PostgreSQL

- **Streaming replication** (`wal_level=replica`, `max_wal_senders=5`).
- Replication lag target: < 5 s. Alert at 30 s, page at 2 min.
- **Failover**: automatic with Patroni or managed RDS Multi-AZ. Replica becomes writer; old writer enters standby when recovered.
- GDPR: tenants with EU data residency requirements are assigned to the `eu-west-1` writer via per-tenant routing in `tenant_sla_config`.

### ClickHouse

- Distributed table `events_dist` over all shards.
- Each shard has a replica in the same region; cross-region replication runs over ZooKeeper quorum.
- Replication lag target: < 10 s. Alert at 60 s.

### Redis

- Read replicas in secondary regions for cache warming; sentinel setup for HA within a region.
- Session data: replicated. Ephemeral rate-limit keys: local only.

### Object storage (S3/R2)

- Backup objects replicated to a second bucket in an alternate region via bucket replication rules.
- Plugin artifacts: single bucket with multi-region access enabled.

---

## 4. Traffic routing & failover

### Healthy-region selection

The global LB runs active health checks every 10 s against `GET /api/health`. A region is removed from rotation if:

- HTTP status ≠ 200 for 3 consecutive checks, **or**
- Latency p99 > 2 s for 5 consecutive checks.

### Planned failover (maintenance)

```bash
# Drain traffic from us-east-1 before maintenance window
# 1. Weight us-east-1 to 0 in LB config
# 2. Wait for in-flight requests to drain (~60 s)
# 3. Perform maintenance
# 4. Restore weight

# CloudFlare example
cf_zone_id=<ZONE_ID>
cf_record_id=<RECORD_ID>
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${cf_zone_id}/dns_records/${cf_record_id}" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -d '{"data":{"weight":0}}'
```

### Unplanned failover

1. PagerDuty alert fires (`region_health_check` rule).
2. On-call SRE confirms outage (`./scripts/health_check.sh --region us-east-1`).
3. Execute **runbook** `RB-003-region-failover` (auto-generated; see §7).
4. Postgres: promote replica via Patroni or `aws rds promote-read-replica`.
5. Update `DATABASE_URL` secret in secondary region to the new writer endpoint.
6. Restart API pods: `kubectl rollout restart deployment -n aisoc -l app.kubernetes.io/name=api`.

---

## 5. Deployment procedures

### Rolling update (standard)

```bash
# Bump image tag in CI/CD (GitHub Actions), then:
helm upgrade aisoc infra/helm/aisoc \
  --namespace aisoc \
  --atomic \
  --timeout 5m \
  --set services.api.image.tag=${GIT_SHA} \
  --set services.ingest.image.tag=${GIT_SHA}
```

`maxUnavailable: 0` and `maxSurge: 1` are enforced in `deployment.yaml`; pods are updated one at a time.

### Blue/green release

1. Deploy new version to a parallel namespace (`aisoc-green`).
2. Run smoke tests against `green` ingress host.
3. Switch LB to `green` namespace via weighted routing.
4. Keep `blue` idle for 1 hour (rollback window).
5. Delete `blue` namespace.

### Rollback

```bash
helm rollback aisoc 0 --namespace aisoc   # 0 = previous release
# or target a specific revision:
helm history aisoc --namespace aisoc
helm rollback aisoc <REVISION> --namespace aisoc
```

---

## 6. Observability & alerting

AiSOC emits **OpenTelemetry** traces, metrics, and structured logs to a configurable OTLP endpoint (`global.otelEndpoint` in `values.yaml`).

### Key SLIs

| Service | Metric | SLO target |
|---|---|---|
| `api` | `http_request_duration_p99` | < 500 ms |
| `api` | `http_error_rate` | < 0.5 % |
| `ingest` | `event_ingestion_lag_p99` | < 2 s |
| `alert-fusion` | `alert_fusion_latency_p99` | < 5 s |
| `agents` | `agent_run_duration_p95` | < 30 s |
| All | Pod ready ratio | > 99 % |

### Recommended dashboards

- **Service map**: trace-based topology from OTLP backend (Tempo, Jaeger, Honeycomb).
- **Golden signals**: per-service latency / error / saturation / traffic (Grafana `aisoc-golden-signals.json`).
- **SLA tracker**: AiSOC built-in `/sla` dashboard (`/apps/web/src/app/(app)/sla/page.tsx`).

### Alerting rules (Prometheus/AlertManager)

```yaml
# Example PrometheusRule
- alert: AiSOCHighErrorRate
  expr: |
    rate(http_requests_total{service="aisoc-api",status=~"5.."}[5m])
    / rate(http_requests_total{service="aisoc-api"}[5m]) > 0.005
  for: 3m
  labels:
    severity: page
  annotations:
    summary: "AiSOC API error rate > 0.5%"

- alert: AiSOCIngestLag
  expr: histogram_quantile(0.99, rate(ingest_lag_seconds_bucket[5m])) > 2
  for: 5m
  labels:
    severity: warn
```

---

## 7. Runbooks

Runbooks are auto-generated from live OTel trace data by `scripts/generate_runbook.py`. The output lives in `docs/operations/runbooks/`. Each runbook follows the format:

```
RB-NNN-<slug>.md
  Title
  Trigger condition
  Impact assessment
  Diagnosis steps (from trace topology)
  Remediation steps
  Verification steps
  Escalation path
```

### Available runbooks

| ID | Slug | Trigger |
|---|---|---|
| RB-001 | `api-high-latency` | `http_request_duration_p99 > 500ms` |
| RB-002 | `postgres-replica-lag` | Replication lag > 30 s |
| RB-003 | `region-failover` | Region health check failure |
| RB-004 | `ingest-pipeline-stall` | Ingest lag > 30 s |
| RB-005 | `agent-runner-oom` | OOMKilled in `agents` pods |
| RB-006 | `cert-expiry` | TLS cert expires in < 14 days |

To regenerate all runbooks:

```bash
OTEL_ENDPOINT=http://tempo:4317 \
  python scripts/generate_runbook.py \
  --output docs/operations/runbooks/ \
  --lookback-hours 168    # 1 week of traces
```

---

## 8. Recovery objectives (RTO / RPO)

| Failure scenario | RPO | RTO |
|---|---|---|
| Single pod crash | 0 s | < 30 s (K8s restarts) |
| Availability zone failure | < 30 s | < 5 min |
| Region failure (warm standby) | < 60 s | < 15 min |
| Region failure (cold DR) | < 5 min | < 60 min |
| Total data loss (from backup) | 24 h | < 4 h |

---

## 9. Chaos engineering checklist

Run monthly in the `staging` environment:

- [ ] Kill 50 % of `api` pods; confirm remaining pods handle load and HPA scales up.
- [ ] Inject 500 ms network latency to `postgres`; confirm circuit breaker opens.
- [ ] Stop Kafka consumer group for `ingest`; confirm lag alert fires within 5 min.
- [ ] Simulate AZ failure by cordoning one node group; confirm pods reschedule.
- [ ] Promote Postgres replica; confirm API recovers within RTO.
- [ ] Delete and restore from backup; confirm RPO.

---

## 10. Contact & escalation matrix

| Severity | First responder | Escalate to | SLA |
|---|---|---|---|
| P1 – Production down | On-call SRE (PagerDuty) | Engineering lead | 15 min response |
| P2 – Degraded performance | On-call SRE | Engineering lead | 1 h response |
| P3 – Non-critical issue | Slack `#aisoc-ops` | — | Next business day |
| P4 – Informational | Ticketing system | — | Best effort |

---

*This document is maintained alongside the codebase. Run `scripts/generate_runbook.py --update-toc` to refresh section links after adding runbooks.*
