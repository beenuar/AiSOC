# AiSOC API Reference

This document describes the REST endpoints exposed by AiSOC services. For the auto-generated, exhaustive schema visit `/docs` (Swagger) on each running service.

| Service | Base URL (local) |
|---------|-------------------|
| Core API | `http://localhost:8000` |
| Agents | `http://localhost:8001` |
| Actions | `http://localhost:8002` |
| Fusion | `http://localhost:8003` |
| Threat Intel | `http://localhost:8005` |
| Purple Team | `http://localhost:8006` |
| Connectors | (internal scheduler — no external port) |

All examples assume:

```bash
export AISOC_TOKEN="$(curl -sX POST http://localhost:8000/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@aisoc.local","password":"changeme"}' | jq -r .access_token)"
export AISOC_TENANT="00000000-0000-0000-0000-000000000001"
```

---

## 1. Graph (Neo4j) — `/v1/graph`

Service: `services/api`.

### 1.1 `GET /v1/graph/attack-path/{case_id}`

Reconstructs the kill-chain for a case by traversing `(:Case)-[:CONTAINS]->(:Alert)-[:USES]->(:Technique)-[:PART_OF]->(:Tactic)`.

```bash
curl -H "authorization: Bearer $AISOC_TOKEN" \
  http://localhost:8000/v1/graph/attack-path/$CASE_ID
```

**Response**

```json
{
  "case_id": "…",
  "tactics": [
    { "id": "TA0001", "name": "Initial Access" },
    { "id": "TA0002", "name": "Execution" }
  ],
  "techniques": [
    { "id": "T1566", "name": "Phishing", "alert_id": "…" },
    { "id": "T1059.001", "name": "PowerShell", "alert_id": "…" }
  ]
}
```

### 1.2 `GET /v1/graph/blast-radius`

Returns 1-3 hop neighborhood of a node, used to gate high-impact actions.

| Query param | Required | Description |
|-------------|----------|-------------|
| `entity_type` | yes | One of `host`, `user`, `ioc` |
| `entity_id` | yes | Node identifier |
| `max_hops` | no (default `2`) | 1-3 |

```bash
curl -H "authorization: Bearer $AISOC_TOKEN" \
  "http://localhost:8000/v1/graph/blast-radius?entity_type=host&entity_id=HOST-42&max_hops=2"
```

**Response**

```json
{
  "root": { "type": "Host", "id": "HOST-42" },
  "nodes": 17,
  "edges": 24,
  "hosts": ["HOST-42", "HOST-71"],
  "users": ["alice@corp"],
  "iocs": ["1.2.3.4", "evil.tld"],
  "alerts": ["A-1", "A-7"]
}
```

### 1.3 `GET /v1/graph/neighbors`

1-hop neighborhood for the SOC console "context" panel.

### 1.4 `GET /v1/graph/mitre-coverage`

Aggregated counts of distinct techniques observed per tenant.

| Query param | Default | Description |
|-------------|---------|-------------|
| `window` | `7d` | `1h`, `24h`, `7d`, `30d` |

---

## 2. Detection Rules — `/v1/rules`

Service: `services/api`.

### 2.1 `GET /v1/rules`

| Query param | Description |
|-------------|-------------|
| `language` | `sigma` · `yara` · `kql` · `lucene` · `regex` |
| `enabled` | `true`/`false` |
| `severity` | `low`-`critical` |

### 2.2 `POST /v1/rules`

```json
{
  "name": "Suspicious PowerShell encoded command",
  "language": "sigma",
  "severity": "high",
  "rule": "title: Suspicious PowerShell\n…",
  "tags": ["attack.execution", "attack.t1059.001"],
  "enabled": true
}
```

### 2.3 `POST /v1/rules/{id}/execute`

Run a single rule on demand against the last `lookback` of telemetry.

```json
{
  "lookback": "1h",
  "indices": ["events-*"],
  "limit": 100
}
```

**Response**

```json
{
  "rule_id": "…",
  "matches": 7,
  "duration_ms": 138,
  "results": [
    { "event_id": "…", "host": "…", "user": "…", "ts": "…" }
  ]
}
```

### 2.4 `POST /v1/rules/hunt`

Multi-rule, time-bounded threat hunt.

```json
{
  "rule_ids": ["rule-1", "rule-2"],
  "from": "2026-04-25T00:00:00Z",
  "to":   "2026-05-01T00:00:00Z",
  "limit_per_rule": 50
}
```

### 2.5 `PATCH /v1/rules/{id}` / `DELETE /v1/rules/{id}`

Standard CRUD with optimistic concurrency via `If-Match` ETag.

---

## 3. Detection Proposals (Detection-as-Code) — `/v1/detection-proposals`

Service: `services/api`.

The DAC lifecycle manages detection rule proposals from creation through eval-gated promotion into the live rule set. Every proposal carries an eval result from `scripts/run_evals.py`; candidates that regress MITRE accuracy by ≥ 1 pp cannot be promoted.

### 3.1 `GET /v1/detection-proposals`

| Query param | Description |
|-------------|-------------|
| `status` | `draft` · `in_review` · `approved` · `rejected` · `promoted` |

### 3.2 `POST /v1/detection-proposals`

```json
{
  "title": "Detect rundll32 network connections",
  "description": "Flags rundll32.exe making outbound connections — common LOLBin technique.",
  "logic": "title: Rundll32 Outbound\nstatus: experimental\n…",
  "mitre_tags": ["attack.defense_evasion", "attack.t1218.011"]
}
```

### 3.3 `GET /v1/detection-proposals/{id}`

Returns proposal detail including comments and attached eval results.

### 3.4 `POST /v1/detection-proposals/{id}/comment`

```json
{ "body": "Looks good — verified against last 30 days of telemetry." }
```

### 3.5 `POST /v1/detection-proposals/{id}/eval`

Attach eval result (metric deltas from `scripts/run_evals.py`).

```json
{
  "mitre_accuracy_delta": 0.02,
  "alert_reduction_delta": -0.01,
  "investigation_completeness_delta": 0.0,
  "response_quality_delta": 0.0
}
```

### 3.6 `POST /v1/detection-proposals/{id}/decide`

```json
{ "decision": "approve" }
```

Valid decisions: `approve`, `reject`.

### 3.7 `POST /v1/detection-proposals/{id}/promote`

Promotes an approved proposal into `detection_rules`. Returns the new rule ID.

### 3.8 `GET /v1/detection-proposals/baseline`

Current eval baseline metrics used as the promotion gate reference.

### 3.9 `POST /v1/detection-proposals/baseline`

Reset eval baseline to the latest harness run (admin-only).

---

## 4. Federated Search — `/v1/federated`

Service: `services/api` → `services/connectors`.

Fan out a single query to connected SIEMs. The API translates the query into each target's native dialect (SPL for Splunk, KQL for Sentinel, ES|QL for Elastic).

### 4.1 `POST /v1/federated/query`

```json
{
  "query": "process.name = \"rundll32.exe\" AND network.direction = \"outbound\"",
  "targets": ["splunk-prod", "sentinel-corp"],
  "time_range": { "from": "2026-05-01T00:00:00Z", "to": "2026-05-06T00:00:00Z" }
}
```

**Response**

```json
{
  "results": [
    { "target": "splunk-prod", "dialect": "spl", "hits": 14, "events": [ … ] },
    { "target": "sentinel-corp", "dialect": "kql", "hits": 3, "events": [ … ] }
  ]
}
```

---

## 5. Threat Intel IOC Search — `/v1/iocs`

Service: `services/threatintel`.

### 5.1 `GET /v1/iocs/search`

| Query param | Description |
|-------------|-------------|
| `q` | Lexical query (OpenSearch) |
| `type` | `ip` · `domain` · `url` · `sha256` · `md5` |
| `actor` | Filter by named actor |
| `since` | ISO timestamp |

### 5.2 `POST /v1/iocs/semantic`

Vector similarity search against Qdrant.

```json
{
  "text": "powershell encoded base64 mshta DownloadString",
  "k": 10,
  "min_score": 0.6
}
```

### 5.3 `GET /v1/iocs/{value}`

Resolve a single indicator with all enrichment + actor links.

### 5.4 `GET /v1/feeds/status`

```json
{
  "feeds": [
    { "name": "mitre-taxii", "last_run": "…", "ioc_count": 12345 },
    { "name": "cisa-kev",    "last_run": "…", "ioc_count": 1023 }
  ]
}
```

### 5.5 `POST /v1/feeds/{name}/poll`

Trigger an immediate poll (admin-only).

---

## 6. ML Fusion — `/ml`

Service: `services/fusion`.

### 6.1 `GET /ml/status`

```json
{
  "anomaly_model": {
    "trained": true,
    "samples": 482,
    "last_trained_at": "2026-04-30T12:00:00Z"
  },
  "ranker_model": {
    "trained": false,
    "feedback_buffer": 73,
    "feedback_required": 100
  }
}
```

### 6.2 `POST /ml/feedback`

Submitted by analysts when triaging an alert.

```json
{
  "alert_id": "…",
  "tenant_id": "…",
  "analyst_id": "alice@corp",
  "is_true_positive": true,
  "assigned_priority": 2,
  "notes": "Confirmed lateral movement"
}
```

### 6.3 `POST /ml/retrain`

Force a retrain. Returns the new model metadata.

```json
{ "status": "scheduled", "job_id": "…" }
```

---

## 7. Vulnerability Match Stream

Vulnerability matches are surfaced both via Kafka (`vulnerability.matches` topic) and the API:

### 7.1 `GET /v1/vulnerabilities`

Lists recent KEV-correlated matches with host context joined from Neo4j.

| Query param | Description |
|-------------|-------------|
| `cve` | Filter by CVE ID |
| `host_id` | Filter by host |
| `kev_only` | `true`/`false` (default `true`) |

---

## 8. Cases — `/v1/cases`

Unchanged from v1, but now joined with Neo4j attack paths via `GET /v1/cases/{id}/attack-path`.

---

## 9. Hunt-as-Code — `/api/v1/hunts`

Service: `services/agents`.

YAML hunt definitions live in `hunts/`. Each file declares a hypothesis,
MITRE ATT&CK tags, log sources, indicators, expected outcomes, and an
optional schedule. The agents service loads the corpus at startup and
exposes it via these endpoints.

### 9.1 `GET /api/v1/hunts`

List all hunts in the YAML corpus.

### 9.2 `GET /api/v1/hunts/{hunt_id}`

Single hunt definition (hypothesis, MITRE tags, indicators, schedule).

### 9.3 `POST /api/v1/hunts/{hunt_id}/run`

Run a hunt on demand. Returns run output including findings.

### 9.4 `GET /api/v1/hunts/runs`

Recent hunt runs (DB-backed). Query param: `limit` (default 50, max 500).

### 9.5 `GET /api/v1/hunts/findings`

Recent findings across all hunts. Query params: `hunt_id`, `status`, `limit`.

### 9.6 `POST /api/v1/hunts/reload`

Reload the corpus from disk and re-sync the catalog table.

---

## 10. Entity Risk (Risk-Based Alerting)

Service: `services/fusion`.

Time-decayed risk scores per entity (user, host, src_ip, domain).
Alerts contribute severity-weighted points that decay with a configurable
half-life. When an entity crosses `rba_promotion_threshold` it is
promoted to an incident with contributing alerts attached.

The entity-centric queue surfaces the top-N highest-risk entities to
analysts instead of raw alert lists, supporting alert-to-incident
ratios of ≥ 50:1.

Entity risk data is stored in Redis hashes (per entity, namespaced by
tenant) with ZSET-backed top-N sorted queues for O(log N) reads.

> Entity risk is accessed internally by the fusion engine. The web
> console reads the queue via the `/entity-risk` endpoints on the
> API service (see the Docusaurus REST reference for the public surface).

---

## 11. Authentication

* JWT issued by `POST /v1/auth/login`.
* API keys via `Authorization: ApiKey <key>` header.
* All requests must specify a tenant context — either implicit (from JWT) or explicit (`X-Tenant-Id` header for service-to-service calls).

---

## 12. Errors

All endpoints return RFC 7807 Problem Details:

```json
{
  "type": "https://example.com/errors/rule-validation",
  "title": "Sigma rule failed validation",
  "status": 422,
  "detail": "Unknown field 'EventID' in selection 'sel_powershell'",
  "instance": "/v1/rules"
}
```

---

## 13. Rate Limits

| Tier | Requests/min |
|------|--------------|
| Default | 600 |
| `/v1/rules/hunt` | 30 |
| `/ml/retrain` | 6 |

Limits are tenant-scoped and enforced by Redis.

---

## 14. Versioning

The API follows semver via the URL prefix `/v1`. Breaking changes will move to `/v2` and the previous version remains supported for at least 6 months.
