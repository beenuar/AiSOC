# AiSOC API Reference

This document describes the REST endpoints introduced by the v2 enterprise upgrade. For the auto-generated, exhaustive schema visit `/docs` (Swagger) on each running service.

| Service | Base URL (local) |
|---------|-------------------|
| Core API | `http://localhost:8000` |
| Agents | `http://localhost:8001` |
| Actions | `http://localhost:8002` |
| Fusion | `http://localhost:8003` |
| Threat Intel | `http://localhost:8005` |

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

## 3. Threat Intel IOC Search — `/v1/iocs`

Service: `services/threatintel`.

### 3.1 `GET /v1/iocs/search`

| Query param | Description |
|-------------|-------------|
| `q` | Lexical query (OpenSearch) |
| `type` | `ip` · `domain` · `url` · `sha256` · `md5` |
| `actor` | Filter by named actor |
| `since` | ISO timestamp |

### 3.2 `POST /v1/iocs/semantic`

Vector similarity search against Qdrant.

```json
{
  "text": "powershell encoded base64 mshta DownloadString",
  "k": 10,
  "min_score": 0.6
}
```

### 3.3 `GET /v1/iocs/{value}`

Resolve a single indicator with all enrichment + actor links.

### 3.4 `GET /v1/feeds/status`

```json
{
  "feeds": [
    { "name": "mitre-taxii", "last_run": "…", "ioc_count": 12345 },
    { "name": "cisa-kev",    "last_run": "…", "ioc_count": 1023 }
  ]
}
```

### 3.5 `POST /v1/feeds/{name}/poll`

Trigger an immediate poll (admin-only).

---

## 4. ML Fusion — `/ml`

Service: `services/fusion`.

### 4.1 `GET /ml/status`

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

### 4.2 `POST /ml/feedback`

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

### 4.3 `POST /ml/retrain`

Force a retrain. Returns the new model metadata.

```json
{ "status": "scheduled", "job_id": "…" }
```

---

## 5. Vulnerability Match Stream

Vulnerability matches are surfaced both via Kafka (`vulnerability.matches` topic) and the API:

### 5.1 `GET /v1/vulnerabilities`

Lists recent KEV-correlated matches with host context joined from Neo4j.

| Query param | Description |
|-------------|-------------|
| `cve` | Filter by CVE ID |
| `host_id` | Filter by host |
| `kev_only` | `true`/`false` (default `true`) |

---

## 6. Cases — `/v1/cases`

Unchanged from v1, but now joined with Neo4j attack paths via `GET /v1/cases/{id}/attack-path`.

---

## 7. Authentication

* JWT issued by `POST /v1/auth/login`.
* API keys via `Authorization: ApiKey <key>` header.
* All requests must specify a tenant context — either implicit (from JWT) or explicit (`X-Tenant-Id` header for service-to-service calls).

---

## 8. Errors

All endpoints return RFC 7807 Problem Details:

```json
{
  "type": "https://aisoc.dev/errors/rule-validation",
  "title": "Sigma rule failed validation",
  "status": 422,
  "detail": "Unknown field 'EventID' in selection 'sel_powershell'",
  "instance": "/v1/rules"
}
```

---

## 9. Rate Limits

| Tier | Requests/min |
|------|--------------|
| Default | 600 |
| `/v1/rules/hunt` | 30 |
| `/ml/retrain` | 6 |

Limits are tenant-scoped and enforced by Redis.

---

## 10. Versioning

The API follows semver via the URL prefix `/v1`. Breaking changes will move to `/v2` and the previous version remains supported for at least 6 months.
