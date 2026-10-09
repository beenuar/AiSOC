# AiSOC API Reference

This document describes the REST endpoints exposed by AiSOC services. For the
auto-generated, exhaustive schema visit `/api/docs` (Swagger) on a running API
service — the app mounts it there, not at `/docs`.

> The maintained, published API reference is
> [`apps/docs/docs/api/rest.md`](../../apps/docs/docs/api/rest.md) on the docs
> portal. This page is the longer-form companion; where the two disagree, the
> generated OpenAPI schema at `/api/openapi.json` wins.

| Service | Base URL (local) |
|---------|-------------------|
| Core API | `http://localhost:8000` |
| Agents | `http://localhost:8001` |
| Actions | `http://localhost:8002` |
| Fusion | `http://localhost:8003` |
| Threat Intel | `http://localhost:8005` |
| Purple Team | `http://localhost:8006` |
| Connectors | `http://localhost:8088` |

All examples assume:

```bash
# AISOC_ADMIN_PASSWORD is the password `make bootstrap` printed. There is no
# default credential — each deployment generates its own at first run.
export AISOC_TOKEN="$(curl -sX POST http://localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d "{\"email\":\"admin@aisoc.internal\",\"password\":\"$AISOC_ADMIN_PASSWORD\"}" \
  | jq -r .access_token)"
export AISOC_TENANT="00000000-0000-0000-0000-000000000001"
```

---

## 1. Graph (Neo4j) — `/api/v1/graph`

Service: `services/api`.

### 1.1 `GET /api/v1/graph/attack-path/{case_id}`

Reconstructs the kill-chain for a case by traversing `(:Case)-[:CONTAINS]->(:Alert)-[:USES]->(:Technique)-[:PART_OF]->(:Tactic)`.

```bash
curl -H "authorization: Bearer $AISOC_TOKEN" \
  http://localhost:8000/api/v1/graph/attack-path/$CASE_ID
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

### 1.2 `GET /api/v1/graph/blast-radius/{entity_type}/{entity_id}`

Returns 1-3 hop neighborhood of a node, used to gate high-impact actions.
`entity_type` and `entity_id` are **path** segments; only `max_hops` is a
query parameter.

| Parameter | Where | Description |
|-----------|-------|-------------|
| `entity_type` | path | One of `host`, `user`, `ioc` |
| `entity_id` | path | Node identifier |
| `max_hops` | query (default `2`) | 1-3 |

```bash
curl -H "authorization: Bearer $AISOC_TOKEN" \
  "http://localhost:8000/api/v1/graph/blast-radius/host/HOST-42?max_hops=2"
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

### 1.3 `GET /api/v1/graph/neighbors/{entity_type}/{entity_id}`

1-hop neighborhood for the SOC console "context" panel. Same path-parameter
shape as blast radius.

### 1.4 `GET /api/v1/graph/mitre-coverage`

Aggregated counts of distinct techniques observed per tenant.

| Query param | Default | Description |
|-------------|---------|-------------|
| `window` | `7d` | `1h`, `24h`, `7d`, `30d` |

---

## 2. Detection Rules — `/api/v1/rules`

Service: `services/api`.

### 2.1 `GET /api/v1/rules`

| Query param | Description |
|-------------|-------------|
| `language` | `sigma` · `yara` · `kql` · `lucene` · `regex` |
| `enabled` | `true`/`false` |
| `severity` | `low`-`critical` |

### 2.2 `POST /api/v1/rules`

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

### 2.3 `POST /api/v1/rules/{id}/execute`

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

### 2.4 `POST /api/v1/rules/hunt`

Multi-rule, time-bounded threat hunt.

```json
{
  "rule_ids": ["rule-1", "rule-2"],
  "from": "2026-04-25T00:00:00Z",
  "to":   "2026-05-01T00:00:00Z",
  "limit_per_rule": 50
}
```

### 2.5 `PATCH /api/v1/rules/{id}` / `DELETE /api/v1/rules/{id}`

Standard CRUD with optimistic concurrency via `If-Match` ETag.

---

## 3. Detection Proposals (Detection-as-Code) — `/api/v1/detection-proposals`

Service: `services/api`.

The DAC lifecycle manages detection rule proposals from creation through eval-gated promotion into the live rule set. Every proposal carries an eval result from `scripts/run_evals.py`; candidates that regress MITRE accuracy by ≥ 1 pp cannot be promoted.

### 3.1 `GET /api/v1/detection-proposals`

| Query param | Description |
|-------------|-------------|
| `status` | `draft` · `in_review` · `approved` · `rejected` · `promoted` |

### 3.2 `POST /api/v1/detection-proposals`

```json
{
  "title": "Detect rundll32 network connections",
  "description": "Flags rundll32.exe making outbound connections — common LOLBin technique.",
  "logic": "title: Rundll32 Outbound\nstatus: experimental\n…",
  "mitre_tags": ["attack.defense_evasion", "attack.t1218.011"]
}
```

### 3.3 `GET /api/v1/detection-proposals/{id}`

Returns proposal detail including comments and attached eval results.

### 3.4 `POST /api/v1/detection-proposals/{id}/comment`

```json
{ "body": "Looks good — verified against last 30 days of telemetry." }
```

### 3.5 `POST /api/v1/detection-proposals/{id}/eval`

Attach eval result (metric deltas from `scripts/run_evals.py`).

```json
{
  "mitre_accuracy_delta": 0.02,
  "alert_reduction_delta": -0.01,
  "investigation_completeness_delta": 0.0,
  "response_quality_delta": 0.0
}
```

### 3.6 `POST /api/v1/detection-proposals/{id}/decide`

```json
{ "decision": "approve" }
```

Valid decisions: `approve`, `reject`.

### 3.7 `POST /api/v1/detection-proposals/{id}/promote`

Promotes an approved proposal into `detection_rules`. Returns the new rule ID.

### 3.8 `GET /api/v1/detection-proposals/baselines`

Current eval baseline metrics used as the promotion gate reference.

### 3.9 `POST /api/v1/detection-proposals/baselines`

Reset eval baseline to the latest harness run (admin-only).

---

## 4. Federated Search — `/api/v1/federated`

Service: `services/api` → `services/connectors`.

Fan out a single query to connected SIEMs. The API translates the query into each target's native dialect (SPL for Splunk, KQL for Sentinel, ES|QL for Elastic).

### 4.1 `POST /api/v1/federated/search`

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

## 5. Threat Intel IOC Search — `/api/v1/iocs`

Service: `services/threatintel` (port 8005). Note the full prefix: the route
is declared on the app, so it is `/api/v1/iocs/search` on the threat-intel
service, not on the core API.

### 5.1 `GET /api/v1/iocs/search`

| Query param | Description |
|-------------|-------------|
| `q` | Lexical query (OpenSearch) |
| `type` | `ip` · `domain` · `url` · `sha256` · `md5` |
| `actor` | Filter by named actor |
| `since` | ISO timestamp |

This is the only IOC route the service exposes. Earlier revisions of this page
also listed `POST /iocs/semantic`, `GET /iocs/{value}`, `GET /feeds/status` and
`POST /feeds/{name}/poll`; none of them was ever implemented. IOC records the
core API stores are at `GET`/`POST /api/v1/threat-intel/iocs`.

---

## 6. ML Fusion — `/api/v1/fusion`

Service: `services/fusion` (port 8003), proxied by the core API.

### 6.1 `GET /api/v1/fusion/ml/status`

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

`POST /ml/feedback` and `POST /ml/retrain` exist on the fusion service itself
(`services/fusion/app/api/router.py`) but are **not** proxied by the core API,
so they are reachable only from inside the compose network at
`http://fusion:8003/ml/feedback` and `http://fusion:8003/ml/retrain`.

---

## 7. Vulnerability Match Stream

Vulnerability matches are surfaced on the Kafka `vulnerability.matches` topic.
There is no `GET /api/v1/vulnerabilities` route; this page previously claimed
one. KEV exposure is read through the posture surface
(`services/api/app/api/v1/endpoints/posture.py`).

---

## 8. Cases — `/api/v1/cases`

Standard CRUD. The attack path for a case is read from the graph surface —
`GET /api/v1/graph/attack-path/{case_id}` (§1.1) — not from a route under
`/cases`.

---

## 9. Hunt-as-Code — `/api/v1/hunts`

Service: `services/api` (`app/api/v1/endpoints/hunts.py`).

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

### 9.4 `GET /api/v1/hunts/{hunt_id}/runs`

Recent runs for one hunt (DB-backed). Query param: `limit`.

### 9.5 `GET /api/v1/hunts/{hunt_id}/findings`

Recent findings for one hunt. Query params: `status`, `limit`.

Both are scoped to a single hunt; there are no corpus-wide `/hunts/runs` or
`/hunts/findings` routes, and no `POST /hunts/reload`. The corpus is loaded at
startup.

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

> Entity risk is accessed internally by the fusion engine. The web console
> reads the queue through the API's fusion proxy:
> `GET /api/v1/fusion/entity-risk/queue`, `/entity-risk/stats` and
> `/entity-risk/{entity_type}/{entity_value}`.

---

## 11. Authentication

* JWT issued by `POST /api/v1/auth/login`.
* API keys via `Authorization: ApiKey *** header.
* All requests must specify a tenant context — either implicit (from JWT) or explicit (`X-Tenant-Id` header for service-to-service calls).
* SSO (feature-flagged `SSO_ENABLED`): `GET /api/v1/auth/sso/status` advertises
  enabled connections; the OIDC callback lands the session on `/login?next=…`
  with tokens in the URL fragment (never in query strings or server logs).
  JIT provisioning defaults to `viewer`; `admin` is unreachable from SSO by
  construction unless an explicit allowlisted admin group mapping exists.

## 11a. Users Administration — `/api/v1/admin/users`

Admin only (`roles:write`); every mutation requires a `reason`, writes an
audit row, and revokes the target's active sessions. See
[Roles & Permissions](../roles-and-permissions.md) for the full model.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/admin/users` | Paginated list (`q`, `role`, `status`, `sort`, `dir`, `page`, `size`) — server-side only |
| `GET` | `/api/v1/admin/users/{id}` | Detail incl. roles, provider, last login |
| `PUT` | `/api/v1/admin/users/{id}/roles` | Replace role set (catalog-validated, last-admin guard) |
| `POST` | `/api/v1/admin/users/{id}/roles` | Add one role |
| `DELETE` | `/api/v1/admin/users/{id}/roles/{role}` | Remove one role |
| `PATCH` | `/api/v1/admin/users/{id}` | Enable/disable (`{"is_active": bool}`) |
| `DELETE` | `/api/v1/admin/users/{id}?reason=…` | Permanent delete; audit retains identity snapshot |

Errors: `401` unauthenticated · `403`/`401` insufficient role (fail-closed)
· `404` unknown or cross-tenant id · `409` self-delete or last-admin
violation · `422` missing/oversized reason.

---

## 12. Errors

All endpoints return RFC 7807 Problem Details:

```json
{
  "type": "https://example.com/errors/rule-validation",
  "title": "Sigma rule failed validation",
  "status": 422,
  "detail": "Unknown field 'EventID' in selection 'sel_powershell'",
  "instance": "/api/v1/rules"
}
```

---

## 13. Rate Limits

| Tier | Requests/min |
|------|--------------|
| Default | 600 |
| `/api/v1/rules/hunt` | 30 |

Limits are tenant-scoped and enforced by Redis.

---

## 14. Versioning

The API follows semver via the URL prefix `/api/v1`. Breaking changes will move
to `/api/v2` and the previous version remains supported for at least 6 months.
