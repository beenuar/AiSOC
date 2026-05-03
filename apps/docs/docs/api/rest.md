---
sidebar_position: 1
---

# REST API Reference

AiSOC exposes a fully documented OpenAPI 3.1 REST API.

## Base URL

| Environment | URL |
|-------------|-----|
| Local dev | `http://localhost:8000/api/v1` |
| Docker Compose | `http://api:8000/api/v1` |
| Kubernetes | `https://your-domain.com/api/v1` |

## Authentication

### JWT Bearer (User)

```bash
# Obtain a token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@aisoc.local","password":"changeme"}'

# Use the token
curl http://localhost:8000/api/v1/cases \
  -H "Authorization: Bearer <token>"
```

### API Key (Service-to-Service)

```bash
curl http://localhost:8000/api/v1/alerts \
  -H "X-API-Key: <api-key>"
```

API keys are created via `POST /api/v1/api-keys` and can be scoped to specific permissions.

## Interactive Docs

When running locally, interactive Swagger UI is available at:

- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **OpenAPI JSON**: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

The full spec is also committed at [`docs/openapi.yaml`](https://github.com/beenuar/aisoc/blob/main/docs/openapi.yaml).

## Endpoint Groups

### Identity & Access

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login` | Obtain JWT |
| `POST` | `/auth/refresh` | Refresh JWT |
| `POST` | `/auth/logout` | Revoke token |
| `POST` | `/auth/saml/login` | Initiate SAML SSO |
| `GET` | `/auth/saml/callback` | SAML ACS endpoint |
| `POST` | `/auth/oidc/login` | Initiate OIDC flow |
| `GET` | `/auth/oidc/callback` | OIDC redirect handler |
| `GET` | `/users/me` | Current user profile |
| `GET/POST` | `/api-keys` | List / create API keys |
| `DELETE` | `/api-keys/{id}` | Revoke an API key |
| `GET/POST/PUT/DELETE` | `/rbac/roles` | Role management |
| `GET/POST/PUT/DELETE` | `/rbac/permissions` | Permission management |

### Detection & Hunting

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/alerts` | List / ingest alerts |
| `GET/PATCH/DELETE` | `/alerts/{id}` | Alert detail / update / delete |
| `POST` | `/alerts/{id}/assign` | Assign to analyst |
| `GET/POST` | `/rules` | Detection rule catalog |
| `PUT/DELETE` | `/rules/{id}` | Update / delete a rule |
| `POST` | `/rules/{id}/enable` | Enable a rule |
| `GET/POST` | `/detections` | Detection events |
| `GET` | `/detections/stats` | Aggregated detection metrics |

### Cases & Response

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/cases` | Case list / create |
| `GET/PATCH/DELETE` | `/cases/{id}` | Case detail / update / close |
| `POST` | `/cases/{id}/comments` | Add comment |
| `POST` | `/cases/{id}/timeline` | Add timeline event |
| `GET/POST` | `/playbooks` | Playbook catalog |
| `POST` | `/playbooks/{id}/execute` | Execute a playbook |
| `GET` | `/playbooks/{id}/runs` | Execution history |
| `POST` | `/actions/dry-run` | Simulate an action |

### Threat Intelligence

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/intel/iocs` | IOC search / ingest |
| `POST` | `/intel/enrich` | Enrich an indicator |
| `GET` | `/intel/feeds` | Connected feed status |
| `POST` | `/intel/feeds/{id}/sync` | Force feed sync |

### UEBA

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/ueba/anomalies` | List anomalies |
| `GET` | `/ueba/anomalies/{id}` | Anomaly detail |
| `GET` | `/ueba/baselines` | User baselines |
| `GET` | `/ueba/baselines/{entity_id}` | Per-entity baseline |
| `DELETE` | `/ueba/baselines/{entity_id}` | Reset baseline |
| `GET` | `/ueba/stats` | Aggregate UEBA metrics |

### Honeytokens

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/honeytokens` | List / create tokens |
| `GET/DELETE` | `/honeytokens/{id}` | Token detail / revoke |
| `GET` | `/honeytokens/{id}/events` | Touch events for a token |
| `GET` | `/honeytokens/events` | All touch events |
| `GET` | `/honeytokens/stats` | Deployment statistics |
| `GET` | `/honeytokens/track/{token_id}` | Public tracking endpoint (triggers alert) |

### Purple Team

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/purple-team/atomic-tests` | Atomic Red Team test catalog |
| `POST` | `/purple-team/executions` | Run an atomic test |
| `GET/DELETE` | `/purple-team/executions/{id}` | Execution status / cancel |
| `GET` | `/purple-team/coverage` | ATT&CK coverage heatmap |
| `GET/POST` | `/purple-team/tabletop` | Tabletop session list / create |
| `POST` | `/purple-team/tabletop/{id}/steps` | Add step to session |

### Governance

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/compliance/frameworks` | Available compliance frameworks |
| `GET` | `/compliance/controls` | Control library |
| `GET/POST` | `/compliance/evidence` | Evidence list / upload |
| `GET` | `/compliance/dashboard/{framework}` | Framework dashboard data |
| `GET` | `/audit` | Immutable audit log |
| `GET` | `/sla/configs` | SLA configuration |
| `PUT` | `/sla/configs/{id}` | Update SLA thresholds |
| `GET` | `/sla/events` | SLA breach events |

## Rate Limits

| Caller | Limit |
|--------|-------|
| API key | 1000 req/min |
| User JWT | 100 req/min |

Rate-limit headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

## Pagination

All list endpoints support cursor-based pagination:

```bash
GET /api/v1/alerts?limit=50&cursor=<opaque-cursor>
```

Response includes `"next_cursor"` when more pages exist.

## Client SDKs

| Language | Package |
|----------|---------|
| Python | `packages/sdk-py` |
| TypeScript | `packages/sdk-ts` |
| Go | `packages/sdk-go` |
