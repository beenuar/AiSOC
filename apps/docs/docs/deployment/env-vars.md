---
sidebar_position: 3
---

# Environment Variables

## Core (Required)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL async connection string (`postgresql+asyncpg://...`) |
| `JWT_SECRET` | Random hex secret for JWT signing — `openssl rand -hex 32` |
| `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` | At least one LLM provider key is required |

## Core (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker list |
| `API_HOST` | `http://localhost:8000` | Internal API URL |
| `AGENTS_HOST` | `http://localhost:8001` | Internal agents URL |
| `REALTIME_HOST` | `ws://localhost:8002` | WebSocket server URL |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `DRY_RUN` | `true` | Global dry-run flag for all actions |
| `MAX_CONCURRENT_INVESTIGATIONS` | `5` | Max parallel investigations |
| `ENVIRONMENT` | `production` | `development`, `staging`, `production` |

## LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `openai` | `openai` or `anthropic` |
| `LLM_MODEL` | `gpt-4o` | Model identifier |
| `LLM_TEMPERATURE` | `0.1` | Temperature (0–1) |
| `LLM_MAX_TOKENS` | `4096` | Max tokens per LLM call |

## Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `MISP_URL` | — | MISP instance base URL |
| `MISP_API_KEY` | — | MISP automation key |
| `OTX_API_KEY` | — | AlienVault OTX API key |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API v3 key |
| `SHODAN_API_KEY` | — | Shodan API key |
| `TAXII_SERVER_URL` | — | TAXII 2.1 collection URL |
| `TAXII_API_KEY` | — | TAXII authentication key |

## SSO (SAML 2.0 / OIDC)

| Variable | Default | Description |
|----------|---------|-------------|
| `SAML_IDP_METADATA_URL` | — | IdP SAML metadata XML endpoint |
| `SAML_SP_ENTITY_ID` | — | Service provider entity ID |
| `SAML_ACS_URL` | — | Assertion Consumer Service URL |
| `OIDC_DISCOVERY_URL` | — | OIDC `/.well-known/openid-configuration` |
| `OIDC_CLIENT_ID` | — | OIDC client ID |
| `OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `SSO_GROUP_ROLE_MAPPING` | `{}` | JSON: `{"admins": "admin", "soc": "analyst"}` |

## UEBA Service

| Variable | Default | Description |
|----------|---------|-------------|
| `UEBA_DATABASE_URL` | Same as `DATABASE_URL` | Dedicated DB URL for UEBA |
| `UEBA_KAFKA_TOPIC_INPUT` | `security.events` | Kafka topic for raw security events |
| `UEBA_KAFKA_TOPIC_ANOMALIES` | `security.anomalies` | Kafka topic for published anomalies |
| `UEBA_ZSCORE_THRESHOLD` | `3.0` | Z-score threshold for anomaly flagging |
| `UEBA_MIN_SAMPLES` | `30` | Minimum events before scoring begins |

## Honeytokens Service

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYTOKENS_DATABASE_URL` | Same as `DATABASE_URL` | Dedicated DB URL |
| `HONEYTOKENS_SECRET_KEY` | Derived from `JWT_SECRET` | HMAC-SHA256 signing key |
| `HONEYTOKENS_BASE_URL` | `https://your-domain.com` | Public base URL for URL tokens |
| `HONEYTOKENS_WEBHOOK_TIMEOUT` | `10` | Webhook delivery timeout (seconds) |

## Purple Team Service

| Variable | Default | Description |
|----------|---------|-------------|
| `PURPLE_TEAM_DATABASE_URL` | Same as `DATABASE_URL` | Dedicated DB URL |
| `CALDERA_URL` | `http://localhost:8888` | Caldera server URL |
| `CALDERA_API_KEY` | — | Caldera REST API key |
| `ATOMIC_RED_TEAM_PATH` | `/data/atomic-red-team` | Mounted ART repository path |

## Observability (OpenTelemetry)

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP gRPC endpoint (e.g. `http://localhost:4317`) |
| `OTEL_SERVICE_NAME` | `aisoc-api` | Service name in traces |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` | Sampling rate (0–1) |

## Backup & Encryption

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_ENCRYPTION_KEY` | — | AES-256-GCM key for encrypted backups |
| `BACKUP_S3_BUCKET` | — | S3/R2 bucket for off-site backup upload |
| `BACKUP_S3_PREFIX` | `aisoc-backups/` | Object key prefix |

## Example `.env`

```bash
# Core
DATABASE_URL=postgresql+asyncpg://aisoc:changeme@localhost:5432/aisoc
JWT_SECRET=<run: openssl rand -hex 32>
OPENAI_API_KEY=sk-...

# Services
REDIS_URL=redis://localhost:6379
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
LOG_LEVEL=INFO
DRY_RUN=true

# LLM
LLM_MODEL=gpt-4o
LLM_TEMPERATURE=0.1

# Honeytokens
HONEYTOKENS_BASE_URL=https://aisoc.example.com
HONEYTOKENS_SECRET_KEY=<run: openssl rand -hex 32>

# Purple Team
CALDERA_URL=http://caldera:8888
CALDERA_API_KEY=your-caldera-key

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317
```
