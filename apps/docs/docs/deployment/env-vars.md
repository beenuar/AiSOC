---
sidebar_position: 4
---

# Environment Variables

This page is the source of truth for every environment variable AiSOC reads at runtime. Each section maps to a single service, mirroring the layout of [`services/`](https://github.com/beenuar/AiSOC/tree/main/services) in the repo.

If you spot drift between this page and the code, please open a PR — the matching config files are linked at the top of every section.

---

## API service (`services/api`)

Source: [`services/api/app/core/config.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/config.py)

The API uses bare environment variable names (no prefix). Booleans accept `true` / `false`; lists accept comma-separated strings.

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `AiSOC API` | Display name in OpenAPI docs |
| `APP_VERSION` | `0.1.0` | Reported in `/healthz` |
| `ENV` / `ENVIRONMENT` | `development` | One of `development`, `staging`, `production` |
| `DEBUG` | `false` | Enables verbose error responses — never enable in production |
| `API_PREFIX` | `/api/v1` | Mount point for the versioned API |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Security and tokens

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production-at-least-32-chars` | **Required in production.** Signs primary access/refresh JWTs. Generate with `openssl rand -hex 32`. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Lifetime of an access token |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Lifetime of a refresh token |
| `ALGORITHM` | `HS256` | JWT signing algorithm |

### Migration runner

Source: [`services/api/app/scripts/run_migrations.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/scripts/run_migrations.py)

The migration runner is invoked by deploy orchestrators (Fly's `release_command`, Render's `preDeployCommand`, the Kubernetes `Job` in the Helm chart) the moment a new API VM boots. It races against Postgres becoming reachable — these knobs control how that race is handled.

| Variable | Default | Description |
|----------|---------|-------------|
| `AISOC_MIGRATIONS_REQUIRED` | `1` (required) | **Default is safe — leave it alone for production.** When set to `0` / `false` / `no` / `off`, the runner exits `0` instead of `1` if it cannot reach Postgres after exhausting its retry budget (6 attempts, exponential back-off, ~31 s total). This is for *demo* environments where the API code deploy must not be held hostage by a Postgres outage — the running app keeps serving the last-good schema and dataset, and the deploy log carries a loud `MIGRATION SKIPPED` line for an operator to chase. A *hard* migration failure (Postgres reachable, SQL statement failed) still aborts the deploy regardless of this flag — a schema-change PR with a bad migration must always get human attention. |

The Fly demo (`infra/fly/api/fly.toml`) sets `AISOC_MIGRATIONS_REQUIRED = "0"` and pairs it with a shell wrapper in `release_command` that uses a `/tmp/aisoc-migrations-ok` sentinel to decide whether to also run `seed_demo` — a soft-failed migration run skips the seeder (which would just hit the same connect failure through SQLAlchemy and crash the deploy anyway).

### Audit log

Source: [`services/api/app/services/audit.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/audit.py), [`services/api/app/core/trusted_proxy.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/trusted_proxy.py), [`services/api/app/services/audit_redaction.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/audit_redaction.py). Background: [Security operations → Audit logging](../operations/security#audit-logging).

| Variable | Default | Description |
|----------|---------|-------------|
| `AISOC_TRUSTED_PROXIES` | _empty_ | Comma-separated list of CIDRs (e.g. `10.0.0.0/8,192.168.0.0/16`) for trusted ingress / load balancer hops. When empty, `X-Forwarded-For` is **ignored** and `actor_ip` is the direct TCP peer — set this in production so the audit log records the real client IP without being spoofable from the public side. |
| `AISOC_AUDIT_MAX_CHANGES_BYTES` | `65536` | Hard cap on the serialized `changes` payload stored per audit row. Over-sized values are replaced with a `{ "_truncated": true, "_size": <bytes> }` marker. Set higher only if you genuinely need richer diffs and have provisioned the storage. |

### Passkeys (WebAuthn)

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSKEY_RP_ID` | `localhost` | Relying-party ID — must match the eTLD+1 of the PWA origin (no scheme, no port) |
| `PASSKEY_RP_NAME` | `AiSOC` | Display name shown in the OS passkey prompt |
| `PASSKEY_RP_ORIGINS` | `http://localhost:3000,http://localhost:3001` | Comma-separated list of allowed origins |
| `PASSKEY_CHALLENGE_TTL_SECONDS` | `300` | Lifetime of a single ceremony challenge |

### SSO — OIDC

Source: [`services/api/app/auth/oidc.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/auth/oidc.py)

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ISSUER` | — | OIDC issuer URL (used for `.well-known/openid-configuration` discovery) |
| `OIDC_CLIENT_ID` | — | OAuth client ID |
| `OIDC_CLIENT_SECRET` | — | OAuth client secret (omit if PKCE-only) |
| `OIDC_REDIRECT_URI` | — | Redirect URI registered with the IdP |
| `OIDC_SCOPES` | `openid profile email` | Space-separated scope list |
| `OIDC_PKCE` | `true` | Enable PKCE for the authorization code flow |
| `JWT_SECRET` | `changeme-insecure-default` | **Required in production.** Signs SSO-issued session JWTs. |
| `JWT_ALGORITHM` | `HS256` | SSO JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `480` | SSO JWT lifetime |

### SSO — SAML 2.0

Source: [`services/api/app/auth/saml.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/auth/saml.py)

| Variable | Default | Description |
|----------|---------|-------------|
| `SAML_SP_ACS_URL` | `http://localhost:8000/auth/saml/acs` | SP Assertion Consumer Service URL |
| `SAML_SP_ENTITY_ID` | — | Service provider entity ID |
| `SAML_SP_PRIVATE_KEY` | — | PEM-encoded SP signing key |
| `SAML_SP_CERT` | — | PEM-encoded SP certificate |
| `SAML_IDP_ENTITY_ID` | — | IdP entity ID |
| `SAML_IDP_SSO_URL` | — | IdP single sign-on URL |
| `SAML_IDP_SLO_URL` | — | IdP single logout URL |
| `SAML_IDP_CERT` | — | PEM-encoded IdP certificate |
| `SAML_DEBUG` | `false` | Verbose SAML logging — disable in production |

### Database, cache, queue

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc` | Async Postgres DSN |
| `DATABASE_POOL_SIZE` | `20` | SQLAlchemy pool size |
| `DATABASE_MAX_OVERFLOW` | `10` | SQLAlchemy max overflow |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis DSN |
| `REDIS_POOL_SIZE` | `20` | Redis connection pool size |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Comma-separated broker list (canonical name; `KAFKA_BROKERS` is honored as a back-compat alias) |
| `KAFKA_TOPIC_EVENTS` | `aisoc.normalized_events` | Topic for normalized events |
| `KAFKA_TOPIC_ALERTS` | `aisoc.alerts` | Topic for emitted alerts |

### Search and graph

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_URL` | `http://localhost:9200` | OpenSearch base URL |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j user |
| `NEO4J_PASSWORD` | — | Neo4j password |
| `QDRANT_URL` | `http://localhost:6333` | Qdrant base URL |
| `CLICKHOUSE_HOST` / `CLICKHOUSE_PORT` / `CLICKHOUSE_DATABASE` / `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` | `localhost` / `9000` / `aisoc` / `default` / — | ClickHouse connection details |

### Realtime, demo, and feature toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `REALTIME_BASE_URL` | `http://realtime:8086` | Internal URL the API uses to fan out push events |
| `REALTIME_INTERNAL_TOKEN` | — | Shared secret with the realtime service for internal RPC |
| `AISOC_CORS_ORIGINS` | _(uses service default)_ | Canonical, repo-wide, comma-separated CORS allow-list. Applies to every API, agent, ingest, enrichment, realtime, UEBA, honeytoken, purple-team, and connectors process. See [CORS configuration](#cors-configuration) below for the full rules. |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:3001` | Legacy alias kept for backwards compatibility. `AISOC_CORS_ORIGINS` takes precedence when both are set. |
| `OTEL_ENDPOINT` | — | OTLP collector endpoint |
| `MAX_TENANTS` | `1000` | Hard cap for multi-tenant deployments |
| `DEFAULT_TENANT_PLAN` | `starter` | Default plan for newly provisioned tenants |
| `AISOC_PLUGINS_DIR` | `/opt/aisoc/plugins` | Filesystem path the plugin loader scans |
| `PLUGIN_TRUST_MODE` | `warn` | `disabled` skips signature checks, `warn` records `signature_status` but loads anyway, `strict` rejects unsigned/invalid plugins (including OCI installs). See [Operations → Security → OCI install hardening](../operations/security#oci-install-hardening-h-3). |
| `PLUGIN_TRUSTED_KEYS_DIR` | `/etc/aisoc/plugin-keys` | Directory of Ed25519 public keys (`*.pem`/`*.pub`) that are allowed to sign plugins. |
| `AISOC_DEMO_MODE` | `false` | When `true`, mutating requests outside the demo tenant return 403 |
| `AISOC_DEMO_TENANT` | `demo` | Tenant slug allowed to write in demo mode |
| `AISOC_DEMO_BANNER` | `Demo data resets daily at 00:00 UTC. All write actions are disabled.` | Banner text rendered by the web app |
| `AISOC_DISABLE_KAFKA` / `AISOC_DISABLE_CLICKHOUSE` / `AISOC_DISABLE_OPENSEARCH` / `AISOC_DISABLE_NEO4J` / `AISOC_DISABLE_QDRANT` | `false` | Skip the corresponding subsystem at boot — endpoints that need it return 503 |

---

## Agents service (`services/agents`)

Source: [`services/agents/app/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app)

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | **Required.** OpenAI key used by the investigator and copilot agents |
| `OPENAI_MODEL` | `gpt-4o` | LLM identifier — set per agent if you need different models |
| `DATABASE_URL` | `postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc` | Postgres DSN for the Investigation Ledger |
| `QDRANT_URL` | `http://localhost:6333` | Vector store for case memory and RAG |
| `ENRICHMENT_SERVICE_URL` | `http://enrichment:8011` | URL of the enrichment service (Go) |
| `API_SERVICE_URL` / `API_URL` | `http://api:8000` | URL of the FastAPI service |
| `REALTIME_URL` | `http://realtime:8086` | Realtime service URL for streaming agent traces |
| `REALTIME_INTERNAL_TOKEN` / `INTERNAL_TOKEN` | — | Shared secret matching the API/realtime services |
| `PLAYBOOK_STORE_DIR` | `/data/playbooks` | Filesystem path for executable playbook DSL files |
| `PLAYBOOK_PACK_ROOT` | `/data/playbook-packs` | Root directory for community playbook packs |
| `ATTCK_DATA_PATH` | — | Path to a local MITRE ATT&CK STIX bundle (falls back to the bundled snapshot) |
| `OTEL_SERVICE_NAME` | `aisoc-agents` | Service name in OTel traces |
| `AISOC_VERSION` | `0.1.0` | Reported in OTel resource attributes |
| `JAEGER_HOST` / `JAEGER_PORT` | `localhost` / `6831` | Jaeger agent endpoint (used when `OTEL_EXPORTER=jaeger`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP collector endpoint |
| `OTEL_EXPORTER` | `otlp` | One of `otlp`, `jaeger`, `console` |
| `AISOC_SSRF_ALLOWED_SCHEMES` | `http,https` | Comma-separated list of URL schemes allowed for outbound `http_request` and `notify` playbook steps. Anything else is rejected. |
| `AISOC_SSRF_ALLOW_PRIVATE` | `false` | When `true`, lets playbook steps reach loopback / RFC1918 / link-local destinations. Leave off in production; enable only for self-hosted webhooks on a private network. |
| `AISOC_SSRF_EXTRA_BLOCKED_HOSTS` | — | Comma-separated extra hosts or IPs to deny in addition to the built-in cloud-metadata block list (`169.254.169.254`, `metadata.google.internal`, …). |

---

## Realtime service (`services/realtime`)

Source: [`services/realtime/src/index.ts`](https://github.com/beenuar/AiSOC/blob/main/services/realtime/src/index.ts)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8086` | TCP port for the WebSocket and push endpoints |
| `LOG_LEVEL` | `info` | Pino log level (`trace`, `debug`, `info`, `warn`, `error`) |
| `REDIS_URL` | `redis://localhost:6379/4` | Redis connection used for the push subscription store |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka brokers — the realtime service consumes the fused-alerts topic to push to clients |
| `KAFKA_TOPIC_FUSED` | `aisoc.alerts.fused` | Topic with fused alerts that should reach connected SOC clients |
| `VAPID_PUBLIC_KEY` | — | VAPID public key for Web Push — generate with `npx web-push generate-vapid-keys` |
| `VAPID_PRIVATE_KEY` | — | VAPID private key — keep in a secret manager |
| `VAPID_SUBJECT` | `mailto:soc@example.com` | Contact email or URL surfaced to push services |
| `INTERNAL_TOKEN` | — | Must match the API's `REALTIME_INTERNAL_TOKEN` (used by the API to fan out push events) |

---

## MCP server (`services/mcp`)

Source: [`services/mcp/src/config.ts`](https://github.com/beenuar/AiSOC/blob/main/services/mcp/src/config.ts)

The MCP server runs as a sidecar that exposes Investigation Ledger tools to LLM clients (Claude Desktop, Cursor, Copilot, …) via the Model Context Protocol.

| Variable | Default | Description |
|----------|---------|-------------|
| `AISOC_URL` | `http://localhost:8081` | Base URL of the AiSOC API |
| `AISOC_API_URL` | falls back to `AISOC_URL` | Override the API URL independently if the API and web app live on separate hosts |
| `AISOC_API_KEY` | — | Long-lived API key (preferred for server-to-server use) |
| `AISOC_TOKEN` | — | Short-lived JWT (alternative to `AISOC_API_KEY`) |
| `AISOC_TIMEOUT_MS` | `20000` | HTTP timeout for outbound calls to the AiSOC API |
| `AISOC_MCP_VERBOSE` | `0` | Set to `1` to log every tool invocation to stderr |

---

## Ingest service (`services/ingest`)

Source: [`services/ingest/internal/config/config.go`](https://github.com/beenuar/AiSOC/blob/main/services/ingest/internal/config/config.go)

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `8080` | HTTP listener port |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Comma-separated broker list (canonical; `KAFKA_BROKERS` accepted as alias) |
| `KAFKA_TOPIC` | `security.events` | Topic for normalized events |
| `REDIS_ADDR` | `localhost:6379` | Redis address (for dedup and rate limiting) |
| `DATABASE_DSN` | `postgres://aisoc:aisoc@localhost:5432/aisoc?sslmode=disable` | Postgres DSN |
| `ATTCK_DATA_PATH` | — | Path to MITRE ATT&CK STIX bundle for technique tagging |
| `NORMALIZER_MODE` | `auto` | `auto`, `strict`, or `passthrough` |
| `MAX_BATCH_SIZE` | `1000` | Max events flushed per batch |
| `WORKER_COUNT` | `4` | Number of normalization workers |
| `TENANT_HEADER_KEY` | `X-AiSOC-Tenant` | HTTP header that carries the tenant slug |
| `JWT_SECRET` | — | **Required outside `ENV=development`.** HMAC secret used to verify ingest tokens. |
| `METRICS_PORT` | `9090` | Prometheus exporter port |
| `SHODAN_API_KEY` | — | Optional — enables Shodan enrichment when paired with `SHODAN_ENRICH_ENABLED=true` |
| `SHODAN_ENRICH_ENABLED` | `false` | Toggle Shodan IP enrichment |
| `SHODAN_CACHE_EXPIRY_SECS` | `86400` | Cache TTL for Shodan lookups |
| `VULN_CORREL_ENABLED` | `false` | Toggle CVE correlation against ingested events |
| `VULN_KAFKA_TOPIC` | `security.vulnerabilities` | Topic for emitted vulnerability findings |
| `NVD_API_KEY` | — | NVD API key (raises NVD rate limits when set) |

---

## UEBA service (`services/ueba`)

Source: [`services/ueba/app/core/config.py`](https://github.com/beenuar/AiSOC/blob/main/services/ueba/app/core/config.py)

Every variable in this section accepts **both** an unprefixed name (e.g. `DATABASE_URL`, `KAFKA_BOOTSTRAP_SERVERS`) and the legacy `UEBA_`-prefixed name (e.g. `UEBA_DATABASE_URL`, `UEBA_KAFKA_BOOTSTRAP_SERVERS`). When both are set, the **unprefixed form wins** — this matches the convention used by every other Python service in the repo and the `services/ueba` section of `docker-compose.yml`, which exports unprefixed names.

The table below shows the canonical (unprefixed) name first and the legacy alias second. New deployments should prefer the unprefixed form. (See PR [#135](https://github.com/beenuar/AiSOC/pull/135) for the implementation and [Issue #134](https://github.com/beenuar/AiSOC/issues/134) for the original report.)

| Variable | Legacy alias | Default | Description |
|----------|--------------|---------|-------------|
| `DATABASE_URL` | `UEBA_DATABASE_URL` | `postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc` | Postgres DSN for baselines and anomalies |
| `KAFKA_BOOTSTRAP_SERVERS` | `UEBA_KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka brokers |
| `KAFKA_INPUT_TOPIC` | `UEBA_KAFKA_INPUT_TOPIC` | `security.events` | Topic the scorer consumes |
| `KAFKA_OUTPUT_TOPIC` | `UEBA_KAFKA_OUTPUT_TOPIC` | `ueba.anomalies` | Topic the scorer emits to |
| `KAFKA_CONSUMER_GROUP` | `UEBA_KAFKA_CONSUMER_GROUP` | `ueba-service` | Kafka consumer group ID |
| `BASELINE_WINDOW_DAYS` | `UEBA_BASELINE_WINDOW_DAYS` | `30` | History window used to compute behavioural baselines |
| `ANOMALY_THRESHOLD` | `UEBA_ANOMALY_THRESHOLD` | `3.0` | Z-score threshold for flagging an event as anomalous |
| `PEER_GROUP_MIN_SIZE` | `UEBA_PEER_GROUP_MIN_SIZE` | `3` | Minimum peers required for peer-group analysis |
| `SCORING_BATCH_SIZE` | `UEBA_SCORING_BATCH_SIZE` | `100` | Events processed per scoring batch |
| `OTEL_ENDPOINT` | `UEBA_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP gRPC endpoint |
| `SERVICE_NAME` | `UEBA_SERVICE_NAME` | `aisoc-ueba` | OTel service name |
| `HOST` | `UEBA_HOST` | `0.0.0.0` | HTTP listener interface |
| `PORT` | `UEBA_PORT` | `8004` | HTTP listener port |

`services/ueba/alembic/env.py` follows the same rule: it reads `DATABASE_URL` first and falls back to `UEBA_DATABASE_URL`, so `alembic upgrade head` and the running service always see the same DSN.

---

## Honeytokens service (`services/honeytokens`)

Source: [`services/honeytokens/app/core/config.py`](https://github.com/beenuar/AiSOC/blob/main/services/honeytokens/app/core/config.py)

All variables use the `HONEYTOKEN_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYTOKEN_DATABASE_URL` | `postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc` | Postgres DSN for token metadata and triggers |
| `HONEYTOKEN_ALERT_WEBHOOK_URL` | — | Webhook called when a token is triggered |
| `HONEYTOKEN_ALERT_WEBHOOK_SECRET` | `changeme` | **Rotate before going live.** HMAC-SHA256 secret for webhook signing |
| `HONEYTOKEN_TOKEN_TTL_DAYS` | `365` | Default token expiry |
| `HONEYTOKEN_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |
| `HONEYTOKEN_SERVICE_NAME` | `aisoc-honeytokens` | OTel service name |
| `HONEYTOKEN_HOST` | `0.0.0.0` | HTTP listener interface |
| `HONEYTOKEN_PORT` | `8005` | HTTP listener port |

---

## Purple Team service (`services/purple-team`)

Source: [`services/purple-team/app/core/config.py`](https://github.com/beenuar/AiSOC/blob/main/services/purple-team/app/core/config.py)

All variables use the `PURPLE_TEAM_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `PURPLE_TEAM_DATABASE_URL` | `postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc` | Postgres DSN for emulation runs and findings |
| `PURPLE_TEAM_CALDERA_URL` | `http://localhost:8888` | Caldera server URL |
| `PURPLE_TEAM_CALDERA_API_KEY` | `ADMIN123` | **Rotate before going live.** Caldera REST API key |
| `PURPLE_TEAM_ART_REPO_PATH` | `/opt/atomic-red-team` | Filesystem path to the Atomic Red Team checkout |
| `PURPLE_TEAM_ART_ATOMICS_PATH` | `/opt/atomic-red-team/atomics` | Path to the `atomics/` directory inside ART |
| `PURPLE_TEAM_ATTACK_STIX_URL` | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` | URL to the MITRE ATT&CK STIX bundle |
| `PURPLE_TEAM_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |
| `PURPLE_TEAM_SERVICE_NAME` | `aisoc-purple-team` | OTel service name |
| `PURPLE_TEAM_HOST` | `0.0.0.0` | HTTP listener interface |
| `PURPLE_TEAM_PORT` | `8006` | HTTP listener port |

---

## Web app (`apps/web`)

The Next.js frontend reads only public, build-time variables. Anything sensitive belongs in the API layer.

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Base URL the browser uses to reach the API |
| `NEXT_PUBLIC_REALTIME_URL` | `http://localhost:8086` | HTTP base of the realtime service (used for VAPID subscription registration) |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8086` | WebSocket URL for the realtime feed |
| `NEXT_PUBLIC_VAPID_PUBLIC_KEY` | — | Must match the realtime service's `VAPID_PUBLIC_KEY` |

---

## CORS configuration

CORS is configured the same way across every AiSOC service — Python (FastAPI), Go (`ingest`, `enrichment`), and TypeScript (`realtime`) — by reading a single environment variable. This is the variable to set when you put AiSOC behind a custom domain or want to restrict cross-origin access in production.

### Variables

| Variable | Priority | Description |
|----------|----------|-------------|
| `AISOC_CORS_ORIGINS` | **1 (canonical)** | Comma-separated allow-list. Set this in every environment. |
| `CORS_ORIGINS` | 2 (legacy alias) | Honoured when `AISOC_CORS_ORIGINS` is unset. Existing Helm charts and dev scripts that already use this keep working. |
| _(none set)_ | 3 (default) | Each service falls back to `http://localhost:3000`, `http://localhost:3001`, `http://127.0.0.1:3000`, `http://127.0.0.1:3001`, `https://tryaisoc.com`, `https://www.tryaisoc.com`. |

Examples:

```bash
# Production, single console domain
AISOC_CORS_ORIGINS=https://soc.example.com

# Multiple consoles (analyst app + responder PWA on a subdomain)
AISOC_CORS_ORIGINS=https://soc.example.com,https://responder.example.com

# Local dev across the standard ports (matches the default)
AISOC_CORS_ORIGINS=http://localhost:3000,http://localhost:3001
```

### Production safety guard

The Python helper at [`services/api/app/core/cors.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/cors.py) (vendored byte-identical into every Python service) and the TypeScript guard in [`services/realtime/src/index.ts`](https://github.com/beenuar/AiSOC/blob/main/services/realtime/src/index.ts) both **refuse to start** if the allow-list contains `*` while `allow_credentials` is `true` and any of `AISOC_ENV`, `ENVIRONMENT`, or `APP_ENV` equals `production` or `prod`. This catches the canonical CORS misconfiguration (wildcard + cookies / `Authorization` headers) before the deploy goes live.

Outside production the same combination logs a warning and silently disables credentials — local dev stays usable when someone exports `CORS_ORIGINS=*`.

The `honeytokens`, `purple-team`, and `ueba` services run with `allow_credentials=false` by design (no session cookies cross-origin), so wildcard origins are allowed there even in production — useful when honeytoken trip pixels are fetched from arbitrary origins.

### Go services (`ingest`, `enrichment`) and the realtime service (`realtime`)

These services read the same `AISOC_CORS_ORIGINS` / `CORS_ORIGINS` pair and fall back to the same default allow-list. `ingest` and `enrichment` keep `AllowCredentials: false` (they are token-authenticated per request, not cookie-authenticated). The realtime service runs with credentials enabled because the SSE / WebSocket streams carry the console's session cookie; it enforces the same production wildcard guard as the Python helper.

---

## Example `.env` (full stack)

```bash
# --- API ---
SECRET_KEY=$(openssl rand -hex 32)
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=postgresql+asyncpg://aisoc:changeme@localhost:5432/aisoc
REDIS_URL=redis://localhost:6379/0
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
OPENSEARCH_URL=http://localhost:9200
QDRANT_URL=http://localhost:6333
# Canonical, applies to every service. Legacy CORS_ORIGINS still works.
AISOC_CORS_ORIGINS=http://localhost:3000

# --- API: SSO (set both blocks if you actually use SSO) ---
JWT_SECRET=$(openssl rand -hex 32)

# --- Agents ---
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
ENRICHMENT_SERVICE_URL=http://enrichment:8011

# --- Realtime ---
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
VAPID_SUBJECT=mailto:soc@example.com
INTERNAL_TOKEN=$(openssl rand -hex 32)
REALTIME_INTERNAL_TOKEN=${INTERNAL_TOKEN}

# --- MCP ---
AISOC_URL=http://localhost:8000
AISOC_API_KEY=...

# --- Ingest ---
HTTP_PORT=8080
KAFKA_TOPIC=security.events
DATABASE_DSN=postgres://aisoc:changeme@localhost:5432/aisoc?sslmode=disable
JWT_SECRET=${JWT_SECRET}

# --- UEBA / Honeytokens / Purple Team ---
UEBA_DATABASE_URL=${DATABASE_URL}
HONEYTOKEN_DATABASE_URL=${DATABASE_URL}
HONEYTOKEN_ALERT_WEBHOOK_SECRET=$(openssl rand -hex 32)
PURPLE_TEAM_DATABASE_URL=${DATABASE_URL}
PURPLE_TEAM_CALDERA_API_KEY=...

# --- Web ---
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_REALTIME_URL=ws://localhost:8086
NEXT_PUBLIC_VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY}
```

Before going to production, run through the [Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md) to make sure every secret has been rotated away from the example values above.
