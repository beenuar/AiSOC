# Local Development Runbook

This runbook walks you from a freshly cloned repository to a running AiSOC stack on your laptop, and describes how to develop and debug each service in isolation.

---

## 1. Prerequisites

| Tool | Min version | Why |
|------|-------------|-----|
| Docker | 24.0 | Container runtime for the full stack |
| Docker Compose | v2.20 | Multi-service orchestration |
| Node.js | 20.x | Frontend (`apps/web`) and `services/realtime` |
| pnpm | 8.x | Workspace package manager |
| Go | 1.21 | `services/ingest`, `services/enrichment` |
| Python | 3.11 | All FastAPI services and the agent runner |
| Poetry | 1.8 | Python service dependency management |
| `gh` CLI | 2.40+ | Optional, used by some helper scripts |

Memory budget: the full stack uses **~6 GB RAM** with all services running. If you only need a subset, use the targeted commands in §4.

---

## 2. Clone & Configure

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env
```

Edit `.env`. The defaults work for a no-LLM local run, but for the AI agents you must populate at least one of:

```env
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

For full threat-intel enrichment also set:

```env
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...
SHODAN_API_KEY=...
OTX_API_KEY=...
TAXII_URL=https://cti-taxii.mitre.org/taxii/
```

---

## 3. Bring up the full stack

```bash
docker compose up -d --build
```

First boot takes 3–5 minutes (Postgres init, OpenSearch warmup, Kafka topic auto-create, Python image build). Subsequent boots are ~30 s.

```bash
# Service status
docker compose ps

# Tail a specific service
docker compose logs -f api
docker compose logs -f fusion
docker compose logs -f agents
docker compose logs -f threatintel
```

### 3.1 Verify health

| Service | Health check |
|---------|--------------|
| Core API | `curl http://localhost:8000/health` |
| Agents | `curl http://localhost:8001/health` |
| Actions | `curl http://localhost:8002/health` |
| Fusion | `curl http://localhost:8003/health` |
| Threat Intel | `curl http://localhost:8005/health` |
| Enrichment | `curl http://localhost:8080/health` |
| Ingest | `curl http://localhost:8081/health` |
| Realtime | `curl http://localhost:8086/health` |
| Web Console | `curl -I http://localhost:3000` |
| Postgres | `docker exec aisoc-postgres pg_isready -U aisoc` |
| Redis | `docker exec aisoc-redis redis-cli -a redis_dev_secret ping` |
| Kafka | `docker exec aisoc-kafka kafka-broker-api-versions --bootstrap-server localhost:9092` |
| OpenSearch | `curl http://localhost:9200` |
| Qdrant | `curl http://localhost:6333/healthz` |
| ClickHouse | `curl http://localhost:8123/ping` |
| Neo4j | open `http://localhost:7474` (login `neo4j` / `neo4j_dev_secret`) |

A first-time success of every endpoint is the gate before you proceed.

### 3.2 Optional profiles

```bash
# Pull TAXII / MISP / OTX / KEV feeds (already bundled in default compose)
docker compose --profile threatintel up -d

# Connector workers (CrowdStrike, Splunk, AWS, Okta, Sentinel)
docker compose --profile connectors up -d

# Prometheus + Grafana
docker compose --profile monitoring up -d
```

---

## 4. Run only the infrastructure (recommended for backend dev)

```bash
docker compose up -d \
  postgres redis kafka zookeeper \
  clickhouse opensearch qdrant neo4j
```

Then run individual services on the host where iteration is fastest.

### 4.1 Core API (`services/api`)

```bash
cd services/api
poetry install
poetry run alembic upgrade head            # apply DB migrations
poetry run uvicorn app.main:app --reload --port 8000
```

Browse `http://localhost:8000/docs`.

### 4.2 Fusion (`services/fusion`)

```bash
cd services/fusion
poetry install
poetry run uvicorn app.main:app --reload --port 8003
```

Background Kafka worker boots automatically via FastAPI's `lifespan`.

### 4.3 Agents (`services/agents`)

```bash
cd services/agents
poetry install
ATTCK_DATA_PATH=$(pwd)/data/enterprise-attack.json \
poetry run uvicorn app.main:app --reload --port 8001
```

The first run downloads the MITRE ATT&CK STIX bundle (~12 MB) into `data/`.

### 4.4 Threat Intel (`services/threatintel`)

```bash
cd services/threatintel
poetry install
poetry run uvicorn app.main:app --reload --port 8005
```

The poller starts an APScheduler loop on boot and writes IOCs to OpenSearch + Qdrant + Neo4j.

### 4.5 Ingest (`services/ingest`, Go)

```bash
cd services/ingest
go run main.go
```

The Go ingester reads from Kafka topic `events.raw`, normalizes to OCSF, and emits to `ocsf.events` and `vulnerability.matches`.

### 4.6 Enrichment (`services/enrichment`, Go)

```bash
cd services/enrichment
go run main.go
```

### 4.7 Realtime (`services/realtime`, Node.js)

```bash
cd services/realtime
pnpm install
pnpm dev
```

WebSocket endpoint exposed inside compose at `ws://localhost:8086/ws` (host) / `4000` (container).

### 4.8 Web console (`apps/web`)

```bash
cd apps/web
pnpm install
NEXT_PUBLIC_API_URL=http://localhost:8000 \
NEXT_PUBLIC_WS_URL=ws://localhost:8086 \
pnpm dev
```

Browse `http://localhost:3000`.

---

## 5. Smoke-test path (≈ 5 minutes)

```bash
# 1. Get a token
TOKEN=$(curl -s -X POST http://localhost:8000/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@aisoc.local","password":"changeme"}' | jq -r .access_token)

# 2. Send a synthetic event into Kafka
docker exec -i aisoc-kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic events.raw <<'JSON'
{"src":"crowdstrike","ts":"2026-05-01T12:00:00Z","host":{"hostname":"HOST-42"},"user":{"name":"alice@corp"},"event":{"id":"e1","name":"PowerShell encoded command","severity":4}}
JSON

# 3. Fusion should produce a fused alert; query the API
curl -s -H "authorization: Bearer $TOKEN" \
  http://localhost:8000/v1/alerts?limit=5 | jq

# 4. Inspect ML status
curl -s http://localhost:8003/ml/status | jq

# 5. Submit analyst feedback
curl -s -X POST http://localhost:8003/ml/feedback \
  -H 'content-type: application/json' \
  -d '{"alert_id":"REPLACE_ME","tenant_id":"00000000-0000-0000-0000-000000000001","analyst_id":"alice@corp","is_true_positive":true,"assigned_priority":2}'

# 6. Trigger the agent on the alert
curl -s -X POST http://localhost:8001/v1/agents/investigate \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"alert_id":"REPLACE_ME"}' | jq

# 7. Inspect the attack-path graph
CASE_ID=$(curl -s -H "authorization: Bearer $TOKEN" http://localhost:8000/v1/cases | jq -r '.items[0].id')
curl -s -H "authorization: Bearer $TOKEN" \
  http://localhost:8000/v1/graph/attack-path/$CASE_ID | jq
```

---

## 6. Common operations

### 6.1 Reset the stack

```bash
docker compose down -v       # also removes volumes (data loss!)
docker compose up -d --build
```

### 6.2 Rebuild a single image

```bash
docker compose build --no-cache fusion
docker compose up -d fusion
```

### 6.3 Tail Kafka topics

```bash
docker exec -it aisoc-kafka \
  kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic ocsf.events --from-beginning --max-messages 10
```

Topics created by the stack:

* `events.raw` — raw connector events
* `ocsf.events` — normalized events
* `enriched.events` — IOC-enriched events
* `vulnerability.matches` — KEV-correlated matches
* `fused.alerts` — deduped, scored alerts
* `agent.investigations` — agent run results

### 6.4 Database access

```bash
# Postgres shell
docker exec -it aisoc-postgres psql -U aisoc

# ClickHouse shell
docker exec -it aisoc-clickhouse clickhouse-client -u aisoc --password clickhouse_dev_secret

# Neo4j cypher shell
docker exec -it aisoc-neo4j cypher-shell -u neo4j -p neo4j_dev_secret
```

### 6.5 Run database migrations

```bash
cd services/api
poetry run alembic upgrade head
```

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `api` container restarts | Postgres not ready or migrations failed | `docker compose logs api` and run `alembic upgrade head` |
| `fusion` 500 on `/ml/feedback` | DB schema missing | Run migrations (above) |
| `agents` boot loop | No `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | Set one in `.env`, `docker compose up -d agents` |
| OpenSearch refuses connection | Memory ulimit | Run `sysctl -w vm.max_map_count=262144` (Linux) |
| Kafka cannot resolve `kafka:29092` | Stale DNS / restart loop | `docker compose restart kafka` |
| Neo4j unreachable from API | Wrong env var | Confirm `NEO4J_URI=bolt://neo4j:7687` |
| Web console blank | API CORS / ports | Verify `NEXT_PUBLIC_API_URL=http://localhost:8000` |
| `port already in use` | Another process owns 8000/3000/etc. | `lsof -i :8000` and stop the conflicting service |

### 7.1 Inspect a service's environment

```bash
docker compose exec api env | grep -E 'NEO4J|REDIS|KAFKA|DATABASE'
```

### 7.2 Re-seed sample data

```bash
docker compose exec api python -m app.scripts.seed_demo
```

---

## 8. Tests

```bash
# Frontend
cd apps/web && pnpm test

# Core API
cd services/api && poetry run pytest

# Fusion (incl. ML scorer)
cd services/fusion && poetry run pytest

# Threat Intel
cd services/threatintel && poetry run pytest

# Go services
cd services/ingest && go test ./...
cd services/enrichment && go test ./...
```

---

## 9. Tearing down

```bash
docker compose down            # keeps volumes
docker compose down -v         # removes volumes + data
docker system prune -f         # reclaim build cache
```

---

## 10. Where to go next

* [System Design](../architecture/SYSTEM_DESIGN.md)
* [API Reference](../api/API_REFERENCE.md)
* [PROGRESS.md](../../PROGRESS.md)
