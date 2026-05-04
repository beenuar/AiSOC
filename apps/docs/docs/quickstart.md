---
sidebar_position: 2
---

# Quick Start

Get AiSOC investigating a real case in your browser in under **5 minutes**.

There are two paths:

1. **One-shot demo (recommended)** — `pnpm aisoc:demo` brings up a slim
   stack from prebuilt GHCR images, seeds canonical demo data, kicks off an
   AI investigation, and opens your browser at the live case.
2. **Full development stack** — every microservice (UEBA, Honeytokens,
   Purple Team, ClickHouse, OpenSearch, Neo4j, Qdrant, MCP, …) for hacking
   on AiSOC itself.

## Prerequisites

| Tool | Minimum version |
|------|-----------------|
| Docker & Docker Compose | v2.x |
| Node.js | ≥ 20 |
| pnpm | ≥ 8 |
| Python | 3.11+ (only needed for the eval harness and the dev stack) |
| Go | 1.21+ (only needed if you hack on the Go services or plugins) |

## Path A — one-shot demo

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
pnpm aisoc:demo
```

That single command:

1. Pulls prebuilt images from `ghcr.io/beenuar/*` (≈90s on a warm cache).
2. Brings up the slim demo profile defined in
   [`docker-compose.demo.yml`](https://github.com/beenuar/AiSOC/blob/main/docker-compose.demo.yml):
   `postgres`, `redis`, `kafka`, `api`, `agents`, `realtime`, `web`.
3. Waits for healthchecks to go green.
4. Seeds canonical demo data (tenants, users, alerts, IOCs, attack paths).
5. Kicks off an AI investigation against a seeded case.
6. Opens your browser at `/cases/<uuid>` so you land on a **live** investigation.

| Step | Target |
|---|---|
| `docker compose pull` | ~90s |
| `docker compose up` + healthchecks | ~60s |
| Seed canonical data | ~30s |
| Kick off investigation | ~30s |
| **Total time-to-first-investigation** | **~3.5 min** |

When you're done:

```bash
pnpm aisoc:demo:down    # stops the stack and deletes the demo volumes
pnpm aisoc:demo:logs    # tails logs while the stack is up
```

The orchestrator script lives at
[`scripts/aisoc-demo.ts`](https://github.com/beenuar/AiSOC/blob/main/scripts/aisoc-demo.ts).

## Path B — full development stack

Use this when you want to hack on AiSOC itself, run the eval harness, or
exercise UEBA / Honeytokens / Purple Team / MCP.

### 1. Clone & configure

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env
pnpm install
```

Open `.env` and fill in at least one AI provider:

```bash
# AI providers (at least one required)
OPENAI_API_KEY=sk-...
# or
ANTHROPIC_API_KEY=sk-ant-...

# API JWT signing key — generate with: openssl rand -hex 32
SECRET_KEY=change-me-in-production-at-least-32-chars

# Optional enrichment / feeds / SSO / Purple Team — see .env.example
```

### 2. Start the full stack

```bash
docker compose up -d
docker compose ps
```

This starts the full set of services:

- **PostgreSQL** (5432) · **Redis** (6379) · **Kafka** (9092)
- **ClickHouse** · **OpenSearch** · **Neo4j** · **Qdrant**
- **api** (8000, FastAPI core) · **agents** (8001, LangGraph) ·
  **realtime** (8086, Node.js + VAPID Web Push) · **web** (3000)
- **fusion** (8003) · **actions** (8002) · **threatintel** (8005) ·
  **ueba** (8007) · **honeytokens** (8008) · **purple-team** (8006) ·
  **ingest** (8081, Go) · **enrichment** (8080, Go) · **mcp** (TypeScript)

### 3. Run database migrations

```bash
docker compose exec api alembic upgrade head
docker compose exec ueba alembic upgrade head
docker compose exec honeytokens alembic upgrade head
docker compose exec purple-team alembic upgrade head
```

The `api` migrations include
[`008_investigation_ledger.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/008_investigation_ledger.sql)
(replayable agent decision log) and
[`009_responder_pwa.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/009_responder_pwa.sql)
(passkeys, on-call rotation, approvals).

### 4. Seed demo data

```bash
pnpm seed:demo
```

### 5. Verify

```bash
pnpm aisoc:doctor
```

Runs a one-shot health check across ports, containers, demo data, the API,
and the WebSocket gateway. If anything is red, it tells you exactly what to
fix.

### 6. Run the public eval harness (optional but recommended)

```bash
# Generate 200 synthetic incidents and run all four substrate eval suites
python scripts/run_evals.py --count 200 --report eval_report.json

# Or run a single eval gate
pytest services/agents/tests/test_mitre_accuracy.py
```

The harness writes `eval_report.json` and `eval_mitre_accuracy_report.json`,
which the [eval harness page](./benchmark) renders. The same harness runs in
CI on every PR — see
[`.github/workflows/ci.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/ci.yml).

> **Important**: the harness runs deterministic substrate code (extractors,
> fusion, templates, judges) against synthetic data — it does **not** call
> the live LLM agent. Three of the four metrics are substrate self-consistency
> gates rather than agent accuracy scores. The
> [eval harness page](./benchmark) documents exactly what each suite measures
> and what it doesn't.

### 7. Open the UI

Visit [http://localhost:3000](http://localhost:3000) and log in with the
default seeded credentials: `admin@aisoc.local` / `changeme`.

The mobile **Responder PWA** lives at
[http://localhost:3000/responder](http://localhost:3000/responder) — install
it on your phone via "Add to Home Screen" and sign in with a passkey.

### Console Tour

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/dashboard` | Live alert stream, case queue, KPI tiles |
| Alerts | `/alerts` | Raw signal feed with Ambient Copilot suggestions |
| Cases | `/cases` | Unified case management |
| Case workspace | `/cases/<id>` | Evidence timeline + **Investigation Ledger** + attack graph |
| Detections | `/detections` | Sigma/YARA/KQL rule catalog (200+ rules) |
| Playbooks | `/playbooks` | SOAR automation builder (50+ packs) |
| UEBA | `/ueba` | User behavior anomaly timeline |
| Honeytokens | `/honeytokens` | Deceptive token lifecycle |
| Purple Team | `/purple-team` | ATT&CK coverage · emulation runs · tabletop |
| Marketplace | `/marketplace` | 15 plugins + 50+ playbooks + 200+ detections |
| Benchmark | `/benchmark` | Public eval harness — alert reduction + substrate self-consistency gates |
| Compliance | `/compliance` | SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA |
| Audit Log | `/audit` | Immutable, tenant-scoped activity ledger |
| Responder PWA | `/responder` | Mobile passkey-only console for on-call analysts |

## Next Steps

- [Architecture deep-dive](./architecture)
- [Concepts: Cases & Investigation Ledger](./concepts/cases)
- [Write your first detection rule](./concepts/detections)
- [Build a playbook](./concepts/playbooks)
- [Install a community plugin](./plugins/overview)
- [Connect your IDE via MCP](./integrations/mcp)
- [Run the public eval harness](./benchmark)
- [Deploy to Kubernetes](./deployment/kubernetes)
