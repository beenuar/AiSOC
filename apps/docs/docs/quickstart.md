---
sidebar_position: 2
---

# Quick Start

Two paths to a running AiSOC instance:

1. **One-shot demo** — `pnpm aisoc:demo` brings up a slim stack from prebuilt
   GHCR images, seeds canonical demo data, kicks off an investigation, and
   opens your browser at the live case. Roughly 3-4 minutes on a warm Docker
   daemon.
2. **Full development stack** — every microservice (UEBA, Honeytokens, Purple
   Team, ClickHouse, OpenSearch, Neo4j, Qdrant, MCP) for hacking on AiSOC
   itself.

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

| Step | Approximate time |
|---|---|
| `docker compose pull` | ~90s |
| `docker compose up` + healthchecks | ~60s |
| Seed canonical data | ~30s |
| Kick off investigation | ~30s |
| Total | ~3.5 min |

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

### 6. Run the public eval harness (optional)

```bash
# Run all four substrate eval suites against the bundled 200-incident
# dataset and write a JSON report. The dataset size is fixed by
# services/agents/tests/eval_data/synthetic_incidents.json — there is no
# --count flag.
python scripts/run_evals.py --out eval_report.json

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

### 8. Connect your first source in 5 minutes

The seeded demo data is enough to fly the UI through; pointing AiSOC at a
live source takes about five minutes per connector and zero code changes:

1. Generate a vault key and put it in `.env` —
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   then set `AISOC_CREDENTIAL_KEY=<that-string>`. In dev the API will
   bootstrap an ephemeral key if you skip this; in prod the API refuses
   to start without one. Full threat model and rotation procedure:
   [Operations: Credentials](./operations/credentials).
2. Restart the `api` and `connectors` services so they pick up the key.
3. In the console, click **Connectors** → **Add connector**, pick a
   source from the catalog (Microsoft Entra, GCP Cloud Audit, GitHub, …
   — full list at [docs/connectors](./connectors)), and fill out the
   schema-driven form.
4. Click **Test connection**. The wizard runs a live auth round-trip
   against the vendor API before saving — bad credentials never hit the
   database.
5. Click **Save & enable**. The in-process scheduler picks up the
   instance within 30 seconds, polls every 5 minutes by default, and
   pushes normalized OCSF events to the ingest spine. Watch the
   **Connectors** page for `events_added` to start ticking up; watch
   `/alerts` for them to flow through fusion and detection.

Each per-connector page (e.g.
[Microsoft Entra](./connectors/azure-entra),
[GCP Cloud Audit](./connectors/gcp-cloud-audit),
[GitHub](./connectors/github)) walks through the cloud-side prereqs
(Azure AD app, GCP service account, GitHub fine-grained PAT) with exact
permissions / scopes / role assignments and a troubleshooting section.

### Console Tour

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/dashboard` | Live alert stream, case queue, KPI tiles |
| Alerts | `/alerts` | Raw signal feed with Ambient Copilot suggestions |
| Cases | `/cases` | Unified case management |
| Case workspace | `/cases/<id>` | Evidence timeline + **Investigation Ledger** + attack graph |
| Detections | `/detections` | Sigma/YARA/KQL rule catalog (800 native + ~6,000 imported, filterable by tier) |
| Playbooks | `/playbooks` | SOAR automation builder (50+ packs) |
| UEBA | `/ueba` | User behavior anomaly timeline |
| Honeytokens | `/honeytokens` | Deceptive token lifecycle |
| Purple Team | `/purple-team` | ATT&CK coverage · emulation runs · tabletop |
| Marketplace | `/marketplace` | 15 plugins + 50+ playbooks + 6,900+ detections (tier-filtered) |
| Benchmark | `/benchmark` | Public eval harness — alert reduction + substrate self-consistency gates |
| Compliance | `/compliance` | SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA |
| Audit Log | `/audit` | Immutable, tenant-scoped activity ledger |
| Responder PWA | `/responder` | Mobile passkey-only console for on-call analysts |

## Next Steps

- [Architecture deep-dive](./architecture)
- [Connect your first source](./connectors)
- [Operations: Credentials](./operations/credentials) — vault, key rotation, hosted-OAuth roadmap
- [Concepts: Cases & Investigation Ledger](./concepts/cases)
- [Write your first detection rule](./concepts/detections)
- [Build a playbook](./concepts/playbooks)
- [Install a community plugin](./plugins/overview)
- [Connect your IDE via MCP](./integrations/mcp)
- [Run the public eval harness](./benchmark)
- [Deploy to Kubernetes](./deployment/kubernetes)
