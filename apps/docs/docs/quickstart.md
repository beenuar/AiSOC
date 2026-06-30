---
sidebar_position: 3
---

# Quick Start

Four paths to a running AiSOC instance, in increasing order of how much you
already have installed:

0. **Zero-prerequisite bootstrap** — one shell command from a freshly-imaged
   machine. Installs Docker, Node, pnpm, git, and clones the repo; then runs
   Path A automatically. See [One-click install](./installation).
1. **One-shot demo** — `pnpm aisoc:demo` brings up a slim stack from prebuilt
   GHCR images, seeds canonical demo data, kicks off an investigation, and
   opens your browser at the live case. Roughly 3-4 minutes on a warm Docker
   daemon.
2. **Full development stack** — every microservice (UEBA, Honeytokens, Purple
   Team, ClickHouse, OpenSearch, Neo4j, Qdrant, MCP, osquery TLS server,
   Slack bot) for hacking on AiSOC itself.
3. **Founder-style CLI** — the same dev stack as Path B, but driven entirely
   through the `aisoc` CLI: `aisoc serve`, `aisoc db upgrade`, `aisoc submit`,
   `aisoc mcp serve`. Ideal for screen-recording demos and for operators who
   prefer a single binary over `docker compose` + `alembic` + `curl`.

This page covers Paths A, B, and C. If you don't have Docker / Node / pnpm
yet, or if you just want a guaranteed-clean environment in one command, start
with [Path 0 (One-click install)](./installation).

## Prerequisites

| Tool | Minimum version | Required for |
|------|-----------------|--------------|
| Docker & Docker Compose | v2.x | Both paths |
| Node.js | ≥ 20 LTS | Both paths |
| pnpm | ≥ 8 | Both paths |
| Python | 3.11+ | Eval harness, dev stack only |
| Go | 1.25+ | Only if hacking on Go services or plugins |

> If you don't have all of the above, just use the
> [One-click installer](./installation) — it installs every prerequisite
> idempotently for Linux, macOS, and Windows, then runs Path A for you.

## Path A — one-shot demo

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
pnpm aisoc:demo
```

That single command:

1. Pulls prebuilt images from `ghcr.io/beenuar/*` (≈90s on a warm cache).
2. Brings up the slim demo profile defined in
   [`infra/compose/docker-compose.demo.yml`](https://github.com/beenuar/AiSOC/blob/main/infra/compose/docker-compose.demo.yml):
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

### Acceptance gate

The buyer-value contract for v1.0 is **clone-to-investigation in ≤ 5 minutes on
a clean Mac**. We measure it with a dedicated harness:

```bash
pnpm aisoc:acceptance          # warm start, default 5-minute budget
pnpm aisoc:acceptance --cold   # prune cached demo images first (true clean clone)
pnpm aisoc:acceptance --history-only   # print the trend ledger
```

The harness wraps `aisoc:demo`, enforces the budget, and appends a JSONL entry
to `.aisoc/acceptance-history.jsonl` per run so regressions are visible across
commits. Exit codes — `0` pass, `3` over budget, `4` showcase case never
reached — make it easy to wire into CI without parsing logs. Source:
[`scripts/aisoc-acceptance.ts`](https://github.com/beenuar/AiSOC/blob/main/scripts/aisoc-acceptance.ts).

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

## Path C — founder-style CLI

Same backing services as Path B (full dev stack), but every step is one
`aisoc <verb>` command. This is the path the recorded product demo follows
and the fastest way to go from "fresh clone" to "alert submitted, agent
investigating" without remembering the `docker compose` / `alembic` /
`curl` invocations.

### 1. Clone & install the CLI

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env

python -m venv .venv && source .venv/bin/activate
pip install -e packages/aisoc-cli
```

`.env.example` is already wired up with a working `POSTGRES_PASSWORD` and a
pre-generated dev `AISOC_CREDENTIAL_KEY`. Add at least one AI provider key
(`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) before continuing.

Confirm the CLI is on PATH:

```bash
aisoc --help
```

You should see the operator commands: `serve`, `db`, `mcp`, `submit`,
`plugin`, `detection`, `keygen`.

### 2. Start the dev stack

```bash
aisoc serve
```

Under the hood this runs `docker compose -f infra/compose/docker-compose.dev.yml up -d`
against the full dev profile (Postgres, Redis, Kafka, ClickHouse, api,
agents, fusion, ingest-worker, web, mcp, …). The command resolves the repo
root automatically, so it works from any subdirectory.

Use `aisoc serve --no-detach` if you want to watch the logs inline, or run
`docker compose ps` separately to confirm every container is healthy.

### 3. Run database migrations

```bash
aisoc db upgrade
```

This shells into the `api` container and runs the project's migration
script against Postgres. It is idempotent — safe to re-run after each
`aisoc serve`.

### 4. Submit your first alert

The repo ships a canonical OCSF / Okta System Log fixture under
[`examples/alerts/lateral-movement.json`](https://github.com/beenuar/AiSOC/blob/main/examples/alerts/lateral-movement.json):
two `user.session.start` events for the same user — first from a New York
corporate IP, then from Saint Petersburg eight minutes later — designed to
trip the impossible-travel detector.

```bash
aisoc submit examples/alerts/lateral-movement.json
```

What this does:

1. Reads the JSON file. The fixture is self-describing — its
   `connector_id` / `connector_type` / `source_format` (if present) win
   over the CLI flags, so the same fixture works against any environment.
2. POSTs to `http://127.0.0.1:8000/api/v1/alerts/submit` (override with
   `--api-url` or `AISOC_API_URL`) using the canonical envelope:
   `connector_id`, `connector_type`, `source_format`, `events`. The API
   service synthesises a single `Alert` row directly from the batch
   (severity normalised across the canonical five-tier ladder, MITRE /
   affected entities derived from the OCSF payload), persists it, and
   returns the new `alert_id`.
3. Sends the required `X-Tenant-ID` header (override with `--tenant-id`
   or `AISOC_TENANT_ID`). When no `Authorization` header is supplied and
   the API is running in dev mode (the default for `docker compose up`),
   the request is authenticated as the demo tenant operator.
4. Prints the `alert_id` plus `accepted` / `rejected` counts.

A non-zero exit code means the API service rejected the payload or
isn't reachable; the error message tells you to run `aisoc serve` first
if the latter.

Why direct-to-API instead of via the ingest spine? The Kafka-based
detection / correlation pipeline is still wiring up in the demo
environment, so events POSTed to `/v1/ingest/batch` accept cleanly but
never become `Alert` rows. The `/api/v1/alerts/submit` endpoint
short-circuits that gap so the recorded demo's "submit → see in console"
moment works on a fresh clone today. Production deployments still flow
events through `services/ingest` → Kafka → fusion → detection; this
endpoint is for fixtures and tabletop exercises.

#### Hardening / limits on `POST /api/v1/alerts/submit`

The submit endpoint enforces five guard-rails so it's safe to expose to
connectors and the CLI in production:

- **Payload caps** (tunable via env vars):
  - `AISOC_SUBMIT_MAX_EVENTS` (default `1000`) — max events per batch.
  - `AISOC_SUBMIT_MAX_EVENT_BYTES` (default `262144` — 256 KiB) — max
    serialised size per event.
  - `AISOC_SUBMIT_MAX_TOTAL_BYTES` (default `8388608` — 8 MiB) — max total
    batch size. Over-cap requests return HTTP 413 with the limit that fired.
- **Idempotency** — set the `Idempotency-Key` header (1–128 chars,
  `^[A-Za-z0-9._:/-]+$`) and retries with the same key return the original
  `alert_id` instead of creating duplicates. Scoped per tenant — different
  tenants can reuse the same key.
- **`raw_event` redaction** — values for keys matching a recursive
  case-insensitive blocklist (`password`, `token`, `secret`, `api_key`,
  `authorization`, `cookie`, `client_secret`, `private_key`, `bearer`,
  `session_id`, `csrf`, `x-api-key`) are replaced with `"[REDACTED]"`
  before storage. Stats are emitted to structured logs so SOC operators
  can spot leaky connectors.
- **Timestamp bounds** — event timestamps are clamped to
  `[now - AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS, now + AISOC_SUBMIT_MAX_FUTURE_SECONDS]`
  (defaults 90 days and 300 s). Clamped events still ingest; the alert's
  `metadata.timestamp_clamped` counter records how many were rewritten.

### 5. Watch the alert land in the console

```bash
# List alerts via the API
curl -s http://localhost:8000/api/v1/alerts | jq

# Or open the UI and watch /alerts populate
open http://localhost:3000/alerts
```

Within a couple of seconds you should see the synthesised alert
(severity `medium`, title derived from the highest-severity event in
the batch, affected user `alice@example.com`, affected IPs from both
sessions) on the alerts board.

### 6. Hook your IDE in over MCP (optional)

If you use Cursor, Claude Desktop, or Continue, point them at the local
MCP server so you can talk to your running AiSOC instance from the editor:

```bash
# Stand up the MCP server over stdio (Cursor / Claude / Continue)
aisoc mcp serve --transport stdio

# Or auto-wire it into a specific IDE config
aisoc mcp install --host cursor
aisoc mcp install --host claude
aisoc mcp install --host continue
```

`aisoc mcp serve` prefers the local TypeScript build at
`services/mcp/dist/index.js` when present, and falls back to
`npx @aisoc/mcp` otherwise — so it works on a fresh clone before you've
run `pnpm build`.

### 7. Tear down

```bash
docker compose -f infra/compose/docker-compose.dev.yml down
```

Or keep the stack running and re-submit different fixtures — `aisoc
submit` accepts any JSON file shaped like a single event, a list of
events, or `{ "events": [...] }`. Drop in your own Okta / Entra / GitHub
sample exports to dogfood your detection content end to end.

### Founder-style CLI cheat sheet

| Step | Command |
|---|---|
| Start the dev stack | `aisoc serve` |
| Apply DB migrations | `aisoc db upgrade` |
| Submit a sample alert | `aisoc submit examples/alerts/lateral-movement.json` |
| Run the MCP server over stdio | `aisoc mcp serve --transport stdio` |
| Wire MCP into Cursor / Claude / Continue | `aisoc mcp install --host <host>` |
| Validate a plugin manifest | `aisoc plugin validate plugins/<id>` |
| Validate a Sigma rule | `aisoc detection validate detections/<id>.yml` |
| Generate a vault `AISOC_CREDENTIAL_KEY` | `aisoc keygen` |

## Next Steps

### Learn the platform

- [Architecture deep-dive](./architecture)
- [Capabilities](./concepts/capabilities) — full feature inventory by tier
- [Glossary](./glossary) — security and AiSOC-specific terminology
- [FAQ](./operations/faq) — common questions about scope, deployment, data, and licensing

### Connect data and detections

- [Connect your first source](./connectors)
- [Write your first detection rule](./concepts/detections)
- [Build a playbook](./concepts/playbooks)
- [Concepts: Cases & Investigation Ledger](./concepts/cases)

### Extend AiSOC

- [Install a community plugin](./plugins/overview)
- [Connect your IDE via MCP](./integrations/mcp)
- [Run the public eval harness](./benchmark)

### Operate in production

- [Deploy to Kubernetes](./deployment/kubernetes)
- [Operations: Credentials](./operations/credentials) — vault, key rotation, hosted-OAuth roadmap
- [Security model](./operations/security) — RBAC, MFA/SSO, audit logs, multi-tenant isolation
- [Upgrades & versioning](./operations/upgrades) — release cadence, deprecation policy, in-place upgrades
- [Troubleshooting](./operations/troubleshooting) — common errors, log locations, recovery

### Got stuck?

If `pnpm aisoc:demo` failed, healthchecks went red, or migrations didn't run cleanly,
the [troubleshooting page](./operations/troubleshooting) has runbooks for the most
common failure modes.
