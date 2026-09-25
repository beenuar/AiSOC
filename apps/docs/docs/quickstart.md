---
sidebar_position: 3
---

# Quick Start

Three commands take a fresh clone to a running AiSOC that has demonstrably
processed an event:

```bash
git clone https://github.com/beenuar/AiSOC.git && cd AiSOC
cp .env.example .env
make up
make smoke
```

`make up` starts the CORE stack and finishes by creating an administrator.
`make smoke` posts one real event to the ingest API and follows it through
Kafka, detection, correlation and Postgres, then reads the resulting alert
back out of the public API. That second command is the one that matters: a
console with data in it is not evidence that the pipeline works, and until
`make smoke` passes you have not seen the product run.

The rest of this page is the same journey with the detail filled in, plus two
other ways to drive the same services.

| Path | What it is |
| --- | --- |
| **A** | The canonical path above — CORE stack, administrator, pipeline proof. |
| **B** | CORE plus the lake, graph, vector store, search and enrichment, for hacking on AiSOC itself. |
| **C** | The same services driven through the `aisoc` CLI instead of `make` + `curl`. |

If you have none of the prerequisites below, or you just want a
guaranteed-clean environment in one command, start with the
[one-click installer](./installation) — it installs every prerequisite
idempotently on Linux, macOS and Windows and then runs Path A for you.

## Prerequisites

| Requirement | Minimum | Needed for |
|---|---|---|
| Docker + Compose v2 | v2.x | everything |
| RAM available to Docker | **6.5 GB** (CORE) · 12 GB (`full`) | `make up` · `make up-full` |
| Free Docker disk | **~18 GB** | `make up` |
| `bash` | any | `make up` — its pre-flight port check is a shell script |
| `python3` | 3.11+ | `make smoke`, `make stats`, the eval harness |
| Node.js | 22 LTS | `install.sh` / `install.ps1`, and building the web console |
| pnpm | ≥ 8 | as above |
| Go | 1.25+ | only if you are hacking on the Go services or plugins |

Three of those are easy to miss, because nothing names them until the command
that needs them fails:

- **`bash`.** `make up` runs `scripts/doctor.sh --ports-only` before it calls
  compose, so a port conflict is reported against the process holding the
  port rather than as a `Bind for 0.0.0.0:5432 failed` against whichever
  container lost the race. It is a hard gate: no bash, no `make up`.
- **`python3` on the host**, not just in the containers. `make smoke` runs
  `tests/e2e/golden_pipeline/run_golden_pipeline.py` on your machine, against
  the stack's published ports. Without it you can start AiSOC but you cannot
  prove it works.
- **Free Docker disk.** Below roughly 18 GB the images and volumes do not
  comfortably fit, and the failure is quiet rather than loud: Kafka corrupts
  its log directory and *still passes its healthcheck*, so the stack reports
  green while nothing flows. `make doctor` checks the space you have and says
  whether it is enough.

Windows has no `make`. `install.ps1` runs the same steps natively — see
[one-click install](./installation).

## Path A — run it, then prove it works

### 1. Clone and configure

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env
```

`.env.example` ships a working `POSTGRES_PASSWORD` (`aisoc_dev_secret`), so
the database comes up without you touching anything.

**It does not ship a usable `AISOC_CREDENTIAL_KEY`.** The line you copy is:

```bash
AISOC_CREDENTIAL_KEY=replace-me-with-a-freshly-generated-fernet-key
```

That placeholder is not a Fernet key, and it is worse than leaving the
variable empty: an unset key makes the API generate an ephemeral one and warn,
while a malformed key makes the credential vault raise, so the first request
that touches a connector secret returns HTTP 500. Generate a real one and
paste it in before you go near the Connectors page:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Nothing in Path A needs it — the pipeline proof below does not touch the
vault — so you can also come back to this when you connect your first source.
Full threat model and rotation procedure:
[Operations: Credentials](./operations/credentials).

AI triage additionally needs a provider key (`OPENAI_API_KEY` or
`ANTHROPIC_API_KEY`). Without one the stack still boots and every alert is
triaged by the deterministic path, and the console labels it as such —
nothing pretends the AI ran.

### 2. Start the stack

```bash
make up
```

This checks the ports first, starts the CORE profile, waits for every
container to report healthy, and then creates the first administrator. A
container that exited or is crash-looping fails the wait rather than passing
it, so `make up` returning 0 means the services are actually up.

```
  Console:  http://localhost:3000
  API:      http://localhost:8000/api/docs
```

### 3. Prove the pipeline works

```bash
make smoke
```

```
[PASS] raw telemetry accepted by ingest
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
```

The runner POSTs a single suspicious-PowerShell event to
`http://localhost:8081/v1/ingest/batch` and then observes every stage from
the outside — Kafka, fusion, detection, promotion, Postgres, and finally the
public API. It does not insert an alert, stub Kafka or reach into fusion's
internals, because a test that reaches past a component cannot tell you that
component works. Each stage reports PASS or FAIL independently, so a break
names the boundary that broke.

The alert title carries a fresh run id every time, so a re-run cannot pass by
finding the previous run's alert.

If a stage fails, `make doctor` diagnoses every dependency and prints the
command that investigates each one.

### 4. Sign in

Open [http://localhost:3000](http://localhost:3000).

There are no default credentials. `make up` runs `make bootstrap`, which
creates `admin@aisoc.internal` with a password generated on your machine and
printed once — it is stored nowhere, so copy it when you see it. If the
terminal has already scrolled away, mint a new one:

```bash
make bootstrap ARGS=--reset-password
```

To choose the address, or supply your own password instead:

```bash
AISOC_ADMIN_EMAIL=you@yourcompany.com make bootstrap
printf '%s' "$MY_PASSWORD" | docker compose run --rm -T api \
  python -m app.scripts.bootstrap_admin --password-stdin
```

The address has to be one the login route accepts. It is validated with the
same library the API uses, so reserved domains (`.local`, `.test`, `.invalid`,
`.localhost`) are refused here with an explanation rather than producing an
account that fails at the login form with a schema error.

The mobile **Responder PWA** lives at
[http://localhost:3000/responder](http://localhost:3000/responder) — install
it on your phone via "Add to Home Screen" and sign in with a passkey.

### 5. Look around with synthetic data

```bash
make demo
```

Loads a synthetic dataset so the console has something to show before you
connect a real source. Every row it writes is marked `is_synthetic = true` in
the database and labelled in the console. It is not a benchmark, a customer,
or a real incident.

### Day-to-day commands

| Command | What it does |
| --- | --- |
| `make status` | every service and its health |
| `make logs` | follow logs (`SERVICE=fusion` to narrow) |
| `make doctor` | diagnose every dependency, with the fix for each |
| `make smoke` | re-run the end-to-end pipeline check |
| `make down` | stop the stack, keep the data |
| `make clean` | stop the stack and delete all volumes |

:::caution Not the same thing as `pnpm aisoc:demo`
`infra/compose/docker-compose.demo.yml` — what `pnpm aisoc:demo` starts — is a
UI preview over a pre-seeded database. It has no ingest service and no fusion
service, and it sets `AISOC_DISABLE_KAFKA=true`: everything visible in that
console came from a seed script writing rows straight into Postgres. Use it to
look at the interface. Do not use it to decide whether AiSOC works, because it
cannot answer that question. `make up` is the stack this page, the README and
CI all mean.
:::

## Path B — the full stack

Use this when you want to hack on AiSOC itself, run the eval harness, or
exercise UEBA / Honeytokens / Purple Team / MCP.

```bash
make up-full
```

That starts CORE plus the event lake, entity graph, vector store, search and
enrichment, sets the lake and graph writers on (they target stores that only
exist in this profile), and waits for every container to report healthy.

### What is in which profile

Most non-CORE services sit behind a compose profile, so a bare
`docker compose up -d` starts neither UEBA nor Honeytokens nor Purple Team.
`make up` and `make up-full` are the supported spellings for the first two
rows, and additionally wait for health, which a bare `docker compose up -d`
does not.

| Profile | Services |
| --- | --- |
| *(default — CORE)* | **postgres** (5432) · **redis** (6379) · **zookeeper** · **kafka** (9092) · **qdrant** (6333) · **litellm** (4000, LLM gateway) · **ollama** (11434, local model) · **ollama-pull** (one-shot model fetch) · **ingest-worker** (8081, Go) · **fusion** (8003) · **api** (8000) · **agents** (8001) · **threatintel** (8005) · **realtime** (8086) · **web** (3000) |
| `full` | **clickhouse** (8123/9000) · **neo4j** (7474/7687) · **opensearch** (9200) · **ueba** (8007) · **connectors** (8088) · **enrichment** (8080, Go) · **kafka-ui** (8090) · **actions** (8002) |
| `extras` | **honeytokens** (8008) · **purple-team** (8006) |
| `chatops` | **slack-bot** (8009) · **actions** (8002) |
| `monitoring` | **prometheus** (9091) · **grafana** (3001) · **alertmanager** (9094) · **tempo** (3200) · **otel-collector** (4317/4318) |
| `osquery` | **osquery-tls** (8091) |

CORE is 14 long-running services — 15 counting `ollama-pull`, which fetches
the model once and exits — and `full` is 22; `actions` is in both `full` and
`chatops`, so it is counted once. Named profiles compose, so
`docker compose --profile full --profile extras up -d` is valid; it just does
not wait for health the way `make up-full` does.

**What this gives you about AI.** CORE contains both halves: the `litellm`
gateway, which is the only thing that resolves AiSOC's task aliases
(`aisoc-triage`, `aisoc-investigation`, …), and `ollama` running a pinned
~2 GB `llama3.2:3b-instruct-q4_K_M` behind it. Neither was there to begin with,
and moving only the first was only half the fix: a gateway with no model still
left the default install routing a key nobody had
([ADR-0006](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0006-llm-gateway-in-core.md)).

- **Out of the box, no key**: alerts are triaged by a real model. Real
  generated text, real token counts in the Investigation Ledger. A 3B
  quantized model is not a frontier model, and the console does not claim it
  is.
- **With a provider key**: set `OPENAI_API_KEY`, `AISOC_LLM_MODEL_FAST`,
  `AISOC_LLM_MODEL_DEEP` and an empty `AISOC_LLM_API_BASE` in `.env`, then
  `make up` again. The cost dashboard then reports what each call actually
  cost, because the gateway reports it.
- **If no model is reachable at all**: every alert takes the deterministic
  path and the console labels it as such. Nothing pretends the AI ran.

### Database migrations — nothing to run

Every schema is applied by the stack itself; there is no manual migration
step, and there is nothing to remember to run in the right order.

- **api** applies its raw-SQL chain
  (`services/api/migrations/*.sql`) from
  [`app.scripts.run_migrations`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/scripts/run_migrations.py)
  during startup. It has no `alembic.ini` and never did, so
  `docker compose exec api alembic upgrade head` — which earlier revisions of
  this page told you to run — fails with `No 'script_location' key found`.
- **ueba**, **honeytokens**, **purple-team** and **osquery-tls** own their
  schemas through alembic. Each container runs
  [`app/_migrate.py`](https://github.com/beenuar/AiSOC/blob/main/services/ueba/app/_migrate.py)
  before its server: it applies the chain, reads the applied revision back,
  and refuses to start the service unless it matches head. Re-running is
  free — a database already at head applies nothing.

Those four apply their chain as the **owner**, not as the role they serve
requests with: `docker-compose.yml` sets `DATABASE_MIGRATION_URL` alongside
`DATABASE_URL` for each, and their `env.py` prefers it. The runtime role
holds no `CREATE` on schema public, by design — that is what stops it
turning row-level security off — so a chain applied as the runtime
credential fails on the first `CREATE TABLE`. See
[Env vars → the four services that manage their own schema](deployment/env-vars#the-four-services-that-manage-their-own-schema).

To confirm the schemas landed, ask the database rather than the logs. Each
chain records its revision in its **own** version table, because four chains
numbering their revisions `0001`, `0002`, … against one database previously
shared `alembic_version` and the second chain to run believed it was already
done:

```bash
docker compose exec postgres psql -U aisoc -d aisoc -c \
  "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'alembic_version%' ORDER BY 1"
```

Four rows — `alembic_version_honeytokens`, `alembic_version_osquery_tls`,
`alembic_version_purple_team`, `alembic_version_ueba` — means all four ran.
A service whose chain did not reach head does not serve at all: its
container exits and `docker compose ps` shows it unhealthy rather than
running.

### Run the public eval harness (optional)

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

### Connect your first source in 5 minutes

Pointing AiSOC at a live source takes about five minutes per connector and
zero code changes. Connectors are a `full`-profile service, so start the stack
with `make up-full`.

1. Put a real Fernet key in `.env` as `AISOC_CREDENTIAL_KEY` (see
   [Clone and configure](#1-clone-and-configure) above) — connector
   credentials are encrypted with it. In development the API will bootstrap
   an ephemeral key if the variable is *empty*; it will not if the variable
   holds the placeholder `.env.example` ships.
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

### Console tour

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/dashboard` | Live alert stream, case queue, KPI tiles |
| Alerts | `/alerts` | Raw signal feed with Ambient Copilot suggestions |
| Cases | `/cases` | Unified case management |
| Case workspace | `/cases/<id>` | Evidence timeline + **Investigation Ledger** + attack graph |
| Detections | `/detections` | Sigma/YARA/KQL rule catalog, filterable by tier |
| Playbooks | `/playbooks` | SOAR automation builder |
| UEBA | `/ueba` | User behavior anomaly timeline |
| Honeytokens | `/honeytokens` | Deceptive token lifecycle |
| Purple Team | `/purple-team` | ATT&CK coverage · emulation runs · tabletop |
| Marketplace | `/marketplace` | Plugins, playbooks and detection packs (tier-filtered) |
| Benchmark | `/benchmark` | Public eval harness — alert reduction + substrate self-consistency gates |
| Compliance | `/compliance` | SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA |
| Audit Log | `/audit` | Immutable, tenant-scoped activity ledger |
| Responder PWA | `/responder` | Mobile passkey-only console for on-call analysts |

Run `make stats` to recount the figures the README publishes — detection
counts and connector counts are produced from the tree rather than typed in,
so this page does not restate them.

## Path C — founder-style CLI

The same services as Path A and B, driven through `aisoc <verb>` instead of
`make` + `curl`. This is the path the recorded product demo follows.

### 1. Install the CLI

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env

python -m venv .venv && source .venv/bin/activate
pip install -e packages/aisoc-cli
```

Set `AISOC_CREDENTIAL_KEY` to a generated Fernet key as described in
[Clone and configure](#1-clone-and-configure), and add at least one AI
provider key (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) if you want AI triage.

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
against the dev profile. The command resolves the repo root automatically, so
it works from any subdirectory.

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

#### `alerts/submit` versus the ingest spine

Both work, and they answer different questions.

`POST /v1/ingest/batch` on the **ingest** service is the production path:
normalize → Kafka → fusion → detection → correlation → an `Alert` row. That
is what `make smoke` exercises and what the README uses as its proof, so it is
the one to use when the question is "does the pipeline work".

`POST /api/v1/alerts/submit` on the **api** service short-circuits that and
writes the alert directly. It is the right tool for fixtures, tabletop
exercises and demo scripts, where you want a specific alert to exist without
waiting on the spine — and it is what the CLI uses so a single fixture lands
deterministically. It is not a fallback for a broken pipeline: if events sent
to the ingest spine are not becoming alerts, that is a defect, and
`make doctor` plus `make smoke` will localise it.

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

If your editor speaks MCP, point it at the local MCP server so you can talk to
your running AiSOC instance from the editor:

```bash
# Stand up the MCP server over stdio
aisoc mcp serve --transport stdio

# Or auto-wire it into a specific IDE config
aisoc mcp install --host <editor>
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
| Wire MCP into an editor | `aisoc mcp install --host <editor>` |
| Validate a plugin manifest | `aisoc plugin validate plugins/<id>` |
| Validate a Sigma rule | `aisoc detection validate detections/<id>.yml` |
| Generate an **Ed25519 plugin-signing** key pair | `aisoc keygen` |

`aisoc keygen` writes `~/.aisoc/signing.key` and `signing.pub` for signing
plugin manifests. It does **not** generate the vault's
`AISOC_CREDENTIAL_KEY`, which is a Fernet key — use the `python -c` one-liner
in [Clone and configure](#1-clone-and-configure) for that.

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

Run `make doctor` first — it checks every dependency and prints the command
that investigates each failure. If `make up` never went healthy or `make
smoke` failed a stage, the
[troubleshooting page](./operations/troubleshooting) has runbooks for the most
common failure modes.
