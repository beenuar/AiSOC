## Learned User Preferences

- Always track progress locally (e.g. in a TODO/PROGRESS file) so work can be resumed after IDE crashes or restarts.
- Complete all planned tasks without stopping mid-way; work through the full list until done.
- Do not mention competitor names (Prophet Security, Torq) anywhere in code, comments, or docs — this is an open-source project.
- Before pushing to GitHub, ensure no secrets, API keys, tokens, or sensitive data are present in any public repo files.
- Host codebase on GitHub once fully built out; keep documentation in sync.
- Never edit plan files directly — implement the plan as specified without modifying the plan document itself.

## Learned Workspace Facts

- Project: AiSOC — open-source, AI-powered Security Operations Center maintained by the AiSOC community under the MIT license.
- Monorepo managed with pnpm (pnpm@8.15.1) and Turborepo; workspaces defined in `apps/*` and `packages/*`.
- Apps: `apps/web` (Next.js frontend), `apps/docs` (documentation site).
- Backend services in `services/`: `api` (FastAPI/Python 3.11), `agents`, `alert-fusion`, `connectors`, `demo-producer`, `enrichment`, `fusion`, `ingest`, `realtime`, `threatintel`, `ocsf`.
- API service stack: FastAPI, Uvicorn, SQLAlchemy (async), asyncpg (PostgreSQL), Alembic (migrations), Redis, python-jose (JWT), Pydantic v2.
- Packages: `packages/types` (shared TypeScript types), `packages/ui`, `packages/sdk-go`, `packages/sdk-py`, `packages/sdk-ts`, `packages/plugin-sdk-go`, `packages/plugin-sdk-py`.
- Docker Compose used for local dev (`docker-compose.dev.yml`); Terraform in `infra/terraform/` for infrastructure.
- CI uses GitHub Actions (`.github/workflows/`); includes workflows for OpenAPI checks, CI, docs deployment, marketplace sync, and detection validation.
- Detection rules stored in `detections/` (YAML format, categorized by cloud/endpoint/identity/network/application).
- Marketplace plugin index at `marketplace/index.json`, synced to `apps/web/public/marketplace/` via `pnpm marketplace:sync`.
- Connector platform conventions:
  - Connectors live under `services/connectors/app/connectors/<name>.py`. Each subclasses `BaseConnector` and declares a `schema()` classmethod returning a `ConnectorSchema(name, label, description, category, fields, oauth, default_poll_interval_seconds)`. Categories are `edr | siem | cloud | iam | saas | vcs | network`.
  - Discovery is registry-based — add the class to `_CONNECTOR_CLASSES` in `services/connectors/app/connectors/__init__.py` (no other wiring required).
  - Sensitive `auth_config` fields are marked `secret=True` in the schema and encrypted at the application layer using `CredentialVault` (Fernet AES-128-CBC + HMAC-SHA256). Key in `AISOC_CREDENTIAL_KEY`; rotation supported via `MultiFernet` + `AISOC_CREDENTIAL_KEY_ROTATION_FROM`. Vault token format is `vault:v1:<base64>`.
  - The API service (`services/api`) holds the encrypt/decrypt keypair authority; `services/connectors` ships a vendored read-path `decrypt_dict()` so the scheduler can decrypt at poll time without owning the write path.
  - Polling runs in-process inside `services/connectors` via APScheduler (`ConnectorScheduler`). One job per enabled instance, 5-min default cadence, overridable per-instance via `connector_config.poll_interval_seconds`. The scheduler reloads jobs every 30s. Disable in tests with `AISOC_CONNECTORS_DISABLE_SCHEDULER=1`.
  - Normalized events flow through `IngestClient` (`services/connectors/app/ingest_client.py`) to `services/ingest`'s `/v1/ingest/batch` endpoint with an `X-Tenant-ID` header.
  - Severity ladder is exactly four tiers: `info | low | medium | high`. Vendor-native ladders (Azure 5-tier, SCC 5-tier, GitHub 4-tier) collapse into this set in each connector's `normalize()` method.
  - Every connector ships a marketplace manifest at `plugins/<connector-id>/plugin.yaml` mirroring its `schema()`. Run `pnpm marketplace:sync` after adding one.
  - Per-connector setup walkthroughs live under `apps/docs/docs/connectors/<connector-id>.md` and are indexed by `apps/docs/sidebars.ts` under the `Connectors` category. The vault threat model + rotation procedure live in `apps/docs/docs/operations/credentials.md`.
- v1.4 eval harness conventions:
  - Synthetic dataset is fixed at 200 incidents (`services/agents/tests/eval_data/synthetic_incidents.json`) plus an aligned synthetic telemetry corpus (`synthetic_telemetry.jsonl`). Three of the four metrics (`alert_reduction`, `investigation_completeness`, `response_quality`) are substrate self-consistency gates, not agent accuracy scores; only `mitre_accuracy` measures the live agent. The benchmark page (`apps/docs/docs/benchmark.md`) explains which is which.
  - PRs touching the agent, orchestrator graph, prompts, tools, RAG corpus, or detection content must re-grade against the harness and include before/after deltas in the PR body if any axis regresses.
