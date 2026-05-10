## Learned User Preferences

- Always track progress locally (e.g. in a TODO/PROGRESS file) so work can be resumed after IDE crashes or restarts.
- Complete all planned tasks without stopping mid-way; work through the full list until done.
- Do not mention competitor names (Prophet Security, Torq) anywhere in code, comments, or docs — this is an open-source project.
- Before pushing to GitHub, ensure no secrets, API keys, tokens, or sensitive data are present in any public repo files.
- Host codebase on GitHub once fully built out; keep documentation in sync.
- Never edit plan files directly — implement the plan as specified without modifying the plan document itself.
- After every significant change, push code and update documentation on GitHub immediately — don't wait to be asked.
- Benchmark data and documentation must be transparent about what is synthetic vs. real; never present fabricated metrics as actual measured performance.
- When the task is clear, act autonomously — don't ask unnecessary clarifying questions.

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
- Project website at `tryaisoc.com`; domain registered through Cloudflare.
- Production hosting target is Fly.io for backend services.
- v1.0 buyer-value plan (`aisoc_v1.0_—_buyer-value_plan_c8116970.plan.md`) is fully implemented (all WS-A through WS-H workstreams completed as of May 2026). Key additions:
  - WS-A: Demo seed script at `services/api/app/scripts/seed_demo.py` — 15 realistic incidents, one-click Render deploy (`render.yaml` + README badge).
  - WS-C: 25 named parameterised playbooks (WS-C1), playbook gallery with eval gate (WS-C2/C3).
  - WS-D: Auto-summary at investigation close with PDF export (WS-D2), replayable investigation timeline (WS-D3), rate-limit + real-test hardening (WS-D1).
  - WS-F: Light/dark theme persisted in user profile (WS-F1), WCAG AA axe-core CI gate (WS-F2), saved views on Alerts/Cases/Playbooks + drag-drop dashboard widgets (WS-F3), visual SOAR studio (undo/redo, edge validation, schema-driven forms — WS-F4), empty-state polish + v1.1 deferred badges (WS-F5).
  - WS-G: Slack Bolt service at `services/slack-bot/` with `/aisoc` ChatOps commands (WS-G1); executive digest with auto-generated PDF + weekly scheduler in `services/api/app/services/digest_pdf.py` and `services/api/app/api/v1/endpoints/reports.py` (WS-G2).
  - WS-H: LLM cost dashboard (`services/api/app/services/cost_dashboard.py` + `apps/web/src/app/(admin)/costs/page.tsx` — WS-H1); BYOK per-tenant LLM credentials vault-encrypted via `CredentialVault`, model `TenantLlmCredential`, settings UI in `apps/web/src/components/settings/SettingsView.tsx` (WS-H2); compliance audit export CSV + HTML bundles at `services/api/app/services/audit_export.py` (WS-H3); air-gapped / local-LLM mode via Ollama/LiteLLM overlay + zero-external-call demo seed (WS-H4).
  - Threat actor attribution engine v0 at `services/threatintel/` (rebased, hardened, open as PR #43).
