# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Click-and-connect cloud connector platform

This pass turns connectors from a hardcoded, code-edit-only feature into a
runtime, schema-driven, click-and-connect surface — and lights up nine new
cloud / SaaS / VCS sources (Microsoft Entra, Azure Activity, Defender XDR,
GCP Cloud Audit, GCP SCC, Microsoft 365 audit, Google Workspace, Cloudflare,
GitHub) on top of the original CrowdStrike / Splunk / AWS Security Hub /
Okta / Microsoft Sentinel set.

#### Added

- **`CredentialVault`** (`services/api/app/security/credential_vault.py`,
  `services/connectors/app/security/credential_vault.py`) — Fernet
  (AES-128-CBC + HMAC-SHA256) wrapper for `auth_config` JSON, keyed off the
  new `AISOC_CREDENTIAL_KEY` env var. Supports `MultiFernet` rotation via
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`. The `services/connectors`
  read-path mirror decrypts only; writes always go through the API
  service. Documented in [docs/operations/credentials](apps/docs/docs/operations/credentials.md).
- **Self-describing connector schemas** (`services/connectors/app/connectors/base.py`)
  — `BaseConnector` gained a `Field` / `OAuthHints` / `ConnectorSchema`
  trio and an abstract `schema()` classmethod. Each connector class is now
  the source of truth for its own `name`, `connector_category`, fields
  (text / secret / select / textarea / oauth), default poll interval, and
  hosted-OAuth roadmap hints. The hardcoded dict in
  `services/connectors/app/api/router.py` is gone — schema responses come
  from the registry built in `services/connectors/app/connectors/__init__.py`.
- **`/api/v1/connectors` CRUD endpoints**
  (`services/api/app/api/v1/endpoints/connectors.py`,
  `services/api/app/schemas/connector.py`) — `GET /catalog`, `POST /test`,
  `GET / POST / PATCH / DELETE /instances`, `POST /instances/{id}/test`.
  Tenant-scoped via the existing auth dependency, secrets encrypted on
  write through the vault, and proxied to the connectors microservice for
  schema lookups and live `Test connection` calls.
- **`ConnectorScheduler`** (`services/connectors/app/scheduler.py`) —
  APScheduler in-process inside `services/connectors`, started in the
  FastAPI lifespan. One job per enabled instance, polls
  `fetch_alerts(since_seconds=300)` every 5 min by default
  (`connector_config.poll_interval_seconds` overrides per instance),
  decrypts via the read-path vault, normalizes events through the
  connector's `normalize()` method, and pushes the batch to
  `services/ingest/v1/ingest/batch` via the new `IngestClient`. Set
  `AISOC_CONNECTORS_DISABLE_SCHEDULER=1` to skip wiring the scheduler in
  tests.
- **Nine new connectors** in `services/connectors/app/connectors/`:
  `azure_entra` (Microsoft Graph audit logs), `azure_activity` (ARM
  Activity Log via Resource Graph + blast-radius `_HIGH_BLAST_RADIUS_VERBS`
  list), `azure_defender` (Microsoft Graph Security alerts),
  `gcp_cloud_audit` (Cloud Logging API with hand-rolled RS256 JWT
  signing for service-account auth), `gcp_scc` (Security Command Center
  findings, same JWT signer), `m365_audit` (Office 365 Management
  Activity API, sharing the Azure AD app from `azure_entra`),
  `google_workspace` (Reports API with domain-wide delegation),
  `cloudflare` (Audit Logs), and `github` (Org Audit Log + Code Scanning
  alerts). Every connector ships unit tests covering schema contract,
  normalization, and `test_connection()` happy/sad paths
  (`services/connectors/tests/test_*_connectors.py`,
  `test_schemas.py`, `test_scheduler.py`).
- **Frontend click-and-connect wizard**
  (`apps/web/src/components/connectors/AddConnectorModal.tsx`,
  `ConnectorInstanceList.tsx`, rewired
  `ConnectorsView.tsx`, typed client in `apps/web/src/lib/api.ts`) —
  two-step modal: (1) catalog grid grouped by category, (2)
  schema-driven form with `text` / `secret` / `select` / `textarea`
  fields, an inline `Test connection` button, and a `Save & enable`
  action. `framer-motion` for transitions, `react-hot-toast` for
  feedback. Existing connector cards now render from the live API via
  SWR.
- **Marketplace + plugin manifests** —
  `plugins/{azure-entra, azure-activity, azure-defender, gcp-cloud-audit,
  gcp-scc, m365-audit, google-workspace, cloudflare, github}/plugin.yaml`
  carry the new `schema()` shape so `scripts/build_marketplace.py` can
  surface them in the in-app Marketplace, and
  `apps/web/public/marketplace/index.json` is regenerated via
  `pnpm marketplace:sync`.
- **Documentation** — `apps/docs/docs/connectors/index.md` (catalog
  landing with a connector walkthrough and category taxonomy), nine
  per-connector setup walkthroughs (prereqs, scopes, screenshots),
  `apps/docs/docs/operations/credentials.md` (vault threat model, key
  rotation procedure, hosted-OAuth roadmap), and a new `Connectors`
  section in `apps/docs/sidebars.ts`.

#### Changed

- **`services/api/app/core/config.py`** — added `AISOC_CREDENTIAL_KEY`,
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`, `CONNECTORS_SERVICE_URL`,
  `CONNECTORS_SERVICE_TIMEOUT_SECONDS`. Documented in `.env.example`.
- **`services/api/app/main.py`** — the new `/api/v1/connectors` router is
  mounted alongside the existing v1 router set.
- **`services/connectors/app/api/router.py`** — schema responses lookup
  the registry instead of returning a hardcoded dict; new
  `POST /connectors/{connector_id}/test` endpoint runs an
  unauthenticated dry-run `test_connection()` for the wizard's
  pre-save Test step.
- **`services/connectors/app/main.py`** — the FastAPI lifespan now wires
  the scheduler, with `AISOC_CONNECTORS_DISABLE_SCHEDULER` honored for
  tests and CI.

#### Why this matters

Before this pass: adding a connector meant editing Python in three places,
shipping a release, and reading docs to discover the auth fields. Secrets
sat in plain JSON in Postgres. After this pass: connectors are runtime
data; secrets are encrypted with a key the operator controls; rotation
is a documented procedure; the wizard's `Test connection` round-trip
catches bad credentials before they're saved; and the per-connector docs
each give an analyst a 5-minute path from "I have a tenant" to "alerts
are flowing into the console."

---

### Eval harness v1.4 — synthetic telemetry + per-template macros

This pass addresses two questions raised on the public launch thread about
the v5.2 eval harness:

1. **"Any interest in shipping synthetic telemetry (M365 audit, CloudTrail,
   Sysmon) backing each incident?"** — Yes. A companion
   `synthetic_telemetry.jsonl` corpus is now generated alongside
   `synthetic_incidents.json` and gives connector and Sigma PRs a concrete
   contract to wire against without provisioning a real tenant.
2. **"INC-EVAL-044, 099, and 154 are the same template with `{user}/{host}`
   swapped — what does the multiplier buy vs. the dilution in regression
   signal?"** — The multiplier still buys breadth for connector regressions,
   but the eval suites now report a per-template macro alongside the
   per-case mean so a single broken template (~4 cases) moves the regression
   signal by ~1.8% rather than ~0.5%, and the failing template IDs are
   surfaced inline.

#### Added

- **Synthetic telemetry corpus**
  (`services/agents/tests/eval_data/synthetic_telemetry.jsonl`,
  `scripts/generate_eval_incidents.py`) — 361 backing events spanning 14
  log sources (Sysmon, Windows Security, M365 audit, Azure sign-in, Okta,
  CloudTrail, Linux auditd, journald, EDR, firewall, DNS, VPN, DB audit,
  IdP), wired to all 200 incidents. Each event is a templated dictionary
  with `{user}/{host}/{ip}/{campaign}` placeholders resolved against the
  incident it backs, and carries the fields a real connector pivots on
  (process tree, principal, source IP, log source, event ID).
- **Telemetry event factories + recursive resolver**
  (`scripts/generate_eval_incidents.py`) — `_sysmon`, `_winsec`, `_m365`,
  `_cloudtrail`, `_okta`, `_auditd`, `_journald`, etc. produce base event
  shapes; a recursive resolver walks nested dicts and substitutes incident
  context. The 55 templates in `_TEMPLATES` each now carry a
  `template_id`, a `template_index`, and a tuple of telemetry events.
- **Schema + coverage gate** (`services/agents/tests/test_synthetic_telemetry.py`)
  — five new assertions: every incident has ≥ 1 backing event, every
  expected source is present, every event carries the source-specific
  pivot fields a real connector needs, all placeholders resolve, and no
  single template dominates the source distribution.
- **Per-template macros on every scoring suite**
  (`services/agents/tests/test_mitre_accuracy.py`,
  `test_investigation_completeness.py`, `test_response_quality.py`,
  `scripts/run_evals.py`) — each result now carries a
  `per_template_summary()` (mean, median, min, max, count, failing IDs)
  alongside the per-case mean, plus a new test gating macro accuracy ≥
  0.80 for MITRE / completeness and ≥ 0.75 for response-plan quality. A
  template-distribution-balance test asserts no single template accounts
  for > 5% of incidents (currently 0.5–2.0% each).
- **`run_evals.py` output expansion** — each suite headline now prints
  the per-case mean *and* the per-template macro with the failing
  template IDs inline; the human-readable summary appends a synthetic-
  telemetry footer (event count, source count, incident coverage, file
  path); `--json` output adds `per_template` and `telemetry` blocks.

#### Changed

- **Incident schema** — `synthetic_incidents.json` entries now include
  `template_id` (e.g. `m365_admin_impersonation`) and `template_index`
  fields. Existing fields are unchanged. Regenerated deterministically
  from the seeded RNG.
- **`apps/docs/docs/benchmark.md`** — added a "What's new (v1.4)"
  section, a "Per-case vs. per-template metrics" section explaining the
  ~0.5% vs ~1.8% sensitivity argument with worked examples, and a new
  "Synthetic telemetry corpus" section documenting the 14 sources, the
  pivot fields, the placeholder resolver, and the five schema/coverage
  checks. The "Help us harden the harness" call-outs now include adding
  a connector + Sigma rule against the corpus and adding a new template
  with backing telemetry. The "What this is not" section is updated to
  call out that the corpus is hand-shaped (not captured from a live
  tenant) and that the per-template macro is the non-tautological signal
  on top of the otherwise self-consistent gates.
- **`README.md`** — capability bullet rewritten to call out five suites
  (was four), 55 distinct templates, per-case + per-template macros, and
  the synthetic-telemetry coverage gate. The comparison table flags the
  eval harness as having a synthetic-telemetry corpus + per-template
  macros. Step 5b (`Run the public eval harness`) documents the new
  `python scripts/generate_eval_incidents.py` workflow for regenerating
  the dataset and the corpus together.
- **Eval signature on completeness + response-quality runs** — calls
  from `run_evals.py` now use `keep_per_incident=True` so the per-
  template summary is computable. Default behaviour unchanged for
  existing direct callers.

#### Why this matters

The v5.2 harness gave deterministic numbers but two real concerns existed:
duplicates could mask a broken template behind 199 working duplicates, and
there was no concrete telemetry shape for connector contributors to wire
against. v1.4 closes both: the per-template macro is the dilution-resistant
regression signal that surfaces template-class breaks, and the synthetic
telemetry corpus is the connector-development contract.

---

### Honesty + scale pass (P0–P4 of the post-gimmick improvement plan)

This is a "fix the foundations" pass: tighten security defaults, drop
overclaims, harden CI, fix DX rough edges, scale detection content from
~200 to 6,913 rules with explicit tiering, and ship a public demo
hosted on `tryaisoc.com` via Cloudflare Tunnel.

#### Security defaults (P0)

- **GraphQL tenant scoping** (`services/api/app/graphql/`) — every
  resolver is wrapped with a `tenant_scope` helper, GraphiQL is forced
  off in production, and a tenant-isolation regression test asserts
  cross-tenant reads return 0 rows.
- **Plugin signature gate** (`services/api/app/services/plugin_manager.py`,
  `packages/plugin-sdk-py/src/aisoc_plugin_sdk/loader.py`,
  `packages/plugin-sdk-go/aisoc/loader.go`) — Ed25519 signature
  verification is required before loading any plugin. `PLUGIN_TRUST_MODE`
  controls policy: `strict` (default, signed only), `permissive` (warn
  + load), `dev` (skip). Publisher signing flow is documented in
  `packages/plugin-sdk-py/README.md` and `packages/plugin-sdk-go/README.md`.
- **`/metrics` and compose hardening** (`docker-compose.yml`,
  `docker-compose.demo.yml`, `services/api/app/main.py`,
  `services/api/app/core/security.py`) — service ports bind to
  `127.0.0.1` by default, the API logs a loud warning if `SECRET_KEY`
  is unset or default, the `admin` role permissions are corrected to
  match the documented matrix, and `/metrics` is gated behind
  `METRICS_TOKEN`.

#### Honesty surface (P1)

- **Fusion pipeline framing** (`services/agents/app/fusion/`,
  `apps/docs/docs/architecture.md`) — replaced "real fusion pipeline"
  with the actual scope (rule-based + ML scoring fan-in, no
  reinforcement learning).
- **CI cadence wording** (`README.md`, `CONTRIBUTING.md`) — "every
  commit" → "every push and PR to `main`".
- **Eval harness honesty** (`scripts/eval/`, `apps/docs/docs/`) —
  removed "Macro F1" references, reframed the 200-incident synthetic
  dataset as substrate self-consistency, dropped the hardcoded
  `SUITES` constant, fixed the broken `--report` flag, and aligned
  Prophet usage in code and docs.

#### CI gates (P2)

- **No more `|| true`** (`.github/workflows/ci.yml`) — removed every
  silent failure suppression.
- **Web Vitest smoke** — `apps/web` ships a Vitest suite covering
  marketplace filters, detection coverage view, and core layouts.
- **SDK + service jobs** — added Python pytest + Vitest jobs for
  `packages/sdk-{py,ts,go}` and `packages/plugin-sdk-{py,go}`, plus
  pytest jobs for `services/{api,agents,actions,connectors}`.
- **Detection + playbook validation in CI**
  (`.github/workflows/validate-detections.yml`,
  `.github/workflows/check-openapi.yml`) — `validate_detections.py`
  runs against all 6,913 rules and the OpenAPI spec is regenerated
  and compared on every PR.

#### DX (P3)

- **`aisoc-doctor` probes fixed** (`tools/aisoc-doctor/`) — checks
  match the actual ports, env var names, and service URLs.
- **CLI consistency** (`packages/cli/`, `README.md`,
  `apps/docs/docs/`) — `npx aisoc` and `aisoc` resolve identically;
  package names, missing pnpm scripts, and the `mcp` service
  reference are corrected; branching/tooling and env var names match
  across docs.
- **Infra READMEs** — `infra/k8s/`, `infra/helm/`, `infra/terraform/`,
  `infra/render/`, `infra/fly/`, `infra/railway/`, `infra/coolify/`
  each have a `README.md` documenting prerequisites, secrets, and
  invocation.

#### Detection scale + tiering (P4)

- **800 native rules** — added 600 new Sigma-shaped detections across
  five new spec modules (`scripts/detection_specs_part3_cloud.py`,
  `_identity.py`, `_endpoint.py`, `_network.py`,
  `_application.py`), each with `match_when`, MITRE tagging, and
  auto-generated positive/negative fixtures via
  `scripts/detection_specs_part3_helpers.py`. Native total:
  200 → **800**.
- **6,113 imported rules with provenance** — wired importers under
  `tools/detection_import/{sigma,splunk,chronicle,car}_importer.py`
  for SigmaHQ, Splunk Security Content, Chronicle, and MITRE CAR.
  Each imported rule is tagged with its source, license, and original
  ID; rules whose mappings cannot be replayed against AiSOC fixtures
  are quarantined under `detections/<source>-imports/quarantine/`
  (~5,937 quarantined, ~6,113 active).
- **Title → name migration** — imported YAMLs now use the canonical
  `name:` field instead of `title:`, matching `validate_detections.py`'s
  required schema. `tools/detection_import/common.py` was updated and
  6,113 existing files were migrated in place.
- **Marketplace tier UX** (`apps/web/src/components/marketplace/MarketplaceView.tsx`,
  `MarketplaceView.test.tsx`, `marketplace/index.json`,
  `apps/web/public/marketplace/index.json`,
  `scripts/build_marketplace.py`) — items now expose a `tier` field
  (`stable` / `beta` / `imported` / `community`), the marketplace UI
  defaults to `stable` and shows per-tier counts on filter chips,
  and `build_marketplace.py` infers tiers from `plugin.yaml` and
  source paths.
- **MITRE ATT&CK coverage view** (`apps/web/src/app/(app)/detection/coverage/`,
  `apps/web/src/lib/mitreTactics.ts`) — new in-app dashboard rendering
  the coverage matrix from the marketplace index.
- **Documentation refresh** — updated `README.md`,
  `apps/docs/docs/intro.md`, `apps/docs/docs/quickstart.md`,
  `apps/docs/docs/concepts/detections.md`,
  `apps/docs/docs/contributing/dev-setup.md`,
  `detections/README.md`, and `.github/workflows/validate-detections.yml`
  to reflect 800 native + ~6,000 imported (filterable by tier) and
  drop stale "200+ rules" claims.

#### Public demo on `tryaisoc.com`

- **Cloudflare Tunnel infra** (`infra/cloudflare/`) — `config.yml.example`,
  `tunnel.sh`, and a README explaining how to run the demo profile
  behind `tryaisoc.com` via `cloudflared`. Tunnel script reads
  `DOMAIN`, `TUNNEL_NAME`, `SUBDOMAINS`, `SKIP_DNS`, `SKIP_RUN` env
  vars; defaults publish apex + `api.`, `ws.`, `docs.` subdomains.
- **`pnpm demo:public` script** (`scripts/demo-public.sh`) — boots
  `docker-compose.demo.yml` (read-only demo profile with seeded
  incidents) via `pnpm aisoc:demo --no-open`, then brings up the
  Cloudflare Tunnel that maps `tryaisoc.com` → web (`:3000`),
  `api.tryaisoc.com` → api (`:8000`), `ws.tryaisoc.com` → realtime
  (`:4000`), and `docs.tryaisoc.com` → Docusaurus (`:3001`).
  Companion scripts: `pnpm demo:public:tunnel-only` (skip stack
  bring-up, just run the tunnel) and `pnpm demo:public:setup`
  (provision tunnel + DNS without running cloudflared, for
  `cloudflared service install` flows).
- **Public-host-agnostic web bundle** (`apps/web/next.config.js`,
  `apps/web/src/lib/api.ts`) — the Next.js client now emits
  same-origin relative paths (`/api/v1/...`, `/ws/...`) instead of
  `localhost:8000`-baked URLs, with server-side rewrites proxying
  to api/agents/realtime by Docker DNS name. The same image works
  on `localhost:3000`, behind Cloudflare Tunnel on `tryaisoc.com`,
  or behind any reverse proxy without a rebuild.
- **README "Try it live"** — top-of-README link to the public demo
  with a one-liner for hosting your own on a Cloudflare-managed
  domain.

---

## [5.2.0] — 2026-05-04

### Added

This release groups four areas of work: an append-only investigation
ledger, a public eval harness, a mobile responder PWA, and a hosted
demo profile. Details below.

#### Auditable agent — Investigation Ledger

- **Investigation Ledger** (`services/api/migrations/008_investigation_ledger.sql`,
  `services/api/app/models/investigation.py`,
  `services/agents/app/investigator/ledger.py`) — every prompt the agent
  emits, every tool call, every retrieved evidence shard, and every
  rationale is persisted as an append-only `investigation_step` row,
  scoped to a tenant + case.
- **Investigation Ledger UI** (`apps/web/src/components/cases/InvestigationLedger.tsx`)
  — replayable step-by-step view in the case workspace with prompt,
  response, and tool-call diffs.
- **`GET /api/v1/investigations/*` endpoints** (`services/api/app/api/v1/endpoints/investigations.py`)
  for listing, retrieving, and replaying ledger entries by case.
- **Investigator graph upgrades**
  (`services/agents/app/investigator/{orchestrator,recon_agent,forensic_agent,responder_agent,report_writer_agent,state}.py`)
  — every node now writes a ledger entry on entry and exit, including
  the structured input it received and the structured output it produced.

#### Public eval harness — Pillar-1 eval suite

- **200-incident synthetic dataset**
  (`services/agents/tests/eval_data/synthetic_incidents.json`) — 200
  deterministic, regenerable cases covering all 14 MITRE ATT&CK enterprise
  tactics across roughly the top 50 techniques. Generated by
  `scripts/generate_eval_incidents.py`.
- **Four eval gates** under `services/agents/tests/`:
  - `test_alert_reduction.py` — **real measurement**: 1 000 noisy alerts →
    ~250 incidents via 3-tier fusion, with explicit storm and
    near-duplicate handling
  - `test_mitre_accuracy.py` — **substrate self-consistency gate**:
    tactic-level accuracy / precision / recall / F1 between the
    hand-curated extractor and the dataset that was written to feed it
  - `test_investigation_completeness.py` — **substrate self-consistency
    gate**: evidence-keyword coverage on a templated report
  - `test_response_quality.py` — **substrate self-consistency gate**:
    5-criterion offline rubric on a templated response plan (action class,
    severity awareness, MITRE alignment, evidence grounding, actionability)
- **`scripts/run_evals.py`** — one-shot harness with `--json` and `--ci`
  output modes. Total runtime ~25 ms on a laptop. CI-gated on every
  commit via `.github/workflows/ci.yml`. Runs deterministic substrate code
  against synthetic incidents — does not call the live LLM agent.
- **Public eval harness page** (`apps/docs/docs/benchmark.md`,
  `apps/web/src/app/benchmark/page.tsx`,
  `apps/web/src/components/benchmark/`) — published numbers, full
  method, comparison to other AI SOC offerings, and explicit framing of
  which suites measure substrate self-consistency vs real behaviour.
  Linked from the README and the docs landing page.

#### Mobile responder — Responder PWA

- **Responder PWA** (`apps/web/src/app/(responder)/`,
  `apps/web/src/components/responder/`,
  `apps/web/src/components/pwa/`) — installable, offline-aware, push-
  enabled responder console for on-call analysts. Service worker at
  `apps/web/public/sw.js`, manifest at `apps/web/public/manifest.json`,
  offline shell at `apps/web/public/offline.html`.
- **Passkey authentication** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/passkeys.py`,
  `apps/web/src/lib/responder/`) — WebAuthn registration and login for
  the Responder surface; FIDO2 platform authenticators only, no SMS
  fallback.
- **On-call schedule + handoff** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/oncall.py`) — current responder per
  tenant, surfaced in the Responder home page and in alert pages on the
  desktop console.
- **Approvals workflow** (`services/api/app/api/v1/endpoints/approvals.py`)
  — long-lived approval requests for blast-radius-gated SOAR actions,
  approvable from the Responder PWA with hardware-attested passkey.
- **Web Push delivery** (`services/realtime/src/push.ts`,
  `services/api/app/api/v1/endpoints/push.py`) — VAPID-signed push
  notifications wired into the realtime gateway. Subscriptions persist
  per-device and follow the on-call rotation.
- **Migration** — `services/api/migrations/009_responder_pwa.sql`.

#### Ambient Copilot

- **Contextual actions** (`services/agents/app/api/contextual.py`,
  `apps/web/src/components/alerts/AlertDetailView.tsx`,
  `apps/web/src/components/cases/CaseWorkspace.tsx`,
  `apps/web/src/components/detections/RuleEditor.tsx`,
  `apps/web/src/components/playbooks/PlaybookEditor.tsx`) — the AI Copilot
  now reads the surface the analyst is standing on (alert / case / rule /
  playbook) and proposes the next two or three concrete actions with the
  correct payloads pre-filled. One click invokes the agent with the
  right tool.
- **Investigator graph awareness** — every contextual action is grounded
  in the same Investigation Ledger so the analyst sees, before clicking,
  which prompts and tool calls will be issued.

#### MCP server — first-class IDE / chat integration

- **`@aisoc/mcp`** (`services/mcp/`) — Model Context Protocol server
  exposing 11 AiSOC tools to Claude Desktop, Cursor, Cody, and Continue.
- **Discovery tools** — `aisoc_list_alerts`, `aisoc_list_cases`,
  `aisoc_query_detections`.
- **Deep-dive tools** — `aisoc_get_case`, `aisoc_get_investigation`,
  `aisoc_get_alert`.
- **Action / replay tools** — `aisoc_run_investigation`,
  `aisoc_replay_decision`, `aisoc_explain_step`, `aisoc_create_case`,
  `aisoc_assign_alert`. The replay set walks the Investigation Ledger
  step-by-step inside the IDE / chat.
- **Install command** — `npx -y @aisoc/mcp install --host claude --aisoc-url … --api-key …`.
- **Documentation** — `apps/docs/docs/integrations/mcp.md`,
  `services/mcp/README.md`.

#### Hosted demo — `pnpm aisoc:demo`

- **Slim demo profile** (`docker-compose.demo.yml`) — postgres + redis +
  kafka + api + agents + realtime + web. ClickHouse, OpenSearch, Neo4j,
  and Qdrant are gated behind compose profiles for production.
- **Prebuilt images** — `ghcr.io/beenuar/aisoc-{api,agents,realtime,web,…}`
  built and published by `.github/workflows/publish-images.yml` on every
  release tag.
- **One-shot orchestrator** (`scripts/aisoc-demo.ts`) — pulls images,
  brings up the stack, waits on healthchecks, seeds canonical demo data,
  kicks off an agent investigation against a seeded case, and opens the
  browser at `/cases/<uuid>` with the live ledger view selected.
- **Demo mode middleware** (`services/api/app/middleware/demo_mode.py`)
  — gates write operations, resets state every UTC midnight, and
  watermarks the UI as read-only. Tests at
  `services/api/tests/test_demo_mode.py`.
- **Target time-to-first-investigation:** roughly 3–5 minutes on a warm
  Docker daemon, depending on image cache state.
- **Cleanup** — `pnpm aisoc:demo:down` removes the volumes; logs at
  `pnpm aisoc:demo:logs`.

#### Deployment — one-click everywhere

- **Fly.io** (`infra/fly/`) — first-class config for `api`, `agents`,
  `realtime`, `web`. Deploys via `infra/fly/fly-demo-deploy.sh`,
  ~$14/mo for the whole stack.
- **Render** (`infra/render/render.yaml`) — managed, sleep-on-idle
  config suitable for hobbyists and design partners.
- **Railway** (`infra/railway/railway.toml`) — pay-as-you-go PaaS.
- **Coolify** (`infra/coolify/README.md`) — self-hosted on your own VPS,
  reuses the existing `docker-compose.yml`.

#### Marketplace — content as code

- **~200 detection rules** in `detections/` covering MITRE ATT&CK
  Enterprise (cloud, identity, endpoint, network, application). Sigma
  format, with MITRE technique IDs in `tags`, fixtures under
  `detections/fixtures/`, and `detections/README.md` documenting the
  schema.
- **50+ response playbooks** in `playbooks/packs/v1/` — IAM, EDR,
  network, application, generic. JSON DSL with explicit decision trees,
  human-approval gates, and rollback steps. Schema in
  `playbooks/README.md`.
- **15 plugins** in `plugins/` — both Go and Python implementations for
  CrowdStrike, Splunk, Sentinel, AWS Security Hub, Okta, Cloudflare WAF,
  Defender, GuardDuty, Pagerduty, Slack, Teams, Jira, ServiceNow,
  VirusTotal, AbuseIPDB. Each ships with manifests, tests, and SDK
  helpers.
- **Marketplace index** (`marketplace/index.json`,
  `apps/web/public/marketplace/index.json`) — auto-generated by
  `scripts/build_marketplace.py` from the on-disk content tree.
- **Validation tooling** —
  - `scripts/validate_detections.py` (Sigma + MITRE ID schema)
  - `scripts/validate_playbooks.py` and `scripts/lint_playbooks.py`
    (DSL well-formedness + safety)
  - `.github/workflows/{validate-detections,validate-playbooks,sync-marketplace}.yml`
    enforce the gates on every PR.
- **In-app marketplace** (`apps/web/src/app/(app)/marketplace/page.tsx`,
  `apps/web/src/components/marketplace/MarketplaceView.tsx`) — filterable
  by category, ratings, verified vs community badge.

#### Plugin & client SDKs

- **`packages/plugin-sdk-go`** — Go plugin SDK
  (`module github.com/beenuar/aisoc/plugin-sdk-go`) with action,
  connector, enricher, registry, widget, and loader primitives.
  Examples under `packages/plugin-sdk-go/examples/`.
- **`packages/plugin-sdk-py`** — Python plugin SDK with the matching
  primitives, decorators, and a registry. Tests under
  `packages/plugin-sdk-py/tests/`.
- **`packages/sdk-py`** (PyPI: `aisoc-sdk`) — async Python client SDK
  for the AiSOC API.
- **`packages/sdk-ts`** (npm: `@aisoc/sdk`) — TypeScript client SDK
  with auto-generated types.
- **`packages/sdk-go`** — Go client SDK with OpenAPI-generated models.

#### Marketing & docs

- **`/why-open-source`** page (`apps/web/src/app/why-open-source/page.tsx`)
  — long-form description of the project's open-source posture and
  trade-offs.
- **Updated landing** (`apps/web/src/components/landing/{Hero,LandingNav,Footer,OpenSource}.tsx`)
  — the "live demo" button lands directly on a seeded investigation;
  comparison rows reference specific behaviours rather than generic
  claims.
- **Docusaurus refresh** — new MCP integration page, benchmark page,
  Investigation Ledger references, Responder PWA mentions in concepts
  and quickstart.

### Changed

- **Repository home** — all `cyble-inc/AiSOC` and `aisoc-os/aisoc` URLs
  updated to `beenuar/AiSOC` across docs, README, SDKs, and benchmark
  badges.
- **`packages/sdk-go` module path** is now `github.com/beenuar/aisoc/sdk-go`
  for the API client SDK; the plugin SDK is at
  `github.com/beenuar/aisoc/plugin-sdk-go`.
- **`alerts` API** (`services/api/app/api/v1/endpoints/alerts.py`,
  `services/api/app/models/alert.py`) — surfaces copilot context
  (suggested next actions) inline on the alert detail response.
- **API router** (`services/api/app/api/v1/router.py`) — wires up
  `approvals`, `investigations`, `marketplace`, `oncall`, `passkeys`,
  `push`.

### Fixed

- **CI Docker build contexts** — `.github/workflows/{ci,release,publish-images}.yml`
  now set explicit `context` and `file` parameters per service; multi-
  service builds no longer race on a stale build root.
- **Docker Compose obsolete `version` warning** — removed `version: '3.8'`
  from `docker-compose.demo.yml`.
- **Repository hygiene** — added `.gocache/`, `*.tsbuildinfo`,
  `apps/docs/.docusaurus/`, `apps/docs/build/`, `.cursor/hooks/state/`,
  `plugins/**/*-build-test`, `plugins/**/*-build`,
  `eval_report.json`, and `eval_mitre_accuracy_report.json` to
  `.gitignore`. Removed previously tracked Docusaurus cache and Cursor
  hook state files from the index.

---

## [5.1.0] — 2026-05-03

### Added

- **UEBA service** (`services/ueba`) — User & Entity Behavior Analytics
  - Welford online algorithm for incremental baseline computation
  - Z-score anomaly scoring with configurable sensitivity
  - Peer-group analysis (same role / department / location clustering)
  - Kafka consumer (`security.events`) → producer (`security.anomalies`) integration with `fusion` service
  - Alembic migrations, Dockerfile, Helm deployment template
- **Honeytokens service** (`services/honeytokens`) — deceptive credential & file traps
  - HMAC-SHA256 signed token generator (URL, file, AWS key, email flavors)
  - Webhook handler for first-touch alerting (HTTP signed callbacks)
  - Token lifecycle management: active / triggered / expired states
  - React UI: create tokens, view trigger log, copy lure URLs
  - Alembic migrations, Dockerfile, Helm deployment template
- **Purple Team service** (`services/purple-team`) — adversary emulation & tabletop
  - Atomic Red Team YAML parser (any `atomics/` directory)
  - Caldera REST integration for remote execution
  - ATT&CK coverage heatmap (tactic × technique matrix)
  - Test execution tracking with detection reporting (true positive / false negative)
  - Tabletop exercise session manager with finding capture
  - React UI: Coverage tab, Executions tab, Tabletop tab
  - Alembic migrations, Dockerfile, Helm deployment template

---

## [5.0.0] — 2026-05-03

### Added

- **SAML 2.0 + OIDC authentication** (`services/api/app/auth/`)
  - IdP-initiated and SP-initiated SAML 2.0 flows (python3-saml)
  - OIDC authorization-code + PKCE flow with `authlib`
  - JWT issuance on successful SSO login
- **Multi-tenant Row-Level Security** (Postgres RLS)
  - `tenant_id` column on all data tables
  - RLS policies enforced at the database level
  - SQLAlchemy `set_tenant()` middleware in FastAPI deps
- **Granular RBAC** (`services/api/app/api/v1/endpoints/rbac.py`)
  - `roles`, `role_permissions`, `user_roles` tables
  - `require_permission("resource:action")` FastAPI dependency
  - Admin UI at `/settings/rbac`
- **Immutable Audit Log**
  - Append-only `audit_log` table with a before-UPDATE trigger
  - FastAPI middleware auto-logs every mutating request
  - `GET /api/v1/audit` paginated endpoint with tenant filter
  - Audit log viewer UI at `/audit`
- **Compliance dashboards**
  - SOC 2 evidence auto-collection + PDF export (`/compliance/soc2`)
  - ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA framework heatmaps
  - `GET /api/v1/compliance/{framework}` endpoint with control mapping
- **SLA tracking** — MTTD / MTTR / MTTC
  - `tenant_sla_config` + `alert_sla_events` tables
  - `GET /api/v1/sla/metrics` + `GET /api/v1/sla/breaches`
  - SLA dashboard widget at `/sla`
- **HA Helm chart** — HPA, PDB, Ingress per service
- **Backup & restore scripts** (`scripts/backup.sh`, `scripts/restore.sh`) for Postgres + ClickHouse + plugins → S3/R2
- **Operational runbook generator** (`scripts/generate_runbook.py`) from live OTel trace data
- **Multi-region deployment guide** (`docs/operations/multi-region.md`)
- **OpenTelemetry instrumentation** across API, UEBA, Honeytokens, and Purple Team services

---

## [4.1.0] — 2026-05-03

### Added

- **AiSOC CLI** (`packages/aisoc-cli`) — `scaffold`, `validate`, `publish` commands for plugins and detections
  - `aisoc scaffold plugin <name>` — generate plugin skeleton
  - `aisoc validate detection <file>` — Sigma/YAML schema validation
  - `aisoc publish plugin <path>` — submit to community registry with Ed25519 signing
- **Plugin publishing flow**
  - `community_plugins` table with signature, author, review state
  - `POST /api/v1/plugins/publish` — signed submission
  - `POST /api/v1/plugins/{id}/approve` / `reject` — curator review endpoints
  - Ed25519 signature verification on every submission
- **Marketplace v2** — ratings, install counts, verified badges, category filter, sort options
  - `plugin_ratings` table + `POST /api/v1/plugins/{id}/rate`
  - `GET /api/v1/marketplace?category=&sort=` with pagination
- **Detection catalog** (`/detection/catalog`) — paginated Sigma rule browser
  - Install-to-tenant action from catalog
  - `GET /api/v1/detections/catalog` endpoint
- **Playbook community submissions**
  - `community_playbooks` table + submit / curate API
  - Community tab in PlaybooksView UI
- **Docusaurus documentation site** (`apps/docs`) — full API, architecture, deployment, plugin SDK, quickstart

---

## [3.0.0] — 2026-05-02

### Added
- **Threat Intelligence Enrichment (13 providers)**
  - Open-source/freemium: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan.io, IPinfo
  - Commercial: Cyble Vision, Recorded Future, Mandiant, Crowdstrike Intel, Anomali, IBM X-Force, Flashpoint, Intel 471, DomainTools, RiskIQ
  - New enrichment types: `DarkWebContext`, `VulnerabilityRef`, `BrandRisk`
  - Concurrent fan-out enrichment engine in Go
- **Go module path migration** — all services updated from `github.com/cyble/aisoc` to `github.com/beenuar/aisoc`
- **SECURITY.md** — vulnerability disclosure policy and security contacts
- `services/enrichment/README.md` — full enrichment service documentation

### Changed
- All GitHub repository references updated to `https://github.com/beenuar/AiSOC`
- Helm chart container images updated from `ghcr.io/cyble/aisoc-*` to `ghcr.io/beenuar/aisoc-*`
- `.env.example` expanded with API keys for all commercial TI providers

---

## [2.0.0] — 2026-05-01

### Added
- **Knowledge Graph** — Neo4j-backed entity relationship visualization (`services/api/app/services/graph_service.py`)
- **ML Fusion Engine** — multi-model alert scoring and deduplication (`services/fusion/app/services/`)
- **Rule Engine** — YAML-based detection rules with MITRE ATT&CK mapping (`services/api/app/services/rule_engine.py`)
- **Attack Graph** viz with D3.js force layout (`apps/web/src/components/graph/`)
- **MITRE ATT&CK Heatmap** on dashboard
- **AI Copilot dock** — streaming LLM assistant integrated into case and alert views
- **Threat Hunt page** — query builder with saved hunts and timeline scrubbing
- **Case Workspace** — full case lifecycle: evidence, timeline, collaborators, MITRE tagging
- **Detection Rule Builder** — visual rule editor with backtesting
- **Settings page** — RBAC, notifications, API key management, threat intel feed config
- **Live Dashboard** — WebSocket-powered real-time alert/event feed
- **Command Palette** (cmd-K) — fuzzy search for navigation and actions
- **Marketing Landing Page** — hero, feature highlights, open-source section, footer
- **Design Token System** — Tailwind + CSS vars, Framer Motion animations, responsive layouts
- **Demo Producer** — synthetic event generator for local development
- `scripts/seed_demo.py` — database seeding for demos

### Changed
- Web app migrated to Next.js App Router
- All API routes versioned under `/api/v1`

---

## [1.0.0] — 2026-04-30

### Added
- Initial release of AiSOC — AI Security Operations Center
- FastAPI backend (`services/api`) with alert ingestion, case management, detection rules
- Next.js 14 frontend (`apps/web`) with dashboard, alerts, cases, connectors, threat-intel pages
- Real-time service (`services/realtime`) using WebSockets
- Ingest service (`services/ingest`) in Go for high-throughput event ingestion
- Enrichment service (`services/enrichment`) in Go
- Docker Compose stack for local development
- Helm chart for Kubernetes deployment (`infra/helm/aisoc/`)
- MIT License

[Unreleased]: https://github.com/beenuar/AiSOC/compare/v5.2.0...HEAD
[5.2.0]: https://github.com/beenuar/AiSOC/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/beenuar/AiSOC/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/beenuar/AiSOC/compare/v4.1.0...v5.0.0
[4.1.0]: https://github.com/beenuar/AiSOC/compare/v3.0.0...v4.1.0
[3.0.0]: https://github.com/beenuar/AiSOC/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/beenuar/AiSOC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/beenuar/AiSOC/releases/tag/v1.0.0
