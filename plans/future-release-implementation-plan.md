# Future Release Implementation Plan

> **Status**: Draft v1 — derived from a codebase + docs scout on 2026-05.
> **Scope**: Everything in the AiSOC monorepo currently shipped as a stub,
> simulation, "coming soon", placeholder, or roadmap entry.
> **Convention**: Mirrors `PROGRESS.md`. Use `[ ]` → `[~]` (in flight) → `[x]`
> (shipped). Each item lists files, acceptance criteria, eval impact, and
> dependencies so any contributor can pick it up cold.

---

## Why this plan exists

Three different categories of "future release" markers exist in the repo today,
and they were not previously tracked in one place:

1. **Silent simulation stubs** — code paths that look implemented from the API
   surface but return `SIM-*` IDs and never call out. Most of the SOAR
   containment surface is in this state. **Highest risk** — the platform
   advertises capabilities it cannot deliver in production.
2. **`ROADMAP.md` v7.0 + Ideas Backlog** — features explicitly scheduled or
   parked. Tracked, but not broken down into shippable units.
3. **UI `coming soon` toasts and "planned" doc references** — small surface
   gaps that block end-to-end flows even when the backend exists.

This plan rolls all three into five sequenced milestones. Milestone 1 must
ship before any production-tier customer trusts the platform. Milestones 2–5
are ordered by user impact / dependency depth.

---

## Milestone 1 — Production SOAR Hardening (BLOCKER for prod)

**Theme**: Replace simulation executors with real integrations. Today the
`actions` service answers every containment request with a fake `SIM-*` rule
ID. The orchestrator, audit log, and UI all believe the action ran.

**Target release**: v6.x patch series (back-portable).
**Eval impact**: New executor-integration tests; `response_quality` axis of
the eval harness should grow real-vs-simulated coverage. PRs touching these
files trigger the harness re-grade rule in `AGENTS.md`.

### 1A — Real EDR host isolation
- [ ] **What**: Wire `IsolateHostExecutor` to CrowdStrike Falcon, SentinelOne,
      and Microsoft Defender for Endpoint. Honor `rollback()` (de-isolate).
- [ ] **Files**:
  - `services/actions/app/executors/endpoint.py` (replace `TODO`)
  - new `services/actions/app/integrations/edr/{crowdstrike,sentinelone,defender}.py`
  - `services/connectors/app/connectors/{crowdstrike,sentinelone,defender}.py`
    extend with action-channel methods (existing connectors are read-only).
  - `services/api/migrations/` — new table for `executor_credentials` keyed by
    tenant + EDR vendor, encrypted via existing `CredentialVault`.
- [ ] **Acceptance**:
  - Integration test against a CrowdStrike sandbox tenant successfully
    isolates and de-isolates a host.
  - `output.note` no longer contains "Simulation mode".
  - Audit log records vendor, isolation_id, and rollback_id.
  - `blast_radius=high` confirmation gate (already in
    `services/actions/app/blast_radius.py`) blocks unattended runs unless
    `AISOC_ALLOW_HIGH_BLAST_AUTO=1`.
- [ ] **Risk**: Vendor API rate limits, partial-isolation states. Mitigate with
      idempotency keys keyed on `action_id`.

### 1B — Real network-layer IP block
- [ ] **What**: Wire `BlockIPExecutor` to Palo Alto PAN-OS, FortiGate FortiOS,
      AWS Security Groups / Network Firewall, and Cloudflare WAF.
- [ ] **Files**: `services/actions/app/executors/network.py`,
      `services/actions/app/integrations/firewall/*.py`.
- [ ] **Acceptance**:
  - Per-vendor integration test creates and removes a block rule; firewall
    audit confirms.
  - `rollback_data.rule_type` matches what was created (address group vs.
    deny-list vs. SG ingress rule).
  - Conflict handling: if rule already exists, return `COMPLETED` idempotently
    rather than `FAILED`.
- [ ] **Risk**: Cloudflare and AWS SG have very different change-windows than
      on-prem firewalls. Document expected propagation time per vendor.

### 1C — Real DNS sinkhole / domain block
- [ ] **What**: Wire `BlockDomainExecutor` to Cisco Umbrella, Cloudflare
      Gateway, and a generic RPZ pusher for self-hosted BIND / Unbound.
- [ ] **Files**: `services/actions/app/executors/network.py`,
      `services/actions/app/integrations/dns/*.py`.
- [ ] **Acceptance**: Same shape as 1B.
- [ ] **Risk**: Wildcard vs. exact-match semantics differ across vendors. The
      `parameters.match_mode` field needs to land in `ActionRequest.parameters`
      and be reflected in the playbook schema.

### 1D — Real ticketing / case-system create
- [ ] **What**: Wire `CreateTicketExecutor` to Jira Cloud / Jira Server,
      ServiceNow ITSM, and PagerDuty Incidents. Reuse existing read-side
      connectors where present.
- [ ] **Files**: `services/actions/app/executors/notification.py`,
      `services/actions/app/integrations/ticketing/*.py`.
- [ ] **Acceptance**:
  - Creates ticket with incident summary, MITRE techniques, top entities,
    deep-link back to AiSOC case.
  - Stores remote ticket key in `incident.external_refs` (new column).
  - Idempotent: re-running the same playbook step doesn't create duplicates
    (use `external_refs.{system}_dedupe_key`).
- [ ] **Risk**: Jira custom-field maps vary per tenant. Ship with a
      `ticketing_field_map.yaml` per-tenant config and a fallback minimal map.

### 1E — Real EDR file quarantine and process kill
- [ ] **What**: Implement `QuarantineFileExecutor` and `KillProcessExecutor`
      against the same EDR set as 1A.
- [ ] **Files**: `services/actions/app/executors/endpoint.py`.
- [ ] **Acceptance**: Hash-based quarantine for files; PID + name match for
      processes; rollback unsupported (document this and reject the rollback
      call cleanly rather than returning `True`).

### 1F — Live event-warehouse provider for hunt scheduler
- [ ] **What**: Replace the empty-stream `ingest` placeholder in
      `services/agents/app/hunt/scheduler.py` with a real reader over the
      federated-search layer (`w3-fed`). When `w3-fed` is the configured
      provider, hunts run against live OpenSearch / ClickHouse.
- [ ] **Files**: `services/agents/app/hunt/scheduler.py`,
      `services/agents/app/hunt/providers/ingest.py` (new),
      `services/api/app/services/federated_search.py` (existing).
- [ ] **Acceptance**:
  - `HUNT_TELEMETRY_PROVIDER=ingest` returns >0 events on a populated dev
    cluster within 30s of a hunt's `cron` firing.
  - Synthetic harness still works unchanged (regression gate).
  - PR re-grades the eval harness; `mitre_accuracy` must not regress.

---

## Milestone 2 — Console & Ops Polish (UI completeness)

**Theme**: Eliminate every `coming soon` toast in `apps/web`. Make the
day-to-day analyst console a closed loop without dropping into the API.
**Target release**: v6.x minor.

### 2A — Manual alert creation
- [ ] **File**: `apps/web/src/components/alerts/AlertsView.tsx` (replace toast).
- [ ] **What**: Modal that posts to existing `POST /api/v1/alerts`. Fields:
      title, severity, source, raw payload, owner.
- [ ] **Acceptance**: New alert appears in stream within 2s; audit log records
      `alert.created.manual` with operator user_id.

### 2B — Case creation wizard
- [ ] **File**: `apps/web/src/components/cases/CasesView.tsx`.
- [ ] **What**: Multi-step wizard (name → linked alerts → assignee → SLA tier
      → tags) posting to existing case API. Replaces the current toast.
- [ ] **Acceptance**: Created case is linked to selected alerts and visible in
      the timeline; SLA timer starts.

### 2C — Connector edit / re-auth UI
- [ ] **File**: `apps/web/src/components/connectors/ConnectorsView.tsx`,
      `apps/web/src/components/connectors/ConnectorEditDrawer.tsx` (new).
- [ ] **What**: Edit non-secret fields in place; re-auth flow for OAuth
      connectors that posts back through `services/connectors` `/auth/refresh`.
- [ ] **Acceptance**: Editing a connector does not require delete + re-add.
      Vault token (`vault:v1:*`) is rotated on credential change.

### 2D — Detection starter-pack import
- [ ] **File**: `apps/web/src/components/detections/DetectionsView.tsx`.
- [ ] **What**: Picker over the Sigma starter-pack bundles in `detections/`
      (cloud / endpoint / identity / network / application). Posts via DAC
      pipeline so each rule runs through CI validation before activation.
- [ ] **Acceptance**: Selecting a pack queues a draft PR-equivalent in the
      DAC store; rules go live only after passing `pnpm detections:validate`.

### 2E — Custom avatar upload
- [ ] **File**: `apps/web/src/components/settings/SettingsView.tsx`.
- [ ] **What**: Upload to S3-compatible store (existing MinIO container);
      thumbnail served via signed URL; falls back to initials avatar.
- [ ] **Acceptance**: Upload, replace, and delete all work; image scanned
      with existing file-type sniffer; max 1 MB.

### 2F — Light theme + WCAG AA
- [ ] **Files**: `apps/web/src/styles/`, all components using hardcoded
      `dark:*` Tailwind variants.
- [ ] **What**: Token-driven color system (already partially in place) wired
      to a theme switcher; full WCAG AA contrast pass; keyboard nav audit.
- [ ] **Acceptance**: axe-core CI job (new) reports zero AA violations on the
      five primary views (Alerts, Cases, Detections, Connectors, Settings).

### 2G — Saved views + custom dashboard widgets
- [ ] **Files**: `apps/web/src/lib/savedViews.ts` (new), backend persistence
      in `services/api/app/api/v1/endpoints/preferences.py` (extend existing).
- [ ] **What**: Save a filtered table (alerts, cases, detections) as a named
      view; pin views to a custom dashboard with widgets (counter, trend,
      table). Per-user, per-tenant.
- [ ] **Acceptance**: Saved view persists across sessions; shareable via URL
      slug scoped to tenant.

---

## Milestone 3 — v7.0 Reach Surfaces

**Theme**: Take AiSOC out of the desktop-browser comfort zone.
**Target release**: v7.0.

### 3A — Mobile responder app
- [ ] **What**: Promote the existing responder PWA to a Capacitor / React
      Native shell with native push (already have VAPID), biometric unlock,
      and offline triage queue.
- [ ] **Files**: new `apps/mobile/`, reuse `packages/ui`, share auth with
      `services/api` via existing JWT + passkey flows.
- [ ] **Acceptance**: TestFlight / internal-track build; analyst can ack,
      assign, and run a low-blast-radius playbook from the phone.

### 3B — Slack / Teams native bot
- [ ] **What**: Replace today's webhook-only notification path with a slash-
      command bot (`/aisoc ack`, `/aisoc assign @alice`, `/aisoc run isolate`)
      that respects the blast-radius confirmation gate.
- [ ] **Files**: new `services/chatops/` (FastAPI), connector schemas in
      `services/connectors/app/connectors/{slack,teams}.py` extended.
- [ ] **Acceptance**: Round-trip from Slack thread → AiSOC API → playbook
      execution → reply in same thread, all under 5s p50. ChatOps actions
      are signed (Ed25519) so they show up in the immutable audit log.

### 3C — Weekly executive digest
- [ ] **What**: Auto-generated PDF (or rich HTML email) summarizing alerts,
      cases, MTTR, top techniques, and SLA breaches. Per-tenant cron.
- [ ] **Files**: new `services/api/app/services/digest.py`, template via
      existing `apps/docs` build pipeline or `weasyprint`.
- [ ] **Acceptance**: Emailed each Monday 09:00 tenant-local; bounce-handled;
      opt-out per user.

### 3D — Hosted OAuth — Phase 2 + Phase 3
- [ ] **What**: Move from "BYO OAuth app per tenant" (Phase 1) to a hosted
      OAuth broker for cloud customers (Phase 2), and a signed-bundle export
      for air-gapped customers (Phase 3). See
      `apps/docs/docs/operations/credentials.md` for design.
- [ ] **Files**: new `services/api/app/auth/oauth_broker.py`,
      `services/connectors/app/connectors/base.py` (drop the "Hosted OAuth
      coming soon" badge once Phase 2 lands per-connector).
- [ ] **Acceptance**:
  - Phase 2: User can connect Google Workspace / Microsoft 365 / Okta with
    one click — no redirect-URI configuration.
  - Phase 3: `aisoc bundle export` produces a signed offline OAuth bundle;
    air-gapped install verifies signature before accepting.

---

## Milestone 4 — Plugin Marketplace v3

**Theme**: Move the marketplace from "starter index of first-party plugins"
to a real ecosystem.
**Target release**: v7.x.

### 4A — Commercial plugin publishing
- [ ] **Files**: `marketplace/index.json` schema bump, `apps/web/public/marketplace/`
      sync, `scripts/build_marketplace.py` (resolve current `XXXX` placeholders).
- [ ] **What**: Publishers can ship paid plugins with license keys; AiSOC
      core verifies entitlement at install.
- [ ] **Acceptance**: Two reference paid plugins (one connector, one action)
      ship through the publishing flow end-to-end.

### 4B — Licensing + revenue-share rails
- [ ] **What**: Stripe Connect-backed payouts; per-tenant license enforcement
      via signed JWT entitlement tokens; offline-grace mode for air-gapped.
- [ ] **Files**: new `services/billing/`.
- [ ] **Acceptance**: A test purchase flows end-to-end (Stripe test mode);
      plugin disables itself with a clear UI message after 7 days offline.

### 4C — Plugin SDK gaps
- [ ] **What**: Today the SDK ships read-side enrichers and connectors well,
      but lacks first-class action and widget extension points beyond the
      schemas. Close the gaps.
- [ ] **Files**: `packages/plugin-sdk-py/`, `packages/plugin-sdk-go/`,
      `packages/sdk-ts/`.
- [ ] **Acceptance**: Sample plugin in each language registers a connector,
      an enricher, an action, and a UI widget without monkey-patching core.

---

## Milestone 5 — Intelligence Backlog (ROADMAP "Ideas")

**Theme**: The unscheduled items in `ROADMAP.md` "Ideas Backlog". Sized,
sequenced, and tied to existing surfaces.
**Target release**: rolling, v7.x → v8.x.

### 5A — "Explain this alert"
- [ ] **What**: Button in alert detail that calls the agent investigator with
      a constrained prompt and renders a markdown explanation with citations
      back to enrichment evidence.
- [ ] **Files**: `apps/web/src/components/alerts/AlertDetail.tsx`,
      `services/agents/app/api/contextual.py` (new endpoint, replace `TODO`).
- [ ] **Acceptance**: 90th-percentile response under 6s; eval harness gains
      an "explanation faithfulness" axis (LLM judge against ground truth).

### 5B — NL → Query (real translation, not template)
- [ ] **What**: Replace the template fallback in
      `services/api/app/api/v1/endpoints/nl_query.py` with an LLM-backed
      translator that emits ES|QL (OpenSearch) and KQL (Kusto-style) and
      validates against a generated grammar before execution.
- [ ] **Files**: `services/api/app/api/v1/endpoints/nl_query.py`,
      `services/agents/app/nl_query/translator.py` (new).
- [ ] **Acceptance**:
  - Removes every `TODO: translate` comment.
  - Eval set of 50 NL→ES|QL prompts; ≥85% syntactic validity, ≥70% semantic
    match against gold queries.

### 5C — AI threat-intel briefings
- [ ] **What**: Daily briefing summarizing inbound feed activity, mapped to
      tenant's environment (assets, exposed services, recent detections).
- [ ] **Files**: `services/threatintel/app/briefing.py` (new).
- [ ] **Acceptance**: Briefing posted to the `intel` channel of each tenant;
      links resolve back into AiSOC.

### 5D — Auto IOC sharing to MISP
- [ ] **What**: Bidirectional sync with a MISP instance — pull feeds and push
      tenant-confirmed IOCs (with tenant tag) on case close.
- [ ] **Files**: `services/connectors/app/connectors/misp.py` (already exists
      read-side; extend for push).
- [ ] **Acceptance**: Closing a case with `share_iocs=true` results in a MISP
      event within 60s, observable via MISP API; reverse sync of new
      community feeds works on default cron.

### 5E — Red-team coverage on dashboard
- [ ] **What**: Surface MITRE ATT&CK heatmap of detection coverage on the
      home dashboard, comparing detections in `detections/` vs. ATT&CK matrix.
- [ ] **Files**: `services/api/app/services/coverage.py` (new),
      `apps/web/src/components/dashboard/CoverageHeatmap.tsx` (new).
- [ ] **Acceptance**: Heatmap renders within 1s on tenants with up to 5k
      detections; CSV export available.

### 5F — Incident cost estimator
- [ ] **What**: Per-incident cost estimate based on analyst hours, downtime
      proxy (severity × asset criticality), and external response cost
      heuristics. Configurable per tenant.
- [ ] **Files**: `services/api/app/services/cost.py` (new).
- [ ] **Acceptance**: Estimate appears on case detail; tunable from settings.

### 5G — SLA breach predictor
- [ ] **What**: Lightweight model predicting which open cases are at risk of
      missing their SLA, fed by historical case telemetry. Re-trained nightly.
- [ ] **Files**: `services/agents/app/predictors/sla.py` (new), nightly job
      via existing APScheduler harness.
- [ ] **Acceptance**: AUC ≥0.75 on held-out historical cases; predictions
      visible as a column in case list.

---

## Milestone 6 — Smaller cleanups (one-PR each)

These are real but small. Group as a single "tech-debt sweep" sprint.

- [ ] Replace `# TODO: implement enrichment logic` in
      `packages/aisoc-cli/src/aisoc_cli/main.py` with a call to the existing
      enrichment service.
- [ ] Resolve `XXXX` placeholders in `scripts/build_marketplace.py`.
- [ ] Replace `CVE-2024-XXXXX` placeholder in
      `.github/ISSUE_TEMPLATE/detection_rule_proposal.yml` with real example.
- [ ] Remove `placeholder` reference in
      `services/connectors/app/connectors/duo_security.py`.
- [ ] Tidy quarantine sample
      `detections/sigma-imports/_quarantine/renamed-paexec-execution.yaml`
      (the `XXXXX` markers there are real holes in the rule).
- [ ] Tighten test stub note in
      `services/connectors/tests/test_push_capabilities.py` so it doesn't
      ship a `raise NotImplementedError # placeholder` masquerading as
      production behavior under `pytest --runxfail`.

---

## Milestone 7 — Items already covered by feature flags

All `AISOC_FEATURE_*` flags in `services/api/app/core/config.py` currently
default to `True`. **Action**: audit each flag and either (a) remove it now
that the capability is fully shipped, or (b) keep it and document it under
`apps/docs/docs/operations/feature-flags.md` (new) with a default + deprecation
date. Avoid permanently-on flags — they accumulate as dead code.

- [ ] Inventory and triage every `AISOC_FEATURE_*` flag.
- [ ] Delete or document each.

---

## Cross-cutting requirements (apply to every milestone)

- **Eval harness gate**: Per `AGENTS.md`, any change to the agent,
  orchestrator graph, prompts, tools, RAG corpus, or detection content must
  re-grade the harness and include before/after deltas in the PR body.
  Milestones 1F, 5A, 5B, 5C, 5G are the items that will trip this gate.
- **No competitor names** in code, comments, or docs (per AGENTS.md).
- **Secret hygiene**: Every new integration in M1 must store credentials via
  the existing `CredentialVault` and emit `vault:v1:*` tokens. CI secret-scan
  must remain green.
- **Connector convention**: New connectors land class + schema +
  `_CONNECTOR_CLASSES` registration + `plugins/<id>/plugin.yaml` +
  `apps/docs/docs/connectors/<id>.md` + sidebar entry, then run
  `pnpm marketplace:sync`.
- **CHANGELOG**: Each merged item updates `CHANGELOG.md` `[Unreleased]`.
- **Progress tracking**: Each merged item flips its checkbox here from
  `[ ]` → `[x]` in the same PR.

---

## Sequencing summary

| # | Milestone                          | Why now                                    | Blocks |
|---|------------------------------------|--------------------------------------------|--------|
| 1 | Production SOAR Hardening          | Stops the platform from lying              | All prod customer onboarding |
| 2 | Console & Ops Polish               | Closes UX dead-ends; makes M1 usable       | M3, M5 (UI surfaces) |
| 3 | v7.0 Reach Surfaces                | Headline release; mobile + chatops + digest| Marketing for v7.0 |
| 4 | Plugin Marketplace v3              | Ecosystem & monetization                   | M5 plugins |
| 5 | Intelligence Backlog               | Differentiation; depends on stable core    | — |
| 6 | Tech-debt sweep                    | Anytime — single-PR cleanups               | — |
| 7 | Feature-flag audit                 | Anytime — pure hygiene                     | — |

---

## Owner placeholders

Replace with real handles in the PR that adopts this plan.

| Area                 | Suggested owner |
|----------------------|------------------|
| Actions / SOAR (M1)  | `@TBD-soar`      |
| Web console (M2)     | `@TBD-web`       |
| Mobile + ChatOps (M3)| `@TBD-reach`     |
| Marketplace (M4)     | `@TBD-platform`  |
| Intelligence (M5)    | `@TBD-agents`    |
| Tech debt (M6, M7)   | rotates per PR   |
