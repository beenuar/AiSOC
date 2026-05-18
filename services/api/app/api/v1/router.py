"""API v1 router aggregating all endpoint modules."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    airgap,
    alert_explain,
    alerts,
    api_keys,
    approvals,
    assets,
    attack_chain,
    audit,
    auth,
    autonomy_policy,
    business_context,
    cases,
    community,
    compliance,
    connectors,
    costs,
    deployment,
    detection_compat,
    detection_loop,
    detection_proposals,
    detection_rules,
    easm,
    effective_permissions,
    federated,
    feedback,
    fusion,
    graph,
    graph_ws,
    health,
    hunts,
    identity_graph,
    identity_timeline,
    inbox,
    inbox_itsm,
    insider_threat,
    insights,
    investigations,
    knowledge_base,
    lake,
    llm_credentials,
    llm_status,
    marketplace,
    metrics,
    mssp,
    nl_detection,
    nl_query,
    oauth,
    oncall,
    passkeys,
    phishing,
    playbooks,
    plugins,
    posture,
    push,
    rbac,
    remediation,
    reports,
    rule_tuning,
    saved_hunts,
    saved_views,
    shifts,
    sla,
    stix_taxii,
    tenant_provision,
    tenants,
    threat_intel,
    translation,
    waitlist,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(api_keys.router)
api_router.include_router(alerts.router)
# Structured AI explainer (POST /alerts/{id}/explain) — single-shot
# JSON envelope counterpart to the agent service's NDJSON stream.
api_router.include_router(alert_explain.router)
api_router.include_router(cases.router)
# Attack-chain timeline (T3.3 — v8.0 parallel team plan).
# Backs apps/web/src/app/(app)/cases/[id]/attack-chain/page.tsx with a
# ranked timeline (graph-distance + temporal proximity + risk overlap)
# of every alert that shares an entity with the case's seed alert,
# plus the side-by-side entity graph the right column renders.
api_router.include_router(attack_chain.router)
api_router.include_router(connectors.router)
# Hosted OAuth one-click for connectors (Workstream 2 of AI Stack plan).
# /oauth/start mints a state nonce + 302 to the provider; /oauth/callback
# swaps the code, encrypts tokens via the credential vault, and lands the
# operator back on /onboarding.
api_router.include_router(oauth.router)
api_router.include_router(tenants.router)
api_router.include_router(detection_rules.router)
# Frontend-shape facade: /api/v1/detection/rules + /api/v1/detection/test
api_router.include_router(detection_compat.router)
api_router.include_router(detection_proposals.router)
# Detection rule tuning workbench — PR-6 (W8) v1.5 console plan.
# /detection/tuning projects every rule into actionable suggestions
# (disable / suppress / raise_threshold / tune_confidence / review_stale)
# scored from rule.fp_rate + total_hits + confidence + last_triggered.
# Mutations stamp suppression_config and write detection.tuning.* audit log.
api_router.include_router(rule_tuning.router)
api_router.include_router(federated.router)
api_router.include_router(graph.router)
api_router.include_router(playbooks.router)
api_router.include_router(plugins.router)
api_router.include_router(community.router)
api_router.include_router(marketplace.router)
api_router.include_router(rbac.router)
api_router.include_router(audit.router)
api_router.include_router(compliance.router)
api_router.include_router(metrics.router)
# Pipeline health snapshot — v1.5 SOC Console parity.
# /health/pipeline returns the 5-stage ingest→normalize→fuse→correlate→alert
# strip with {backlog, p95_latency_ms, error_rate, status} per row, sharing
# the PipelineHealth schema declared in endpoints/metrics.py so the funnel
# and pipeline-health widgets on /dashboard speak the same language.
api_router.include_router(health.router)
# SOC Insights aggregator (T3.1 — v8.0 parallel team plan).
# Backs apps/web/src/app/(app)/dashboards/soc-insights/page.tsx with a
# single deterministic payload (7 tiles + sparklines + delta vs the
# preceding window) so the dashboard can render in one round trip.
api_router.include_router(insights.router)
api_router.include_router(sla.router)
api_router.include_router(investigations.router)
# Effective permissions resolver (T3.2 — v8.0 parallel team plan).
# Resolves "what can principal X actually do?" across AWS / Azure / GCP /
# Okta / Google Workspace and caches the result as :EFFECTIVE_PERMISSION
# edges in Neo4j. Backs apps/web/src/app/(app)/identity/permissions.
api_router.include_router(effective_permissions.router)

# Cost dashboard — WS-H1 (buyer-value plan).
# Aggregates LLM spend / token volume from aisoc_run_costs joined with
# investigation_runs, plus action counts from audit_log and BYOK savings
# imputed from public list pricing. Backs apps/web/src/app/(admin)/costs.
api_router.include_router(costs.router)

# Mobile responder PWA (Phase 4B)
api_router.include_router(push.router)
api_router.include_router(oncall.router)
api_router.include_router(approvals.router)
api_router.include_router(passkeys.router)

# Per-user saved views — WS-F3 (analyst quality-of-life).
# Backs the saved-views menu on Alerts/Cases/Investigations/Playbooks
# list pages. Per-user-per-tenant CRUD; tenant scoping via RLS, user
# scoping in the API layer (every query filters on user_id).
api_router.include_router(saved_views.router)

# Wave 3 — operational maturity
api_router.include_router(assets.router)
api_router.include_router(mssp.router)
api_router.include_router(insider_threat.router)
api_router.include_router(remediation.router)

# Analyst feedback loop
api_router.include_router(feedback.router)

# Configurable autonomy guardrails — three-tier per-action confidence (Tier 1.3)
api_router.include_router(autonomy_policy.router)

# Business Context Rules — Track 3, T3.5 (v8.0 parallel team plan).
# YAML rule engine that mutates fused alerts (severity bump, route, suppress,
# tag) before they reach the triage agent. Backs the
# /settings/business-context Monaco editor with a dry-run preview API.
api_router.include_router(business_context.router)

# NL detection authoring (Tier 2)
api_router.include_router(nl_detection.router)

# Closed-loop detection engineering: FP → LLM Sigma draft → DAC proposal (Tier 2)
api_router.include_router(detection_loop.router)

# Natural-language query → ES|QL / SPL / KQL translation + execution (Tier 2)
api_router.include_router(nl_query.router)

# Identity-centric investigation timeline (Tier 2)
api_router.include_router(identity_timeline.router)

# Cross-platform detection rule translation: Sigma↔SPL↔KQL↔UDM↔ES|QL (Tier 2)
api_router.include_router(translation.router)

# Hypothesis-driven hunt workbench (Tier 2)
api_router.include_router(hunts.router)

# Saved natural-language hunts — Track 3, T3.4 (`/hunt` NL surface).
# Backs the "Saved hunts" sidebar on the /hunt page. Stores the analyst's
# plain-English question + translator output, optionally on a cron. Tenant-
# shared (every analyst in the tenant sees every saved hunt). Distinct from
# /hunts (above), which is the heavyweight detection-engineer hunt workbench.
api_router.include_router(saved_hunts.router)

# Email-security + phishing-triage workflow (Tier 3)
api_router.include_router(phishing.router)

# Knowledge-base + RAG over org docs/runbooks (Tier 3)
api_router.include_router(knowledge_base.router)

# Wave 4 — advanced capabilities
api_router.include_router(threat_intel.router)
api_router.include_router(posture.router)
api_router.include_router(easm.router)
api_router.include_router(identity_graph.router)
api_router.include_router(reports.router)

# Air-gap status snapshot for operators — Tier 3.1 (air-gapped certification)
api_router.include_router(airgap.router)

# LLM provider visibility for the "Deployment & AI" Settings panel.
# Mirrors /airgap/status: read-only env-var snapshot, never returns the
# API key itself. Same code path the egress gate uses, so the indicator
# in the UI cannot drift from runtime behaviour (WS-H2/H4 visibility).
api_router.include_router(llm_status.router)

# BYOK per-tenant LLM credentials — WS-H2 (buyer-value plan).
# Settings-write CRUD over tenant_llm_credentials. The plaintext API key
# is encrypted via the credential vault before it touches Postgres; the
# read path returns has_api_key/last_rotated_at but never the key itself.
# Resolution order at request time is per-tenant row > env-var fallback
# (see llm_status.py + agents/explain.py).
api_router.include_router(llm_credentials.router)

# STIX/TAXII threat intelligence publishing (Tier 4)
api_router.include_router(stix_taxii.router)

# Shift handoff and SOC analyst scheduling
api_router.include_router(shifts.router)

# Deployment configuration and air-gap bundle management
api_router.include_router(deployment.router)

# Fusion gateway: proxies to services/fusion when FUSION_URL is set, otherwise
# returns graceful empty payloads so the analyst console renders cleanly.
api_router.include_router(fusion.router)

# Agent-facing tool surface (Workstream 4 of AI Stack plan).
# /agents/tools returns the tenant-scoped, downscope-filtered list of
# (connector instance × capability) pairs the agent layer is allowed to
# invoke. Read-only — actual invocation lives in the agents service.
api_router.include_router(agents.router)

# Universal capture push paths (Workstream 6 of AI Stack plan).
# /inbox/templates + /inbox/tokens manage the per-tenant rotatable inbox
# URLs the wizard's "Push (any vendor)" card hands out. Vendor traffic
# itself terminates at services/ingest, which resolves the token to a
# tenant + template_id and reuses the existing OCSF normalizer.
api_router.include_router(inbox.router)

# Bidirectional ITSM webhook receiver (Workstream 8 of AI Stack plan).
# /inbox/itsm/{tenant_token}/{connector_instance_id} accepts inbound
# Jira / ServiceNow webhooks, resolves the external ticket back to its
# AiSOC case via case_external_refs, and mirrors the status onto
# aisoc_cases. This is the *inbound* counterpart to case_fanout (which
# handles outbound AiSOC → ITSM projection) and is what makes the
# operator's existing ITSM the source of truth for case status.
api_router.include_router(inbox_itsm.router)

# Tenant lake API (Workstream 7 of AI Stack plan).
# /lake/sql executes a tenant-scoped SELECT against the warm tier
# (ClickHouse) after passing through the SQL rewriter, which enforces a
# table allowlist, injects tenant_id predicates, clamps LIMIT, and
# rejects DML/DDL/table-valued functions. /lake/schema returns the
# allowlisted table catalog so operators (and LLM agents) can author
# queries without column-name guesswork.
api_router.include_router(lake.router)

# Managed-instance onboarding — T6.1 (`tryaisoc.com` beta).
# /waitlist exposes the public signup + admin entries CRUD that feeds
# the sales funnel; /admin/tenants promotes approved entries into live
# tenants. Admin endpoints gate on `admin:waitlist` / `admin:tenants`
# (falling back to `settings:write` for tenants whose RBAC rows have
# not been migrated to the granular admin scope yet).
api_router.include_router(waitlist.router)
api_router.include_router(tenant_provision.router)

# Public-facing graph-update WebSocket proxy — T1.4 (v8.0 parallel team plan).
# /graph_ws/stream authenticates the browser's session token, rebinds the
# tenant_id from the resolved user, and proxies to the internal ingest
# broadcaster (AISOC_INGEST_GRAPH_WS_URL). Backs the RealtimeGraph
# Cytoscape view; gates on graph:read.
api_router.include_router(graph_ws.router)
