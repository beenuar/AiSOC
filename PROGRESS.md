# AiSOC v6 Capability Roadmap — Implementation Progress

Tracking against `/Users/beenu/.cursor/plans/aisoc_capability_roadmap_7d918072.plan.md`.
This file is for local resume only and is gitignored.

## Session — 2026-05-05
- Web `tsc`: fixed `ThreatIntelView` (severity `info`, typed configs, optional `description`/`tags`/dates), added `src/cytoscape-fcose.d.ts`, fixed `MarketplaceView.test.tsx` fetch mock typing. `pnpm --filter @aisoc/web type-check` green; marketplace Vitest file passes (act warnings unchanged).
- Open GitHub PRs are mostly Dependabot (deps); merge after CI review, not bulk-closed from here.
- SEO: expanded `DISCOVERY_KEYWORDS` in `apps/web/src/lib/site.ts` for tryaisoc.com / self-host discovery.
- SLA dashboard: 2026 KPI bar table + breach badges + `EditKpiBarModal` → `PUT /api/v1/sla/kpi-targets` (`apps/web/src/components/sla/SLADashboard.tsx`). Web `tsc --noEmit` green.

## Wave 1 — close 2026 table-stakes
- [x] w1-rba: Risk-Based Alerting + entity rollup (engine, API, UI, KPI test ≥50:1, docs)
- [x] w1-confidence: Detection confidence + explainability surface (scorer w/ feature flag, API, FusionEngine integration, AlertDetailView + AlertsView UI, 13 unit tests)
- [x] w1-chatops: ChatOps user verification (Slack/Teams) — `services/actions` executor + token + API callback
- [x] w1-drift: Detection drift monitoring — `services/purple-team` scheduler + drift services + migration
- [x] w1-kpi-bar: 2026 KPI bar in SLA dashboard (API + `SLADashboard` UI + edit targets)

## Wave 2 — eval-graded differentiation
- [x] w2-dac: Detection-as-code lifecycle gated by run_evals.py
  - `services/api/migrations/010_detection_as_code.sql` — `detection_rule_proposals` + `detection_eval_baselines` tables w/ RLS + touch trigger
  - `services/api/app/models/detection_proposal.py` — ORM models (proposal lifecycle + eval baseline snapshots)
  - `services/api/app/api/v1/endpoints/detection_proposals.py` — propose / comment / attach-eval / decide / promote + baselines (router prefix `/detection-proposals`)
  - `scripts/run_evals.py` — `--baseline` + `--max-regression-pp` flags; exit-code 2 on ≥1pp MITRE drop (Wave 2 — w2-dac)
  - `.github/workflows/ci.yml` p1-eval — pulls last published baseline from `eval-results` branch on PRs and gates merges
  - `apps/web/src/lib/api.ts` — `detectionProposalsApi` client + `DetectionProposal*` types
  - `apps/web/src/components/detections/DetectionProposalsView.tsx` + `apps/web/src/app/(app)/detection/proposals/page.tsx` — operator queue (filter / approve / reject / promote, MITRE delta + gate verdict)
  - `apps/web/src/components/detections/DetectionsView.tsx` — header `Proposals` link
- [x] w2-hac: Hunt-as-code corpus + continuous scheduler
  - `services/api/migrations/011_hunt_as_code.sql` — `hunt_hypotheses` / `hunt_runs` / `hunt_findings` w/ RLS + per-table touch triggers
  - `hunts/` corpus — 5 YAML hypotheses (svc-account-after-hours, dns-tunneling, cloud-iam, oauth-mass-consent, lolbin-rundll32)
  - `services/agents/app/hunt/loader.py` — `HuntCorpus` + `HuntDefinition`/`HuntIndicator` (operators: equals/in/regex/gte/lte/exists/contains_any/iendswith)
  - `services/agents/app/hunt/engine.py` — stateless `HuntEngine` matcher, `HuntFindingDraft` / `HuntRunResult`
  - `services/agents/app/hunt/store.py` — asyncpg `HuntStore` (sync_catalog, record_run, record_finding) mirroring `investigator/ledger.py`
  - `services/agents/app/hunt/scheduler.py` — APScheduler-driven continuous runs; honours `HUNT_TELEMETRY_PROVIDER`
  - `services/agents/app/api/hunts.py` — list / get / run / findings router; wired into `main.py` lifespan
  - `services/agents/tests/eval_data/synthetic_hunt_telemetry.jsonl` — dedicated hunt-grade corpus (positives + negatives per hunt)
  - `services/agents/tests/test_hunt_corpus.py` — eval gate: 5 tests, 15 subtests; positives fire, negatives don't, telemetry fully owned
- [x] w2-benchmark: Public benchmark scoreboard at tryaisoc.com/benchmark
  - `apps/web/src/components/benchmark/BenchmarkResults.tsx` — `fetchLatestEvalReport()` ISR fetch from `eval-results/eval/results/latest.json` w/ snapshot fallback + `_stale`/`_source` flags
  - `apps/web/src/components/benchmark/KpiBar.tsx` — derives alert-to-incident ratio from `alerts_in / incidents_out`; renders 4 KPI targets w/ live pass/fail
  - `apps/web/src/components/benchmark/CommunitySubmissions.tsx` — submission rules + linked GitHub issue template + empty-state leaderboard
  - `apps/web/src/app/benchmark/page.tsx` — `async` page renders live-from-main badge, KPI bar, BenchmarkResults, dynamic per-suite headlines, reproduce snippet from live data, CommunitySubmissions
  - `.github/ISSUE_TEMPLATE/benchmark_submission.yml` — structured intake (agent name/url, commit, command, report.json, confirmations)
  - CI `p1-eval` already publishes `eval/results/<sha>.json` + `eval/results/latest.json` to `eval-results` branch on every push to main
- [x] w2-aivai: AI-vs-AI adversary eval (sixth suite)
  - `scripts/generate_adversary_incidents.py` — deterministic attacker-LLM mutator (synonym swap + leetspeak + zero-width injection + fragmentation) across heavy/medium/light buckets w/ grammar guard against defender-keyword leaks
  - `services/agents/tests/eval_data/adversary_incidents.json` — 200 mutated incidents (deterministic, seedable)
  - `services/agents/tests/test_adversary_eval.py` — graceful-degradation gate (overall ≥0.40, light ≥0.85, heavy ≤0.50)
  - `scripts/run_evals.py` — wired in as sixth suite (`adversary_eval`)

## Wave 3 — operational maturity
- [x] w3-fed: Federated search across SIEMs
  - `services/connectors/app/federated/query.py` — `UnifiedQuery` dataclass (free-text + structured indicators + since/limit) shared by all backends
  - `services/connectors/app/federated/translators/` — pure `to_spl` / `to_kql` / `to_esql` translators (Splunk SPL, Sentinel KQL, Elastic ES|QL); honours operator semantics (equals/in/regex/contains_any/gte/lte) without leaking values into logs
  - `services/connectors/app/connectors/base.py` — added `supports_federated_search` flag + optional async `query()` on `BaseConnector`
  - `services/connectors/app/connectors/splunk.py` — `query()` opts in, executes a Splunk search-job round-trip and normalises rows
  - `services/connectors/app/connectors/microsoft_sentinel.py` — `query()` opts in via Log Analytics REST (KQL)
  - `services/connectors/app/connectors/elastic.py` — new `ElasticConnector` (registered in `__init__.py`) with ES|QL `_query` POST + row-flattening fallback
  - `services/connectors/app/api/router.py` — `POST /api/v1/connectors/{id}/query` endpoint; 501 when connector class hasn't opted in
  - `services/connectors/tests/test_federated.py` — 14 tests pinning translator output shapes + `BaseConnector.query` behaviour
  - `services/api/app/api/v1/endpoints/federated.py` — `GET /api/v1/federated/backends` + `POST /api/v1/federated/search`; decrypts creds via vault, fans out to enabled SIEM connectors with bounded `httpx.AsyncClient`, merges rows w/ `_aisoc_source` provenance, never raises on a single backend failure (per-source verdict). Audits to `audit_logs` w/ `metadata_["indicator_fields"]` only — values are tenant-shared and stay out of the audit row.
  - `services/api/app/core/config.py` — `AISOC_FEATURE_FED_SEARCH` flag (default on); `_ensure_feature_enabled()` returns 404 when off so the route is invisible
  - `services/api/app/api/v1/router.py` — `federated.router` included
  - `services/api/tests/test_federated_endpoint.py` — 17 tests pinning the proxy/merge layer (decrypt failure, network failure, 4xx/5xx/501, row tagging, non-dict row coercion, audit-row PII guard)
- [x] w3-mssp: MSSP / parent-tenant console
  - `services/api/migrations/012_mssp_console.sql` — `mssp_tenant_notes`, `mssp_delegations`, `mssp_tenant_metrics` tables; `is_mssp_parent` flag on tenants
  - `services/api/app/models/mssp.py` — ORM: `MSSPTenantNote`, `MSSPDelegation`, `MSSPTenantMetrics`
  - `services/api/app/api/v1/endpoints/mssp.py` — list child tenants, onboard, notes CRUD, delegation management, rollup metrics
- [x] w3-asset: Asset inventory + vuln-to-alert correlation
  - `services/api/migrations/013_asset_inventory.sql` — `assets`, `asset_vulnerabilities`, `alert_asset_correlations` tables
  - `services/api/app/models/asset.py` — ORM: `Asset`, `AssetVulnerability`, `AlertAssetCorrelation`
  - `services/api/app/api/v1/endpoints/assets.py` — assets CRUD, vulnerability management, alert correlation
- [x] w3-insider: Insider-threat module
  - `services/api/migrations/014_insider_threat.sql` — `user_risk_profiles`, `insider_indicators`, `insider_peer_groups` tables
  - `services/api/app/models/insider_threat.py` — ORM: `UserRiskProfile`, `InsiderIndicator`, `InsiderPeerGroup`
  - `services/api/app/api/v1/endpoints/insider_threat.py` — risk profiles, indicators, watchlist, peer groups
- [x] w3-maturity: L0–L4 auto-remediation maturity tiers
  - `services/api/migrations/015_remediation_maturity.sql` — `remediation_maturity`, `remediation_gate_log`, `remediation_whitelist` tables
  - `services/actions/app/services/maturity.py` — `evaluate_gate()` core logic: tier-based decision + blast-radius check + whitelist bypass
  - `services/api/app/models/remediation.py` — ORM: `RemediationMaturity`, `RemediationGateLog`, `RemediationWhitelist`
  - `services/api/app/api/v1/endpoints/remediation.py` — config get/put, gate-log, whitelist CRUD

## Wave 4 — strategic moat
- [x] w4-int-ti: Internal threat-intel generation
  - `services/api/migrations/016_threat_intel.sql` — `threat_intel_iocs`, `threat_actors`, `threat_intel_feeds` tables
  - `services/api/app/models/threat_intel.py` — ORM: `ThreatIntelIOC`, `ThreatActor`, `ThreatIntelFeed`
  - `services/api/app/api/v1/endpoints/threat_intel.py` — IOC CRUD, actor management, feed subscriptions
- [x] w4-cspm: Cloud security posture (CSPM/KSPM)
  - `services/api/migrations/017_cspm.sql` — `posture_findings`, `posture_scan_runs`, `posture_drift_events` tables
  - `services/api/app/models/posture.py` — ORM: `PostureFinding`, `PostureScanRun`, `PostureDriftEvent`
  - `services/api/app/api/v1/endpoints/posture.py` — findings CRUD + suppress/resolve actions + summary stats + scan run history
- [x] w4-idgraph: Identity-centric correlation graph
  - `services/api/migrations/018_identity_graph.sql` — `identity_nodes`, `identity_edges`, `alert_identity_links` tables
  - `services/api/app/models/identity_graph.py` — ORM: `IdentityNode`, `IdentityEdge`, `AlertIdentityLink`
  - `services/api/app/api/v1/endpoints/identity_graph.py` — node/edge CRUD, per-node edge traversal, alert-identity linking
- [x] w4-boardrpt: Auto-generated board reports
  - `services/api/migrations/019_board_reports.sql` — `report_templates`, `report_artefacts` tables
  - `services/api/app/models/report.py` — ORM: `ReportTemplate`, `ReportArtefact`
  - `services/api/app/api/v1/endpoints/reports.py` — template management, async report generation, artefact retrieval

## 2026 H2 Roadmap — Tier 1: Agent Intelligence
- [x] t1-memory: Three-tier agent memory (session/working/institutional)
  - `services/agents/app/memory/models.py` — `MemoryEntry`, `MemoryTier`, `OverrideFeedback` Pydantic models
  - `services/agents/app/memory/session.py` — in-process LRU (bounded 512 entries, asyncio-safe)
  - `services/agents/app/memory/working.py` — Redis-backed with 24 h TTL + in-process fallback
  - `services/agents/app/memory/institutional.py` — PostgreSQL-backed permanent store with tag index + pgvector-ready schema
  - `services/agents/app/memory/manager.py` — `MemoryManager` unified API (write/recall/delete/search/ingest_override)
- [x] t1-autonomy: Autonomy guardrails (per-action confidence thresholds)
  - `services/agents/app/policy/guardrails.py` — `GuardrailPolicy` + `ActionResult`; default thresholds for 20 actions; DB-backed tenant overrides from `aisoc_autonomy_thresholds`
  - `services/agents/app/policy/__init__.py` — module exports
- [x] t1-cost: Investigation cost telemetry
  - `services/agents/app/core/cost_telemetry.py` — `CostTracker` context manager; per-model pricing table; `aisoc_run_costs` DB persistence; structlog events
  - `services/agents/app/investigator/orchestrator.py` — wraps `invoke()` and `stream()` with `CostTracker`; threads `cost_summary` into `InvestigatorState`
  - `services/api/app/api/v1/endpoints/investigations.py` — `RunDetail.model_costs` (per-run breakdown via `_fetch_model_costs`); new `GET /investigations/costs/aggregate` endpoint with `GROUPING SETS` for per-model + grand-total rollup; tenant-scoped via JOIN on `investigation_runs.tenant_id` (UUID, not the agents-side tenant slug)
  - `apps/web/src/lib/api.ts` — `LedgerModelCost`, `LedgerRunDetail.model_costs`
  - `apps/web/src/components/dashboard/SOCMetricsDashboard.tsx` — `CostTelemetryPanel` (window selector, KPIs, per-model table)
  - `apps/web/src/components/cases/InvestigationLedger.tsx` — `ModelCostsCard` + companion `useSWR` hook on `ledger.run` keyed to `resolvedRunId`; refreshes every 4 s while live so the breakdown materializes as soon as `_flush_to_db` lands
- [x] t1-metrics-ui: SOC metrics dashboard (MTTD/MTTR/FPR/ATT&CK heatmap)
  - `services/api/app/api/v1/endpoints/metrics.py` — `GET /soc` endpoint returning `SOCMetrics` (KPIs + heatmap)
  - `apps/web/src/components/dashboard/SOCMetricsDashboard.tsx` — React component with KPI cards + ATT&CK heatmap, auto-refresh every 60 s
- [x] t1-override: Analyst-override feedback loop feeding institutional memory
  - `services/api/app/api/v1/endpoints/feedback.py` — `POST /feedback/alert-override` + `GET /feedback/summary`
  - `services/api/app/models/alert.py` — added `disposition` + `first_seen_at` columns
  - `services/api/migrations/020_soc_metrics_h2.sql` — schema migration for all H2 tables

## 2026 H2 Roadmap — Tier 2: Detection Intelligence
- [x] t2-nl-detection: NL detection authoring + cross-platform translation
  - `services/api/app/api/v1/endpoints/nl_detection.py` — `POST /nl-detection/translate` (Sigma/KQL/SPL/ES|QL); LLM-powered with template fallback
- [x] t2-detection-loop: Closed-loop detection engineering (FP → LLM-drafted Sigma PR → DAC proposal)
  - `services/api/app/api/v1/endpoints/detection_loop.py` — `POST /detection-loop/suggest` (alert ID + analyst note → Sigma fix draft + auto DAC proposal); `GET /detection-loop/suggestions`; LLM-powered with template fallback
- [x] t2-nl-query: Natural-language query → ES|QL/SPL/KQL translation + Elasticsearch execution
  - `services/api/app/api/v1/endpoints/nl_query.py` — `POST /nl-query/translate` (NL → ES|QL/SPL/KQL); `POST /nl-query/execute` (translate + live ES query execution with structured results); LLM-powered with template fallback
- [x] t2-identity: Identity-centric investigation timeline
  - `services/api/app/api/v1/endpoints/identity_timeline.py` — `POST /identity-timeline/build` (builds chronological event timeline anchored to user/device/IP); `GET /identity-timeline` (quick lookup); queries `aisoc_alerts` + `aisoc_events`, computes risk score

## 2026 H2 Roadmap — Tier 2: Detection Intelligence (continued)
- [x] t2-translation: Cross-platform detection rule translation (Sigma↔SPL↔KQL↔UDM↔ES|QL)
  - `services/api/app/api/v1/endpoints/translation.py` — `POST /translation/translate` (source + target format selection; LLM-powered with heuristic fallback; supports sigma/spl/kql/esql/yara-l2/udm)
  - `services/api/migrations/012_case_management.sql` — `aisoc_cases` + `aisoc_case_comments` tables (case management prerequisite)
  - Integrated into `services/api/app/api/v1/router.py`
- [x] t2-cases: First-class case management API
  - `services/api/app/api/v1/endpoints/cases.py` — full lifecycle CRUD (open/in-progress/escalated/resolved/closed), observable graph, evidence chain, comments, SLA tracking
- [x] t2-compliance: Compliance evidence trails
  - `services/api/migrations/013_compliance_evidence.sql` — `aisoc_compliance_evidence` table with hash-chain integrity
  - `services/api/app/api/v1/endpoints/compliance.py` — audit-grade evidence records; supports SOC2/PCI-DSS/HIPAA/ISO27001/NIST-CSF framework tags
- [x] t2-hunting: Hypothesis-driven hunt workbench
  - `services/api/migrations/014_hunt_workbench.sql` — `aisoc_hunts` + `aisoc_hunt_runs` tables
  - `services/api/app/api/v1/endpoints/hunts.py` — define hypothesis → LLM auto-generates ES|QL/SPL/KQL queries → track findings per run

## 2026 H2 Roadmap — Tier 3: Advanced Analyst Workflows
- [x] t3-phishing: Email-security + phishing-triage workflow
  - `services/api/migrations/015_phishing_triage.sql` — `aisoc_phishing_submissions` table with IOC and verdict fields
  - `services/api/app/api/v1/endpoints/phishing.py` — submit email/URL/attachment; LLM extracts IOCs, assigns verdict, maps MITRE; heuristic fallback; case linkage
- [x] t3-rag: Knowledge-base + RAG over org docs/runbooks
  - `services/api/migrations/016_knowledge_base.sql` — `aisoc_kb_documents` table with FTS index on content
  - `services/api/app/api/v1/endpoints/knowledge_base.py` — ingest + chunking + list/delete; `POST /kb/query` does full-text search + optional LLM answer synthesis with citation
- [x] cross-docs-ia: Docs site capabilities section
  - `apps/docs/docs/concepts/capabilities.md` — full index of Tier 1, 2, and 3 capabilities with API prefixes, detection rule format table, severity ladder, compliance frameworks, connector categories
- [x] cross-docs-readme: README + Hero updated
  - `README.md` — "What's in the box" section updated with cross-platform translation, hunting, phishing triage, and KB+RAG entries
  - `apps/web/src/components/landing/Hero.tsx` — hero paragraph updated to include new capabilities

## 2026 H2 Roadmap — Tier 3: Platform Expansion
- [x] tier3-airgap: Air-gapped certification (local LLM, zero-egress, no model phone-home)
- [x] tier3-mssp: MSSP multi-tenancy (tenant isolation + per-tenant detection scoping)
  - Migration `023_mssp_detection_scoping.sql` — `mssp_rule_packs`, `mssp_rule_pack_rules`, `mssp_rule_pack_assignments`, `mssp_rule_overrides` + `mssp_effective_tenant_rules` view
  - ORM models in `app/models/mssp.py` aligned to migration
  - `app/services/mssp_rule_resolver.py` — `resolve_effective_rules` + `count_effective_rules` (tenant + builtin + packs − overrides)
  - Wired resolver into `POST /api/v1/detection-rules/hunt`
  - Full CRUD API for rule packs, assignments, and per-tenant overrides in `app/api/v1/endpoints/mssp.py` (parent-only)
  - `services/api/app/core/config.py` — `AISOC_AIRGAPPED` (bool, default false) + `AISOC_AIRGAP_ALLOWLIST` (list[str])
- [x] tier3-byoc: BYOC deployment (Terraform + docs)
  - `infra/terraform/byoc/` — minimal EKS + RDS + ElastiCache starter
  - README with quick-start and security notes
- [x] tier3-vuln: Vuln↔alert correlation w/ exploit-in-wild boost
  - [x] Extend `FusedAlert` with `exploit_in_wild: bool` flag
  - [x] Create `vuln_boost.py` (`apply_vuln_boost`) that inspects enrichments for exploited CVEs
  - [x] Wire into `FusionEngine.process` after confidence scoring step
  - [x] Feature flag `AISOC_VULN_BOOST` (default true)

## 2026 H2 Roadmap — Tier 3: Platform Expansion (continued)
- [x] tier3-easm: EASM module (external attack surface inventory + drift detection)
  - [x] New `Asset` subtype `external` + `services/api/app/models/easm.py`
  - [x] Passive + active discovery connectors (Shodan/Censys + lightweight port scan)
    - `services/api/app/services/easm_discovery.py` — `_shodan_search`, `_censys_search`, `_active_scan`, `run_discovery` orchestrator
    - Config flags: `AISOC_FEATURE_EASM`, `AISOC_EASM_SHODAN_API_KEY`, `AISOC_EASM_CENSYS_API_ID/SECRET`, `AISOC_EASM_ACTIVE_SCAN_ENABLED`, `AISOC_EASM_SCAN_PORTS`
  - [x] Drift detection (new ports, new certs, new sub-domains) → alert generation
    - `services/api/app/services/easm_drift.py` — `detect_drift` upserts assets + emits `new_asset`/`new_port`/`gone_port` drift records
  - [x] `POST /api/v1/easm/scan` + `GET /api/v1/easm/assets` + `GET /api/v1/easm/drift`
    - Scan endpoint wired to background task running discovery + drift
  - [x] Migration `024_easm.sql` — `external_assets`, `external_asset_drift` tables w/ RLS
  - [x] `services/api/tests/test_easm.py` — 15 tests (discovery parsing, active scan, drift detection, orchestrator flags)

- [x] tier3-cloud-detections: Cloud-native detection content gap fill (Azure/GCP/M365)
  - [x] 20 new M365-native detections (det-cloud-192 – det-cloud-211)
    - Exchange Online: transport rule redirect, audit bypass, eDiscovery search, eDiscovery export, OAuth mailbox access
    - SharePoint: external sharing enabled at org/tenant level, site collection admin added, site admin external user
    - Teams: external access enabled, external domain added, app sideloading enabled
    - Defender for Office 365: Safe Attachments disabled, Safe Links disabled, anti-phishing weakened
    - Purview: DLP policy disabled, sensitivity label removed, retention policy deleted
    - Power Platform: DLP connector policy modified, flow shared externally
    - Entra ID: conditional access disabled, PIM global admin activated, cross-tenant policy changed
  - [x] 3 new Azure-native detections (det-cloud-212 – det-cloud-214)
    - Key Vault purge protection disabled, management group elevated access, Defender for Cloud plan disabled
  - [x] 4 new GCP-native detections (det-cloud-215 – det-cloud-218)
    - Org policy constraint removed, VPC firewall allow-all ingress, Cloud Armor policy removed, audit log sink deleted

- [x] cross-eval-expansion: Extend eval harness with per-feature suites (calibration, memory recall, override accuracy, autonomy adherence)
  - [x] `services/agents/tests/test_confidence_calibration.py` — Brier score + ECE gates for triage & investigation (pre-existing)
  - [x] `services/agents/tests/test_autonomy_guardrails.py` — autonomy policy adherence tests (pre-existing)
  - [x] `services/agents/tests/test_memory_recall.py` — 14 cases: fidelity, priority, isolation, session clearing, structured-value fidelity, override ingestion, institutional search-by-tag, missing-key, delete
  - [x] `services/agents/tests/test_override_accuracy.py` — 6 cases: ingestion fidelity, retrieval accuracy, multi-override consistency, idempotent upsert, cross-tenant isolation, verdict patterns
  - [x] `scripts/run_evals.py` wired: `memory_recall` + `override_accuracy` suites added to unified runner with floor gates

- [x] cross-content-velocity: Community detection PR template + contributor leaderboard
  - [x] `.github/PULL_REQUEST_TEMPLATE/detection_rule.md` — structured PR template for community-submitted detection rules (metadata table, contribution type, testing evidence, schema checklist)
  - [x] `.github/ISSUE_TEMPLATE/detection_rule_proposal.yml` — GitHub issue template for proposing detection rules before PR (category/severity/MITRE dropdowns, log source, FP scenarios)
  - [x] `apps/web/src/components/detections/ContributorLeaderboard.tsx` — sortable contributor leaderboard with badge tiers (platinum/gold/silver/bronze), category breakdown, contribute CTA
  - [x] `apps/web/src/components/detections/DetectionsView.tsx` — wired ContributorLeaderboard below detection rules list

- [x] ship-progress: All changes committed and pushed to GitHub
  - 118 files changed, 11,144 insertions(+), 217 deletions(-)
  - Commit pushed to `main` at `4a4741d`

## Cross-cutting commitments
- Every capability ships behind a feature flag (`services/api/app/core/config.py`).
- Every capability adds at least one eval-harness scenario.
- README.md and CHANGELOG.md updated at the end of each wave.
