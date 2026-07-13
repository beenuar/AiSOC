# Claim-to-Gate Matrix

Every marketing/capability claim in `README.md` mapped to the CI job that proves it, or `NO GATE`.

Rule (enforced from Phase 2 onward by `scripts/check_claim_gate_matrix.py`, wired into `.github/workflows/security.yml`): **no row may say `NO GATE`.** A `NO GATE` row is either a claim to delete or a gate to build. Rows marked `PARTIAL` name the gap that a later phase closes.

Statuses: `GATED` (a CI job fails when the claim stops being true) · `PARTIAL` (some aspect gated, gap named) · `NO GATE` (unproven).

| Claim | Source | Gate (workflow :: job) | Status | Closes in |
|---|---|---|---|---|
| Offline sandbox demo runs with no key/network in < 5 s | README L38 | `readme-gates.yml :: sandbox-offline` (ubuntu+macos matrix) | GATED | - |
| `pnpm aisoc:demo` boots the real stack | README L40, L45 | `compose-smoke.yml` (cold health) + `integration.yml :: spine` (Phase A3 — default `docker compose up` ships connectors + graph-at-ingest by default; asserts cold-boot → ingest → lake + detection engine → alert row with the spine test's measured raw-event→alert latency) | GATED | - |
| 69 connectors | README L116, L168 | `ci.yml :: python-lint` (`generate_connector_count.py --check`) | GATED (count) | - |
| Connectors: schema-driven config + vault-encrypted secrets | README L168 | `ci.yml` connectors matrix (`test_schemas.py` + `test_conformance.py` — secret-shaped fields must be `type=secret`); vault tests | PARTIAL (schema + vault + secret-field-marking + runtime-contract conformance gated; live-vendor API smoke, rate-limit, checkpoint durability deferred) | Phase 10b |
| Connectors: live Test connection | README L168 | `ci.yml` connectors matrix (`test_conformance.py` — every connector implements the async `test_connection` contract) + `connector_conformance.py --check` published matrix | PARTIAL (contract conformance gated; live-vendor sandbox smoke deferred) | Phase 10b |
| Investigation Ledger stores every step | README L61, L169 | `ci.yml :: api tests` (`audit_hash`, audit immutability) | PARTIAL (write path gated; UI replay only in hermetic e2e) | Phase 3.2 |
| Public eval harness gates every PR | README L62, L77 | `ci.yml :: p1-eval` | GATED (but suites are self-consistency; see reality report) | Phase 4 |
| Alert-reduction is a real measurement | README L62 | `ci.yml :: p1-eval` (`alert_reduction`) | PARTIAL (gates an in-test fusion re-impl, not `services/fusion`) | Phase 4 |
| Runs entirely on your infrastructure / no data exfiltration | README L63 | `ci.yml :: python-test` (agents) runs `test_privacy_redactor.py` (zero raw PII survives) | PARTIAL (redaction gated + README made precise per mode; air-gapped egress-blocked CI + Helm NetworkPolicy in continuation/Phase 2) | Phase 2 |
| Detection-as-Code rejects candidates that regress MITRE accuracy | README L170 | `ci.yml :: python-test` (`test_detection_eval.py` — candidate `rule_body` run through the real engine vs its own positive/negative fixtures; approval requires it) + `p1-eval` w2-dac baseline | GATED | - |
| 800+ native detection rules | README L78, L170 | `validate-detections.yml` (strict fixture replay) | GATED | - |
| 6000+ imported detection rules | README L78 | `validate-detections.yml` (parse/provenance + `detection_truth_table.py --check`); README cites the executable figure (939) not the on-disk figure for coverage | GATED | - |
| L0-L4 automation maturity gates every action | README L171 | `ci.yml` autonomy-policy drift test + `test_autonomy_safety.py` (dry-run-default, rollback-capability contract, verification-mandate, scorecard) | PARTIAL (thresholds + dry-run-default + rollback-capability + verification-mandate gated at the policy layer; live-router wiring of `decide()` into `/dispatch` is 9b) | Phase 9b |
| Hunt-as-Code + `/hunt` | README L172 | `ci.yml :: p1-eval` (`hunt_corpus`) | GATED | - |
| Weekly benchmark scoreboard runs live against `main` | README L173 | `wet-eval.yml` (weekly) | NO GATE (no-ops without secret; live-agent tables are placeholders) | Phase 4 Tier 1 |
| MCP server exposes 13 tools | README L179 | `ci.yml :: mcp` | GATED | - |
| Plugin SDK Python/TS/Go | README L79, L193 | `ci.yml :: sdk-*` | PARTIAL (build/test gated; OpenAPI breaking-change now gated via `openapi-breaking.yml`, so a spec change that would break the generated SDKs is caught; per-language generated-client contract-drift is 11b) | Phase 11b |
| Prompt-injection resistance | (implied by agent claims) | `ci.yml :: python-test` (agents) runs `test_prompt_sanitizer.py` + `test_prompt_envelope.py` | PARTIAL (unit-level nonce envelope + guard gated; 150-payload adversarial eval + tool-call provenance in Phase 4 Tier 2) | Phase 4 |
| Cross-tenant isolation (Postgres) | (implied by multi-tenant) | `cross-tenant-rbac.yml` (nightly, 3 endpoints) + `ci.yml` | PARTIAL (Postgres only, compiled-SQL not live DB) | Phase 1.3 |
| Cross-tenant isolation (Qdrant/Neo4j/Redis/ClickHouse/Kafka) | (implied by multi-tenant) | `isolation.yml` (offline: read paths construct a tenant scope) + `isolation-live.yml` (live A-vs-B replay: Neo4j property filter, Redis keyspace namespacing, ClickHouse via production `lake_sql.rewrite_for_tenant`, Kafka per-tenant envelope filter) | GATED | - |
| SAST | README badge (CodeQL) | `codeql.yml` | GATED | - |
| Dependency CVE scanning | (implied by security) | `security-audit.yml` | GATED | - |
| OpenSSF Scorecard | README badge L13 | `scorecard.yml` | GATED | - |
| Container image / IaC / secret scanning (Trivy/checkov/tfsec/gitleaks/Semgrep) | (implied by security) | `security.yml` (claim-matrix ratchet HARD; gitleaks/Semgrep/Trivy/checkov/tfsec observe) | PARTIAL (matrix ratchet enforced; secret + code/IaC/container scanners report-and-ratchet, allowlist at `.security/allowlist.yml` / `.gitleaksignore`; GitHub push-protection is the always-on hard secret gate) | Phase 2 |
| Signed / attested release artifacts | (implied by "run next to crown jewels") | `release.yml` + `publish-images.yml` (cosign keyless signatures, CycloneDX SBOM attestation, BuildKit SLSA provenance + SPDX SBOM per image; SHA-pinned actions), `build-extensions.yml` (extension cosign) | GATED | - |
| Insecure defaults hard-fail in production | (implied by self-host) | `ci.yml` api tests (`test_security_defaults.py::test_enforce_*`; `enforce_secure_defaults` raises at boot in production) | GATED | - |
| OpenAPI stability for 3 SDKs + MCP | (implied by SDKs) | `check-openapi.yml` (drift) + `openapi-breaking.yml` (`scripts/openapi_diff.py` — PR spec vs base fails on removed endpoint/schema/field, type change, tightened request, or dropped enum value) | GATED | - |
| Ingested events land in the queryable ClickHouse lake | README (SIEM / lake) | `integration.yml :: spine` (Phase A1 — after the spine ingests, asserts `SELECT count() FROM aisoc.raw_events > 0` against the live ClickHouse container; `services/fusion` `LakeWriter` archives every normalized event) | GATED | - |
| Detection rules fire on the live event stream (not just CI fixtures) | README L170 (detection engine) | `integration.yml :: spine` (Phase A2 — posts an event matching the native `aws-root-account-login` rule, asserts the fusion `DetectionEngine` produces the alert) + `validate-detections.yml` (exported-ruleset drift `--check`) + fusion `test_detection_engine.py` / `test_detection_matcher_parity.py` | GATED | - |
| Three-model AI: behavioral (UEBA) model feeds alert scoring in production | README (multi-model) | `ci.yml` fusion job (`test_ueba_signal.py` — the `ueba.anomalies` stream warms a per-entity cache that boosts fuse-time confidence + anomaly score; wired in `fusion_engine.process`) | GATED | - |
| Agent auto-triages every alert (not manual/API-only) | README (autonomous triage) | `ci.yml` agents job (`test_fused_alert_worker.py` — `FusedAlertTriageWorker` consumes `aisoc.alerts.fused`, auto-triages each alert copilot/read-only with cost-governor dedup + circuit-breaker, degrades to deterministic triage without an LLM key, never dispatches a response) | GATED | - |
| Connector credentials reach the SOAR executors (not simulation-only) + autonomy policy governs every real execution | README (SOAR / response) | `ci.yml` actions job (`test_credential_resolver.py` — per-vendor auth_config→executor-param translation pinned; `test_governed_dispatch.py` — Phase 9a `decide()` wired into live dispatch: above-tier ⇒ dry-run preview, dry-run-disabled ⇒ queued approval, L0 ⇒ blocked, executor never invoked when queued/blocked) | GATED | - |
| Rollback is real (not "return True"), post-action verified, and approvals are restart-durable | README (response / rollback) | `ci.yml` actions job (`test_rollback.py` — real vendor reverse calls, honest simulated/failed states, REVERSIBLE_ACTIONS gated against the actual reverse impls; `test_verification.py` — re-queries vendor, never a false VERIFIED) + slack-bot job (`test_timer_store.py` — pending SLA timers persist + recover across restart) | GATED | - |
| Environment-specific noise reduction (business context) applied post-fusion → pre-triage | README (noise reduction) | `ci.yml` agents job (`test_business_context_hotpath.py` — YAML when/then rules mutate severity/route/tags and suppress before any triage spend, wired into `FusedAlertTriageWorker.triage`; `AISOC_BUSINESS_CONTEXT_ENABLED` gate) | GATED | - |
| Related alerts auto-collapse into one ordered attack chain at fuse time | README (attack chains) | `ci.yml` fusion job (`test_attack_chain_grouper.py` — shared-entity alerts join one chain within the window, members ordered by MITRE kill-chain stage, cross-entity link via shared IP; wired into `fusion_engine.process` → `enrichments.attack_chain`) | GATED | - |
| Effective Permissions resolves against a live posture snapshot (not empty stub) | README (effective permissions) | `ci.yml` api job (`test_posture_loader.py` — assembles the Okta resolver snapshot from connector `get_resource_config` calls and resolves it; cloud providers consume a connector-provided reconciled snapshot; failures degrade to empty, never fabricated) + connectors `/connectors/{id}/resource_config` endpoint | GATED | - |
| Unified Data Explorer (NL + SQL across the lake) replaces the SIEM context-switch | README (data explorer) | `ci.yml` web-test job (`ExploreView.test.tsx` — NL question → `nl-query/translate` → `lake/sql` → BI table; raw-SQL run; source pivots to identity/graph/intel; error surfaced) + web-lint type-check | GATED | - |

## Summary

- GATED: 26
- PARTIAL: 10
- NO GATE: 1 (progressively closed through Phases 2–11 and A1–A4: insecure-defaults, secret/IaC scanning, signed releases, cross-store isolation, DAC candidate-rule + imported-count honesty, connector live-test, OpenAPI breaking-change, ClickHouse lake population (A1), live-stream detection (A2), default cold-boot stack (A3), and the behavioral-model fusion (A4). The **last** NO GATE row — wet-eval live-agent scoreboard tables — closes in Phase 4c/E1, which needs a budgeted live-agent run)

The ratchet is enforced by `scripts/check_claim_gate_matrix.py` (wired into `security.yml`): the NO GATE count may only decrease.

The Definition of Done requires zero `NO GATE` and zero unclosed `PARTIAL`. Each row's "Closes in" column is the binding commitment.
