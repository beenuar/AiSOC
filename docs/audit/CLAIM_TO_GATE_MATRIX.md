# Claim-to-Gate Matrix

Every marketing/capability claim in `README.md` mapped to the CI job that proves it, or `NO GATE`.

Rule (enforced from Phase 2 onward by `scripts/check_claim_gate_matrix.py`, wired into `.github/workflows/security.yml`): **no row may say `NO GATE`.** A `NO GATE` row is either a claim to delete or a gate to build. Rows marked `PARTIAL` name the gap that a later phase closes.

Statuses: `GATED` (a CI job fails when the claim stops being true) · `PARTIAL` (some aspect gated, gap named) · `NO GATE` (unproven).

| Claim | Source | Gate (workflow :: job) | Status | Closes in |
|---|---|---|---|---|
| Offline sandbox demo runs with no key/network in < 5 s | README L38 | `readme-gates.yml :: sandbox-offline` (ubuntu+macos matrix) | GATED | - |
| `pnpm aisoc:demo` boots the real stack | README L40, L45 | `compose-smoke.yml`, `compose-smoke-nightly.yml` (cold) | PARTIAL (health-probe only, no time-to-first-investigation assertion) | Phase 3.4 |
| 69 connectors | README L116, L168 | `ci.yml :: python-lint` (`generate_connector_count.py --check`) | GATED (count) | - |
| Connectors: schema-driven config + vault-encrypted secrets | README L168 | `ci.yml :: python-services-test` (`test_schemas.py`); vault tests | PARTIAL (schema + vault gated; live API conformance, rate-limit, checkpoint durability ungated) | Phase 10 |
| Connectors: live Test connection | README L168 | none | NO GATE | Phase 10 |
| Investigation Ledger stores every step | README L61, L169 | `ci.yml :: api tests` (`audit_hash`, audit immutability) | PARTIAL (write path gated; UI replay only in hermetic e2e) | Phase 3.2 |
| Public eval harness gates every PR | README L62, L77 | `ci.yml :: p1-eval` | GATED (but suites are self-consistency; see reality report) | Phase 4 |
| Alert-reduction is a real measurement | README L62 | `ci.yml :: p1-eval` (`alert_reduction`) | PARTIAL (gates an in-test fusion re-impl, not `services/fusion`) | Phase 4 |
| Runs entirely on your infrastructure / no data exfiltration | README L63 | none | NO GATE | Phase 1.4 |
| Detection-as-Code rejects candidates that regress MITRE accuracy | README L170 | `ci.yml :: p1-eval` (w2-dac baseline) | PARTIAL (circular: candidate `rule_body` never evaluated) | Phase 4 |
| 800+ native detection rules | README L78, L170 | `validate-detections.yml` (strict fixture replay) | GATED | - |
| 6000+ imported detection rules | README L78 | `validate-detections.yml` (parse/provenance) | PARTIAL (97% quarantined/non-executable; heatmap is tag-based) | Phase 4 Tier 3 |
| L0-L4 automation maturity gates every action | README L171 | `ci.yml` autonomy-policy drift test | PARTIAL (thresholds gated; rollback/post-verify/dry-run ungated) | Phase 9 |
| Hunt-as-Code + `/hunt` | README L172 | `ci.yml :: p1-eval` (`hunt_corpus`) | GATED | - |
| Weekly benchmark scoreboard runs live against `main` | README L173 | `wet-eval.yml` (weekly) | NO GATE (no-ops without secret; live-agent tables are placeholders) | Phase 4 Tier 1 |
| MCP server exposes 13 tools | README L179 | `ci.yml :: mcp` | GATED | - |
| Plugin SDK Python/TS/Go | README L79, L193 | `ci.yml :: sdk-*` | PARTIAL (build/test gated; contract-drift vs `docs/openapi.yaml` ungated) | Phase 11 |
| Prompt-injection resistance | (implied by agent claims) | `ci.yml :: python-test` (agents) runs `test_prompt_sanitizer.py` + `test_prompt_envelope.py` | PARTIAL (unit-level nonce envelope + guard gated; 150-payload adversarial eval + tool-call provenance in Phase 4 Tier 2) | Phase 4 |
| Cross-tenant isolation (Postgres) | (implied by multi-tenant) | `cross-tenant-rbac.yml` (nightly, 3 endpoints) + `ci.yml` | PARTIAL (Postgres only, compiled-SQL not live DB) | Phase 1.3 |
| Cross-tenant isolation (Qdrant/Neo4j/Redis/ClickHouse/Kafka) | (implied by multi-tenant) | none | NO GATE | Phase 1.3 |
| SAST | README badge (CodeQL) | `codeql.yml` | GATED | - |
| Dependency CVE scanning | (implied by security) | `security-audit.yml` | GATED | - |
| OpenSSF Scorecard | README badge L13 | `scorecard.yml` | GATED | - |
| Container image / IaC / secret scanning (Trivy/checkov/tfsec/gitleaks/Semgrep) | (implied by security) | none | NO GATE | Phase 2 |
| Signed / attested release artifacts | (implied by "run next to crown jewels") | `release.yml` (SPDX source SBOM), `build-extensions.yml` (extension cosign) | PARTIAL (images unsigned; no per-image SBOM/SLSA) | Phase 2 |
| Insecure defaults hard-fail in production | (implied by self-host) | none (warn-only) | NO GATE | Phase 2 |
| OpenAPI stability for 3 SDKs + MCP | (implied by SDKs) | `check-openapi.yml` (drift only) | NO GATE (no breaking-change semantics) | Phase 11 |

## Summary

- GATED: 9
- PARTIAL: 12
- NO GATE: 6 (Phase 1.1 moved prompt-injection resistance from NO GATE to PARTIAL)

The Definition of Done requires zero `NO GATE` and zero unclosed `PARTIAL`. Each row's "Closes in" column is the binding commitment.
