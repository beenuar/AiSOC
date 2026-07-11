# AiSOC Reality Report

Phase 0 of the world-class program (`AISOC_CURSOR_PROMPT_V2.md`). This document classifies every headline claim in `README.md` against the code that is supposed to back it. It changes no code.

- Repo state audited: `main` @ `982ef2ca`, `VERSION` 7.5.0.
- Method: source-level reconciliation (read the code, not the docs) across the agent, eval harness, data spine, connectors, SOAR, storage, supply chain, and governance surfaces.

## Status legend

- `production` — unit tests **and** an integration test against a real dependency, gated in CI.
- `functional-untested` — works, no gate.
- `template-fallback` — the "AI" path silently degrades to a curated template/regex without an LLM key, and the template is what CI exercises.
- `demo-only` — only reachable via the seeder or a demo profile.
- `stub` — route/page exists, logic does not.

## Claim-by-claim classification

### "What AiSOC is" — the three differentiators (`README.md` L59-65)

| Claim | Code path | Status | Test evidence | Gated in CI? |
|---|---|---|---|---|
| Agent decisions are logged: Ledger stores prompt, response, evidence, tool calls per step | `services/agents/app/investigator/ledger.py` (records `model_used`, per-event `agent`, `input_hash`/`output_hash`); tamper-evident hash chain `services/api/app/services/audit_hash.py` (migration `043`) | functional-untested | `services/api/tests/test_audit_*`; ledger write covered | Partial — write path via `ci.yml` API tests; UI replay only in hermetic `e2e.yml` |
| Public eval harness in CI: five suites gate every PR; alert reduction is real; three rubric suites are self-consistency; fifth validates telemetry corpus | `scripts/run_evals.py` + `services/agents/tests/test_*` | production (honestly labelled) | `p1-eval` job in `.github/workflows/ci.yml` | Yes — but see Circular Gates below |
| Runs entirely on your infrastructure; no callbacks to a vendor cloud and no data exfiltration | Default cloud-LLM path `services/agents/app/security/llm_resolver.py`; no redaction before egress | functional-untested (OVERCLAIM) | none — no egress-blocked test, no PII-in-payload test | No |
| Orchestrator is a ~600-line LangGraph | `services/agents/app/orchestrator/` | functional-untested | approximate size claim, not gated | No |

### "What's in the box" (`README.md` L164-173)

| Claim | Code path | Status | Test evidence | Gated in CI? |
|---|---|---|---|---|
| 69 click-and-connect connectors, schema-driven config, live Test connection, vault-encrypted secrets | `services/connectors/app/connectors/` (69 modules), `base.py` (`schema()`, `test_connection()`, `fetch_alerts()`), `services/api/app/security/credential_vault.py` | functional-untested (count + schema production; live-connection untested) | `services/connectors/tests/test_schemas.py` runs vs every registered connector; vault tests in api/connectors/actions | Count gated (`scripts/generate_connector_count.py --check`); schema conformance gated; live API conformance NOT gated |
| Investigation Rail + replayable Ledger — every prompt/tool call/evidence/rationale stored, replayable in UI | `apps/web` Investigation Rail; `alert_rail.py`, `narrative_projection.py` | functional-untested | rail projection unit tests | Replay UI NOT gated (e2e hermetic) |
| Detection-as-Code lifecycle — propose to promote; CI rejects any candidate that regresses MITRE accuracy | `services/api/app/api/v1/endpoints/detection_proposals.py` | template-fallback (CIRCULAR) | eval gate never receives `rule_body` | Gated but circular — see below |
| 800+ native Sigma rules in `detections/` | `detections/<category>/` = 861 native (endpoint 304 / cloud 226 / identity 160 / network 81 / application 70 / data-exfil 20) | production (content) | `validate-detections.yml` strict fixture replay; 862 positive + 862 negative fixtures | Yes for native fixtures |
| L0-L4 automation maturity — gate every action on per-action confidence + blast-radius | `services/actions/app/services/maturity.py`; thresholds `services/agents/app/policy/guardrails.py` | functional-untested | thresholds + autonomy-policy drift test | Threshold sync gated; rollback/verify NOT gated |
| Hunt-as-Code + NL `/hunt` workbench | `services/api/app/api/v1/endpoints/saved_hunts.py`; `apps/web/src/app/(app)/hunt/` | functional-untested | `hunt_corpus` eval suite | Yes (corpus coverage) |
| Public weekly benchmark scoreboard — same harness, weekly against `main` | `.github/workflows/wet-eval.yml`; `apps/docs/docs/benchmark-scoreboard.mdx` | functional-untested (OVERCLAIM) | wet-eval no-ops without `WET_EVAL_OPENAI_KEY`; live-agent tables are unfilled placeholders | Effectively No for live-agent numbers |

### "How AiSOC compares" table (`README.md` L71-81)

| Claim | Reality | Status |
|---|---|---|
| Detection content: 800 native + 6000+ imported | 861 native + 6113 imported, of which ~5921 (`_quarantine`, `enabled: false`) are non-executable; ATT&CK heatmap counts metadata tags, not firing rules | OVERCLAIM (imported count implies working coverage) |
| Public substrate eval harness: CI-gated, reproducible, synthetic telemetry corpus + per-template macros | Accurate and honestly labelled in `apps/docs/docs/benchmark.md` | production |
| Agent decision audit trail: public Investigation Ledger | Real | functional-untested |

### MCP + SDK (`README.md` L177-193)

| Claim | Code path | Status | Gated in CI? |
|---|---|---|---|
| MCP server exposes 13 tools | `services/mcp/` | functional-untested | Yes (`ci.yml` MCP job: type-check/test/build) |
| Plugin SDK Python/TypeScript/Go | `packages/sdk-{py,ts,go}` | functional-untested | Build/test gated; contract-drift vs `docs/openapi.yaml` NOT gated |

## Overclaims (ranked)

1. **"No data exfiltration / runs entirely on your infrastructure."** The default investigation path uses a cloud LLM (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) and reasons over raw evidence. There is no PII pseudonymization (`services/agents/app/privacy/` does not exist), so usernames, hostnames, internal IPs, file paths, and command lines are sent verbatim to a third-party provider. The claim is only true in the local-model / air-gapped configuration, which is not the default and has no egress-blocked CI proof. Fix in Phase 1.4 + Phase 2.
2. **"6000+ imported detection rules."** ~5921 of 6113 imported rules live under `_quarantine/` (`enabled: false`) because their upstream query language (SPL / YARA-L / CAR pseudocode) does not execute on the engine. The coverage heatmap (`scripts/build_marketplace.py::coverage_block`) counts MITRE tags on rule metadata, not rules that fire. Fix in Phase 4 Tier 3 + Phase 10.
3. **"Detection-as-Code ... CI rejects any candidate that regresses MITRE accuracy."** True in letter, misleading in spirit: the gate never evaluates the proposed rule (see Circular Gates). Fix in Phase 4.
4. **"Public weekly benchmark scoreboard — same harness, weekly against `main`."** The weekly wet-eval no-ops without a secret and its live-agent result tables are still `<!-- placeholder -->`. Published scoreboard numbers are substrate self-consistency, not live-agent accuracy. Fix in Phase 4 Tier 1.
5. **"800 native Sigma rules."** They are AiSOC-native YAML (a bespoke `match_when` schema), not Sigma format; on-disk count is 861. Minor imprecision. Fix in Phase 2 README honesty pass.

## Load-bearing untested paths (ranked)

1. **The Kafka spine end-to-end.** No CI proves raw event -> OCSF normalize -> enrich -> fuse -> alert row -> WS frame -> agent -> ledger. `compose-smoke.yml` boots the stack but only probes `/health` + web 200. Everything else in `ci.yml` is offline/mocked. Fix in Phase 3.1.
2. **Prompt-injection defenses.** `services/agents/app/investigator/prompt_sanitizer.py` (envelope wrap + injection redaction) and `services/agents/app/llm/contract.py` (fail-closed input contract) are real and wired in, but `services/agents/tests/test_prompt_sanitizer.py` is not in the agents job's hardcoded file list in `.github/workflows/ci.yml`, so the defense is effectively ungated. Fix in Phase 1.1.
3. **Cross-tenant isolation outside Postgres.** `services/threatintel/app/storage/qdrant.py` has zero tenant scoping (global collections, no `tenant_id` filter). Neo4j/Redis/ClickHouse/Kafka have no isolation tests. `cross-tenant-rbac.yml` is nightly, Postgres-only, 3 endpoints, and asserts against compiled SQL (no live DB). Fix in Phase 1.3.
4. **SOAR rollback + post-action verification.** `rollback()` is real only for the `aws_sg` path in `services/actions/app/executors/network.py`; other vendors return `True` without a reverse call, and the live-actions layer omits rollback entirely. There is no post-action verification that a containment actually took effect. Fix in Phase 9.
5. **Backup/restore.** `backup.sh` / `restore.sh` exist; nothing tests them and no RTO/RPO is published. Fix in Phase 3.3.
6. **Approval SLA timers.** `services/slack-bot/app/services/approval_timeout.py` is in-memory; a restart wipes pending approvals (fail-safe default is reject, but the timer state is lost). Fix in Phase 9.
7. **Migration down-paths.** No per-service `downgrade base` round-trip test. Fix in Phase 3.1.

## Circular gates (ranked)

1. **DAC promotion gate.** `services/api/app/api/v1/endpoints/detection_proposals.py::_run_eval_subprocess` shells out to `scripts/run_evals.py` **without passing the proposed `rule_body`**. Approval (`/decide`) requires `eval_result.passed`, but "passed" means the repo's global substrate MITRE accuracy did not regress vs. a stored baseline — a value entirely independent of the rule being proposed. A bad rule passes its own exam. Fix in Phase 4.
2. **The gated eval suites are self-consistency.** Of the PR-gated suites, `mitre_accuracy`, `investigation_completeness`, and `response_quality` judge templated output against the data that generated it. `mitre_accuracy` runs an offline keyword extractor (`extract_tactics_from_text`), **not the live LangGraph agent** — so no live-agent accuracy is gated on any PR. This is disclosed in `apps/docs/docs/benchmark.md`, but it remains the hard ceiling on the project's credibility. Fix in Phase 4 Tier 1.
3. **`alert_reduction` gates a re-implementation, not the product.** The only non-tautological accuracy-style suite runs against an in-test fusion re-implementation, not `services/fusion`, so it does not gate the real fusion path. `detection_fp_rate` (cross-fire FP) is the one suite that tests shipped rule content. Fix in Phase 4.

## Internal inconsistencies found (fix in Phase 2 / Phase 12)

- **License disagreement.** `README.md` L229 and `LICENSE` say MIT; `.github/LICENSES.md` L3 says "AiSOC ships under Apache-2.0" and marks native detections Apache-2.0.
- **Referenced-but-missing CI guard.** `docs/decisions/0002-compliance-claims.md` asserts a CI check at `scripts/audit_compliance_claims.py` exists and fails the build on unqualified framework names. That script does not exist and no workflow references it.
- **Stale internal reference.** `AGENTS.md` and `packages/aisoc-sandbox/src/aisoc_sandbox/investigation.py` reference `services/.../llm_safety.py`; the real file is `services/agents/app/investigator/prompt_sanitizer.py`.
- **AGENTS.md eval claim is wrong.** It states only `mitre_accuracy` measures the live agent; per the code, `mitre_accuracy` is an offline keyword extractor and no PR-gated suite runs the live agent.

## Prompt premises that are already satisfied (build the delta, do not rebuild)

- Phase 1.1 assumes "nothing in the repo defending prompt injection." Reality: `prompt_sanitizer.py` + `llm/contract.py` exist. The genuine deltas are per-run nonces, a `PromptInjectionGuard` (ledger flag + auto-demote to L0), tool-call provenance/allowlisting, an adversarial eval, and CI gating.
- Phase 7 assumes the graph is built per-case at investigation time from events only. Reality: `services/ingest/internal/graph/` builds a Neo4j entity graph at ingest (17 node labels / 15 edge types). The genuine deltas are posture collection (`collect_posture()`), feeding the effective-permissions resolver (snapshot loader is a stub), bi-temporal `valid_from`/`valid_to`, a fusion-time `ContextBundle`, and a unified deterministic->ML->LLM router with tier attribution.
