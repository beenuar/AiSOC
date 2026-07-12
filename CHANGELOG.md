# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 4a — the Detection-as-Code gate is no longer circular.** The reality audit's #1 circular gate: the detection-proposal promote path shelled out to `run_evals.py` **without ever passing the proposed rule body**, so "passed" meant the repo-wide substrate MITRE accuracy didn't move — a value independent of the rule under review. A blind rule (matches nothing) or a noisy rule (matches everything) sailed through its own exam. New `services/api/app/services/detection_eval.py::evaluate_candidate_rule` runs the *candidate `rule_body` itself* through the **real** runtime engine (`rule_engine.execute_rule`) against caller-supplied positive/negative fixtures: it must fire on every positive and stay silent on every negative. New `POST /detection-proposals/{id}/evaluate-rule` stores the verdict under `eval_result["candidate_rule"]`, and `POST /decide` (approve) now **requires** it — a benchmark-only pass is no longer sufficient. `services/api/tests/test_detection_eval.py` (6 tests) is the mutation test that proves the gate rejects a blind rule, rejects a noisy rule, rejects a no-positive-fixture rule, and that the verdict genuinely depends on the rule body. Claim-to-gate matrix: DAC row PARTIAL(circular) → GATED.
- **Phase 4b — detection content truth table (honest coverage).** The README advertised "6000+ imported detection rules", but ~97% live under `_quarantine/` (`enabled: false`) because their upstream query language (SPL / YARA-L / CAR pseudocode) does not execute on the engine. New `scripts/detection_truth_table.py` walks `detections/` and classifies every rule **executable** (fires today) vs **non-executable** (provenance/coverage only), rendering `docs/detections/truth-table.md`. The honest headline: **939 executable** rules (861 native + 77 sigma-imported + 1 community) of 6975 on disk; 5921 quarantined, 115 disabled. `--check` gates the doc in `validate-detections.yml` so the number can never quietly drift from reality, and the README now cites the executable figure for *coverage* (the on-disk figure only describes the imported *library*). Claim-to-gate matrix: 6000+-imported row PARTIAL → GATED (14 GATED / 10 PARTIAL / 3 NO GATE). The LLM-dependent half of Phase 4 (live-agent Tier-1 eval, hallucination/calibration/abstention, model matrix, 150-payload prompt-injection adversarial) is tracked as 4c+ in `docs/audit/PROGRESS.md`.
- **Phase 3.4 — cross-store tenant isolation, now proven against live containers.** The offline `isolation.yml` gate proved each read path *constructs* a tenant scope; it could not prove the scope actually isolates. New `.github/workflows/isolation-live.yml` + `tests/isolation/test_live_stores.py` seed tenant A and tenant B in **real containers** (Neo4j, Redis, ClickHouse, Redpanda/Kafka) and assert a read as A returns zero B data. ClickHouse runs the **production** `lake_sql.rewrite_for_tenant` rewriter against a live warehouse (verified: `SELECT … FROM aisoc.raw_events` becomes `… WHERE tenant_id = '<A>'`, so B's rows never return); Neo4j uses the `tenant_id` property filter; Redis uses the `aisoc:t:<tenant>:*` keyspace namespacing; Kafka replays the `graph_ws` per-tenant envelope filter. Every test also asserts the *unscoped* read sees both tenants, so a scoped pass can never be vacuous on an empty store. The isolation registry (`tests/isolation/stores.py`) flips Neo4j/Redis/ClickHouse/Kafka from `container_pending` → `container_gated`, and the claim-to-gate matrix moves "Cross-tenant isolation (Qdrant/Neo4j/Redis/ClickHouse/Kafka)" PARTIAL → GATED (12 GATED / 12 PARTIAL / 3 NO GATE). The heavy-demo-stack items (Playwright real-stack E2E, demo time-to-first-investigation budget) are tracked as non-blocking 3.5+ in `docs/audit/PROGRESS.md`.
- **Phase 3.3 — upgrade-safety gate ("people upgrade; nothing tested it").** New `upgrade` job in `integration.yml` (matrix `v7.5.0 → HEAD` and `v7.3.1 → HEAD` against a real Postgres 16): install a prior release's migration set, seed 250 probe rows on that released schema, then apply HEAD's migration set — the actual self-host upgrade path — and assert the seeded rows survive **and** every HEAD migration applied. The signal this adds beyond the existing fresh-apply job is **destructive-migration detection**: a migration that drops or rewrites existing data fails here even though it applies cleanly on an empty database. The `v7.3.1 → HEAD` leg lands 8 incremental migrations on a pre-existing populated schema (verified locally: 250/250 rows survived, 55/55 migrations tracked). Uses `git checkout <ref> -- services/api/migrations` with an `rm -rf` first so the released set is exact (a `checkout … -- path` alone leaks HEAD-only files and silently degrades to a fresh apply).
- **Phase 3.2 — Postgres-outage chaos gate (fail-soft + self-heal).** Extends the `integration.yml` spine job with a second chaos scenario beyond the consumer-kill test: kill Postgres mid-stream, assert the fusion consumer keeps running (the `AlertSink` degrades to "fused alerts still stream over Kafka/WS, persistence dropped for the outage window" instead of crashing the worker), then restart Postgres and assert a *fresh* event persists — proving the sink's asyncpg pool and the API's SQLAlchemy pool both self-heal with no service restart. Distinct event titles side-step fusion's in-memory dedup so the post-restart event is a genuine fresh persist. Verified locally against a real Postgres 16 before gating (persist during outage → `None` with no raise; first persist after restart → row written). `scripts/integration/spine_test.py` polling now swallows transient HTTP errors during the recovery window so a 5xx blip while the API reconnects extends the poll rather than failing the run.
- **Phase 3.1 — the event spine is now continuous, and CI proves it with real containers.** The reality audit found two silent gaps in the product's central claim: ingest published normalized OCSF events to `aisoc.raw_events` that nothing consumed, and fusion published to `aisoc.alerts.fused` that nothing persisted — a raw event could never become an alert row without a human calling the API. Both bridges now exist in `services/fusion`: a deterministic promotion policy (`app/services/promoter.py` — OCSF Findings-category events and `severity_id >= 4` telemetry become `RawAlert`s; everything else is left to the detection engine by design) and a fail-soft, idempotent Postgres `AlertSink` (`app/services/alert_sink.py` — dedup-fingerprint-guarded insert, duplicates never persisted, DB outage degrades instead of crashing the consumer). New `.github/workflows/integration.yml` gates three claims against real containers, no mocks: (1) **spine** — `POST /v1/ingest/batch` → OCSF normalize → Kafka → fusion → WebSocket `alert.fused` frame + Postgres row via `GET /api/v1/alerts`, plus duplicate suppression and a chaos step (kill the fusion consumer mid-stream, produce, restart, assert zero event loss) — driver: `scripts/integration/spine_test.py`; (2) **migrations** — the full SQL chain applies on fresh Postgres 16, re-run is a no-op (new `AISOC_MIGRATIONS_STRICT=1` mode fails CI on any failed migration), and the UEBA alembic chain round-trips upgrade → downgrade → upgrade; (3) **backup-restore** — `scripts/backup.sh`/`restore.sh` against Postgres + MinIO: seed → backup → destroy → restore → assert full integrity, with measured RTO published to the job summary. 20 new fusion unit tests cover the mapping/skip logic (`test_promoter.py`, `test_alert_sink.py`); full fusion suite 71/71.

### Fixed

- **Phase 3.1 gates caught two latent bugs before merge** (exactly what the real-container tier is for — both would have shipped invisibly under the previous mock-only CI). (1) **`scripts/restore.sh` never restored anything.** `resolve_timestamp()` ended in a `[[ -z "$TIMESTAMP" ]] && { … }` guard that evaluates *false* once a timestamp is resolved; as the function's last command that non-zero status propagated out and, under `set -e`, aborted the script before the restore began — for **both** `--latest` and `--timestamp`. An untested backup script had been broken the whole time. Converted the guard to an explicit `if` + `return 0`; the backup → destroy → restore gate now restores 500/500 rows with a measured RTO. (2) **`services/fusion` `AlertSink` silently failed to persist every alert.** The dedup fingerprint (`$10`) was used untyped in both the `INSERT … SELECT` target (the `dedup_hash VARCHAR(64)` column) and `WHERE dedup_hash = $10` (varchar comparisons resolve through `text` operators), so asyncpg's prepare raised `inconsistent types deduced for parameter $10: text versus character varying` and the insert threw — the fused alert streamed over Kafka/WebSocket but never reached the alert store, so the spine's `GET /api/v1/alerts` assertion timed out. Pinned both uses to `::text`; the real-container spine gate now observes the alert row end to end.

### Security

- **Phase 2 continuation — signed, attested container images + SHA-pinned CI.** Every `ghcr.io/beenuar/*` service image pushed by `publish-images.yml` (push-to-main) and `release.yml` (tags) is now: (1) signed with `cosign` keyless/OIDC, (2) attested with a CycloneDX SBOM generated by `syft` and attached via `cosign attest --type cyclonedx`, and (3) built with BuildKit `provenance: mode=max` + `sbom: true` so SLSA provenance and an SPDX SBOM ride the image manifest. Every third-party GitHub Action across all 32 workflows is pinned to a full commit SHA (tag retained as a comment) so a tag-hijack of an upstream action cannot change what CI executes. `docs/operations/verifying-releases.md` rewritten with copy-pasteable verification commands for all four artifact types. Claim-to-gate matrix: "Signed / attested release artifacts" moved PARTIAL → GATED (11 GATED / 13 PARTIAL / 3 NO GATE).

- **Phase 2 — supply chain + truth gates.** New `.github/workflows/security.yml`: a claim-to-gate matrix ratchet (`scripts/check_claim_gate_matrix.py` — the NO GATE count may only decrease; enforces the Phase 0 promise) as the HARD gate, plus gitleaks (secret), Semgrep, Trivy (fs), and checkov/tfsec in report-and-ratchet ("observe") mode with a triage allowlist at `.security/allowlist.yml` / `.gitleaksignore` (GitHub push-protection remains the always-on hard secret gate). **Insecure defaults now hard-fail the boot in production**: `enforce_secure_defaults()` (`services/api/app/core/config.py`) raises `InsecureProductionDefaultsError` when `ENVIRONMENT=production` and any placeholder secret remains, wired into `app/main.py` startup and gated by `services/api/tests/test_security_defaults.py::test_enforce_*`. Added `TRADEMARK.md` (the MIT code is free; the name is not), `docs/operations/verifying-releases.md`, a README `Maturity` note, and fixed the `.github/LICENSES.md` license inconsistency (AiSOC ships under MIT, matching `LICENSE`/README, not Apache-2.0). Claim-to-gate matrix now 10 GATED / 14 PARTIAL / 3 NO GATE. Per-image CycloneDX SBOM + cosign signing + SLSA provenance, SHA-pinning all actions, and flipping the code scanners to blocking are the tracked Phase 2 continuation.

- **Phase 1.6 — platform/vault hardening (KMS envelope encryption).** New `services/api/app/security/envelope_cipher.py`: optional envelope encryption for the credential vault. Each secret is encrypted with a fresh per-secret data key (DEK); the DEK is wrapped by a key-encryption key (KEK) that never leaves KMS/HSM (`vault:v2:<kek_id>:<wrapped_dek>:<ciphertext>`), so a DB dump or a leaked env var yields only wrapped DEKs. Pluggable `KeyManager` protocol with `LocalKeyManager` (default, backward-compatible), `AwsKmsKeyManager` (boto3; GCP KMS / Vault Transit implement the same protocol), and an in-memory `FakeKmsKeyManager` for tests. Key rotation is a cheap **re-wrap** (`EnvelopeCipher.rewrap`) that never re-encrypts the secret body. Gated by `services/api/tests/test_envelope_cipher.py` (round-trip, rotation + re-wrap, plaintext-never-in-token, fail-closed on tamper/wrong-KEK). Added `docs/security/platform-threat-model.md` (STRIDE, vault as top asset) and `docs/security/connector-least-privilege.md`. Completes Phase 1.

- **Phase 1.5 — cost-DoS enforcement.** New `services/agents/app/core/cost_governor.py`: a per-tenant `CostGovernor` that turns the existing `aisoc_run_costs` telemetry into enforcement — rolling-window soft/hard USD budgets, a circuit breaker that drops investigations to deterministic-only mode once the hard cap is hit (instead of billing unboundedly), a per-alert token ceiling (`cap_tokens`), and an evidence-hash dedup cache so a flood of identical alerts costs one investigation, not N. Gated by `services/agents/tests/test_cost_governor.py` (10 tests incl. the headline 10 000-identical-alert flood asserting spend stays at exactly one run, and a distinct-alert flood asserting the circuit breaker bounds spend near the hard cap). Live-orchestrator wiring of `get_governor().check(...)` before the LLM call is the tracked continuation.

- **Phase 1.4 — evidence redaction pipeline (honest no-exfiltration).** New `services/agents/app/privacy/redactor.py`: a per-run, per-tenant, in-memory reversible `Pseudonymizer` that replaces the customer's identifying data (internal IPs, emails, file paths, secrets, internal hostnames, usernames) with opaque tokens (`USER_1`, `HOST_2`, `IP_3`) before evidence leaves the process, while preserving public threat indicators so the agent can still reason. `RedactionConfig` defaults every category on. Gated by `services/agents/tests/test_privacy_redactor.py` (golden-corpus assertion: zero raw customer PII survives; round-trip re-hydration; public IOCs preserved). Rewrote the README "no data exfiltration" differentiator to be precise per mode and added `docs/trust/data-flows.md` documenting exactly what leaves the perimeter (local air-gapped / hosted-with-redaction / hosted-raw). Contract-egress enforcement + air-gapped CI job + Helm egress NetworkPolicy are the tracked 1.4 continuation.

- **Phase 1.3 — cross-store tenant isolation (Qdrant + harness).** Closed the Qdrant leak the reality audit flagged: `services/threatintel/app/storage/qdrant.py` had no tenant scoping at all (global collections, no filter, no `tenant_id` in payloads). Added `tenant_scope_filter` + tenant-stamped payloads + tenant-scoped point ids so a search as tenant A can never surface tenant B's private vectors, while global feed intel stays shared under a `SHARED_TENANT` sentinel (backward-compatible with the feed pipeline). Stood up a table-driven `tests/isolation/` suite (registry in `stores.py` so a new store cannot ship without an isolation entry) and a new `.github/workflows/isolation.yml` gate running the offline layer on every PR. Neo4j/Redis/ClickHouse/Kafka live-container replay is registered as `container_pending` for Phase 3's integration tier.

- **Phase 1.2 — memory-poisoning defenses for the override-learning loop.** New pure `services/api/app/services/memory_poisoning.py`: provenance on every memory write (`MemoryProvenance` — no anonymous memory), trust weighting (verified human outranks autonomous closure) with age decay so lessons must be re-confirmed, a `PoisoningDetector` that flags a burst of same-signature false-positive dispositions from low-trust authors, and blast-radius controls for retroactive re-disposition (`plan_redisposition` + `compute_confirmation_token`: capped batches, explicit confirmation token over the exact alert set, quarantine on flagged signatures). Wired into `override_learning.py` (poisoning-resistant signature key now includes the entity-independent severity band; provenance stamped on writes; `apply_redisposition` requires the token and enforces the cap) and the `/feedback` endpoints (preview returns the token + quarantine state; apply rejects stale/tampered/over-cap batches with 409). The farming-attack eval (`services/api/tests/test_memory_poisoning.py::test_farming_attack_then_real_attack_is_not_auto_closed`) gates the api job: a poisoned signature is flagged and its retroactive apply quarantined, so the real intrusion is not auto-closed.

- **Phase 1.1 — prompt-injection structural containment + detection.** New `services/agents/app/prompting/envelope.py`: per-run cryptographic-nonce evidence fence (`EvidenceEnvelope`, `make_nonce`, `system_rule`) so injected text cannot forge the closing delimiter to break out of the data block, and a `PromptInjectionGuard` that scans untrusted evidence for instruction-shaped content (role markers, "ignore previous", secret/prompt exfiltration, SOAR tool-name mentions, base64- and zero-width-obfuscated directives) and, on a high-severity hit, signals demotion of the case autonomy tier to L0. Added `services/agents/tests/test_prompt_envelope.py` (25 tests across every ingest path) and gated it plus the previously-ungated `test_prompt_sanitizer.py` in the CI agents job (fixed its stale agent-wiring expectations — the investigator agents sanitise via `sanitize_text` / `sanitize_iterable_of_strings` / `format_bundle_prompt_append`). Threat model: `docs/security/agent-threat-model.md`.

### Added

- **World-class program Phase 0 — reality audit** (no product code). `docs/audit/REALITY_REPORT.md` classifies every headline `README.md` claim against the code (`production` / `functional-untested` / `template-fallback` / `demo-only` / `stub`) and ranks Overclaims, Load-bearing untested paths, and Circular gates. `docs/audit/CLAIM_TO_GATE_MATRIX.md` maps 27 claims to their CI gate or `NO GATE` (9 GATED / 11 PARTIAL / 7 NO GATE), each with a binding "Closes in" phase. The committed 12-phase status checklist lives in `ROADMAP.md` (per-session working detail is in the gitignored `docs/audit/PROGRESS.md`). Tracking doc: `AISOC_CURSOR_PROMPT_V2.md`.

## [7.5.0] — 2026-06-29

v8.0-milestone and trust-readiness release. Folds in the **AiSOC missing
pieces — Phases 1–5** rollup (PR [#337](https://github.com/beenuar/AiSOC/pull/337);
25 commits, 188 files, +23 743 / -907), four named v8.0 milestones (T3.7
NL→playbook, T3.8 design system v2, T4 wave-3 marketplace + 6 hardened
connectors, T5.3 fidelity loaders), the marketing-shell unification on
`tryaisoc.com`, the threat-actor attribution RBAC + port fix, and a large
Dependabot + security sweep that landed on `main` since v7.4.0.

### Highlights

- **AiSOC missing pieces — Phases 1–5 rollup**
  (PR [#337](https://github.com/beenuar/AiSOC/pull/337)). Closes every
  item in `plans/aisoc-missing-pieces/` in a single landing: trust-critical
  honesty fixes on `/sovereign` + Features + README, CI matrix expanded to
  7 previously-untested Python services (~971 new test signals), coverage
  gates, real SOAR executors for SentinelOne EDR / PAN-OS / FortiGate /
  Cloudflare WAF + DNS / Splunk ES / Elastic / MDE / Entra ID / Google
  Workspace, real `CreateTicketExecutor` wired to Jira / ServiceNow /
  PagerDuty, Azure/GCP/Okta/GWS effective-permissions resolvers, the
  managed-mode auto-provision pipeline (`infra/fly/managed/`), CI-built
  white-paper PDFs + 90 s Playwright screencast, the deterministic
  NL → ES|QL / KQL / SPL translator (**81-case eval at 100 % syntactic +
  100 % semantic**), real-browser visual regression, a buyer-journey E2E,
  and four immutable ADRs (`docs/decisions/0001`-`0004`).
- **v8.0 milestones — design system, playbook generator, wave-3
  connectors, fidelity loaders.**
  T3.7 NL → playbook generator
  (PR [#330](https://github.com/beenuar/AiSOC/pull/330));
  T3.8 design system v2 + Storybook
  (PR [#331](https://github.com/beenuar/AiSOC/pull/331),
  `DraftFromPromptDialog` story restored in
  PR [#335](https://github.com/beenuar/AiSOC/pull/335),
  Storybook publicDir conflict fixed in
  PR [#336](https://github.com/beenuar/AiSOC/pull/336));
  T4 wave-3 marketplace scaffolding + six hardened connectors
  (PR [#333](https://github.com/beenuar/AiSOC/pull/333),
  wave-1 parity hardening in
  PR [#328](https://github.com/beenuar/AiSOC/pull/328));
  T5.3 AIT-LDS + MITRE Engenuity fidelity loaders
  (PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
- **Threat-actor attribution — port fix + optional RBAC.** The
  investigation agent defaulted `AISOC_THREATINTEL_URL` to
  `http://threatintel:8083`, but the service binds **8005** — every
  `POST /api/v1/actors/attribute` from
  `services/agents/app/agents/investigation_agent.py` therefore hit a port
  nothing listens on and silently degraded. Default corrected, docs +
  `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` aligned, regression test added
  (PR [#327](https://github.com/beenuar/AiSOC/pull/327)). Same release
  ships an opt-in shared-secret gate
  (PR [#329](https://github.com/beenuar/AiSOC/pull/329)): when
  `AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
  must present `Authorization: Bearer <token>` (constant-time compared,
  `401` on mismatch); unset keeps the legacy unauthenticated behaviour
  and logs a warning. Resolves the `[#TODO-attribution-rbac]` caveat in
  `docs/threat-actor-attribution.md`.
- **Marketing-shell unification on `tryaisoc.com` (QA wave, 2026-06-29).**
  Every `/(marketing)` page, plus the standalone `/not-found`,
  `/why-open-source`, and `/benchmark` routes, now renders the same
  `StickyNav` + `sections/Footer` shell. The old simpler `LandingNav.tsx`
  and `landing/Footer.tsx` were deleted; eleven marketing pages had their
  per-page nav/footer JSX + imports removed; `(marketing)/layout.tsx`
  centrally injects the shell; `StickyNav`'s anchors were absolutised
  (`/#solution`, `/benchmark`, `/pricing`) so they resolve identically
  from the landing page and from any subpage. Folded together with the
  smaller fixes from the same QA pass: branded `/not-found` page
  (`ISSUE-004`), `308 /signup → /dashboard` for the anonymous demo
  (`ISSUE-003`), `Testimonials` "Become a reference partner" CTA
  repointed from the 404'ing `/partners` to `/contact` (`ISSUE-002`),
  dead `status.tryaisoc.com` footer link removed (`ISSUE-005`), and an
  SSR-whitespace bug on `/about` that rendered "the 69connectors"
  fixed by forcing an explicit `{' '}` token (`ISSUE-007`).
- **Knowledge-base ingest — boundary-aware chunking with overlap**
  (PR [#321](https://github.com/beenuar/AiSOC/pull/321), closes
  [#277](https://github.com/beenuar/AiSOC/issues/277)). KB ingestion no
  longer splits mid-sentence or mid-code-fence; the new chunker prefers
  paragraph / sentence / code-block boundaries, applies a configurable
  overlap so retrieval doesn't lose context across chunks, and keeps the
  produced chunks within the embedding model's hard token budget.
- **Realtime — WS/SSE authenticated via short-lived tickets**
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246), closes
  [#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
  service's WebSocket and SSE endpoints previously accepted any
  connection. They now require a short-lived signed ticket that the API
  mints for the authenticated session, closing the unauthenticated
  fan-out surface that lived between `services/realtime` and `apps/web`.
- **`apps/web` — Create Case button wired on `/alerts/{id}`**
  (PR [#294](https://github.com/beenuar/AiSOC/pull/294), closes
  [#293](https://github.com/beenuar/AiSOC/issues/293)). The button on
  alert detail rendered but did nothing; it now POSTs through the cases
  endpoint and navigates to the new case workspace.
- **Infrastructure — Terraform CI + missing core modules.** Terraform
  workflow on every `infra/terraform/**` change
  (PR [#251](https://github.com/beenuar/AiSOC/pull/251)) runs
  `terraform init -backend=false`, `terraform validate`, and
  `terraform fmt -check -recursive` against the AWS, GCP, Azure, and
  BYOC configurations; the three reusable modules the AWS and BYOC
  references were already importing — `rds`, `elasticache`, `kafka` —
  are now actually present in `infra/terraform/modules/`
  (PR [#252](https://github.com/beenuar/AiSOC/pull/252)) so a fresh
  `terraform init` against the multi-cloud skeletons no longer errors on
  missing sources. GCP sensitive-var taint cleared on `for_each`
  (PR [#243](https://github.com/beenuar/AiSOC/pull/243)); Azure
  Terraform skeleton documented
  (PR [#247](https://github.com/beenuar/AiSOC/pull/247)).
- **Dependency & CI maintenance.** ~15 Dependabot upgrades across the
  Python, JS, and Go services (FastAPI in `services/{api,actions,agents}`
  via [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320);
  `next` 16.2.7 → 16.2.9 in
  [#323](https://github.com/beenuar/AiSOC/pull/323);
  `framer-motion` 11.18.2 → 12.40.0 in
  [#307](https://github.com/beenuar/AiSOC/pull/307);
  `cryptography` in
  [#301](https://github.com/beenuar/AiSOC/pull/301) /
  [#302](https://github.com/beenuar/AiSOC/pull/302); Go `redis/go-redis`
  in [#297](https://github.com/beenuar/AiSOC/pull/297) /
  [#298](https://github.com/beenuar/AiSOC/pull/298);
  `strawberry-graphql` in
  [#318](https://github.com/beenuar/AiSOC/pull/318);
  `actions/checkout` v6 → v7 in
  [#316](https://github.com/beenuar/AiSOC/pull/316); plus
  `@xyflow/react`, `@types/node`, `tsx`, `@tailwindcss/postcss`); pnpm
  audit high/critical findings cleared
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  PR queue could actually merge; a duplicate `@mdx-js/react` key that
  was breaking `pnpm install` removed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)); `aiohttp` bumped
  to 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).

### AiSOC missing pieces — Phases 1–5 (PR [#337](https://github.com/beenuar/AiSOC/pull/337))

The largest single landing in this release. Twenty-five commits implement
the entire `plans/aisoc-missing-pieces/` roadmap; nothing in the plan is
deferred.

**Phase 1 — Trust-critical fixes** (`1.1`–`1.6`): one build-time
generator + CI gate is now the only place the marquee connector count
lives; the hard-coded `★ 2.3k` GitHub-stars badge was replaced with a
live shields.io endpoint; every SOC 2 / ISO 27001 / GDPR / DPDP claim
across `/sovereign`, `Features.tsx`, and `README.md` is now qualified
with the honest *"controls aligned to"* framing pending a Type I audit
(ADR-0002 below); seven 404'ing footer links and two pricing CTAs were
either stubbed, repointed to `mailto:`, or redirected to GitHub; the
real `services/connectors/app/connectors/gitlab.py` connector that the
marquee pill had been claiming was real now exists; and the `/sovereign`
Terraform deep-links route to the correct subdirectories per cloud, with
Azure added and the unsupported clouds struck.

**Phase 2 — Operational readiness** (`2.1`–`2.6`): the seven Python
services that were silently outside the CI matrix
(`services/{ueba,honeytokens,purple-team,osquery-tls,connectors,actions,
threatintel}` in practice) are now included; the `pytest` and Vitest
configurations enforce a coverage floor via `--cov-fail-under` and the
Vitest `coverage.thresholds`; `prometheus.yml` no longer lists scrape
targets that don't exist (CI now gates against drift); Prometheus
alerting rules + Alertmanager container are wired in `docker-compose.yml`;
seven incident runbooks land under `docs/runbooks/`; and every FastAPI
service now exposes `/livez` (the process is up) and `/readyz`
(dependencies are reachable) separate from the existing `/health`.

**Phase 3 — Real SOAR executors** (`3.1`–`3.5`): the executor surface
stops being a façade. SentinelOne EDR has a real client
(`services/actions/app/integrations/sentinelone.py`) wired to
`ContainHostExecutor`; PAN-OS, FortiGate, Cloudflare WAF, and Cloudflare
DNS firewall each have a real client wired to the appropriate `Block…`
executor; `AckAlertExecutor` and `SuppressAlertExecutor` now talk to
Splunk Enterprise Security, Elastic Security, and Microsoft Defender for
Endpoint directly; Entra ID and Google Workspace are wired as real IdP
clients for `DisableUserExecutor`; and `CreateTicketExecutor` no longer
returns `SIMULATED` — it delegates to the existing Jira, ServiceNow, and
PagerDuty connectors.

**Phase 4 — Larger build-out** (`4.1`–`4.8`):

- **4.1** — Azure RBAC, GCP IAM, Okta, and Google Workspace
  effective-permissions resolvers (closes T3.2). The investigation agent
  can now answer "what can this principal actually do?" across all four
  IdPs, not just AWS.
- **4.2** — Managed-mode auto-provision pipeline (closes T6.1):
  `infra/fly/managed/` + a workflow that creates a fresh Fly tenant from
  a push to `main`, dry-run-safe (won't act without `FLY_API_TOKEN`).
- **4.3** — `make papers` builds the white-paper PDFs in CI, and a
  Playwright project records a 90-second product screencast on demand.
- **4.4** — Connector wave finished: Sysdig, Vault, Snowflake, and
  Cloudflare Zero Trust manifests + docs.
- **4.5** — Pluggable event-warehouse provider
  (`services/api/app/services/event_warehouse/`) with Elasticsearch,
  Splunk, and Chronicle implementations; `croniter`-backed hunt
  scheduler (closes Milestone 1F).
- **4.6** — Deterministic NL → ES|QL / KQL / SPL translator. **81-case
  eval, 100 % syntactic, 100 % semantic** — every output is parsed
  through a grammar validator before return.
- **4.7** — Real-browser visual regression: Playwright + Storybook,
  pinned to `mcr.microsoft.com/playwright:v1.49.0-jammy`. First CI run
  needs `--update-snapshots`.
- **4.8** — Buyer-journey E2E covering `/alerts → Investigation Rail →
  /playbooks` runs on `pnpm e2e`.

**Phase 5 — Strategic decisions** (`5.1`–`5.4`): four immutable ADRs.
[`0001-cyble-cti-moat.md`](docs/decisions/0001-cyble-cti-moat.md) retires
the Cyble-only CTI moat in favour of a pluggable MIT-compatible CTI
fusion layer; [`0002-compliance-claims.md`](docs/decisions/0002-compliance-claims.md)
fixes the *"controls aligned to"* framing until a Type I audit lands and
gates it on a concrete enterprise design partner;
[`0003-mssp-pricing-shape.md`](docs/decisions/0003-mssp-pricing-shape.md)
keeps three public tiers, with MSSP getting its own narrative at
`/mssp`; [`0004-live-demo-strategy.md`](docs/decisions/0004-live-demo-strategy.md)
retires the Cloudflare Tunnel demo and provisions a dedicated managed-mode
tenant on Fly.io.

The Playwright projects (`screencast`, `visual`, `journey`) are gated by
`PLAYWRIGHT_PROJECT` so no project's `webServer` boots when another
runs. The four ADRs are immutable: future changes write a new ADR that
supersedes the old one.

### v8.0 milestones — design system v2, NL→playbook, wave-3 connectors, fidelity loaders

**T3.7 — NL → playbook generator**
(PR [#330](https://github.com/beenuar/AiSOC/pull/330)). Operators can
type a runbook in English and the agent emits a structured playbook YAML
that fits the existing `services/actions` schema: graph of executors,
inputs, and conditionals, with the same JSON-schema validation the
console editor enforces. Backed by the same deterministic translator
substrate as Phase 4.6 so the output stays parsable when the LLM goes
sideways.

**T3.8 — Design system v2 + Storybook**
(PR [#331](https://github.com/beenuar/AiSOC/pull/331)). The console
finally has a single source of truth for tokens, primitives, and
composites. `apps/web/src/components/ui/` is now organized as
`tokens / primitives / patterns`, every component renders in Storybook,
and the visual-regression CI gate from Phase 4.7 watches it.
`DraftFromPromptDialog` was momentarily lost during the migration and
restored in PR [#335](https://github.com/beenuar/AiSOC/pull/335). The
Vite `publicDir` copy that broke the Storybook build under the new
config was disabled in PR
[#336](https://github.com/beenuar/AiSOC/pull/336) so main CI stays
green.

**T4 — Wave-3 marketplace scaffolding + six hardened connectors**
(PR [#333](https://github.com/beenuar/AiSOC/pull/333)). The marketplace
registry gains the schema + tooling for the third connector wave; six
wave-2 connectors had their tests and fixtures hardened to wave-1 parity
in PR [#328](https://github.com/beenuar/AiSOC/pull/328) so every
first-party connector ships with the same shape of negative-path
coverage.

**T5.3 — AIT-LDS + MITRE Engenuity fidelity loaders**
(PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
Detection-fidelity scoring now ingests two canonical labelled datasets:
the AI-Threats Labelled Dataset and the MITRE Engenuity ATT&CK
evaluation set, both fronted by deterministic loaders so the
fidelity-score outputs are reproducible across CI runs.

### Threat-actor attribution — port fix + RBAC

Two narrowly-scoped fixes that together close the only path by which the
investigation agent could silently degrade.

`services/agents/app/agents/investigation_agent.py` defaulted
`AISOC_THREATINTEL_URL` to `http://threatintel:8083`. The service binds
**8005** in its Dockerfile, in `docker-compose.yml`, and in the README
service table — every `POST /api/v1/actors/attribute` call therefore hit
a port nothing listens on. The error path was soft-handled, so
attribution wasn't 500-ing; it was returning empty
attribution silently. PR [#327](https://github.com/beenuar/AiSOC/pull/327)
corrects the default to `http://threatintel:8005`, fixes the matching
`docs/threat-actor-attribution.md` references, raises the stale
`AISOC_ATTRIBUTION_TIMEOUT_SECONDS` default from `10` to `30`, and adds
a regression test (`services/agents/tests/test_attribution_service_url.py`)
that pins the URL and timeout so this can't drift again.

PR [#329](https://github.com/beenuar/AiSOC/pull/329) layers an opt-in
shared-secret gate on the actor-attribution router. When
`AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
must present `Authorization: Bearer <token>`; the comparison is
constant-time, `401` on mismatch. When the env var is unset, the
endpoints stay unauthenticated for backward compatibility and emit a
single startup warning so the operator knows the gate isn't on. The
investigation agent forwards the token via its own
`AISOC_THREATINTEL_SERVICE_TOKEN`. Resolves the
`[#TODO-attribution-rbac]` caveat in `docs/threat-actor-attribution.md`.

### Marketing-shell unification on `tryaisoc.com`

Pre-7.5 the marketing surface was rendering two different navigation
components — the richer `StickyNav` on the landing page and the older
`LandingNav` everywhere else — and likewise two footers. Subpage visitors
saw a degraded nav with hash-only anchors that misbehaved (e.g. `#pricing`
on `/about` was a no-op rather than navigating to `/pricing`).

The unification (commit
[`77039a41`](https://github.com/beenuar/AiSOC/commit/77039a41)):

- `apps/web/src/app/(marketing)/layout.tsx` now imports `StickyNav`
  and `sections/Footer` and renders them around `{children}`. Every
  page in the `(marketing)` route group is content-only.
- Eleven marketing pages had their per-page nav/footer JSX + imports
  removed — they now inherit from the layout.
- The standalone routes (`not-found.tsx`, `why-open-source/page.tsx`,
  `benchmark/page.tsx`) — which live *outside* `(marketing)` and so
  can't pick up its layout — import `StickyNav` and `sections/Footer`
  directly.
- `StickyNav`'s `NAV_LINKS` were absolutised so they work from any URL:
  `/#solution`, `/#pillars`, `/#connectors`, `/benchmark`, `/pricing`,
  `docs/intro`. The "Self-host" CTA points at `/pricing` for the same
  reason.
- `apps/web/src/components/landing/LandingNav.tsx` and
  `apps/web/src/components/landing/Footer.tsx` were **deleted**.

Bundled in the same QA wave:

- **`ISSUE-002`** — `Testimonials` "Become a reference partner" CTA was
  pointing at `/partners`, which 404s. Now goes to `/contact`.
- **`ISSUE-003`** — `/signup` 308-redirects to `/dashboard`. The
  anonymous demo dashboard *is* the signup flow; the old form-fronted
  signup is gone.
- **`ISSUE-004`** — `/not-found` is now a branded dark-theme page with
  the unified shell and a "back to home" CTA, replacing Next's default.
- **`ISSUE-005`** — Removed the dead `status.tryaisoc.com` link from
  the footer.
- **`ISSUE-007`** — `/about` rendered "the 69connectors" because
  React's JSX text-children whitespace rules drop the leading space of
  a text segment that wraps right after a `{expression}`. Forced an
  explicit `{' '}` token so the layout-quirk is immune to reflow.

### Knowledge-base — boundary-aware chunking with overlap

PR [#321](https://github.com/beenuar/AiSOC/pull/321) (closes
[#277](https://github.com/beenuar/AiSOC/issues/277)). The previous
chunker split on a flat character budget, which routinely produced
mid-sentence chunks and severed code fences. The new chunker walks the
document with `paragraph → sentence → token` precedence, applies an
overlap (default 64 tokens, configurable) so retrieval doesn't lose
context across chunks, and keeps every produced chunk under the
embedding model's hard token budget. Retrieval quality on the existing
KB ingestion fixtures improved without any model change.

### Realtime — short-lived ticket auth on WS/SSE

PR [#246](https://github.com/beenuar/AiSOC/pull/246) (closes
[#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
service previously accepted any WebSocket or SSE connection — there was
no way to assert which tenant a stream belonged to except via the
client's word for it. Connections now require a short-lived signed
ticket that the API issues to the authenticated session; the ticket
encodes the tenant and the subscription scope and expires after a small
window so a stolen ticket can't long-tail. Closes a multi-tenant
fan-out surface that had been live since the realtime service shipped.

### Infrastructure — Terraform CI + missing core modules

PR [#251](https://github.com/beenuar/AiSOC/pull/251) — every push that
touches `infra/terraform/**` now runs `terraform init -backend=false`,
`terraform validate`, and `terraform fmt -check -recursive` against the
AWS, GCP, Azure, and BYOC configurations. The same gates ran locally in
the v7.4.0 deploys; they're now actually enforced.

PR [#252](https://github.com/beenuar/AiSOC/pull/252) — the AWS and BYOC
references in v7.4.0 imported `infra/terraform/modules/rds`,
`modules/elasticache`, and `modules/kafka` from sources that did not
exist in the repo. The three modules are now actually present, so a
fresh `terraform init` against the multi-cloud skeletons no longer
errors on a missing source. PR
[#243](https://github.com/beenuar/AiSOC/pull/243) drops the
sensitive-var taint from `for_each` in the GCP module so the plan stays
clean. PR [#247](https://github.com/beenuar/AiSOC/pull/247) documents
the Azure Terraform skeleton end-to-end in `apps/docs/`.

### Dependency & CI maintenance

Around fifteen Dependabot landings since v7.4.0; the headline ones:

- **FastAPI** updated in `services/api`, `services/actions`, and
  `services/agents` (PRs
  [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320)).
- **`next`** 16.2.7 → 16.2.9 (PR
  [#323](https://github.com/beenuar/AiSOC/pull/323)).
- **`framer-motion`** 11.18.2 → 12.40.0 (PR
  [#307](https://github.com/beenuar/AiSOC/pull/307)).
- **`cryptography`** updated in `services/api` and `services/actions`
  (PRs [#301](https://github.com/beenuar/AiSOC/pull/301),
  [#302](https://github.com/beenuar/AiSOC/pull/302)).
- **`redis/go-redis/v9`** updated in `services/enrichment` and
  `services/ingest` (PRs
  [#297](https://github.com/beenuar/AiSOC/pull/297),
  [#298](https://github.com/beenuar/AiSOC/pull/298)).
- **`strawberry-graphql`** updated in `services/api`
  (PR [#318](https://github.com/beenuar/AiSOC/pull/318)).
- **`actions/checkout`** v6 → v7 across every workflow
  (PR [#316](https://github.com/beenuar/AiSOC/pull/316)).
- **`aiohttp`** 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).
- **pnpm audit** cleared of all high/critical findings
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  queue could merge without the global gate failing on unrelated noise.
- **`pnpm-lock.yaml`** duplicate `@mdx-js/react` key fixed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)) — was breaking
  `pnpm install` on fresh clones.
- Other dev/test bumps: `@xyflow/react` 12.10.2 → 12.11.0
  (PR [#283](https://github.com/beenuar/AiSOC/pull/283)),
  `@types/node` 20.19.39 → 25.9.2
  (PR [#285](https://github.com/beenuar/AiSOC/pull/285)),
  `tsx` 4.22.1 → 4.22.4 (PR
  [#306](https://github.com/beenuar/AiSOC/pull/306)),
  `@tailwindcss/postcss` 4.3.0 → 4.3.1 (PR
  [#305](https://github.com/beenuar/AiSOC/pull/305)).

### Docs

- `AISOC_V8_PROGRESS.md` tracker re-introduced
  (PR [#334](https://github.com/beenuar/AiSOC/pull/334)) so the v8.0
  milestone burn-down lives at the repo root again.
- `AGENTS.md` updated to record AiSOC (`github.com/beenuar/AiSOC`) as the
  single source of truth — the older `AISOC-Cyble` mirror is now
  archived (PR [#326](https://github.com/beenuar/AiSOC/pull/326);
  archive-notice sync in PR
  [#325](https://github.com/beenuar/AiSOC/pull/325); `plans/cyble-aisoc/`
  subtree merged for posterity in PR
  [#324](https://github.com/beenuar/AiSOC/pull/324)).
- Marketing-page docs links repointed at the Docusaurus site
  (PR [#245](https://github.com/beenuar/AiSOC/pull/245)).
- Connector pages — Vault → Auth0/Okta cross-links unbroken
  (post-merge fix on `main`).
- `README.md` synced to v7.4.0 ahead of this release
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246)).

### Changed

- **`VERSION`** bumped 7.4.0 → 7.5.0.
- **`apps/web/package.json`** bumped 7.3.1 → 7.5.0. The web app's
  `package.json` had drifted from `VERSION` since the v7.3.1 hotfix;
  this release reconciles them.
- **`README.md`** version badge + headline updated to v7.5.0.

### Migration notes

None required for users on v7.4.0 — every change in this release is
either additive (new endpoints, new env vars defaulting to safe
unauthenticated behaviour, new connectors and executors) or a pure bug
fix to existing behaviour. Specifically:

- The threat-actor attribution port fix changes a *default* — if you
  had explicitly set `AISOC_THREATINTEL_URL` in your environment, it is
  honoured unchanged.
- The optional `AISOC_THREATINTEL_SERVICE_TOKEN` gate is off until you
  set it. Set it on both the `agents` and `threatintel` services to
  turn the gate on.
- The Realtime short-lived-ticket auth is enforced server-side; the
  `apps/web` client mints + refreshes tickets automatically against the
  authenticated API session. No client work is required for in-tree
  consumers; external SSE consumers must adopt the ticket flow.
- The marketing-shell unification is a `tryaisoc.com`-only change; it
  doesn't touch the console at `tryaisoc.com/dashboard` or any
  product surface.

## [7.4.0] — 2026-05-29

Security-hardening and platform release. Folds in the May 27–29 hardening wave,
multi-agent routing, and multi-cloud infrastructure skeletons that landed on
`main` since v7.3.1.

### Highlights

- **Security hardening.** Prompt-injection sanitizer wired into the
  classification agents (PR [#219](https://github.com/beenuar/AiSOC/pull/219));
  cross-tenant isolation enforced on the detection-loop suggestion lookups
  (PR [#221](https://github.com/beenuar/AiSOC/pull/221)) and on the compliance,
  phishing, and knowledge-base endpoints
  (PR [#236](https://github.com/beenuar/AiSOC/pull/236)); nightly cross-tenant
  RBAC regression gate (PR [#197](https://github.com/beenuar/AiSOC/pull/197));
  cryptography CVEs cleared and unfixable advisories time-boxed
  (PR [#229](https://github.com/beenuar/AiSOC/pull/229)); CodeQL quality notes
  resolved (PR [#224](https://github.com/beenuar/AiSOC/pull/224)).
- **Multi-agent routing.** `DetectAgent.process` wired to the `FusionEngine`
  over cross-service HTTP (PR [#198](https://github.com/beenuar/AiSOC/pull/198));
  `/investigate` swapped to the `RouterOrchestrator` behind the
  `ROUTER_INVESTIGATE` flag (PR [#196](https://github.com/beenuar/AiSOC/pull/196));
  Redis-backed scheduler singleton guard for in-process workers
  (PR [#218](https://github.com/beenuar/AiSOC/pull/218)).
- **Multi-cloud infrastructure.** Serverless-container Terraform skeletons for
  GCP (Cloud Run + Cloud SQL + Memorystore) and Azure (Container Apps +
  PostgreSQL Flexible Server + Cache for Redis), mirroring the AWS/EKS reference
  file-for-file (PR [#240](https://github.com/beenuar/AiSOC/pull/240)).
- **Live dashboard & landing.** Real `/metrics` data restored on
  `tryaisoc.com/dashboard` (PR [#192](https://github.com/beenuar/AiSOC/pull/192));
  API/agents machines kept warm so the dashboard no longer 500s
  (PR [#234](https://github.com/beenuar/AiSOC/pull/234)); seed timestamps
  re-anchored so the live dashboard never goes empty
  (PR [#235](https://github.com/beenuar/AiSOC/pull/235)); landing CTAs pointed at
  the live dashboard (PR [#233](https://github.com/beenuar/AiSOC/pull/233)).
- **Dependency & CI maintenance.** ~40 Dependabot upgrades across the Python,
  JS, and Go services plus CI stabilization (Ruff cleanup, OpenAPI export
  permissions, pnpm-lock dedupe).

### Bump `@vitejs/plugin-react` 4.7.0 → 6.0.2 in `apps/web`

Dev-only dependency upgrade (PR [#178](https://github.com/beenuar/AiSOC/pull/178)).
`@vitejs/plugin-react@6` is built against vite@8, while vitest@4 (landed in
PR #179) still ships its own internal vite@7. pnpm resolves both side-by-side
without conflict: vitest@4 uses vite@7 for the test runtime, and `react()` is
loaded from the vite@8-flavoured build of the plugin. Vitest is tolerant of
the plugin API surface across vite 5/6/7/8, so `apps/web/vitest.config.ts`
needed no further changes after the cast we already removed in #179.

No production code touched. Locally verified: web 349/349 tests pass, lint
remains at 0 errors / 76 warnings (unchanged baseline), `tsc --noEmit` clean,
production build succeeds.

### Bump `vitest` 2.1.9 → 4.1.6 across the workspace

Dev-only dependency upgrade (PR [#179](https://github.com/beenuar/AiSOC/pull/179))
across `apps/web`, `packages/sdk-ts`, and `services/mcp`. Vitest v3 and v4
introduced two breaking changes that surfaced in our suite:

* **`vitest/config` no longer exports `UserConfig`.** `apps/web/vitest.config.ts`
  used `import('vitest/config').UserConfig['plugins']` to bridge the vitest@2
  (vite@5 types) ↔ `@vitejs/plugin-react@4` (vite@7 types) version mismatch. In
  vitest@4 both packages target vite@7, so the bridging cast is gone and
  `react()` is consumed directly.
* **`global` is no longer in the default DOM lib in `@vitest/runner`'s typing.**
  `packages/sdk-ts/src/client.test.ts` referenced the Node global namespace via
  `(global.fetch as ...)`; it now uses `globalThis.fetch`, which is the
  cross-runtime idiom and was already what every other test in the SDK suite
  used. No runtime behaviour change — `global === globalThis` in Node.

Verified locally: SDK 9/9 tests pass, web 349/349 tests pass, web lint stays at
0 errors (warning count unchanged from PR #193's baseline). No production code
touched, no behavioural change to the published `@aisoc/sdk` package or to the
shipped web bundle.

### Wire `DetectAgent.process` to `FusionEngine` via cross-service HTTP (Issue #190)

Closes [#190](https://github.com/beenuar/AiSOC/issues/190).

Closes the missing edge in the four-agent façade: `DetectAgent` previously
self-described as the public detection surface but had no synchronous entry
point into the fusion pipeline — callers either had to enqueue onto Kafka and
wait, or reach into `services/fusion` internals directly. This change adds the
last mile so a raw alert from any caller (LLM tool calls, ad-hoc CLI, the API
gateway) runs through the same `FusionEngine` instance that backs the Kafka
consumer path — dedup, correlation, ML scoring, confidence labelling, and RBA
all apply identically regardless of how the alert arrived.

Three additive pieces, no behavioural changes to existing paths:

* **`POST /process` on the fusion service**
  (`services/fusion/app/api/router.py`). Accepts a `RawAlert`, returns a
  `FusedAlert`, and is wired to the already-running `FusionWorker`'s engine
  instance via the module-level `_worker_ref` the worker registers on startup.
  Returns `503` when the worker hasn't finished booting (Kafka consumer not
  yet attached) so callers fail loudly instead of getting a half-initialised
  pipeline. Lives at the root path — the router is mounted with no prefix in
  `services/fusion/app/main.py`.
* **`services/agents/app/tools/fusion.py`** — thin async HTTP client used by
  the agents service. Posts to `{FUSION_SERVICE_URL}/process` (defaults to
  `http://fusion:8003/process` inside the docker-compose network), forwards
  an optional bearer token, and **raises** on any non-2xx or transport error.
  This is a deliberate contrast with `app.tools.graph`, which degrades
  gracefully for investigation queries: fusion is the primary detection
  plane, so a silent fallback here would lose alerts.
* **`DetectAgent.process(raw_alert, *, api_token=None)`**
  (`services/agents/app/agents/__init__.py`). Classmethod delegate over the
  HTTP client — keeps `DetectAgent` import-light (no engine instantiation in
  the agents process) and preserves the existing back-compat aliases.

Tests lock the contract on both sides. `services/fusion/tests/test_process_endpoint.py`
exercises the endpoint against an `ASGITransport` + `AsyncClient`: novel
alerts return a `NEW_INCIDENT` envelope, replays return `DUPLICATE`, an
unwired worker yields `503`, a worker without an engine yields `503`,
malformed and bad-severity payloads return `422`, and a regression guard
asserts the endpoint and worker share the same `FusionEngine` instance.
`services/agents/tests/test_fusion_client.py` uses `respx` to lock the
client wiring: it must post to `/process` (not `/api/fusion/process` — that
mismatch was caught and fixed during initial wiring), the Authorization
header is set if and only if a token is supplied, `httpx.HTTPStatusError`
propagates on 503/422, and `httpx.HTTPError` propagates on transport
failures. A final trio of tests pins `DetectAgent.process` as a faithful
delegate to the client (args pass through unchanged, errors propagate, no
swallowed exceptions).

No feature flag and no env gate: the wiring is purely additive — no existing
caller of the fusion service or the agents service changes shape, and the new
endpoint/method only fire when something explicitly invokes them.

### Cross-tenant RBAC regression suite (F013, security)

Closes [#159](https://github.com/beenuar/AiSOC/issues/159).

Pure-unit isolation suites that exercise the tenant boundary at the
endpoint-function level (no live DB, no FastAPI request cycle) so the
contract is testable in milliseconds and survives ORM churn:

- `services/api/tests/test_threat_intel_tenant_isolation.py` — IOC,
  actor, and feed list/get/create/delete are scoped by `tenant_id`,
  cross-tenant lookups resolve to 404, and writes attach
  `current_user.tenant_id` even when the payload smuggles a different
  one.
- `services/api/tests/test_alerts_tenant_isolation.py` — every
  read/write/queue/claim path on `/alerts` binds `tenant_id` into the
  compiled SQL or forwards it to the service layer
  (`build_queue` / `claim_alert`).
- `services/api/tests/test_llm_credentials_tenant_isolation.py` —
  BYOK credential GET/PUT/DELETE scope by `tenant_id`, new rows bind
  the caller's tenant, and `emit_audit` is invoked with the caller's
  tenant + actor (`CredentialVault` is stubbed so the assertions are
  on the persistence boundary, not crypto).

Assertions read the *compiled* SQL bind parameters rather than the
shape of any single query so they don't break on benign rewrites. All
three suites were mutation-tested by temporarily dropping the
`tenant_id` predicate in the corresponding endpoint — every dropped
predicate produced at least one failing test, confirming the suites
are wired to the right surface.

`.github/workflows/cross-tenant-rbac.yml` runs the three suites
nightly on `main` (06:30 UTC, ahead of `compose-smoke-nightly` so a
tenant boundary regression shows up as the first nightly signal) and
on-demand via `workflow_dispatch`. On failure it uploads a JUnit
report and opens a `security`-labelled tracking issue.

### Attack-chain timeline UI (T3.3, v8.0)

`/cases/{id}` now ships an **Attack Chain** tab that visualises the ranked
timeline returned by `/v1/cases/{id}/attack-chain` (shipped earlier under
`8df637b9`). The new `AttackChainPanel` in
`apps/web/src/components/cases/CaseWorkspace.tsx`:

- Window selector with the same vocabulary as the backend `WindowLiteral`
  (`1h`, `6h`, `24h`, `72h`, `7d`, `30d`) — selection is deep-linkable via
  `?window=…` and survives reload.
- One card per `ChainLink` with the alert title, severity chip (driven by
  the canonical 5-tier ladder `info | low | medium | high | critical`),
  confidence percent, MITRE technique IDs, and the deterministic narrative
  reason emitted by `services/api/app/services/attack_chain.py`.
- Entity-graph summary panel — node count grouped by `kind` (`user`,
  `asset`, `process`, `ip`, `domain`, `alert`), top edges, and a per-node
  severity chip when present in `_entity_graph_payload`.
- SWR-keyed on `(case_id, window)` with skeleton, error, and empty states
  that match the rest of the case workspace.
- New `casesApi.getAttackChain` method + `AttackChainTimeline`,
  `AttackChainWindow`, `AttackChainLink`, `AttackChainEntityNode`,
  `AttackChainEntityEdge`, `BackendAttackChainResponse` types in
  `apps/web/src/lib/api.ts`. The wire format matches the backend `to_dict`
  shape exactly (node `kind` rather than `type`; optional `severity` and
  `event_time` from `_entity_graph_payload`).
- Coverage in `apps/web/src/components/cases/CaseWorkspace.test.tsx`:
  empty-state, error-state, and three data-rendering assertions
  (alert titles, confidence percent, MITRE techniques). The SWR mock is now
  key-aware so attack-chain and attack-path fetches stay isolated, and
  `useSearchParams` is stateful so window-selection deep-links round-trip
  cleanly under test. The `WindowSelector` is a labelled
  `role="group"` of buttons with `aria-pressed`, so deep-link assertions
  resolve the active option via the single pressed button inside the
  group rather than a non-existent `<select>` value.

Closes the UI side of T3.3 in `AISOC_V8_PROGRESS.md`. Pre-existing
non-blocking lint warnings in `CaseWorkspace.tsx` are unchanged by this
diff.

### LLM input contract — static regression gate (T2.3, v8.0)

Closes T2.3 by adding the missing **bypass-prevention** layer on top of the
existing fail-closed validator (`services/agents/app/llm/contract.py`). Two
new test files in `services/agents/tests/`:

- `test_llm_contract_extra.py` (10 cases) — fills the coverage gaps in the
  shipped contract: `safe_astream` validates messages exactly once and
  refuses to yield any chunk on violation; `make_safe_chat_model` proxies
  non-LLM attributes through but routes `ainvoke` / `astream` through
  validation; `classify_message` rejects `api_key = '...'` assignments and
  PEM private-key headers; `set_contract_enforcement(False)` lets raw OCSF
  through in soft mode and re-arms cleanly when flipped back to `True`.
- `test_llm_contract_no_bypass.py` (3 cases) — **AST-based static gate**
  that walks every `*.py` file under `services/agents/app/` and fails CI on
  any direct `.ainvoke(...)` / `.astream(...)` call whose receiver is not on
  an explicit allowlist (`_graph`, `investigation_graph`, `graph` — all
  LangGraph control-flow handles, not LLMs) or whose file is not the
  contract module itself. Ships with self-tests proving (a) a synthetic
  `llm.ainvoke(...)` bypass trips the detector and (b) allowlisted
receivers do not. Adding a new agent that calls a chat model directly
now fails the build until it routes through `safe_ainvoke` /
`safe_astream` / `make_safe_chat_model`.

The survey behind this gate confirmed every existing direct chat-model call
under `services/agents/app/` already goes through the safe wrapper — the
remaining `.ainvoke` / `.astream` call sites are LangGraph control-flow on
compiled graphs, which is why those receivers are explicitly allowlisted
rather than silently ignored.

### LLM input contract — CI tests (T2.3, v8.0)

`services/agents/tests/test_llm_contract.py` exercises `classify_message` /
`LLMInputContract.validate` / `validate_messages`: raw OCSF-shaped JSON in a
user message fails closed when `AISOC_AGENTS_LLM_CONTRACT_ENFORCED=1`
(default), and prose plus `summarize_structure_for_llm` output passes. Tests
use `{"role", "content"}` dict messages so they run without importing
`langchain_core` (the contract already coerces LangChain `BaseMessage` and
dicts the same way).

### Real-time graph-update WebSocket (T1.4, v8.0)

Closes the v8.0 loop between the ingest-side graph writer (T1.1) and the
operator console. `services/realtime` now exposes a `graph` WebSocket
channel reachable at `/ws/graph` (or piggy-backed on `/ws/all`) and runs a
dedicated `aisoc-realtime-graph` Kafka consumer group against the
`security.graph_updates` topic that the Go ingest writer publishes to
(`services/ingest/internal/graph/writer.go`). Each `GraphUpdate` envelope
(`entity_id`, `change_type`, `ts`, `label`, `rel_type`, `from`, `to`,
`properties`, `schema_version`) is fanned out to clients scoped by
`tenant_id`, with `default` as the single-tenant fallback so self-hosted
deploys without explicit tenant tagging still light up live. The new
consumer is wired alongside the existing fused-alerts consumer in
non-blocking mode: a missing or unreachable graph topic logs at `warn` and
never blocks the higher-priority alerts/cases/agents/insights fan-out. The
topic name honours both `AISOC_GRAPH_UPDATES_TOPIC` and
`KAFKA_TOPIC_GRAPH_UPDATES` envs (defaults to `security.graph_updates` so
it matches the Go writer's default in
`services/ingest/internal/config/config.go` without manual plumbing), and
setting it to the empty string disables the consumer entirely for tests
that don't spin up Kafka graph traffic. The Investigation Rail and Attack
Chain views (T3.3 UI, in flight) can subscribe today and pick up node /
edge mutations within ~1s of the upstream event reaching ingest.

### Public weekly benchmark scoreboard at /docs/benchmark-scoreboard

Public, append-only weekly scoreboard now lives at
[`/docs/benchmark-scoreboard`](https://docs.tryaisoc.com/docs/benchmark-scoreboard).
One row per published eval run — date, agent version, commit SHA, MITRE
accuracy, MTC p50/p95, total USD, total tokens — sourced from a
checked-in JSON file at `apps/docs/static/data/scoreboard.json` and
validated against `scoreboard.schema.json` on every docs build via the new
`pnpm --filter @aisoc/docs scoreboard:check` script. Substrate rows
(deterministic CI gate, no LLM) are visually separated from wet-eval rows
(real LangGraph agent, real LLM, real cost), so substrate numbers can
never be quoted as live agent performance. Includes an inline SSR-rendered
SVG sparkline of MITRE accuracy over time, no Recharts/client JS bundle
hit. The marketing `/benchmark` page now cross-links to the scoreboard for
the full weekly history. Wet-eval rows arrive automatically once the T5.5
weekly CI workflow lands.

### Connectors — Wazuh Indexer ingest (Stage 2)

New first-class endpoint connector for Wazuh deployments. AiSOC now polls the
Wazuh Indexer API directly (no agent rewrite required) and normalizes alerts
into the platform's OCSF-aligned schema, collapsing Wazuh's native severity
ladder into the four-tier `info | low | medium | high` set used everywhere
else.

- **`services/connectors/app/connectors/wazuh.py`** — `WazuhConnector`
  subclasses `BaseConnector`, polls `wazuh-alerts-*` indices over HTTPX with
  basic-auth, paginates time-windowed queries, retries on 5xx with capped
  backoff, and emits one normalized event per alert hit. Cursor is the
  highest `@timestamp` seen so reruns are idempotent.
- **`services/connectors/app/connectors/__init__.py`** — registered in
  `_CONNECTOR_CLASSES`; the registry now declares 52 first-party connectors.
- **`plugins/wazuh/plugin.yaml`** + `pnpm marketplace:sync` — connector ships
  as a marketplace entry under category `siem`, mirrored into
  `apps/web/public/marketplace/index.json`.
- **`apps/docs/docs/connectors/wazuh.md`** + sidebar entry — operator setup
  walkthrough (API user + role, time-window semantics, severity collapse
  table, troubleshooting matrix).
- **`services/connectors/tests/test_wazuh_connector.py`** — 24 unit tests
  cover schema, auth headers, time-window query shape, retry policy, every
  documented severity bucket, and the empty/error paths.

### CLI — `aisoc plugin new` per-type templates

Replaces the old hard-coded `plugin scaffold` with a real templated generator
keyed on plugin kind (`enricher | connector | responder | detection | widget`).
Templates ship inside the `aisoc-cli` wheel via `importlib.resources` so the
CLI works unchanged after `pip install aisoc-cli`.

- **`packages/aisoc-cli/src/aisoc_cli/main.py`** — `aisoc plugin new <NAME>
  --type <kind>` loads the template tree from
  `src/aisoc_cli/templates/<kind>/`, runs `string.Template` substitution for
  `${slug}`, `${name}`, `${author}`, and writes a project that already
  validates against the manifest schema. `aisoc plugin scaffold` is preserved
  as an alias for backwards compatibility.
- `pyproject.toml` — `force-include` ships the templates tree in the wheel.
- Tests parameterize across all five plugin types and assert the manifest
  validates and no `${...}` placeholders leak through.
- `plugins/templates/README.md` is now a pointer to the canonical templates
  inside the CLI package.
- **`apps/docs/docs/plugins/cli.md`** — documents the new CLI surface and is
  added to the Plugin SDK sidebar.

### Infrastructure — GCP Cloud Run + Cloud SQL Terraform skeleton

Adds a serverless-first BYOC equivalent of the existing AWS module so AiSOC
can be stood up on Google Cloud with one `terraform apply`. Stage 2 #15.

- **`infra/terraform/gcp/`** — Cloud Run for `api`/`web`/`ingest`, Cloud SQL
  Postgres 16 + Memorystore Redis 7.2 on private IPs through a dedicated VPC
  and Serverless VPC Access connector, Secret Manager for every credential
  (auto-generated `postgres_password`, `secret_key`, `credential_key`,
  `redis_auth`, optional `openai_api_key`), and Artifact Registry for images.
  One service account per Cloud Run service with least-privilege
  `secretAccessor` bindings. The skeleton points at the public GHCR demo
  images so a fresh `apply` works zero-config; operators override via
  `api_image` / `web_image` / `ingest_image`.
- **`apps/docs/docs/deployment/gcp.md`** + sidebar entry (between `kubernetes`
  and `env-vars`) — quickstart, state-backend guidance, Cloud SQL Auth Proxy
  notes, cost envelope, and the long-running-services follow-up plan (GKE
  Autopilot for `agents`, `realtime`, `connectors`, `alert-fusion`,
  `threatintel`, `fusion`).
- `infra/terraform/gcp/README.md` mirrors the deploy doc for module-local
  consumption.

### Live Actions — generic vendor/capability dispatcher (Stage 2 #8)

Adds a vendor-pluggable response-action surface so plugins can register
executors against the existing capability taxonomy without forking the
in-tree executor list. The dispatcher always returns a typed
`LiveActionResult`; unknown `(vendor_id, capability)` pairs return `FAILED`
with `error="executor_not_found"` so the agent degrades gracefully instead
of seeing a 500.

- **`services/actions/app/live_actions/models.py`** —
  `LiveActionRequest`/`Result`/`Descriptor` Pydantic models (UTC-aware).
- **`services/actions/app/live_actions/registry.py`** — `LiveActionExecutor`
  ABC + module-level `LiveActionRegistry`.
- **`services/actions/app/live_actions/dispatcher.py`** — structured logging,
  error translation, dry-run + missing-credential semantics
  (`SIMULATED`, never `PARTIAL`).
- Adapters wrap every existing in-tree executor (CrowdStrike, Okta, AWS SG,
  Splunk) so they now show up as `builtin` descriptors.
- **`services/api/app/api/v1/endpoints/live_actions.py`** — `discover`,
  `dispatch`, `dry-run` REST routes; built-ins are registered at app startup.
- 45 new tests across models / registry / dispatcher / router / builtins
  (full actions suite: 99 passed).
- **`apps/docs/docs/concepts/live-actions.md`** + sidebar slot.
- Drive-by: fixed two pre-existing broken doc links flagged by the
  Docusaurus build (osctrl → aisoc-direct stub, `air-gapped` → `env-vars`).

### Agents — deterministic NL→ES|QL translator + 50-pair eval set (Stage 2 #16)

Replaces the template fallback in
`services/api/app/api/v1/endpoints/nl_query.py` with a real, offline-friendly,
deterministic IR + renderer that emits ES|QL, KQL, and SPL and runs every
output through a lightweight grammar validator before returning. An optional
LLM enhancement path (`gpt-4o-mini`) is exposed via `enhance_with_llm` for
callers with credentials; failures fall back to the deterministic path so the
air-gapped story keeps working and the eval harness stays reproducible.

- **`services/agents/app/nl_query/`** — IR, grammar, translator, renderers.
- All `# TODO: translate` comments removed from `nl_query.py`.
- **`services/agents/tests/eval_data/nl_query_eval.json`** — 50-pair gold
  NL→ES|QL eval set.
- **`services/agents/tests/test_nl_query_eval.py`** — 100% syntactic validity,
  100% semantic match (50/50 perfect) against gold intents.
- Pre-existing services/agents tests still green (162 passed) when ignoring
  the asyncpg-dependent suites that fail on a fresh checkout.

### Connectors — auditd file_tail + AiSOC audit.rules profile

Replaces the host-agent dependency for Linux endpoint visibility with a
file-tail connector that consumes `audit.log` directly, plus an opinionated
auditctl ruleset whose `-k` keys map 1:1 to detection rules.

- **`services/connectors/app/connectors/auditd.py`** — `AuditdConnector` tails
  `/var/log/audit/audit.log`, reassembles multi-record events by msg id,
  decodes hex `proctitle`/`argv` blobs, and normalizes via
  `_severity_from_event` using `aisoc_*` keys baked into the audit rules
  profile. Cursor is `(inode, byte_offset)` so log rotation is handled.
- **`profiles/auditd/aisoc.rules`** + `profiles/auditd/README.md` — ships an
  opinionated auditctl ruleset and documents install + reload.
- **`detections/`** — 4 new detection rules pivot off `auditd_key` for
  sudoers / SSH config tampering, kernel module load, and systemd
  persistence. No host-agent dependency.
- `plugins/auditd/plugin.yaml` + `pnpm marketplace:sync` — registers the
  connector in the public marketplace.
- **`apps/docs/docs/connectors/auditd.md`** + sidebar entry — setup doc.
- **`services/connectors/tests/test_auditd_connector.py`** — covers schema,
  hex decode, argv reassembly, multi-record merge, severity heuristic, and
  file tailing (full connectors suite: 444 passed, excluding the
  `apscheduler` dev-dep `test_scheduler.py`).

### Documentation — operator notifications & plugin lifecycle

Two new operator-facing docs pages, both registered in the Docusaurus sidebar:

- **`apps/docs/docs/operations/notifications.md`** — complete inventory of
  every notification surface in AiSOC: Web Push to the responder PWA (VAPID,
  Redis, topic routing), Slack ChatOps via `/aisoc`, Slack/Teams ChatOps
  verification, one-shot `notify_slack` from playbooks, `create_ticket`
  simulation + recommended plugin path, honeytoken first-touch webhooks,
  connector freshness alerts, on-call gating, suppression / quiet-hours, and
  a per-mechanism testing recipe.
- **`apps/docs/docs/plugins/lifecycle.md`** — operator's view of plugin
  states (`Discovered → Loaded → Enabled/Disabled`, plus `signature_status`),
  trust modes (`strict | warn | disabled`), filesystem + OCI discovery, the
  full operator REST API with required permissions, configuration reference,
  upgrade and rollback semantics, and the structlog events worth alerting on.

Both pages cross-link the existing `concepts/live-actions`, `plugins/overview`,
`plugins/publishing`, and `plugins/cli` pages so they sit in the right place
in the information architecture.

### API — blameless case post-mortem endpoint

Mirrors the existing case auto-summary pipeline to produce a deterministic,
blameless retrospective for any case.

- **`services/api/app/services/case_postmortem.py`** — pure builder + async
  DB orchestrator (`build_case_postmortem`). Reuses `SummaryCaseRow` /
  `SummaryCommentRow` / `SummaryTaskRow` fetchers from `case_summary` so the
  post-mortem and the live summary draw from the same source of truth.
  Output is a Pydantic `CasePostmortem` covering incident overview,
  contributing factors, detection timing/gaps, response phases (detect →
  contain → eradicate → recover), blast radius, what went well / what fell
  short, and concrete action items.
- **`services/api/app/services/case_postmortem_html.py`** — pure HTML
  renderer matching the summary renderer (inline CSS, print-friendly,
  defensive escaping, no external assets).
- **`services/api/app/api/v1/endpoints/cases.py`** —
  `GET /api/v1/cases/{case_id}/postmortem` with `?format=json|html`.
- **`services/api/tests/test_case_postmortem.py`** — pure-builder + HTML
  tests including XSS escaping, deterministic ordering, and explicit
  blamelessness assertions (analyst handles must not surface in the
  narrative; the assignee header line is explicitly allow-listed).
- **`apps/docs/docs/operations/case-reports.md`** + sidebar — operator page
  covering both `/summary` and `/postmortem` with audience, output,
  automation, and runbook archive guidance. Cases summary breadcrumb now
  points operators at both endpoints.

### Threat Intelligence — STIX → MISP push (Stage 3 #20)

The threat-intel pipeline already pulled events from MISP (read-only). This
closes the loop with a write path: every STIX 2.1 indicator or bundle
published through `/api/v1/threatintel/stix/...` can be mirrored into the
configured MISP instance as a native event with one or more attributes.

- **`services/api/app/services/misp_push.py`**
  - Pure mappers: `parse_stix_pattern`, `stix_indicator_to_misp_attribute`,
    `stix_bundle_to_misp_event`, `confidence_to_threat_level`. Covers
    `ipv4`/`ipv6`, `domain-name`, `url`, `email-addr`, `file:hashes`
    (MD5/SHA-1/SHA-256/SHA-512) and `file:name`. Untranslatable patterns
    are counted in `skipped_attributes`, never silently dropped.
  - `MispPushClient` — async httpx wrapper for `/users/view/me` (health),
    `/events/add` (push), `/events/view/{id}` (read-back). Every call runs
    through the air-gap gate (`enforce_airgap_for_url`) first.
- **`services/api/app/api/v1/endpoints/stix_taxii.py`**
  - `POST /stix/indicators?push_to_misp=true` — response now includes a
    `misp` block (`pushed`, `misp_event_id`, `misp_event_uuid`, `url`,
    `pushed_attributes`, `skipped_attributes`, `error`).
  - `POST /stix/bundles?push_to_misp=true` — same, but the whole bundle
    becomes one MISP event.
  - `GET /stix/misp/health` — calls MISP `/users/view/me`, never echoes the
    API key back.
  - `POST /stix/misp/dry-run` — returns the exact MISP event payload AiSOC
    *would* send, plus an `airgap_blocked` flag for air-gapped audits.
  - Push failures are intentionally non-fatal: the AiSOC store is the source
    of truth, the MISP mirror is best-effort and surfaces the structured
    error on the same response.
- **`services/api/app/core/config.py`** — new MISP push settings:
  `MISP_VERIFY_SSL`, `MISP_PUSH_AUTO`, `MISP_PUSH_DEFAULT_DISTRIBUTION`,
  `MISP_PUSH_DEFAULT_THREAT_LEVEL`, `MISP_PUSH_DEFAULT_ANALYSIS`,
  `MISP_PUSH_TIMEOUT_SECONDS`. Existing `MISP_URL` / `MISP_API_KEY` are
  reused from the read path.
- **`services/api/tests/test_misp_push.py`** — 76 tests covering pure
  mappers, air-gap gating, MISP HTTP failures (401 / 5xx / timeout), the
  publish endpoints with and without push, the health probe, and the
  dry-run endpoint.
- **`apps/docs/docs/integrations/misp-push.md`** + sidebar entry — operator
  doc with config, endpoints, the STIX→MISP type table, failure modes, and
  the dry-run-as-air-gap-proof workflow.
- **`apps/docs/docs/operations/airgap.md`** — clarifies that the existing
  `MISP_URL` / `MISP_API_KEY` envs cover both pull and push, with a pointer
  to the new integration page.

### Security — MSSP RBAC hardening on `/threat-intel` (Issue F013)

The `/v1/threat-intel/*` endpoints (IOCs, threat actors, intel feeds) were
previously gated only by `get_current_user`, meaning **any authenticated
role**, including `viewer` and `soc_analyst`, could `POST` an IOC, `DELETE`
a feed, or create a new `ThreatActor` profile. In a managed-SOC / MSSP
deployment that is a privilege-escalation vector: a compromised analyst
seat can poison detections across the whole tenant by injecting false IOCs
or deleting the feed that hydrates them.

- **`services/api/app/api/v1/endpoints/threat_intel.py`** — every route now
  declares the explicit permission it needs via
  `Depends(require_permission("threat_intel:read" | "threat_intel:write"))`.
  Read routes (`GET /iocs`, `/iocs/{id}`, `/actors`, `/feeds`) require
  `threat_intel:read`; write routes (`POST /iocs`, `DELETE /iocs/{id}`,
  `POST /actors`, `POST /feeds`, `DELETE /feeds/{id}`) require
  `threat_intel:write`. The legacy `User`-typed dependency was replaced with
  the platform-standard `AuthUser` so JWT and API-key callers are gated by
  the same code path.
- **`services/api/app/core/security.py`** — `ROLE_PERMISSIONS` now grants
  `threat_intel:write` to `tenant_admin` and `soc_lead` in addition to the
  existing `admin` / `platform_admin` / `threat_hunter` set. Without this
  the endpoint hardening would have locked out the two roles that legitimately
  need to manage tenant intel during an investigation.
- **`services/api/tests/test_threat_intel_rbac.py`** — 38 new regression tests
  pin the role/permission map (write-roles must hold `:write`, read-only roles
  must not), assert that `CurrentUser.require_permission` raises HTTP 403 for
  under-privileged roles and 200 for privileged ones, cover the API-key code
  path including scope wildcards, and grep the endpoint module to ensure
  every route still uses `require_permission(...)` (so a refactor that
  silently downgrades a route fails CI).

Tracked as **F013** in `docs/community-feedback/2026-05-12/`.

### Detection quality — per-rule cross-fire FP eval gate (Issue F005)

`scripts/validate_detections.py` already replays each native rule against
its own positive + negative fixture (TP / TN gates), but that test cannot
catch the failure mode operators feel hardest in production: rule **R**
firing on an event that was meant for rule **O**. A single overly-broad
rule that matches every `ConsoleLogin` or every `rundll32.exe` execution
silently drives alert volume up and precision down across the whole pack
without tripping the per-rule TP/TN replay.

- **`services/agents/tests/test_detection_fp_rate.py`** — new pytest
  suite that replays every native rule's `match_when` against every
  *other* rule's positive fixture and grades the per-rule cross-fire
  FPR. Fails CI if any rule exceeds `MAX_PER_RULE_FPR` (default 5%) or
  regresses on its own positive/negative fixture. Failure output groups
  the worst 10 offenders with their cross-fire targets so the operator
  can narrow the rule (or allowlist a deliberate broad-vs-narrow
  overlap via `EXPECTED_CROSS_FIRES`) without re-running a full eval
  sweep. Current corpus: 816 native rules evaluated, mean FPR 0.0,
  worst FPR 0.49% — well under the 5% ceiling.
- **`scripts/run_evals.py`** — wires the new gate into the unified
  eval runner as `suites.detection_fp_rate`, reporting
  `worst_per_rule_fp_rate` (lower-is-better) alongside the existing
  alert-reduction / investigation-completeness / response-quality
  gates so dashboards and CI consume it through the same JSON shape.

Tracked as **F005** in `docs/community-feedback/2026-05-12/`.

### Documentation — install pipeline + v2.2 architecture refresh

Documentation-only refresh that aligns every install / architecture page
with the actual shipped state of the repo. No service code, schema, or
API surface changed.

- **One-click install pipeline** is now a first-class doc surface.
  - New Docusaurus page `apps/docs/docs/installation.md` (sidebar
    position 2) walks through `install.sh` / `install.ps1` end-to-end —
    supported package managers, what gets installed, idempotency, the
    `uninstall.sh` / `uninstall.ps1` graduated cleanup flags, and the
    security model.
  - `apps/docs/docs/quickstart.md` adds it as **Path 0** ("zero-prerequisite
    bootstrap") and renumbers the demo / dev paths.
  - `apps/docs/docs/deployment/docker.md` opens with a callout to the
    installer, refreshes every host/container port mapping against
    `docker-compose.yml`, splits profile-gated services
    (`connectors`, `osquery-tls`, `slack-bot`) out of the default stack,
    and updates the GHCR image list to the full 16-image set.
  - `apps/docs/docs/intro.md` adds the installer to **Get started** and
    corrects the connector-count copy.
  - Root `README.md` already had Path 0 — verified and synced with the
    architecture refresh below.
- **v2.2 architecture surfaces** are now reflected everywhere.
  - `apps/docs/docs/architecture.md` data-flow diagram, monorepo layout,
    and Service Responsibilities table now include `services/osquery-tls`,
    `services/osquery-extensions`, and `services/slack-bot`. Connector
    count corrected to 50 (was 26 / 42 in stale paragraphs).
  - `docs/architecture/SYSTEM_DESIGN.md` connector count corrected to 50,
    Service Responsibilities table extended with the v2.2 services, and a
    new **§13 — v2.2 Additions** appended that documents endpoint
    telemetry (osquery TLS server + extensions), ChatOps (`slack-bot`),
    Responder PWA, MCP server, Investigation Ledger / Ambient Copilot,
    and the one-click install pipeline. v2 / v2.1 narrative preserved.
  - Root `README.md` mermaid diagram + service-map table extended with
    `osquery-tls`, `slack-bot`, `mcp` and the corrected
    `Realtime` / `Web Console` descriptions.
- **Connector count corrected to 50 across the repo.**
  - `apps/docs/docs/connectors/index.md`: catalog count updated and the
    23 missing connectors added across the existing categories
    (cloud / CNAPP / vuln-mgmt, SIEM, EDR/XDR, SaaS, ITSM, network,
    endpoint fleet, container orchestration).
  - `apps/docs/docs/connectors/api-coverage.md`: coverage-table heading
    updated.
  - `apps/web/src/components/onboarding/StartHero.tsx`: in-product copy
    on the onboarding tile updated.
  - `apps/docs/docs/intro.md`: two stale paragraphs updated.
  - Source of truth: `services/connectors/app/connectors/__init__.py`
    (`_CONNECTOR_CLASSES`).

Old historical entries in `AI_STACK_PLAN_PROGRESS.md` reference 42
connectors and are intentionally left as a snapshot of the v2.1 increment
they describe.

## [7.2.0] — 2026-05-11

### Changed — `docker compose up -d` is now pull-by-default

Track 1 + Track 2 of the docker-compose hardening work that began in
[7.1.1](#711--2026-05-10). 7.1.1 fixed the boot-path bugs that surfaced on
a clean clone; this release attacks the *time* dimension. The previous
behaviour — `docker compose up -d` on a fresh checkout building all 15
services from source — took 10–20 minutes on a typical laptop and was the
single largest source of "I tried AiSOC and gave up" reports. With this
release, the same command pulls 12 prebuilt images from GHCR and is
healthy in roughly 90 seconds.

No service code, no API surface, no database schema changed. Every change
in this release is in the boot path, the image-publish path, or the CI
gate that proves both still work.

#### Track 1 — Pull-by-default boot path

- **`docker-compose.yml`**: Every service that previously had a `build:`
  directive now also has an `image:` and `pull_policy: missing`. Compose
  will pull the prebuilt image from `ghcr.io/aisoc-platform/aisoc-<svc>`
  if it exists locally or in the registry; only if the pull fails does it
  fall back to building from source. The 12 backend services that publish
  images (api, agents, realtime, web, ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, slack-bot) are tagged via the
  `${AISOC_VERSION:-latest}` interpolation so the same compose file works
  for `latest`, `main`, a release tag (`v7.2.0`), or a local override.
  The three deferred services (osquery-tls, honeytokens, purple-team) are
  marked with a `# TODO(publish)` comment and continue to build locally.
- **`.env.example`**: Added a new top-of-file `AISOC_VERSION=latest`
  block that documents how to pin the entire backend to a release tag for
  reproducible deploys (`AISOC_VERSION=v7.2.0`), or track the bleeding
  edge (`AISOC_VERSION=main`).
- **`.github/workflows/publish-images.yml`**: Extended the build matrix
  from 4 services to 12 by adding ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, and slack-bot. These are the backend
  services that every full-stack `docker compose up -d` boots; without
  them in the publish matrix, `pull_policy: missing` would resolve to
  "build from source" for two-thirds of the stack and the change would be
  cosmetic.
- **`.github/workflows/release.yml`**: Mirrored the same 12-service
  matrix on tagged-release builds so that `AISOC_VERSION=v7.2.0` resolves
  to a real published image for every service in the compose file, not
  just the demo subset.

#### Track 2 — Build & CI hardening

The pull-by-default path only matters if the underlying images actually
build. Track 2 attacks the two largest historical sources of build-path
flakes — Poetry resolution failures during image build, and Dockerfile
regressions that nobody catches until release day.

- **All seven Python service Dockerfiles**
  (`services/{api,fusion,threatintel,slack-bot,actions,connectors,osquery-tls}/Dockerfile`):
  Added a `poetry install` → `pip install` fallback. The previous pattern
  failed the build on any transient PyPI hiccup, lock-file drift, or
  proxy timeout during `poetry install`. The new pattern wraps the
  install in `set -eux; if poetry install ...; then ...; else
  pip install <pinned list>; fi`, logs which path was taken, and pins
  every runtime dependency explicitly in the fallback list. The pinned
  list is documented as needing to track `pyproject.toml` and is
  exercised by the new nightly cold-cache CI run.
- **`.github/workflows/compose-smoke.yml`** (new): On every PR that
  touches `docker-compose.yml`, `docker-compose.demo.yml`, any service
  Dockerfile, `.env.example`, or the workflow itself, GitHub Actions now
  boots the full stack from a clean checkout and asserts `aisoc-postgres`
  is healthy, `api` returns 200 on `/health`, and `web` returns 200 on
  `/` — all within a 10-minute budget. Pull-by-default by design (so the
  CI run mirrors what the user sees), with automatic detection of
  Dockerfile changes that flips the workflow into rebuild-from-source
  mode so we don't smoke-test against a stale published image. Captures
  `docker compose ps`, `docker compose logs`, disk, and memory on
  failure.
- **`.github/workflows/compose-smoke-nightly.yml`** (new): At 09:00 UTC
  every day, GitHub Actions does a full cold-cache rebuild of every
  service (`docker compose build --no-cache --pull`) and re-runs the
  same smoke gates with a wider 20-minute budget. This is the gate that
  catches the regressions PR smoke physically cannot — upstream
  `python:3.11-slim` breakage, transitive dependency drift,
  `pyproject.toml` ↔ pip-fallback drift in the seven Python services.
  Failures upload a forensics artifact and open a `ci`-labelled tracking
  issue automatically so a nightly break is visible by standup.

### Changed

- **`apps/web/package.json`**: Bumped to `7.2.0`.

### Migration notes

None for users on 7.1.1. The compose file is backwards-compatible —
`pull_policy: missing` only changes behaviour the first time you boot
(it tries the registry before building); existing local images are
honoured. If you want the new fast path explicitly, run `docker compose
pull` once after upgrading. To pin a deploy to this release rather than
tracking `latest`, set `AISOC_VERSION=v7.2.0` in `.env`.

If you skipped 7.1.1, also read its [migration note](#711--2026-05-10)
about the `osquery-tls` host-port change (`8007` → `8091`).

## [7.1.1] — 2026-05-10

### Fixed — `docker compose up -d` first-touch experience

Hotfix in response to user-reported `docker compose up -d` failures on a clean
clone. None of these are functional changes to the running services — every
fix is in the boot path, the boot documentation, or the pre-flight check.

#### Compose hygiene

- **`docker-compose.yml`**: Removed the obsolete `version: '3.8'` declaration,
  which Docker Compose v2 ignores and warns about on every invocation
  (`level=warning msg="...the attribute version is obsolete..."`). The warning
  is harmless but is the very first line of output a new user sees, which
  signals "this project is broken" before the build even starts.
- **`docker-compose.yml`**: Added `mem_limit` + `mem_reservation` to the four
  data-tier containers most likely to OOM-kill on an under-provisioned Docker
  Desktop:
  - `kafka`: 1.5 GB limit / 1 GB reservation
  - `clickhouse`: 1 GB limit / 768 MB reservation
  - `opensearch`: 1 GB limit / 768 MB reservation
  - `neo4j`: 1 GB limit / 768 MB reservation

  Without these caps, a 4 GB Docker Desktop allocation (the default on macOS)
  would silently OOM-kill OpenSearch or Neo4j during JVM warmup, leaving the
  rest of the stack running but the alert/case feeds permanently empty.
- **`docker-compose.yml`** (`osquery-tls` service): Fixed `AISOC_INGEST_BASE_URL`
  pointing at the non-existent `ingest:8080` (the actual service is named
  `ingest-worker`). Also remapped the host port from `8007` to `8091` to
  resolve a host-port collision with the `ueba` service. Both bugs only
  surfaced if the user actually queried the osquery TLS server, which is why
  they survived the previous release; running `docker compose up -d` would
  succeed but `osquery-tls` would log connection-refused errors on every
  agent check-in.

#### README rewrite

- **`README.md`** — *Quick start*: Restructured so `pnpm aisoc:demo` is the
  canonical first-touch path (4 prebuilt images, ~90s to a working SOC
  console) and `docker compose up -d` is explicitly labelled the
  "developer-build path" (22 services, 10–20 min cold build, requires Docker
  with at least 6 GB RAM allocated). The previous structure presented both
  paths as equally valid, which led users with stock Docker Desktop settings
  straight into a stack that physically cannot fit in the daemon's memory.
- **`README.md`** — *Service map*: Updated `osquery-tls` from `:8090` to `:8091`
  and added a `Kafka UI` row at `:8090`, matching the compose hygiene fix
  above.
- **`README.md`** — *Boot section*: Added explicit timing expectations
  ("~5 GB of base image pulls + 10–20 min of build on a typical laptop"), a
  recommendation to run `pnpm aisoc:doctor` before kicking off the build, and
  a troubleshooting note pointing under-provisioned Docker Desktop installs
  at *Settings → Resources*.

#### `aisoc:doctor` hardening

The pre-flight check that the user is now told to run before
`docker compose up -d` was previously useless to first-time users — its
container check used `docker compose ps` (which is project-scoped and
therefore couldn't see containers launched by a sibling compose file), and
it had no opinion on whether Docker itself was provisioned to actually run
the stack. This release fixes both:

- **Docker Compose plugin enforcement**: New check that fails with an
  actionable error if the user only has Compose v1 (`docker-compose` Python
  binary) on PATH, which is now end-of-life and lacks healthcheck semantics
  the stack depends on.
- **Docker daemon RAM check**: Reads `docker info --format json` and asserts
  at least 6 GB allocated for the full stack (4 GB for the demo stack).
  Anything less hard-fails with a pointer to *Docker Desktop → Settings →
  Resources*. This single check would have prevented every variant of "the
  build succeeds but `docker compose ps` shows half my containers in a
  restart loop" reported to date.
- **Cross-compose-project container discovery**: Replaced `docker compose ps`
  with `docker ps -a --format json --filter name=aisoc-`. The doctor now
  detects whether the user is on the demo stack (`aisoc-demo-*` containers)
  or full stack (`aisoc-*` containers) and accepts either as a valid boot,
  so demo users no longer see false `FAIL` rows for services the demo
  intentionally omits (kafka-ui, neo4j, etc.).
- **Exit-code aware container reporting**: When a container exists but is
  not running, the doctor now emits the exact `Exited (255)` status from
  `docker ps` and tells the user `run \`docker logs <container>\``. The
  previous output ("not running") gave the user no signal about whether
  the container had crashed, never started, or been manually stopped.
- **Stack flavor summary**: A new `stack flavor` row reports `demo`,
  `full`, or `mixed`, plus a running/total container count
  (`(4/8 container(s) running)`) so the user can see at a glance whether
  they're looking at a half-broken stack or a fully-broken stack.

### Changed

- **`apps/web/package.json`**: Bumped to `7.1.1`.

### Migration notes

None. This is a docker-compose hygiene release — no service code,
no database schema, no API surface area changed. Pull, re-run
`pnpm aisoc:doctor`, and re-run `docker compose up -d` (the
`osquery-tls` port change means existing deployments need to update any
osquery-agent `tls_hostname:tls_port` config from `localhost:8007` to
`localhost:8091`, but no one was using that interface yet).

## [7.1.0] — 2026-05-10

### Added — Cloud Security Coverage Wave

Six new connectors, three documentation backfills, and one new ingest template.
Closes the biggest cloud-security gap in the connector catalogue: every Tier-1
cloud workload protection platform (Wiz, Prisma Cloud, Orca, Lacework, AWS
Security Hub) now has a first-class integration, AWS gets three native data
sources (GuardDuty, CloudTrail, VPC Flow Logs), and Kubernetes audit logs land
through a dual-mode connector that works on both managed and air-gapped
clusters.

#### Track A — Documentation backfill

- **`apps/docs/docs/connectors/wiz.md`**: Documented the Wiz GraphQL connector
  end-to-end — service-account creation, scope (`read:issues`,
  `read:vulnerabilities`), token rotation, normalised severity mapping, and a
  worked example of a Wiz `Issue` collapsing to `category=cloud_alert` in the
  inbox.
- **`apps/docs/docs/connectors/aws-security-hub.md`**: Documented IAM role vs.
  static-key auth, the `securityhub:GetFindings` permission model, and the
  `BLOCK_IP`/`ALLOW_IP` capabilities backed by
  `services/actions/app/clients/aws_security_groups.py` (i.e. how a SOC analyst
  can quarantine an attacker IP from the Security Hub finding without leaving
  the case workspace).
- **`apps/docs/docs/connectors/lacework.md`**: Documented the Lacework API
  token flow, `api_url` regional variants, and the alert→event severity map.
- **`apps/docs/sidebars.ts`**: Registered all three new docs pages under the
  `Connectors` category, plus the four new connector pages from Tracks B–D
  (`prisma-cloud`, `orca`, `aws-guardduty`, `aws-cloudtrail`, `aws-vpc-flow`,
  `kubernetes-audit`).

#### Track B — New CNAPP connectors

- **`services/connectors/app/connectors/prisma_cloud.py`** —
  `PrismaCloudConnector` with full Prisma Cloud (CSPM/CWPP) coverage. JWT auth
  via `POST /login`, paginated `GET /alert/v1/alert` with `time.from`/`time.to`
  windowing, severity collapse (`critical/high → high`, `medium → medium`,
  `low/informational → low`), and a `compute_url` override for self-hosted
  Compute Edition. Capability: `PULL_ALERTS`. Manifest: `plugins/prisma-cloud/plugin.yaml`,
  docs at `apps/docs/docs/connectors/prisma-cloud.md`, tests in
  `services/connectors/tests/test_prisma_cloud.py`.
- **`services/connectors/app/connectors/orca.py`** — `OrcaConnector` hitting
  `https://api.orcasecurity.io/api/alerts` with an `api_token` field, severity
  collapse (`critical/high/hazardous → high`, `medium → medium`,
  `informational/low → low`). Manifest, docs, and tests follow the same
  pattern. Capability: `PULL_ALERTS`.

#### Track C — Native AWS connectors

- **`services/connectors/app/connectors/aws_guardduty.py`** —
  `AWSGuardDutyConnector` mirroring `AWSSecurityHubConnector`'s shape:
  boto3-based, supports IAM-role or static-key auth, calls
  `guardduty.list_findings` + `get_findings` per detector. Normalises
  GuardDuty's continuous numeric severity scale (`0.1`–`10.0`) into AiSOC's
  four-tier `info|low|medium|high` ladder (`>= 7.0 → high`, `>= 4.0 → medium`,
  `>= 1.0 → low`, else `info`). Capability: `PULL_ALERTS`.
- **`services/connectors/app/connectors/aws_cloudtrail.py`** —
  `AWSCloudTrailConnector` using `cloudtrail.lookup_events`. Ships with a
  curated default allow-list of 21 high-signal event names covering identity
  abuse (`ConsoleLogin`, `AssumeRoleWithSAML`, `GetSessionToken`,
  `GetFederationToken`, `CreateAccessKey`, `CreateLoginProfile`,
  `CreateUser`), persistence (`AttachUserPolicy`, `PutUserPolicy`,
  `CreateRole`, `AttachRolePolicy`), data-plane abuse (`PutBucketPolicy`,
  `PutBucketAcl`, `DeleteBucketPolicy`, `PutObjectAcl`), network exposure
  (`AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`,
  `ModifyDBInstance`), and trail tampering (`DeleteTrail`, `StopLogging`,
  `UpdateTrail`). Allow-list is overridable via the `event_names` config
  field. Pagination handled via `NextToken` with a hard cap to keep poll
  latency bounded. Capability: `PULL_LOGS`.
- **`services/connectors/app/connectors/aws_vpc_flow.py`** —
  `AWSVPCFlowLogsConnector` using `cloudwatch_logs.filter_log_events`. Parses
  both v2 (default 14-field) and v5 (header-defined) flow-log formats. Default
  `filter_pattern` is `?REJECT` to surface dropped traffic only — keeps volume
  manageable while flagging external-facing security groups that are getting
  scanned. Public-IP heuristic (`_is_public_ip`) is RFC-5735-aware, treating
  RFC1918/loopback/link-local/multicast/CGNAT/TEST-NET as private. Severity
  heuristic: public-IP REJECTs → `medium`, internal REJECTs → `low`,
  ACCEPT-only flows → `info`. Capability: `PULL_LOGS`.

#### Track D — Kubernetes audit logs (dual-mode)

- **`services/connectors/app/connectors/kubernetes_audit.py`** —
  `KubernetesAuditConnector` shipping with two delivery modes selected via the
  `mode` config field:
  - **`webhook` (recommended)** — Kubernetes API server pushes audit events
    to AiSOC's new dedicated `POST /v1/ingest/k8s-audit/{tenant_id}` route,
    authenticated with a shared secret in the `X-AiSOC-K8s-Token` header
    (compared in constant time so partial-prefix matches still fail). The
    legacy `/v1/inbox/{token}` path with the `k8s-audit` template is kept
    around as a fallback for control planes that cannot inject custom
    headers into the audit-webhook kubeconfig.
  - **`file_tail`** — AiSOC's connector pod tails a local `audit.log` file
    using a byte-position cursor (atomically written to a `.aisoc-cursor`
    sidecar), with rotation/truncation detection and a hard per-poll byte cap
    so a backlog can't blow up a single poll cycle.
- **`services/ingest/internal/handler/k8s_audit.go`** — New Go handler for
  the dedicated webhook route. Caps body size via `K8S_AUDIT_MAX_BODY_BYTES`
  (default 16 MiB), rejects oversized batches with `413` so the apiserver
  shrinks `--audit-webhook-batch-max-size` and retries, and publishes each
  `EventList.items[]` entry through the existing normalizer + Kafka publisher
  using `connector_type: kubernetes_audit`. The route is disabled (returns
  `503`) until an operator sets `K8S_AUDIT_SHARED_SECRET`, so a fresh
  install never accidentally accepts unauthenticated audit traffic.
- **`services/ingest/internal/normalizer/normalizer.go`** — Added the
  `kubernetes_audit` connector profile. Maps `auditID` to `external_id`,
  `verb` to `activity_name`, `user.username` to `actor.user.name`,
  `objectRef.{namespace,resource,name}` to a composite `target.resource.name`,
  and translates the connector's string severity (`critical|high|medium|low|
  info`) into OCSF integer severities (5/4/3/2/1).
- **`services/ingest/internal/normalizer/templates/k8s-audit.yaml`** — New
  inbox template (legacy path) that maps Kubernetes apiserver `Event`
  payloads (`apiVersion: audit.k8s.io/v1`) onto AiSOC's normalised event
  shape:
  - `external_id ← auditID`
  - `vendor ← "Kubernetes"`, `product ← "apiserver-audit"`,
    `category ← "k8s_audit"`
  - `actor ← user.username` (plus `user.groups` carried through metadata)
  - `target ← objectRef.namespace + "/" + objectRef.resource + "/" +
    objectRef.name`
  - `severity` is derived in the connector's `_classify_severity` heuristic,
    not in the template, so the same logic applies to both delivery modes.
- **Severity heuristic** (`_classify_severity` in `kubernetes_audit.py`):
  - `high` — `exec`/`attach`/`portforward` on a Pod, `create` on
    `ClusterRoleBinding`, `impersonate` verb, `update` on
    `serviceaccounts/token`, any `RequestResponse` event where
    `responseStatus.code >= 500` on a sensitive verb.
  - `medium` — `create`/`patch`/`delete` on `Secret`/`ConfigMap`/
    `ClusterRole`/`Role`, `escalate` verb, failed authentication
    (`responseStatus.code == 401|403`) on a write verb.
  - `low` — successful reads on sensitive resources (`get` on `Secret`),
    successful writes on routine resources.
  - `info` — everything else (health probes, list/watch on benign resources,
    successful low-impact reads).
- **`plugins/kubernetes-audit/plugin.yaml`** — Manifest with a 4-field config
  schema (`mode`, `cluster_name`, `inbox_token`, `audit_log_path`,
  `cursor_path`), `category: cloud`, capabilities `pull_audit` + `pull_alerts`.
- **`apps/docs/docs/connectors/kubernetes-audit.md`** — Includes a complete
  sample `AuditPolicy` (omitStages on RequestReceived for verbosity control;
  Metadata level for routine reads, RequestResponse for writes on Secret /
  ConfigMap / ClusterRoleBinding) and a sample `AuditSink` pointing at AiSOC's
  inbox URL.

#### Cross-cutting

- **`marketplace/index.json` + `apps/web/public/marketplace/index.json`** —
  Rebuilt via `pnpm marketplace:sync`. Plugin count rose from 43 → 49 (+6
  cloud connectors). Total marketplace entries: `total=7104 detections=6993
  playbooks=62 plugins=49 mitre_techniques=493`.
- **`apps/web/package.json`** — Version bumped from `7.0.3` to `7.1.0`; the
  sidebar and landing-page footer both surface the new version automatically.

#### Test footprint

- 43 unit tests for `KubernetesAuditConnector` covering both delivery modes,
  cursor persistence, rotation/truncation, byte-cap drain semantics, and the
  full severity-heuristic decision table.
- 27 unit tests for `AWSVPCFlowLogsConnector` covering v2/v5 parsing,
  public-IP classification edge cases (RFC1918, CGNAT, TEST-NET-1/2/3), and
  the default REJECT filter pattern.
- Mirroring tests for `PrismaCloudConnector`, `OrcaConnector`,
  `AWSGuardDutyConnector`, `AWSCloudTrailConnector` covering schema,
  normalise, pagination, and auth-error paths.
- Full `services/connectors` suite passes at 364 tests; schema-introspection
  tests in `services/api` also pass with the six new connectors added to
  `_CONNECTOR_CLASSES`.

---

## [7.0.3] — 2026-05-10

### Fixed — Hydration mismatch, font preload warnings

#### Web app (`apps/web/`)

- **`src/components/layout/AppShell.tsx`**: Wrapped `<DemoBanner />` in a new
  `<ClientOnly>` boundary so the banner (which reads `NEXT_PUBLIC_DEMO_MODE`)
  is never server-rendered. This eliminates React hydration error #418 caused by
  stale env-var inlining producing a structural tree mismatch (server saw
  `<button>` from Sidebar, client expected `<div>` from DemoBanner).
- **`src/app/layout.tsx`**: Added `preload: false` to the `JetBrains_Mono`
  `next/font/google` config. The monospace font is only used in code blocks and
  is not needed on the initial paint of most pages, causing Chrome to log
  "preloaded but not used within a few seconds" warnings. Lazy-loading the font
  eliminates these warnings without any visible FOUT.

---

## [7.0.2] — 2026-05-10

### Fixed — Version alignment, landing-page footer, documentation

- **`apps/web/package.json`**: Bumped `version` to `7.0.2`; sidebar now shows `v7.0.2` dynamically.
- **`apps/web/src/components/landing/Footer.tsx`**: Replaced hard-coded `v6.1.0` string with a
  dynamic import of `package.json` so the landing page footer always reflects the current package version.
- **`README.md`**: Updated version badge to `7.0.1`; added `osquery-tls` (port 8090) and
  `osquery-extensions` entries to the services table, the Swagger-UI URL table, and the
  directory tree; added osquery TLS server URL to the dev surface table.

---

## [7.0.1] — 2026-05-10

### Fixed — Web app hardening: CodeQL, hydration, Turbopack config

#### Security (CodeQL Code-Scanning — 42 alerts cleared)

- **Python**: Resolved `py/unused-global-variable` in `credential_vault.py`,
  `pack_loader.py`, `executive_digest.py`, `case_summary.py`,
  `cost_dashboard.py`, and `actions/executors/base.py` by refactoring mutable
  state into dictionaries and exposing identifiers via `__all__`.
- **Python**: Resolved `py/cyclic-import` between `osquery-tls` modules by
  extracting `generate_node_key` into a new `app/core/crypto.py` module.
- **Python**: Resolved `py/empty-except` in `api/main.py` and `api/services/github.py`
  by replacing bare `pass` blocks with `logger.debug` calls.
- **Python**: Resolved `py/log-injection` in `github.py`, `detection_proposals.py`,
  and `llm_credentials.py` by switching log format specifiers to `%r`.
- **Python**: Resolved `py/clear-text-logging-sensitive-data` in
  `workers/oauth_refresh.py` by redacting `tenant_id` and sanitising reason strings.
- **Python**: Resolved `py/incomplete-url-substring-sanitization` in
  `llm_resolver.py` by using `urllib.parse.urlparse` for hostname extraction.
- **Python**: Resolved `py/stack-trace-exposure` in `agents/api/explain.py` by
  returning a generic error string from the exception handler.
- **Python**: Resolved `py/call/wrong-arguments` in `agents/tests/smoke_explain.py`
  by importing and passing a `LlmConfig` instance to `_stream_explanation`.
- **Python**: Resolved `py/unused-import` in `osquery-tls/db/env.py`; fixed
  `E402` (import ordering) in the same file.
- **JavaScript**: Resolved `js/unused-local-variable` in `AlertsView.tsx`
  (removed unused `toast` import) and `SettingsView.byok.test.tsx` (removed
  unused `within` import).

#### Web app (`apps/web/`)

- **`next.config.js`**: Removed deprecated `eslint.ignoreDuringBuilds` key that
  Next.js 16 no longer accepts in the config file; added `turbopack.root` so
  Turbopack resolves workspace packages correctly.
- **`src/app/layout.tsx`**: Added `suppressHydrationWarning` to the `<html>`
  element so that the render-blocking `themeBootstrapScript` can freely write
  `data-theme`, `data-theme-preference`, and `style.colorScheme` on the client
  without React reporting a hydration mismatch on every page load.

---

## [7.0.x] — 2026-05-10 — Endpoint telemetry wave (PR1–PR6)

> **⚠️ Reconciliation notice (2026-05-12)**: The work described in this
> section was developed on branch `feat/pr6-osquery-extensions`
> (commits `e0d70fa1` → `3ab5aa81`) but the branch was **not merged into
> `main`** before this changelog entry was written. The files referenced
> below — including `services/osquery-tls/`,
> `services/connectors/app/connectors/aisoc_direct.py`,
> `services/agents/app/playbook/steps/osquery_live_query.py`, and the
> osquery-extensions Go module — exist on that branch and can be reviewed
> there, but are **not present on `main`** as of v7.1.0 planning. Treat
> this section as a record of in-flight work pending PR merge, not as
> shipped functionality. The community-feedback-driven roadmap
> (`docs/community-feedback/2026-05-12/`) builds the generic
> `live_action` interface (Issue #8) on `main` directly rather than
> assuming this section's primitives are in place.

### Added — osctrl, FleetDM, aisoc-osquery-tls, aisoc-direct, native osquery detections, live-query playbook step, FIM, custom virtual tables

Six-PR wave that closes [#44](https://github.com/beenuar/AiSOC/issues/44)
("osctrl connector for fleet-wide osquery telemetry") and significantly extends
osquery coverage end to end. Shipped in the v7.0 release window between the
v7.0.0 baseline and the v7.0.1 hardening patch.

#### PR1 — osctrl + FleetDM connectors

- **`services/connectors/app/connectors/osctrl.py`**, **`fleetdm.py`** — Two new
  `BaseConnector` subclasses with full `schema()`, `validate()`, `fetch_events()`,
  and `normalize()` implementations. Schema-driven setup runs a live
  `Test connection` round-trip before save; secrets encrypted with the
  application-layer `CredentialVault` (Fernet AES-128-CBC + HMAC-SHA256);
  polling on per-instance schedule via `ConnectorScheduler`.
- **`plugins/osctrl/plugin.yaml`**, **`plugins/fleetdm/plugin.yaml`** — Marketplace
  manifests mirroring the connector schemas. `marketplace/index.json` regenerated
  via `pnpm marketplace:sync`.
- **`services/connectors/tests/test_osquery_connectors.py`** — Schema contract +
  severity heuristics tests.

#### PR2 — Native osquery detection schema migration

- **`detections/endpoint/osquery-*.yaml`** — 16 osquery detection rules
  migrated from `_quarantine/` to the native schema, IDs `det-endpoint-281`
  through `det-endpoint-296`. Coverage spans credential access, persistence,
  lateral movement, defense evasion, and discovery on macOS, Linux (auditd),
  and Windows.
- **`detections/fixtures/osquery_*.json`** — Positive / negative test
  fixtures for every migrated rule, gated by the Detection Validation
  workflow in CI.

#### PR3 — Live-query playbook step

- **`services/actions/app/clients/osctrl_client.py`**,
  **`fleetdm_client.py`**, **`aisoc_direct_client.py`** — Production-grade
  HTTP clients with per-vendor auth, retries, and structured error handling.
- **`services/actions/app/clients/osquery_allowlist.py`** — Strict allowlist
  enforcing only safe SELECT-only queries against approved tables (no
  `ATTACH`, no `INSERT`, no `pragma_*` introspection of secrets).
- **`services/agents/app/playbook/engine.py::_handle_osquery_live_query`** —
  New `osquery_live_query` step type, registered in
  `services/agents/app/playbook/models.py` as `StepType.OSQUERY_LIVE_QUERY` and
  dispatched from the `STEP_HANDLERS` table at the bottom of `engine.py`.
  Pushes allowlisted distributed queries to a single host or fleet-wide via
  osctrl / FleetDM / aisoc-direct with HMAC-signed ChatOps approval before
  execution. Tests live in
  `services/agents/tests/test_osquery_live_query_step.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > separate module at `services/agents/app/playbook/steps/osquery_live_query.py`.
  > That module never landed on `main` — the handler is inlined in `engine.py`
  > to keep the playbook engine's dispatch table in one place. The behaviour,
  > tests, and CLI surface are identical to the originally documented design.

#### PR4 — `aisoc-osquery-tls` FastAPI service + `aisoc-direct` connector

- **`services/osquery-tls/`** — New first-party FastAPI service exposing
  `/api/v1/enroll`, `/api/v1/config`, `/api/v1/log`, `/api/v1/distributed/read`,
  `/api/v1/distributed/write`, plus `/api/v1/fim` for file-integrity events.
  Self-hosted osquery TLS plugin endpoints are FleetDM-compatible so any
  off-the-shelf osquery agent can enroll without a third-party SaaS hop.
  Uses dedicated SQLite + Alembic migrations under `services/osquery-tls/db/`.
- **`services/osquery-tls/app/api/v1/endpoints/log.py`** + matching
  `plugins/aisoc-direct/plugin.yaml` and
  `services/actions/app/clients/aisoc_direct_client.py` — Direct-from-agent
  ingest path that consumes the osquery-tls log stream and normalises into
  the standard alert schema; bypasses third-party SaaS entirely. The
  `aisoc-direct` connector is implemented as a **virtual connector**: agents
  push events directly into `/api/v1/log` on the osquery-tls service, which
  fans them out to the same ingest pipeline the polled connectors use. The
  marketplace manifest lives at `plugins/aisoc-direct/plugin.yaml`; the
  outbound client (used by playbooks to drive distributed queries) lives at
  `services/actions/app/clients/aisoc_direct_client.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > polled connector module at
  > `services/connectors/app/connectors/aisoc_direct.py`. That module never
  > landed on `main`. The connector is implemented as a push-based virtual
  > connector (the `osquery-tls` service is itself the ingest endpoint), so
  > there is nothing to register in `services/connectors/app/connectors/__init__.py`.
  > Functionally the data path is identical to the originally documented
  > design.

#### PR5 — Osquery packs + FIM endpoint + FIM dashboard

- **`services/osquery-tls/app/osquery_packs/`** — Bundled IR / OSquery-ATT&CK /
  FIM packs distributed to every enrolled agent on enrollment. Pack loader
  preserves hand-crafted playbooks under `pack root` (do not `rmtree`).
- **`services/osquery-tls/app/api/v1/endpoints/fim.py`** — File-integrity
  monitoring endpoint. Ingests `file_events` and synthesises alerts on writes
  to `/etc/passwd`, `/etc/shadow`, sshd configs, sudoers, and Windows
  registry hives. FIM-specific detection IDs `det-endpoint-297..300`
  (renumbered from 281–284 to avoid collision with osquery-macos rules).
- **`apps/web/src/components/dashboard/FimDashboard.tsx`** — New dashboard
  panel grouping FIM events by host, file, and severity.

#### PR6 — AiSOC osquery extensions (custom virtual tables)

- **`services/osquery-extensions/tables/`** — 5 custom Go-based virtual tables
  shipping with the agent for richer endpoint visibility plus a bidirectional
  response channel:
  - `aisoc_browser_extensions` — installed browser extensions across Chrome,
    Firefox, Edge, Safari profiles.
  - `aisoc_kernel_modules` — currently loaded kernel modules with signing /
    tainting state.
  - `aisoc_attck_persistence` — MITRE ATT&CK persistence locations
    (LaunchAgents, scheduled tasks, systemd units, Run keys).
  - `aisoc_pending_actions` — pending response actions queued for the agent;
    enables host → server → host bidirectional flow.
  - `aisoc_alert_cache` — local cache of alerts the agent has emitted, for
    deduplication and replay.
- **`services/osquery-extensions/tables/pending_actions_test.go`** — Unit
  tests for the bidirectional action queue.
- **`docs/openapi.yaml`** regenerated to include the extensions API endpoints.

#### Cross-cutting CI / housekeeping

- **CI**: Detection Validation workflow now covers the 16 migrated osquery
  rules; Python Tests, Web Build, and the osquery-tls service build are all
  green.
- **Lint**: `ruff format` and `ruff check --fix` applied across the new
  `osquery-tls` service; F401 / UP017 / UP037 / I001 / W291 cleared.
- **Marketplace**: `apps/web/public/marketplace/curated.json` re-synced from
  `marketplace/` after the new connector / plugin manifests landed.

---

## [7.0.0] — 2026-05-10

### Added — v1.0 Buyer-Value Plan: ChatOps, Digest PDF, BYOK, Air-gap, WCAG AA, Analytics

This release ships the complete v1.0 buyer-value plan across 16 workstreams.
All items were designed, implemented, tested, and reviewed by
Beenu Arora <beenu@cyble.com>.

#### WS-A1 — Slack ChatOps Bot (`services/slack-bot/`)

- **`services/slack-bot/`** — New standalone FastAPI service using `slack-bolt`
  async adapter. Ships `/aisoc triage <case_id>`, `/aisoc approve <action_id>`,
  `/aisoc status <case_id>`, and `/aisoc summary <case_id>` slash commands.
  Interactive approval buttons route back through the API approval endpoint so
  human-in-the-loop gates work from Slack without opening the console.
- 61 pytest cases cover the slash-command handlers, interactive payloads, API
  client calls, and error paths (bad token, non-200 API response, missing case).

#### WS-B1/B2 — Executive Digest PDF + Weekly Scheduler

- **`services/api/app/services/digest_pdf.py`** — Generates a branded A4 PDF
  for `ExecutiveDigest` objects using ReportLab. Includes cover page, KPI tiles,
  alert-volume chart, top-rule table, top-actor table, and remediation summary.
- **`services/api/app/workers/weekly_digest_task.py`** — APScheduler task that
  runs every Monday at 06:00 UTC, builds a digest for every active tenant, and
  delivers it via `POST /api/v1/reports/digest/email` or writes it to blob
  storage. Controlled by `DIGEST_SCHEDULE_ENABLED` env flag.
- **`services/api/app/services/digest_html.py`** — HTML mirror of the PDF for
  in-browser preview.
- **`services/api/tests/test_digest_pdf.py`** — 12 pytest cases covering PDF
  generation, chart rendering, and weekly scheduler triggering.

#### WS-C1/C2/C3 — Playbook Gallery, Detection Proposals, GitHub PR Integration

- **`apps/web/src/components/playbooks/PlaybooksGallery.tsx`** — Tabbed gallery
  with 12 curated packs (Phishing, Ransomware, BEC, IAM Key Compromise, …).
  Each card shows TTP coverage badges, author, version, and a one-click
  **Import** button that calls `POST /api/v1/playbooks/import`.
- **`services/api/migrations/039_detection_proposal_github_pr.sql`** —
  Adds `github_pr_url TEXT` and `github_pr_number INT` to `detection_proposals`.
- **`services/api/app/services/github.py`** — `GitHubService` creates draft PRs
  against the tenant's detection repo when a detection proposal is promoted.
  Supports GHES and github.com via `GITHUB_API_URL` env var.
- 25 playbook YAML templates added under `detections/playbooks/` and 12 pre-built
  playbook packs under `playbooks/packs/v1/`.

#### WS-D1 — BYOK Per-Tenant Settings UI

- **`apps/web/src/components/settings/SettingsView.tsx`** — New "AI / LLM"
  settings panel: provider picker (OpenAI, Azure OpenAI, Anthropic, Ollama),
  API-key input, model selector, temperature slider, and connection test button.
- **`apps/web/src/components/settings/SettingsView.byok.test.tsx`** — 12 Vitest
  tests covering form rendering, provider switching, key masking, connection test
  success/error paths, and save confirmation.

#### WS-D2 — Investigation Timeline (Replayable)

- **`apps/web/src/components/copilot/InvestigationTimeline.tsx`** — 684-line
  React component that renders the investigation ledger as a playable timeline.
  Each step shows the agent name, tool call, rationale, duration, and status
  badge. A scrubber lets analysts replay from any step.

#### WS-D3 — Case Auto-Summary + PDF Export

- **`services/api/app/services/case_summary.py`** — LLM-powered case summariser
  (structured output via function-calling). Produces `CaseSummaryResult` with
  `headline`, `severity_rationale`, `recommended_action`, and `evidence_links`.
- **`services/api/app/services/case_summary_html.py`** — HTML renderer for the
  summary, used by the PDF exporter and the in-browser case card.

#### WS-F1 — Light Theme Persisted in User Profile

- **`apps/web/src/components/theme/ThemeProvider.tsx`** — Theme preference
  (`light` | `dark` | `system`) stored in `localStorage` and synced to
  `PATCH /api/v1/users/me/preferences`. Survives logout and device switch.

#### WS-F2 — WCAG AA Accessibility (axe-core CI gate)

- **`apps/web/src/test/a11y.test.tsx`** — 55-line axe-core test suite. Renders
  `AlertsView`, `CasesView`, `PlaybooksView`, `DashboardView`, and 3 modal
  components; fails the build if any WCAG 2.1 AA violation is found.
- Sidebar landmark roles, ARIA labels, focus trapping in modals, skip-navigation
  link, and colour-contrast fixes applied across the entire component tree.

#### WS-F3 — Saved Views + Drag-Drop Dashboard Widgets

- **`apps/web/src/components/dashboard/DashboardView.tsx`** — Dashboard is now
  fully composable: widgets can be dragged, dropped, resized, pinned, and
  removed. Layout serialised to `POST /api/v1/saved-views`.
- **`services/api/app/api/v1/endpoints/saved_views.py`** — CRUD for per-user
  saved views (dashboard layout, column configs, active filters).

#### WS-G1/G2 — Threat Actor Attribution Engine v0 + Air-Gap Mode

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls `POST /actors/attribute` and surfaces attribution results
  in the investigation ledger.
- **`docker-compose.airgap.yml`** — Compose override for fully disconnected
  deployments: disables all external feed pullers, enables Ollama sidecar, and
  sets `AIRGAP_MODE=true` so the API switches to local-only LLM routing.
- **`apps/docs/docs/operations/air-gapped.md`** — Step-by-step air-gap
  deployment guide: image pre-pulling, Ollama model loading, threat-feed
  pre-seeding, and smoke-test checklist.

#### WS-H1 — MSSP Console Improvements

- **`services/api/app/api/v1/endpoints/mssp.py`** — New `GET /mssp/tenants`
  aggregation endpoint: per-child tenant alert counts, open case counts, SLA
  breach rate, and last-seen connector heartbeat.
- **`services/api/app/models/tenant.py`** — Added `parent_tenant_id` and
  `mssp_role` columns supporting the parent-child tenant hierarchy.

#### WS-H2 — BYOK Per-Tenant LLM Credentials

- **`services/api/app/api/v1/endpoints/llm_credentials.py`** — CRUD for per-tenant
  LLM credential records. Secrets encrypted at rest via `CredentialVault`.
- LLM routing layer (`services/api/app/core/config.py`) reads per-tenant
  credentials before falling back to the platform-wide key.

#### WS-H3 — Team Analytics View

- **`apps/web/src/components/analytics/TeamAnalyticsView.tsx`** — Analyst
  leaderboard with MTTR per analyst, alert disposition accuracy, cases closed
  per shift, and false-positive rate trend over the selected window.

#### WS-H4 — Air-Gapped / Ollama Local-LLM Mode

- **`services/api/app/api/v1/endpoints/llm_status.py`** — Reports whether the
  deployment is running in air-gap mode and which local models are available
  via the Ollama sidecar. Used by the settings UI to auto-populate the model
  picker.

### Fixed

- Ruff `E501/W291/W293/B007/B017/F821/I001` violations in `services/api`.
- `mypy` errors across all 16 plan-modified files: `RowMapping` import,
  `Optional` list `len()`, `current_user.user_id` rename, `fetchone()` None
  checks, `sort_key` return type, `PYTHONPATH` subprocess handling.
- Converted structlog-style `logger.info(key=value)` calls to stdlib formatting
  in `rule_engine.py`, `neo4j.py`, and `digest_pdf.py`.
- SQLAlchemy relationship `name-defined` mypy errors suppressed with
  `# type: ignore[name-defined]` in `tenant.py` and `connector.py`.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

---

### Added — Threat Actor Attribution Engine (v0)

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls the attribution API after triage/enrichment and
  records the result on `state.threat_intel["attribution"]`. Failure is
  soft and surfaces a `[medium]` finding rather than aborting the
  investigation.
- **`docs/threat-actor-attribution.md`** — Full operator-facing docs,
  including scoring model, API surface, observability, env vars, v0
  caveats, and instructions for adding custom profiles.

### Configuration

- `AISOC_ATTRIBUTION_THRESHOLD` — Override the default confidence
  threshold (`0.30`). Clamped to `[0.0, 1.0]`; invalid values fall back
  to the default and emit a warning.
- `AISOC_THREATINTEL_URL` — Base URL the agent uses to reach the
  `threatintel` service. Default: `http://threatintel:8083`.
- `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` — HTTP timeout the agent uses for
  attribution calls. Default: `10`.

### Observability

- New Prometheus series exported by `threatintel`:
  - `threatintel_attribution_requests_total{result="matched|unknown|error"}`
  - `threatintel_attribution_score{actor_id}` (histogram)

### Engine internals

- Tool matching uses an alphanumeric-only boundary regex
  (`(?<![a-zA-Z0-9])tool(?![a-zA-Z0-9])`) instead of Python's `\b`.
  Python's `\b` treats `_` as a word character, which broke common
  malware-filename patterns like `miniduke_v3.dll`. The new boundary
  treats `_`, `-`, `.`, and `/` as delimiters while still rejecting
  alphanumeric neighbours (so `x-agent` does not match `x-agentic`).
- Tool matching now also scans the IOC's `description` and `tags`
  fields, not just `value`.
- IOC lookups go through a new public method `OpenSearchStore.match_ioc_values()`
  rather than reaching into `os_store._os.search()` directly.
- The attribution engine accepts a `catalog` constructor argument so
  tests and downstream services can inject custom profiles without
  monkey-patching module-level state.
- An empty catalog now resolves to `actor_id="unknown"` with explicit
  reasoning (`"Actor catalog is empty"`), instead of confusingly
  falling through to the no-match-above-threshold branch.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

## [6.1.0] — 2026-05-07

### Added — v1.5 market-driven feature expansion

A review of G2, Gartner Peer Insights, and customer feedback on AI SOC / SIEM /
SOAR platforms drove this release. Five new agents, eight new console pages,
four new API surfaces, and ten new connectors landed at once. Connector catalog
goes from 16 → **26**.

#### New autonomous agents (`services/agents/app/agents/`)

- **`auto_triage_agent.py`** — Master triage agent classifies each incoming alert
  as `true_positive` / `false_positive` / `benign` with a confidence score.
  Low-confidence noise auto-closes; everything else escalates with rationale.
- **`phishing_agent.py`** — Specialised phishing triage: header analysis, URL
  reputation, attachment sandboxing summary, sender-domain trust.
- **`identity_agent.py`** — Identity-centric reasoning: impossible travel,
  privilege escalation, MFA bypass, and session-token anomaly classification.
- **`cloud_agent.py`** — Cloud posture / threat reasoning across AWS, Azure,
  GCP, and Kubernetes signals.
- **`insider_threat_agent.py`** — Behavioural deviation, peer-group scoring,
  exfiltration intent classification.
- All five are exposed via `POST /api/v1/agents/triage`.

#### New console pages (`apps/web/src/components/`)

- **`/investigate`** — Conversational, multi-turn copilot anchored on a case;
  reads its evidence, ledger, and entity graph for grounded follow-up Q&A.
  Component: `copilot/InvestigationChat.tsx`.
- **`/coverage-advisor`** — Ranks MITRE ATT&CK technique gaps by adversary
  prevalence and recommends rules to close them.
  Component: `coverage/CoverageAdvisorView.tsx`.
- **`/shifts`** — Outgoing/incoming analyst handoff dashboard: active cases,
  in-flight investigations, queued approvals on one screen.
  Component: `shifts/ShiftsView.tsx`.
- **`/easm`** — External Attack Surface Management: discovers public assets,
  exposed services, and certificate-expiry risks.
  Component: `easm/EASMView.tsx`.
- **`/mssp`** — MSSP executive dashboard: KPIs, cross-tenant alert volume, and
  per-customer SLA posture. Component: `mssp/MSSPDashboardView.tsx`.
- **`/noise-tuning`** — Per-rule false-positive rate, suppression candidates,
  one-click tuning. Component: `noise/NoiseTuningView.tsx`.
- **`/analytics/team`** — Analyst leaderboard, MTTR per analyst, dispositions
  accuracy, and shift workload balance.
  Component: `analytics/TeamAnalyticsView.tsx`.

#### New API surfaces (`services/api/app/api/v1/endpoints/`)

- **`shifts.py`** — Shift-handoff CRUD: list active shifts, post handoff
  notes, view queued approvals scoped to a shift window.
- **`stix_taxii.py`** — STIX 2.1 / TAXII 2.1 publishing; pushes the tenant's
  IOCs and threat-actor profiles to upstream / community feeds.
- **`compliance.py`** — Automated compliance evidence collection for SOC 2,
  ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA. One-click evidence pull.
- **`deployment.py`** — Deployment / air-gap toggles; tenants that disallow
  external feeds can flip air-gap mode here.

#### New connectors (`services/connectors/app/connectors/`)

EDR / XDR: `sentinelone.py`, `cortex_xdr.py`. Cloud security: `wiz.py`,
`snyk.py`. Network: `zscaler.py`. SaaS / email: `proofpoint.py`,
`servicenow.py`, `jira.py`. Identity: `1password.py`, `duo_security.py`.
All ten registered in `services/connectors/app/connectors/__init__.py`,
all ship a marketplace manifest under `plugins/<id>/plugin.yaml`, all
collapse vendor severity to the standard four-tier ladder.

#### Other

- **AI-generated incident reports** — Every case now has a one-click "Export
  Report" button that generates a PDF incident report from the Investigation
  Ledger.
- **Air-gap deployment configuration** — Per-tenant toggles disable external
  feeds (threat intel, marketplace sync, push notifications) for fully
  air-gapped deployments.

### Changed

- Connector catalog count **16 → 26**. Landing page hero stat, layout SEO
  metadata, and `apps/docs/docs/connectors/index.md` updated to reflect.
- `apps/docs/docs/architecture.md` adds a v1.5 section and updates the
  service-responsibilities table to include the new API surfaces and
  autonomous agents.
- `apps/docs/docs/intro.md` updated to mention the new connector count and
  v1.5 features.
- Footer release link now points at `v6.1.0`.

## [6.0.1] — 2026-05-06

### Security

- **Log-injection mitigation** (`services/api/app/api/v1/endpoints/connectors.py`) —
  `connector_type` originates from user-supplied query parameters and was previously
  logged verbatim, leaving an injection path for newlines/control characters into
  structured log records. A character-allowlist reconstructor (`_safe_connector_type`)
  now strips every character outside `[a-zA-Z0-9_\-]` before the value reaches any
  log call, breaking CodeQL's taint trace (alert `py/log-injection`).

- **Remove dead rate-limiter code** (`services/realtime/src/index.ts`) —
  The hand-rolled `makeRateLimiter` function was superseded by `express-rate-limit`
  in the previous release but not removed, leaving dead code that masked the
  effective rate-limiting path. The function is now deleted; `express-rate-limit`
  is the sole limiter in production (resolves CodeQL alert `js/unused-local-variable`).

## [6.0.0] — 2026-05-06

### Added

#### Wave 3 — Operational Maturity

- **MSSP / parent-tenant console** (`services/api/migrations/012_mssp_console.sql`,
  `services/api/app/models/mssp.py`, `services/api/app/api/v1/endpoints/mssp.py`) —
  Parent tenants can onboard child tenants, manage cross-tenant delegations, add
  per-tenant notes, and view an aggregated metrics rollup in a single pane.

- **Asset inventory + vuln-to-alert correlation** (`services/api/migrations/013_asset_inventory.sql`,
  `services/api/app/models/asset.py`, `services/api/app/api/v1/endpoints/assets.py`) —
  CRUD for discovered assets with vulnerability findings auto-correlated to alerts.
  Surfaces asset blast radius and enables asset-context enrichment during triage.

- **Insider threat module** (`services/api/migrations/014_insider_threat.sql`,
  `services/api/app/models/insider_threat.py`,
  `services/api/app/api/v1/endpoints/insider_threat.py`) —
  User risk profiles, behavioural indicators, peer-group deviation scoring, and
  watchlist management. Risk scores update incrementally as new indicators arrive.

- **L0–L4 auto-remediation maturity tiers** (`services/api/migrations/015_remediation_maturity.sql`,
  `services/api/app/models/remediation.py`,
  `services/api/app/api/v1/endpoints/remediation.py`,
  `services/actions/app/services/maturity.py`) —
  Per-tenant configuration of remediation autonomy from L0 (manual only) through L4
  (fully autonomous). Gate log records every approve/block decision. Per-action whitelist
  pre-approves low-risk actions regardless of tier.

#### Wave 4 — Advanced Capabilities

- **Internal threat intelligence** (`services/api/migrations/016_threat_intel.sql`,
  `services/api/app/models/threat_intel.py`,
  `services/api/app/api/v1/endpoints/threat_intel.py`) —
  IOC harvesting from alert history, threat actor and campaign profiles, and STIX/TAXII
  feed subscription management, all queryable via the REST API.

- **Cloud security posture management (CSPM/KSPM)** (`services/api/migrations/017_cspm.sql`,
  `services/api/app/models/posture.py`, `services/api/app/api/v1/endpoints/posture.py`) —
  Ingests posture findings from cloud providers, tracks drift between scan runs, and
  surfaces a per-provider posture summary with suppress/resolve workflows.

- **Identity-centric correlation graph** (`services/api/migrations/018_identity_graph.sql`,
  `services/api/app/models/identity_graph.py`,
  `services/api/app/api/v1/endpoints/identity_graph.py`) —
  Graph of users, devices, service accounts, and roles with typed relationship edges.
  Alerts link to identity nodes, enabling blast-radius queries and attack-path
  reconstruction.

- **Auto-generated board reports** (`services/api/migrations/019_board_reports.sql`,
  `services/api/app/models/report.py`, `services/api/app/api/v1/endpoints/reports.py`) —
  Report templates and scheduled generation of PDF/HTML executive summaries. Artefacts
  are stored, versioned, and deliverable via email or webhook.

#### Platform

- **Dashboard metrics API** (`services/api/app/api/v1/endpoints/metrics.py`) —
  `/api/v1/metrics/dashboard` aggregates alert KPIs, case counts, connector source
  stats, top MITRE tactics, 24-hour alert trend, and threats-by-source for the
  frontend dashboard tiles. `/api/v1/metrics/alerts/trend` supports `1h / 24h / 7d / 30d`
  period buckets.

- **Tailscale connector** (`services/connectors/app/connectors/tailscale.py`) —
  Pulls audit logs and policy-file change events from the Tailscale API with
  OAuth client-credential and API-key auth, cursor-based pagination, and four-tier
  severity mapping.

- **AWS GuardDuty credential-exfiltration detection** (`detections/cloud/aws-guardduty-instance-credential-exfiltration.yaml`) —
  Sigma rule covering EC2 instance credential exfiltration via `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

---

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
  log sources (Sysmon, Windows Security, M365 audit, Azure sign-in,
  CloudTrail, Linux auditd, journald, EDR, DNS, web access, Kubernetes
  audit, GitHub audit, VPN, DB audit), wired to all 200 incidents. Each
  event is a templated dictionary with `{user}/{host}/{ip}/{campaign}`
  placeholders resolved against the incident it backs, and carries the
  fields a real connector pivots on (process tree, principal, source IP,
  log source, event ID).
- **Telemetry event factories + recursive resolver**
  (`scripts/generate_eval_incidents.py`) — `_sysmon`, `_winsec`, `_m365`,
  `_azure_signin`, `_cloudtrail`, `_auditd`, `_journald`, `_edr`, `_dns`,
  `_web`, `_k8s`, `_github`, `_vpn`, `_db` produce base event shapes; a
  recursive resolver walks nested dicts and substitutes incident
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
- **Render** (`render.yaml`) — managed, sleep-on-idle
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
  `apps/docs/.docusaurus/`, `apps/docs/build/`,
  `plugins/**/*-build-test`, `plugins/**/*-build`,
  `eval_report.json`, and `eval_mitre_accuracy_report.json` to
  `.gitignore`. Removed previously tracked Docusaurus cache and local
  IDE hook state files from the index.

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
