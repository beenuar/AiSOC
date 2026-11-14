# AiSOC fix pass

> **Status**: Locked plan. Implement as specified, do not edit.
> **Captured**: 2026-10-03, at commit `b1c6925a` (v16.0.0 plus one security fix).
> **Tracking**: `FIX_PASS_PROGRESS.md` mirrors progress; this file is the source of truth.

### Why this plan exists

An independent audit at v16.0.0 found that features the gap-closure and parity programs record as shipped fail on a real deployment, while every recent CI run on `main` is green. The pattern repeats: the test for each feature mocks exactly the boundary where its defect lives. Examples are a fake database connection that answers any query, an injected MCP session that bypasses the transport, and mocked sessions that never reach a missing table.

The claim-to-gate matrix reports 291 of 291 rows GATED while several of those claims are false.

This pass does three things:

- fixes the defects,
- makes the gates catch this class of defect, and
- corrects every claim that says more than the code does.

It adds no capabilities beyond what a fix needs. The open phases resume afterwards under their own plans: gap-closure 6.4, 7, 9, 10 and 13.4, and parity Phases 3 and 4, 5.5 to 5.7, and 6.2 to 6.10.

### Rules for this pass

These are in addition to the inherited rules.

- **Reproduce first, through the real path**, as the instructions above describe.
- **Claim rows.** A row whose gate does not drive the production path on the profile it names is downgraded to PARTIAL now, with the reason. It returns to GATED only in the PR that adds a gate which does. The ratchet limits NO GATE rows, not PARTIAL, so downgrading is always allowed.
- **Progress files.** Where `GAP_CLOSURE_PROGRESS.md` or `PARITY_PROGRESS.md` marks an item `[x]` that this audit found broken, change it to `[~]` with a pointer to the item here.
- **No new containers in CORE.** No feature work beyond what a fix requires.
- **House style.** No em dashes, Conventional Commits with DCO sign-off, no tool attribution, and no competitor product names (`scripts/check_competitor_names.py` scans plan files).

### Wave 1: Security and tenancy (P0)

**1.1 The agents service authenticates to the API as a service, for the tenant it is working on.**

- **Defect: no credential is ever delivered.**
  - The customer tools, the hunting agent and the sandbox tool authenticate with `AISOC_AGENTS_API_KEY` (`services/agents/app/tools/customer_tools.py`, `services/agents/app/hunt/agent.py`, `services/agents/app/tools/sandbox.py`).
  - No compose file, `.env.example` or Helm value delivers that key, so on `make up` all three answer "could not check".
- **Defect: one key serves every tenant.** When the key is set, it belongs to one tenant, so every tenant's investigation reads that tenant's data.
- **Defect: the key cannot carry the right scopes.** The routes need `actions:read`, `lake:query` and `hunts:read`, and none of these is in `VALID_SCOPES` (`services/api/app/api/v1/endpoints/api_keys.py`). Only a `*` key works.
- **Defect: the lake pivots send no credential.** The 11 pivots send only `X-Tenant-ID` (`call_investigation_tool` in `services/agents/app/tools/investigation.py`), so outside dev mode they get 401.
- **Fix:**
  - Replace the API key with the service-token pattern the context routes already use (`services/agents/app/security/tenant_scope.py`, and dual-mode routes such as `/api/v1/feedback/context-statements`).
  - The agents service sends the service token that compose already delivers, together with the tenant of the alert or run it is working on.
  - The API accepts a service caller only with a named tenant, and scopes every query to it.
  - Remove `AISOC_AGENTS_API_KEY`.
- **Reproduce:** set up two tenants, each with its own configured connector. An investigation for tenant B, through the real API app, must reach B's connector and never A's. Today it either fails authentication or reads A.
- **Gate:** extend `scripts/check_service_token_wiring.py` beyond names matching `*SERVICE_TOKEN` and `*INTERNAL_TOKEN`. It should cover every credential a service reads for an internal call, and fail any service-to-service HTTP call that carries no credential.

**1.2 Federated search authenticates to the connectors service.**

- **Defect:**
  - `services/api/app/api/v1/endpoints/federated.py` (the `client.post(url, json=payload)` call, around line 253) posts to the connectors query route with no Authorization and no tenant header.
  - The connectors router requires a console session or a service token (`require_console_or_service_auth`, `services/connectors/app/api/router.py`), so every SIEM answers 401.
  - This breaks the agent's federated tool, console federated search and the retro-hunt SIEM sweep.
  - The catalog proxy already does this correctly (`_service_token` in `services/api/app/api/v1/endpoints/connectors.py`, around line 330).
- **Fix:** one shared helper for every API-to-connectors call, carrying the service token and the tenant.
- **Reproduce:** drive `/api/v1/federated/search` against the real connectors FastAPI app, through an ASGI transport with its real auth dependency, not a mock that accepts anything.

**1.3 Vendor reads match the connectors tenants actually save.**

- **Defect:**
  - The read executors in `services/actions/app/live_actions/investigation_reads.py` register vendor ids `defender`, `entra` and `aws`.
  - Saved connectors use the catalog types `azure_defender`, `azure_entra` and `aws_cloudtrail`.
  - `services/api/app/services/agent_tools/vendor_reads.py` matches with `by_type.get(vendor_id)` and no alias.
  - So three of the five vendors added in gap-closure 4.2 are never offered to the agent, and they dispatch as `no_integration`.
- **Fix:** one alias map from executor vendor id to catalog connector types, used by every matcher: `vendor_reads.py`, `_pick_connector` in `services/api/app/services/playbook_step_dispatch.py`, and live-action dispatch.
- **Gate:** a new `scripts/check_vendor_catalog_ids.py` that fails when any registered executor's vendor id resolves to no catalog connector type.

**1.4 Earned auto-close grants are honoured, and the closure default is decided.**

- **Defect: the grant reader queries a table that does not exist.**
  - `_has_auto_close_grant` in `services/agents/app/closure/policy.py` queries `autonomy_grants`, filtering on `revoked_at` and `expires_at`.
  - The real table is `aisoc_autonomy_grants` (`services/api/migrations/067_autonomy_grants.sql`), and it has its own columns.
  - `require_grant` defaults to true (`078_closure_policy_and_kill_switch.sql`), so a tenant that enables a closure policy can never auto-close.
  - The claim row "Alert closure obeys per-tenant, per-class policy" is gated by a test whose fake connection answers any query.
- **Fix the query:** read the real table and its state columns.
- **Decide the default in an ADR.** Today a tenant with no policy row auto-closes at `AISOC_AUTO_CLOSE_THRESHOLD` (0.85) with no grant at all, which contradicts gap-closure Phase 2's goal.
  - Recommended: no auto-close without an earned grant, plus an explicit, audited per-tenant opt-in to the old threshold.
  - If adopted, this is BREAKING.
- **Reproduce:** on live Postgres with the migrations applied, a tenant with an enabled policy and an earned grant auto-closes a benign verdict at 0.99 confidence. Today it is refused with "relation autonomy_grants does not exist".
- **Gate:** `scripts/check_raw_sql_columns.py` must fail on any statement against a table no migration creates. Remove the `UNMIGRATED_TABLES` credit, or turn each entry into an expiring exception with a written reason.

**1.5 The hunting agent returns its findings, for the right tenant, with a ledger.**

- **Defect:**
  - The agents route builds `matches=list(getattr(result, "matches", []) ...)` (`services/agents/app/api/router.py`), but `HuntAgentResult` only has `findings`. So every hunt that found rows reports `checked: true, matches: []`, which reads as clean.
  - The API route requires `hunts:read` (`services/api/app/api/v1/endpoints/agents.py`), which no role holds except `*`.
  - The tenant the route checks is never passed on (1.1 fixes this).
  - `_record` in `services/agents/app/hunt/agent.py` calls the ledger with a signature the real ledger rejects. The tests pass because they use a fake ledger.
- **Fix:**
  - Return the findings.
  - Grant `hunts:read` to the analyst and threat-hunter roles through `app.core.role_grants`.
  - Pass the tenant through.
  - Write through the real ledger API.
- **Reproduce:** through the real agents app and the real ledger class, a hunt over matching fixture rows returns those rows and writes ledger rows.
- **Gates:**
  - Wire `scripts/check_hunt_agent_boundary.py` into a workflow; today no workflow runs it.
  - Fix `_references` in `scripts/check_gate_coverage.py` so a script path that only appears in a docstring or comment does not count as an invocation.

### Wave 2: The MCP client works over a real connection

**2.1 Transport.**

- **Defect:** `_CappedStream` in `services/agents/app/mcp/client.py` is not an `httpx.AsyncByteStream`. The locked httpx 0.28.1 asserts `isinstance(response.stream, AsyncByteStream)` in `_send_single_request`, so every real `list_tools` and `call_tool` fails.
- **Fix:** subclass `httpx.AsyncByteStream`, implementing `__aiter__` and `aclose`.
- **Reproduce:** run a real FastMCP streamable-HTTP server on a localhost socket and connect through `_CappedTransport`, with no `session_factory`. Keep the byte-cap test.

**2.2 Tool names.** `mcp.<server>.<tool>` (`services/agents/app/mcp/policy.py`) contains dots, which OpenAI-compatible function names reject (`^[a-zA-Z0-9_-]{1,64}$`). Use a valid, reversible encoding, and test every bound name against that pattern.

**2.3 SSRF and air-gap.**

- **Check then resolve again.** The guard resolves the hostname once, and httpx resolves it again when it connects. Either pin the connection to the address that was vetted, or state the limit honestly.
- **Air-gap: code, test and doc disagree.** `apps/docs/docs/operations/mcp-client.md` says internal servers stay reachable in air-gap mode. But `test_air_gap_mode_permits_an_internal_server` in `services/agents/tests/test_mcp_client.py` asserts they are refused, and compose passes no allowlist variable. Make all three agree.

**2.4 Docs and claim rows.**

- `apps/docs/docs/quickstart.md` says the `npx @aisoc/mcp` fallback works on a fresh clone, but the package is unpublished.
- `apps/docs/docs/operations/faq.md` and `apps/docs/docs/api/rest.md` quote stale tool counts, and say playbook actions can be run when only a dry-run preview exists.
- The claim row "MCP server exposes 14 tools" is stale.
- Generate the tool count from the server's registry and gate it.

### Wave 3: Replay, shadow mode and evaluation measure the real thing

**3.1 Frozen context, not empty context.**

- **Defect:**
  - An ordinary replay sends no context block (`services/api/app/services/replay_evaluation/job.py`, around line 228), so `services/agents/app/api/replay_router.py` builds an empty snapshot.
  - The runner passes no business-context rules (`business_context=` in `services/agents/app/replay/runner.py`), while production enables them (`services/agents/app/main.py`).
- **Fix:** capture organisation memory, priors, context statements, active skills and business-context rules as of the split point, and send them.
- **Docs:** `replay.md`, `triage-context.md` and `tenant-skills.md` already claim this happens.

**3.2 No side effects.** A replay must not:

- write shadow-mode decisions (`aisoc_shadow_decisions`)
- write to the live cost ledger
- fire the alert playbook trigger (`alert_trigger.run_for_alert` in `services/agents/app/workers/fused_alert_consumer.py`)
- receive a live verdict from the cost-governor dedup cache (`Decision.DEDUPLICATED`, around line 554)

Reproduce each with shadow mode on and `AISOC_ALERT_PLAYBOOKS_ENABLED=1`.

**3.3 Input shapes.**

- **Defect:** the Elastic and Defender readers return shapes their connector `normalize()` does not expect, and host, user and severity are lost.
  - Elastic: the reader returns search hits; `normalize()` expects flat ES|QL rows.
  - Defender: the reader returns Defender for Endpoint alerts; `normalize()` expects Graph alerts.
- **Fix:** add a per-source adapter.
- **Test:** one end-to-end test covering all five sources: reader output, then `normalize()`, then a triage input with host, user and severity present.

**3.4 Model attribution.** `model=_opt_text(getattr(state, "model_used", None))` in `fused_alert_consumer.py` (around line 785) is always `None`, because nothing sets `model_used` on the triage path, so per-model agreement is empty. Set it from the call that actually answered.

**3.5 Non-degenerate acceptance.** The Phase 1 reproducibility test currently passes over a constant output: every verdict is benign at 0.10. Drive it with a recorded model-response fixture through the real gateway client so verdicts vary, and assert that at least two classes are predicted.

**3.6 Tool calls.** The runner hard-codes `decision.tool_calls = 0`. Record the real count from the ledger.

**3.7 Demotion without a page load.**

- **Defect:**
  - Demotion runs only when someone reads the grants list (`services/api/app/api/v1/endpoints/autonomy_policy.py`).
  - Dispatch reads `state = 'granted'` without re-checking the evidence (`services/actions/app/services/tenant_policy.py`, around line 228).
  - `shadow-mode.md` claims dispatch does re-check.
- **Fix:** evaluate drift whenever a shadow decision or a closure lands, or on a scheduled sweep started in the API lifespan, and have dispatch call the same evaluator.
- **Reproduce:** injected disagreements trigger demotion with no read of the API.

**3.8 Skills.**

- **Activation.** Today activation only checks that two evaluation ids are attached and the version matches (`services/api/app/services/tenant_skills/store.py`, around lines 332 to 345). Require that both evaluations completed successfully, and that a delta was computed over the alerts the skill matches rather than the whole window.
- **LLM path only.** Skills reach triage only on the LLM path (`fused_alert_consumer.py`, around lines 561 to 574). The backtest report must say so.
- **No console editor.** Retract the console claims until parity 6.3 builds one: the claim row "A tenant can author an investigation skill in the console", `tenant-skills.md` and `triage-context.md`.

**3.9 The weekly live evaluation can actually run.**

- **Install.** `.github/workflows/wet-eval.yml` installs a hand-written dependency list that lacks `opentelemetry` and `mcp`. The agent cannot import, so the job prints "not measured" and goes green.
  - Install from `scripts/service_requirements.py agents --locked`, as CI does.
  - Fail the job on an import or setup error, distinguishing "no key" from "broken".
- **Missing data.** The live injection path reports neither proposed actions nor the tools used, so the unsafe-action rate and tool-call deviation cannot be measured. Pass both through from the ledger.
- **Claim row.** "The weekly job cannot go green having measured nothing" is false until this lands.

**3.10 The 9.3% flip rate.** The figure in `CHANGELOG.md` and `RELEASES.md` came from one hand run, on a model that is not the shipped one. State the model, the date, the sample size and that it was a single manual run, or remove the figure.

**3.11 CI runs the live tests.**

- **Dispositions test.** `tests/isolation/test_recent_dispositions_cutoff_live.py` runs in no job that has a database. The claim row "Analyst dispositions are point-in-time during a replay" cites a workflow that skips it.
- **Path filters.** The replay end-to-end and autonomy live tests in `.github/workflows/integration.yml` have pull-request path filters that exclude the code they cover: the triage worker, the SIEM clients, the connector mappings and the autonomy code. Fix the filters.
- **Skips.** When a database is expected and missing, the job must fail, not skip.

**3.12 Pivot counting.** `_classify_pivots` in `services/agents/app/investigator/deep_investigation.py` counts a call that returned `{"error": ...}` as a pivot. Count only calls that succeeded.

### Wave 4: Enterprise identity, white-label and metering

**4.1 SSO completes in the console.**

- **Defect:**
  - The OIDC callback returns the token in the URL fragment (`services/api/app/auth/oidc.py`, around line 433). Its comment says the console stores it, but no console code reads the fragment.
  - The login page offers only email and password.
  - SAML trust comes from process-wide environment variables (`_saml_settings` in `services/api/app/auth/saml.py`), while the stored `metadata_url` and `metadata_xml` in `aisoc_sso_connections` are never read.
- **Fix:**
  - A console callback handler that reads the token from the fragment, stores it and clears the fragment.
  - An SSO entry on the login page.
  - Use the per-connection metadata instead of the environment variables.
- **Reproduce:** end to end in CI, against a containerised OIDC provider and a SAML IdP. The claim row "SSO completes a sign-in" stays PARTIAL until this passes.

**4.2 Console MFA.** TOTP with recovery codes, per-tenant enforcement, and audited enrolment and reset. Today passkeys exist only on the mobile responder.

**4.3 White-label reaches every surface it claims.**

- **Defect:**
  - `sender_name` is read nowhere except the resolver.
  - `services/api/app/services/email_approval.py` hard-codes "[AiSOC]", and `send_approval_email` has no caller at all, so the signed email-approval fallback is not wired.
  - The Slack and Teams bots carry no branding.
  - Investigation and replay PDFs are unbranded.
  - Colours and support contacts are never applied.
  - The login page and page titles hard-code the product name.
  - The sidebar logo is a plain `<img>` pointing at `/api/v1/branding/assets/{id}`, which needs a bearer header an `<img>` cannot send. Verify in a browser and fix.
- **Fix:** brand every surface the doc and the claim row list, or narrow both to what is actually branded.

**4.4 Metering counts what happened.**

- `triages_model` counts alerts with `ai_summary` or `ai_score` set, but the deterministic path writes those columns too. Use the recorded path in `investigation_runs.model_used`.
- `investigations` counts every auto-triage.
- `events_ingested` is not metered on any profile.
- Actions are not split by tier.
- The CSV is per tenant, not per organization.

Fix these, or narrow the doc to what is measured.

**4.5 SCIM.**

- The Okta and Entra sequences run on SQLite against a bare app. Add PATCH, group membership and deactivation to the live Postgres test, through the real app.
- `apps/docs/docs/operations/scim.md` says tokens can be minted in the console. Add the page, or fix the doc.

**4.6 Maturity evidence.** The maturity table rates "SCIM 2.0, white-label, usage metering" as Stable on live Postgres, citing `tests/isolation/test_scim_live.py`. That file tests neither white-label nor metering (`scripts/check_maturity_table.py`). Each row must name evidence that actually exercises it.

### Wave 5: Hunting, intel, sandbox and operations wiring

**5.1 Retro-hunts can be turned on.**

- **Defect:**
  - Compose does not pass `RETRO_HUNT_ENABLED` through.
  - Tenant opt-in exists only as a raw `retro_hunt_settings` row.
- **Fix:**
  - Add the compose pass-through.
  - Add an API route and a console toggle for opt-in.
  - Test the real consumer loop (`run_forever` and `_build_consumer` in `services/api/app/workers/retro_hunt_consumer.py`), fed by the threat-intel pipeline's own producer rather than a hand-written message.

**5.2 KEV exposure gets data.**

- **Defect:** vulnerability rows come only from `POST /api/v1/assets/vulnerabilities`. The Tenable connector models findings as alerts and never writes them there.
- **Fix:** write Tenable findings into the vulnerability table, scoped to the tenant.
- **Test:** exposure end to end.

**5.3 Hunts over the lake.**

- **Defect:**
  - The agents image lacks a ClickHouse driver; `lake-live.yml` installs one by hand.
  - In the `full` profile, the agents container gets no ClickHouse settings.
  - The hunts filter on a `source` field and on derived fields that lake events do not carry.
- **Fix:** add the dependency, the settings and the field mapping, or narrow the README row "68-hunt YAML library, replayed against tenant events".

**5.4 Sandbox and air-gap settings reach the API.**

- Compose passes neither `AISOC_AIRGAPPED` nor the sandbox provider settings to the API, and the air-gap overlay sets the flag only on the agents service.
- With only the mock provider configured, phishing records nothing, which reads as "checked and clean". Record "no sandbox configured" instead.
- The agent tool labels any 403 as air-gap mode.

**5.5 Release channel.**

- **Defect:**
  - `.github/workflows/release.yml` moves `stable` on any non-major release (around line 676), so the first minor or patch of a new major carries it across. That is how it reached v12, v13 and v15.
  - The claim row "`stable` does not cross a major on its own" is backed by a test that only looks at one release at a time.
- **Fix:**
  - Track the channel's current major, and only move `stable` automatically within it.
  - Replace that test with one that runs a sequence of releases.
  - Add the `stable` chart channel the release policy names.

**5.6 Upgrade fixture.** `scripts/upgrade_fixture.sql` inserts into `cases`, which `083_one_case_table.sql` renames, so the upgrade test will break once the previous minor is 16.x. Fix it now.

**5.7 Chaos and HA in CI.**

- `chaos.yml` says it runs the graders live, but it only runs their self-tests. `scripts/chaos/fusion_restart.py` has run live once, by hand.
- `integration.yml`'s kill test posts one event while fusion is down, and checks for loss only.
- **Fix:** run the grader live on a schedule (compose is enough), killing fusion mid-stream and checking for duplicates as well as loss.
- The claim row "A fusion replica can be destroyed mid-stream" stays PARTIAL until a scheduled job runs it.

**5.8 Performance honesty.**

- The floors in `perf.yml` (`--assert-eps-floor 5`, `--assert-p95-ceiling-ms 120000`) sit roughly 35 and 100 times below the published figures. Set them relative to the published numbers.
- `scripts/check_perf_results.py` should require results for both deployments and a freshness bound.
- `scripts/perf/load_profiles.py` and `scripts/perf/throughput_claims.py` have no caller and contradict `apps/docs/docs/operations/performance.md`. Wire them in or delete them.
- Label the kind run as single-host.

### Wave 6: Retract what is not built

Each item below is presented as shipped and has no production caller. Retract or narrow the text now, wherever it appears: claim rows, README, release notes and docs. Each feature comes back with the PR that builds it, under the parity plan.

- **The v16 detection lifecycle.** Nothing reads `detection_rule_versions`, `detection_shadow_matches`, `environment` or `shadow_until` (`084_detection_lifecycle.sql`). Fusion ignores them, and there is no rollback route.
- **Enterprise IAM.** Workload identity, time-boxed elevation and ABAC conditions (`087_enterprise_iam.sql`) are unused, and `narrow_by_conditions` in `services/api/app/core/role_grants.py` has no caller.
- **Overclaims in `apps/docs/docs/intro.md`:**
  - a coverage advisor that "recommends new rules" and offers "one-click detection generation"
  - "Qdrant RAG memory"
  - "STIX/TAXII publishing" with collection management, when the TAXII collections are demo-only literals
- **The phishing playbook** "retracts the message fleet-wide" through an `http` step to an unset `${EMAIL_GATEWAY_URL}` that continues on failure. This is in both `playbooks/packs/v1/phishing/phishing-investigation.playbook.json` and `services/agents/app/playbook/packs/v1/phishing/phishing-investigation.playbook.json`.
- **Two broken detection-tuning routes:**
  - The detection-loop suggestion route (`services/api/app/api/v1/endpoints/detection_loop.py`) reads `aisoc_alerts` and `aisoc_detection_rules`, which no migration creates, and keeps its suggestions in a process-global dict.
  - `/api/v1/detection/tuning/auto-suggest` opens comment-only proposals with a null `base_rule_id` that cannot pass `/decide`.
  - Point both at the real tables with a persistent store, or remove both routes and their claims. Either way, the gate from 1.4 must catch the next one.

### Wave 7: Close the books

- Re-run every claim row this pass touched. No row stays GATED unless its gate drives the production path on the profile the row names.
- Update `GAP_CLOSURE_PROGRESS.md` and `PARITY_PROGRESS.md` so every box matches reality, with links to this pass's PRs.
- Add one `[Unreleased]` entry to `CHANGELOG.md` in house style. Do not tag.
- Write the final report in `FIX_PASS_PROGRESS.md`: each item's reproducing test, fix PR and negative control, and anything left `[!]`.

### Maintainer-only items (record as [!], do not attempt)

- Make the live jobs required checks with branch protection on `main`: replay end-to-end, autonomy live, retro-hunt live, SCIM live and chaos.
- Fund provider keys so the weekly evaluation produces real numbers.
- Provide a real multi-node cluster for the scale run.
- Accept or overrule the closure default proposed in the 1.4 ADR.
