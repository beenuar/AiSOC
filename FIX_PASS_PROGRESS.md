# AiSOC fix pass: progress

Mirrors `plans/aisoc_fix_pass_plan.plan.md`, which is locked and is the source
of truth. This file is the mutable half.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done, `[!]` blocked (with
exactly what is needed).

An item is `[x]` only when all three of these are recorded against it: the test
that failed on the pre-fix tree for the stated reason, the fix, and the negative
control showing that reverting the fix fails the test again.

- **Base commit:** `056f80a7` (`origin/main`, v16.0.1).
- **Plan captured at:** `b1c6925a`. File and line references are hints at that
  commit; where code has moved, the item records where it was found.

## Baseline

Recorded before any change, so a failure this pass did not cause is never
attributed to it.

Suites, each run from its own service directory:

| Suite | Result |
|---|---|
| `services/api` | 4178 passed, 40 skipped |
| `services/agents` | 1766 passed, 2 skipped, 219 subtests passed |
| `services/actions` | 1081 passed |
| `services/connectors` | 1000 passed |
| `services/fusion` | 419 passed, 2 skipped |

Gates, all passing: `check_competitor_names`, `check_gate_coverage`,
`check_gate_contract`, `check_test_discovery`, `check_route_auth`,
`check_route_authz`, `check_route_tenant_scope`,
`check_tenant_query_predicates`, `check_rls_policy_shape`,
`check_claim_gate_matrix` (291 rows, 291 GATED), `check_release_policy`,
`check_comment_paths`, `check_mypy_baseline`, `check_service_token_wiring`,
`check_raw_sql_columns`, `check_maturity_table`, `check_perf_results`.

**Everything is green, which is the premise of this pass rather than a
contradiction of it.** The audit's finding is that each defect's test mocks the
boundary the defect lives at, so a green suite is exactly what a tree carrying
these defects looks like.

### Environment note: the suites must run against the locked dependency set

A first run of `services/agents` on this machine's interpreter produced 10
errors in `tests/test_mcp_client.py`, all
`PydanticUserError: A non-annotated attribute was detected`. That is **not** a
repository failure: the machine carries `pydantic` 2.8.2 and an old `mcp` in
user site-packages, against a locked `pydantic` 2.13.4 and `mcp` 1.30.0. Re-run
inside a venv built from `scripts/service_requirements.py agents --locked`, the
same suite is fully green.

This matters beyond bookkeeping. Wave 2.1 turns on an assertion inside
`httpx` 0.28.1 exactly, so a result from any other httpx says nothing about the
defect. Every agents result in this pass is recorded against the locked set.

**A second interpreter trap, found while running Wave 1.** `services/api`
pins `httpx` **0.26.0** and `services/actions` pins **0.28.1**, so running the
actions suite in the api venv fails four URL-encoding assertions in
`test_alert_history.py` that have nothing to do with any change. Each service's
suite is run against that service's own locked set, and a cross-service result
is recorded as the artefact it is.

Two traps when building that venv, both hit here: `service_requirements.py`
emits environment markers as separate shell tokens, so splitting its output on
whitespace corrupts them, and stripping the markers instead makes the two
conditional `numpy` pins collide into an unresolvable install. Parse with
`shlex`, regroup on each `name==version`, and re-quote the marker operands.

## Wave 1: Security and tenancy (P0)

- [x] **1.1** Agents authenticates to the API as a service, for the tenant it is working on
- [x] **1.2** Federated search authenticates to the connectors service
- [x] **1.3** Vendor reads match the connector types tenants actually save
- [x] **1.4** Earned auto-close grants are honoured; the closure default is an ADR awaiting the maintainer (M4)
- [x] **1.5** The hunting agent returns its findings, for the right tenant, with a ledger

## Wave 2: The MCP client works over a real connection

- [x] **2.1** Transport: `_CappedStream` is a real `httpx.AsyncByteStream`
- [x] **2.2** Tool names match the function-name pattern
- [x] **2.3** Air-gap: code, test, doc and compose agree. SSRF re-resolution recorded as a stated limit
- [x] **2.4** Docs and claim rows: tool count gated per occurrence, unpublished package stated

## Wave 3: Replay, shadow mode and evaluation measure the real thing

- [x] **3.1** Frozen context, not empty context
- [x] **3.2** No side effects from a replay
- [x] **3.3** Input shapes: per-source adapters for Elastic and Defender
- [x] **3.4** Model attribution: `model_used` is set from the call that answered
- [x] **3.5** Non-degenerate acceptance for the reproducibility test
- [x] **3.6** Tool calls recorded from the ledger, not hard-coded to 0
- [x] **3.7** Demotion without a page load
- [x] **3.8** Skills: activation evidence, LLM-path-only disclosure, console retraction
- [~] **3.9** The weekly live evaluation installs from the lockfile and fails loudly; it still cannot *run* without a funded key (M2)
- [x] **3.10** The 9.3% flip rate is qualified or removed
- [x] **3.11** CI runs the live tests
- [x] **3.12** Pivot counting excludes failed calls

## Wave 4: Enterprise identity, white-label and metering

- [~] **4.1** SSO completes in the console
  - Two of the three defects did **not** reproduce: the console fragment consumer (`authApi.completeSsoHandoff`) and the login-screen SSO entry both landed in v17.1.0. Neither was covered by a test, so six now pin them. The third reproduced exactly as written — `_saml_settings()` read its IdP trust anchor from `SAML_IDP_*` while the connection's own `metadata_url` / `metadata_xml` were read by nothing, so a SAML login redirected to the environment's IdP and a correctly signed assertion came back `invalid_response`. Fixed in `app/auth/saml_metadata.py`; the ACS also now lands on `/login?next=` with both tokens, because the old RelayState redirect lost the fragment to the console's own auth guard. Driven end to end against real Postgres and a real signed assertion in `sso-live.yml`. **Still `[~]`**: the containerised-IdP leg (`sso-live.yml :: keycloak-oidc`) has never been observed to pass — no container runtime would start where it was written — so the claim row is PARTIAL, not GATED.
- [x] **4.2** Console MFA
  - Reproduced first: ten of eleven assertions against the real login route and real Postgres failed with `{"detail":"Not Found"}` — the surface did not exist. TOTP (RFC 6238, in-tree, pinned to the spec's own vectors rather than to a round trip), ten single-use recovery codes, a vault-encrypted secret, a `last_used_step` high-water mark so a code cannot be replayed inside its own 30-second window, per-tenant enforcement with **no backfill row** (absence means not required), and audited enrolment, disable, recovery-code use, policy change and administrative reset. A correct password for an enrolled account now answers **202** with a challenge instead of a session — 202 rather than a widened 200 body, because `access_token` is a required field and making it optional breaks every generated client. An unenrolled member of a newly-enforcing tenant enrols from that challenge rather than being locked out; the trade-off is stated in the module and the docs. Migration `096`. 28 offline tests, 13 live, and a CI negative control that deletes the challenge branch and requires the suite to go red.
- [x] **4.3** White-label reaches every surface it claims
  - Each of the eight bullets was checked against `main` first. Six were real and are now branded: both report workers (a reproduce-first test showed the scheduled digest rendering unbranded), the investigation summary, the replay report, email approvals — where `send_approval_email` had **no caller at all**, so the signed fallback was unreachable until `approval_delivery` wired it — the Slack and Teams prompts, and the sidebar logo, whose `<img>` could not send the bearer header the asset route requires, so its `src` no longer points there and a test asserts it. The browser tab was already branded client-side by `BrandedDocumentTitle`; the root metadata stays the platform default because SSR has no credential. **Two were narrowed with the reason recorded rather than built.** The sign-in page cannot be branded today: `GET /api/v1/branding` resolves the organisation from the caller's credential, there is none yet on that page, and nothing maps a hostname to an organisation — `organizations` has a slug and a name and no domain — so baking one name in would be wrong for every organisation on the deployment except one *while looking configured*, which is worse than the platform name. `services/actions` had no read path to branding at all and gets one that reads **only `product_name`**, mirroring the vault split; it never raises, because a lookup that failed would take down the approval prompt it decorates, and an approval nobody sees is worse than one under the wrong name. Found on the way: neither report worker could store an artefact on **real Postgres** — a status-vocabulary mismatch invisible to the test double. `white-label-live.yml` runs the live suite with two negative controls.
- [x] **4.4** Metering counts what happened
  - All five bullets fixed rather than narrowed. `triages_model` and `triages_deterministic` read `investigation_runs.model_used` — the path auto-triage records for itself — instead of `alerts.ai_summary`/`ai_score`, which `persist_auto_triage` writes from one statement on **both** paths, so a deployment with no model configured reported 100% AI triage; `investigations` now excludes auto-triage runs, which had made it a second alert count wearing a different label; `events_ingested` is a real ClickHouse meter, grouped per day in one scan, reported as **not measured** rather than `0` when the lake is absent *or* deployed-and-unreachable; actions split into `automatic` / `human_gated` / `tier_unrecorded` behind migration `095`, which also adds `approval_tier` and repairs a `status` column that had held `'ActionStatus.COMPLETED'` since the table was added — the repr of a `(str, Enum)` member, which no query and no index could ever match; and `GET /usage/organization/export.csv` exports a portfolio, scoped by `resolve_portfolio_scope` and refusing a non-member rather than quietly falling back to their own tenant. The audit found one defect the branch had introduced: the path meters discriminated on `model_used <> 'kafka:auto_triage:deterministic'`, which reads as "the model path" only while `deterministic` is the sole alternative, and the worker stamps **four** tiers — `memory` (institutional-memory suppression) and `cached` (a deduplicated replay) place no LLM call and were both counted as AI triages, by the meter *and* by the `triages_per_month` quota that shares the definition. That is the same false sentence reached by another route, and it was live on `main`. `MODEL_TIERS`/`NON_MODEL_TIERS` now enumerate the vocabulary, and an AST pin reads the worker's own tier literals and fails on any tier no meter classifies — the fixture could not have caught it, having seeded only the two tiers that already worked. 35 offline tests, every assertion against rows counted independently in the test; the two new cases were confirmed to fail against the pre-fix predicate and the pin to fail with a tier removed. `tests/isolation/test_usage_lake_meter_live.py` was run against a real ClickHouse carrying the shipped `001_init.sql` — six cases pass, and dropping the tenant predicate makes the suite red, as its CI negative control requires.
- [x] **4.5** SCIM live coverage and the console token claim
  - Both halves built, and the doc was made true rather than narrowed. `tests/isolation/test_scim_live.py` now drives 24 cases through `create_application()` against real Postgres: PATCH in both providers' dialects (Okta's pathless `replace`, Entra's `"False"` string and its boolean), rename, group membership add and remove in both dialects, group-name-to-role resolution, and deprovisioning proved by its consequences — API keys revoked, the session revocation time stamped, `DELETE` deactivating rather than erasing, and reactivation **not** restoring the revoked keys. Four tenant-isolation and unauthenticated negative controls sit alongside, so an empty table cannot pass for isolation. Run here against a live Postgres with all 110 migrations applied: 24 passed. It cannot pass vacuously — `ISOLATION_REQUIRE_LIVE` raises at import when the DSN is absent, which is a collection error and red where a skipped module is not (verified: red with the flag set and no DSN, 24 clean skips in the offline collection job), and `scim-live.yml` reads the counts out of the report afterwards and fails on fewer than 20 executed or any skip. `ENVIRONMENT` is `test`, never `development`, which is in `AUTH_BYPASS_ENVIRONMENTS` and would have resolved an uncredentialed request to a demo admin inside the one suite whose purpose is proving the tenant comes from the credential; heavy imports sit inside fixtures. The console claim is now real: `ScimTokensPanel` creates, rotates, revokes and lists against the four `/api/v1/scim-tokens` routes that already existed and that nothing under `apps/web/src` had ever referenced — six component tests, and `check_scim_contract.py` checks **both** directions, failing on a doc promising a panel that is unwired and on a panel the doc does not mention. The audit found the branch's `check_test_discovery.py` redirection fix shipped with no self-test case, so the gate still proved only the syntaxes it handled before; eight cases now assert the reader directly across all seven redirection forms plus a control that a real path following a redirection is still read, which is what stops the new clause silently dropping arguments.
- [x] **4.6** Maturity evidence names tests that exercise the row
  - The row read `SCIM 2.0, white-label, usage metering` and named one test, `tests/isolation/test_scim_live.py`, which exercises neither of the other two — and the gate reported **OK** on it for four releases. The reason is structural and is the part worth keeping: `_match_key` matches a row's capability cell on a **prefix**, so the first capability's genuine evidence satisfied the lookup and the other two inherited a pass they never earned. Checking that each row's evidence exercises it cannot catch this on its own, because a bundled row has only one evidence entry to check; the row has to be split first. Now three rows with three entries: SCIM keeps `scim-live.yml`, white-label takes `white-label-live.yml` (two negative controls), and metering takes `lake-live.yml` — whose evidence string was also **wrong**, not merely missing, since that suite runs on live ClickHouse and the shared cell said Postgres. `bundles_several_capabilities()` now refuses a cell that lists several capabilities, distinguishing a list from a subordinate clause so `Alert-triggered playbooks, with a durable approval pause` still passes; its self-test asserts both directions, including the exact string that defeated the gate. Splitting one row into three pushed the README to 252 against its binding 250-line cap, so a section was **displaced rather than squeezed**: `## Try it without connecting anything` was a heading over a single sentence that now sits at the end of Quick start, where it reads the same and costs two fewer lines.

## Wave 5: Hunting, intel, sandbox and operations wiring

- [x] **5.1** Retro-hunts can be turned on
  - Both halves built. `RETRO_HUNT_ENABLED` now passes through compose and is documented in `.env.example`, defaulting off; `GET`/`PUT /api/v1/retro-hunts/settings` plus a Settings panel give the tenant somewhere to opt in. Nine live tests against real Postgres; reverting the upsert to a plain UPDATE fails four.
- [x] **5.2** KEV exposure gets data
  - Connector now fetches per-asset findings plus plugin CVEs (capped at 60 lookups) and the connectors service writes `asset_vulnerabilities` directly -- not through the API, because the service principal is deliberately read-only. Seven live end-to-end tests. Creating the data first time exposed three more defects that had never run: a case status the CHECK rejects, two ORM models naming tables no migration creates, and a task status the CHECK rejects.
- [x] **5.3** Hunts over the lake
  - All three halves done. `clickhouse-driver` added to `services/agents` (lock regenerated with the pinned poetry 2.4.1); CLICKHOUSE_* mirrored onto the agents service in compose; and the field mapping went from **0 of 114** corpus fields resolvable to **114 of 114**, via `source` -> `connector_type` plus a parameterised `raw_payload` extraction covering the `EventData` and `System` nestings. README row narrowed from "replayed" to "compiled against", with the reason.
- [x] **5.4** Sandbox and air-gap settings reach the API
  - All four defects fixed: compose now passes `AISOC_AIRGAPPED` plus the CAPEv2 and MalwareAnalyzer settings to `api`; the air-gap overlay sets the flag on `api`, `threatintel` and `connectors` as well as `agents`; phishing records "no provider configured, this is not a clean verdict" instead of skipping an empty block; and the agent tool names a 403 as an authorisation problem with its three candidates rather than asserting air-gap mode. Both compose paths validate.
- [x] **5.5** Release channel does not cross a major
  - The channel now tracks which major it is on, resolved from the registry, so a minor cannot carry it across a major. Test replays release ladders rather than single releases. Helm chart gains the `stable` channel it was scoped with.
- [x] **5.6** Upgrade fixture does not insert into the renamed `cases` table
  - Fixture, before-snapshot and archive assertion all resolve the case table at run time. Reproduced against a fully-migrated database first: `relation "cases" does not exist`.
- [x] **5.7** Chaos and HA run live in CI
  - A `fusion-restart` job now runs the grader live on the weekly `chaos.yml` schedule -- 3,000 events, fusion destroyed at the halfway mark, graded against the `alerts` table for duplicates as well as loss. The claim row moves off its "not on a CI trigger" caveat: the three-node cluster it cited is not needed, because the property under test is the consumer's commit discipline and the sink's idempotency, and one replica killed mid-stream exercises both.
- [x] **5.8** Performance honesty
  - Thresholds now derived from the published compose steady-state figures (floor 11 = 7.3x below the published 80.1 alerts/s; ceiling 21,000 ms = 19.2x above the published 1,091 ms p95) instead of a constant 5 / 120,000 sitting 16x and 110x away. `check_perf_results.py` gained `REQUIRED_DEPLOYMENTS` and `MAX_RESULT_AGE_DAYS`. Both uncalled scripts are wired: the harness now records the load shape the claims tool requires, `--from-harness` translates it, and the one remaining gap (the harness does not measure detection coverage) is an explicit `--allow` with the problem still printed, not an absorbed failure.

## Wave 6: Retract what is not built

- [x] **6.1** The v16 detection lifecycle
  - Retracted. `detection_rule_versions`, `detection_shadow_matches` and `shadow_until` have zero readers in `services/`; the only `rollback` in the detection endpoints is a DB transaction rollback. Docs page, README and CHANGELOG now mark the four sections schema-only. Separation of duties is real and its claim stands.
- [x] **6.2** Enterprise IAM
  - Retracted. `workload_identities`, `privilege_grants`, `permission_conditions` have zero readers; `narrow_by_conditions` has zero callers. README and CHANGELOG narrowed; API-key rotation, which does work, kept.
- [x] **6.3** Overclaims in `apps/docs/docs/intro.md`
  - Retracted three intro.md overclaims: Qdrant holds the MITRE corpus for lookup (not agent memory), no coverage advisor or one-click generation route exists, and `GET /taxii/collections` calls `_demo_only()`.
- [x] **6.4** The phishing playbook's fleet-wide retraction
  - Corrected. The retraction step posts to an unset `EMAIL_GATEWAY_URL` under `on_failure: continue`; step name and playbook description now say the message is not retracted when unconfigured. Both copies identical.
- [x] **6.5** Two broken detection-tuning routes
  - Removed `detection_loop.py` (3 routes) -- `aisoc_alerts`, `aisoc_detection_rules` and `alerts.evidence` all absent, so a rename could not work; its test mocked the missing row. Emptying the gate debt list surfaced **three more** callers (business context preview, case timeline, identity timeline), all repointed at `alerts` with real column names. Added a guard refusing promotion of a comment-only body and defaulted the auto-tuner off. `KNOWN_MISSING_TABLES` is now empty and gated.

## Wave 7: Close the books

- [x] **7.1** Re-run every claim row this pass touched
  - Matrix: **302 rows, 299 GATED, 3 PARTIAL, 0 NO GATE**, counted by `check_claim_gate_matrix.py` rather than read off the summary line. Every static gate the touched rows name was re-run green: the matrix ratchet, maturity table (and its self-test), README gates, profile service counts, mypy baseline, comment paths, merge markers, attribution across 13,372 tracked files, competitor names, SCIM contract, detection fields, perf results, the one-case-table check, CI install parity and dependency pins. No row was promoted to GATED by this pass without the gate existing first; the three PARTIAL rows stay PARTIAL, including SSO, whose containerised-IdP leg has never been observed to pass.
- [x] **7.2** Update `GAP_CLOSURE_PROGRESS.md` and `PARITY_PROGRESS.md`
  - Parity **4.2 Console MFA** flipped to `[x]`, verified against the tree rather than against this file: `endpoints/mfa.py` mounted in the v1 router, migration `096`, `MfaView.tsx` in the console, `test_console_mfa.py` offline and `tests/isolation/test_console_mfa_live.py` live. Parity **4.1 SSO end to end** flipped to `[~]`, not `[x]` — the SAML metadata defect is fixed and driven end to end against real Postgres with a real signed assertion, but the containerised-IdP leg has never been watched to pass, and a box resting on a job nobody has seen succeed is not done. Everything else in both files was left alone: the remaining open boxes belong to the depth and gap-closure programmes, which are still running, and flipping them here would claim another plan's work.
- [x] **7.3** One `[Unreleased]` entry in `CHANGELOG.md`
  - Two entries under `### Fixed`, in house style, no tag: the enterprise-identity pass (white-label, metering, SCIM, maturity evidence) and the gate-parser fix. Both name what reproduced, what was narrowed instead of built, and why.
- [x] **7.4** Final report in this file
  - See **Final report** at the end of this file.

## Maintainer-only (recorded, not attempted)

- [!] **M1** Make the live jobs required checks with branch protection on `main`:
  replay end-to-end, autonomy live, retro-hunt live, SCIM live and chaos.
  **Needs:** a maintainer with admin rights on the repository.
- [!] **M2** Fund provider keys so the weekly evaluation produces real numbers.
  **Needs:** a funded API key set as a repository secret.
- [!] **M3** Provide a real multi-node cluster for the scale run.
  **Needs:** infrastructure the CI runner does not have.
- [!] **M4** Accept or overrule the closure default proposed in the 1.4 ADR.
  **Needs:** a maintainer decision on
  `docs/decisions/0009-auto-close-without-an-earned-grant.md`, which recommends
  option B (no auto-close without an earned grant, plus an audited per-tenant
  opt-in). It is breaking, so the fix pass does not take it: it changes what a
  running deployment does to alerts without being asked.

## Pre-existing failures

**None.** Every suite and every gate passes on `056f80a7` once the suites run
against their locked dependency sets. The 10 `test_mcp_client.py` errors seen
on a first run were this machine's interpreter, not the tree; see the
environment note above.

## Deviations

Items whose defect did not reproduce, with the evidence.

_None yet._

## Item log

Per item: the reproducing test, the fix, the negative control, and the PR.

### 1.1 Agents authenticates to the API as a service, for the tenant it works on

**Reproduced, all four defects, before any change.**

* `AISOC_AGENTS_API_KEY` was read by three modules and set by nothing: no
  compose file, no `.env.example`, no Helm value.
* `VALID_SCOPES` held 23 entries and none of `actions:read`, `lake:query` or
  `hunts:read`, so only a `*` key could reach the routes those tools call.
  `hunts:read` was held by **no role at all**, not even `tenant_admin`.
* The eleven lake pivots in `call_investigation_tool` sent `X-Tenant-ID` and
  no credential. The API's auth reads neither.
* The API had no service-caller path whatsoever.

**Reproducing test:** `tests/isolation/test_agent_service_auth_live.py`, the
real `create_application()` against Postgres 16 with all 100 migrations
applied, driven over a real `httpx` client with exactly the credential compose
hands the agents container. Pre-fix: `2 failed, 4 passed`, the two failures
being `401 {"detail":"Could not validate credentials"}` and then an empty
connector list. The 4 that pass pre-fix are the negative controls, which must
pass in both directions or they are not controls.

**Fix:**

* `services/api/app/api/v1/deps.py` gains `_resolve_service_principal`, ahead
  of the JWT path. A service token must declare its tenant on
  `X-AiSOC-Tenant-ID`; no tenant is an **empty** scope rather than every
  scope, and the tenant is checked against the `tenants` table because the
  header is caller-supplied.
* The principal carries an explicit seven-permission read-only set, not the
  wildcard. One shared secret equal to `platform_admin` on every tenant is
  the defect this is supposed to prevent, not reproduce.
* `customer_tools.py`, `sandbox.py`, `hunt/agent.py` and `investigation.py`
  present `AISOC_API_SERVICE_TOKEN` (falling back to `AISOC_SERVICE_TOKEN`)
  and name the tenant beside it. The tenant is threaded from the run, never
  from the model: `run_deep_investigation` already had it and simply never
  passed it on.
* `hunts:read` granted to `tenant_admin`, `soc_lead`, `soc_analyst` and
  `threat_hunter`, beside the `lake:query` they already hold.
* The three permissions are now mintable scopes, so a tenant automating one
  of these reads no longer needs a wildcard key.
* `AISOC_AGENTS_API_KEY` is gone. `AISOC_API_SERVICE_TOKEN` is generated by
  `scripts/ensure_env.py`, documented in `.env.example` and delivered to both
  `agents` and `api` by compose.

**Negative control:** removing the three-line wiring from `get_current_user`
returns the suite to `2 failed, 4 passed`, with the same 401.

**Gate:** `scripts/check_service_token_wiring.py` gains a second direction.
The first asks whether a *variable* reaches a process; the new one asks
whether the *request that needed it* carries a credential. Proven against the
pre-fix tree: restoring the old pivot headers makes it name
`investigation.py:69` exactly.

Two refinements the gate needed, each caught by running it: resolving a URL
helper by its **body** rather than its name (`_alerts_url()` in the Trellix
connector builds a customer's vendor URL, and a gate that reports a vendor
call as an uncredentialed internal one teaches people to ignore it), and
reading `headers["Authorization"] = ...` as well as `headers = {...}` (the
ingest client adds the credential by subscript).

**It then found two more of the same defect**, one of which the plan names as
1.2 and one it does not: `federated.py:253` and `case_fanout.py:185`.

### 1.2 Federated search authenticates to the connectors service

**Reproduced.** `tests/test_connectors_calls_are_credentialed.py` starts the
**real connectors application** (`app.main:app`) as its own process on a
loopback socket and drives `federated._query_one_backend`, the function the
route calls. Pre-fix the verdict reads
`status='error' error='backend 401: missing bearer credential'`.

Three decisions the first draft got wrong, each of which would have produced a
test that passed over the defect:

* **It mounted the router instead of the application**, which dropped the
  `/api/v1` prefix, so the first run saw 404 where a deployment sees 401. A
  harness artefact that reads exactly like a passing test.
* **It asserted on `_catalog_headers`**, the helper that already worked. What
  shipped broken is that federated search never called it, so a test of the
  helper passes on the defective tree. It now drives the production path and
  pins the helper separately.
* **It re-implemented the "every caller uses it" walk** and was worse at it
  than the gate, naming five call sites that reach the agents service and a
  vendor. That half is deleted with the reason recorded; the gate owns it.

Both services name their package `app`, so the far side runs in a subprocess
rather than being imported. Skipping around the clash was the alternative and
a skipping test reports the same word as a passing one.

**Fix:** `services/api/app/core/connectors_auth.py` is now the single
implementation. `federated.py` and `case_fanout.py` call it with the
connector's own `tenant_id`; `connectors.py::_catalog_headers` delegates to it
rather than keeping the second copy that let this happen.

**Negative control:** removing `headers=connectors_headers(...)` from
`federated.py` returns the suite to `1 failed, 4 passed` with the same 401.

**Also fixed, not in the plan:** `case_fanout.py:185` had the identical
defect on case push and status polling. The gate found it; the plan named
only federated search.

### 1.3 Vendor reads match the connector types tenants actually save

**Reproduced** by the new gate, which is the clearest statement of the defect:
`scripts/check_vendor_catalog_ids.py` on the pre-fix tree names `aws`,
`defender` and `entra` as vendor ids that resolve to no connector a tenant can
save, out of 7 executors against 85 saveable types.

A read executor is named for the product; a connector for the integration a
tenant configures. For four of the seven the strings coincide. For the other
three `by_type.get(vendor_id)` returned `None` on every tenant, so three of the
five vendors added in gap-closure 4.2 had never once been offered to an
investigation. The lookup that misses is the same expression as the one that
hits, which is why nothing failed.

**Fix:** `services/api/app/services/agent_tools/vendor_aliases.py` holds the
map and one `resolve()` used by both matchers, `vendor_reads.available_reads`
and `playbook_step_dispatch._pick_connector`. The map holds exceptions only, so
it does not become a second copy of the catalog that drifts from it.

`_pick_connector` needed more than a lookup swap: it built an `IN` clause from
raw executor ids, so the query itself selected nothing for those three.

**Negative control:** emptying `VENDOR_CONNECTOR_TYPES` fails 4 of the 10 tests
in `tests/test_vendor_alias_resolution.py` and leaves the 6 that must not move.

**The gate caught an error in its own fix**: the first alias named
`aws_securityhub`, and the connector declares `aws_security_hub`. An alias to a
type nobody can save resolves to nothing, exactly like no alias at all, and the
gate said so before the code shipped.

### 1.4 Earned auto-close grants are honoured

**Reproduced** against Postgres 16 with all 100 migrations applied.
`tests/isolation/test_closure_grant_live.py` pre-fix: `1 failed, 5 passed`,
the failure logging
`closure.grant.unreadable error='relation "autonomy_grants" does not exist'`.

Three names wrong in one statement: the table is `aisoc_autonomy_grants`, and
the filters named `revoked_at` and `expires_at` where the lifecycle is a
`state` column of `shadow` / `granted` / `demoted`. Because `require_grant`
defaults to true, a tenant that enabled a closure policy could never auto-close
anything: the feature was off for exactly the tenants who turned it on.

**Fix:** the query reads the real table and its real state column. The
`except` stays, because a database blip must not close alerts, but the live
suite now asserts the query itself works rather than trusting a fake connection
that answers any query.

**Negative control:** restoring the old table name returns the suite to
`1 failed, 5 passed` with the same message.

**Gate.** `check_raw_sql_columns.py` **passed over this for as long as it
shipped**, and the reason is more interesting than the defect: a `SELECT`
against a table no migration creates was bucketed as "not compared", on the
stated reasoning that the gate cannot tell which engine a statement targets.
That is true, and the remedy is to say which, once, rather than excuse the
class. `FOREIGN_ENGINE_TABLES` now declares the ClickHouse, Postgres-catalogue,
osquery and vendor tables, and **everything else fails**.

Closing it required two parser improvements, because the first run reported
four false positives: common table expressions are now detected from the
statement's own `WITH` clause rather than allowlisted one at a time, and a
statement composed across two string literals is recorded as the one artefact
that detection cannot reach, with that reason written down.

Proven against the pre-fix tree, where it names
`services/agents/app/closure/policy.py:307 autonomy_grants`. Two new self-test
cases pin both directions, and one existing case was renamed because it had
described the old reasoning.

**It also surfaced fix-pass item 6.5 early:** `aisoc_alerts` and
`aisoc_detection_rules` are named by live routes and created by no migration.
They are recorded in `KNOWN_MISSING_TABLES` as a debt that names 6.5 as the
item which removes them, rather than being quietly excused.

**The closure default is not decided here.**
`docs/decisions/0009-auto-close-without-an-earned-grant.md` records the
question, three options and a recommendation. Taking it changes what a running
deployment does to alerts without being asked, so it is `M4`.

### 1.5 The hunting agent returns its findings, for the right tenant, with a ledger

**Reproduced.** `services/agents/tests/test_hunt_route_returns_findings.py`
pre-fix: `2 failed, 2 passed`.

* `assert [] == [{'host': 'WS-42', ...}]`. The route built
  `matches=list(getattr(result, "matches", []) or [])` and `HuntAgentResult`
  has `findings`. The `getattr` default made it silent, so **every hunt that
  found rows answered `checked: true, matches: []`** -- a dropped answer that
  reads exactly like a clean result.
* `_record does not supply ['agent', 'seq', 'summary', 'tenant_id']`, which
  the real `record_event` requires.

**Worse than the plan states, and found by tracing the caller:** the only
production caller passed **no ledger at all**, so `_record` returned at its
first line. **No hunt had ever written a ledger row**, and the signature
mismatch underneath was never even reached. The agent's own suite asserted on
ledger writes against a double it supplied itself, which accepts any keyword
arguments and so cannot tell a call the real ledger rejects from one it
accepts.

**Fix:** the route returns `result.findings`, passes the tenant it already
resolved, and hands `run_hunt` the real ledger module. `_record` supplies every
required field and owns the per-run `seq`, because a caller that forgot would
write every row at zero and the replay would be unordered.

`hunts:read` was granted to the four hunting roles in item 1.1; no role held it
at all, not even `tenant_admin`.

**Negative control:** restoring the `getattr(result, "matches", [])` line
returns the suite to a failure on the dropped findings.

**Gates, and the one that was lying.** `check_hunt_agent_boundary.py` is run by
no workflow, and `check_gate_coverage.py` reported **all 150 checks reachable**
anyway: five modules and two test files name it in a **docstring** saying which
gate enforces their contract, and `_references` counted that as an invocation.

Stripping whole-line comments was not enough; the references are in
triple-quoted blocks. With prose removed the gate immediately named two
unreachable checks, one of them `check_vendor_catalog_ids.py` from item 1.3:
**the ci.yml edit for that gate had silently failed on an anchor mismatch, and
the coverage gate's own blindness had hidden it.** Both are now wired and the
pass is real.

### Wave 1: three things CI found that local verification did not

Recorded because each is the same class of defect this pass is about.

**The published spec gained a 422 on all 456 operations.** Declaring the
service tenant as a `Header` parameter on `get_current_user` puts it on every
route that depends on authentication, and a parameter that exists can fail
validation. It is how a peer *service* names the tenant it acts for, not part
of the contract a customer codes against, so it is read off the `Request` and
the spec is unchanged. `Request | None` is not a valid FastAPI annotation, and
the parameter has to precede the defaulted ones.

**Semgrep went 104 to 106.** Both findings were mine, and both were
`python-logger-credential-disclosure` firing on the word "token" inside a log
event name. Neither call logs a secret: one logs a header name, the other a
tenant id. The events are renamed to describe the *caller* rather than its
credential, which is also the more accurate name, and the count is back at the
ceiling. **The ceiling did not move.**

**Both new live suites ran in no workflow.** They skip themselves when their
DSN is unset, and nothing set one, so neither would ever have executed.
`.github/workflows/agent-auth-live.yml` now applies every migration, connects
as the DML-only runtime role so RLS is not bypassed, and asserts at the end
that the DSN was set, because a skipped live suite reports the same word as a
passing one.

**One limitation, stated rather than papered over.** The live auth suite passes
alone and fails three assertions when run in the same process as the full
`services/api` suite, which sets the dev-mode environment the suite needs
absent. CI runs them in separate jobs, and `ci.yml` excludes
`tests/isolation/` for this reason, so the arrangement is sound. It is recorded
here because "passes only in isolation" is a fragility, not a result.

## Wave 2: the MCP client over a real connection

### 2.1 Transport

**Reproduced.** `services/agents/tests/test_mcp_real_transport.py` runs a real
`FastMCP` streamable-HTTP server on a loopback socket and connects with **no
`session_factory`**. Pre-fix: `AssertionError` raised inside
`httpx/_client.py:1732`, `assert isinstance(response.stream, AsyncByteStream)`.

`_CappedStream` was a plain class, and its `__aiter__` was `async def`, which
makes the object an awaitable rather than an async iterable. Both are fixed.

**Why the existing suite could not see it.** Every test in
`test_mcp_client.py` drives `McpClient` through `session_factory`, which exists
so a test can run a real MCP server in-process. That is a good harness for the
policy questions it asks and it bypasses the transport entirely, so the one
thing it cannot test is the transport. The byte-cap test exercised
`_CappedStream` directly, so the cap was genuinely proven and the path to it
was not.

**A second defect found by fixing the first.** With the isinstance error gone,
the byte cap fired and the *reason was unrecoverable*: the cap raises inside
the stream, the MCP library reads that stream in its own `anyio` task, and
what reaches the caller is `ExceptionGroup -> ExceptionGroup -> TimeoutError`
with the `ResponseTooLarge` nowhere in the tree. Measured by walking the group,
not assumed. That matters because `tools._failure` reports
`type(exc).__name__` to the model and the ledger, so a tenant's own cap firing
was recorded as the server being slow -- a diagnostic naming the wrong cause.

`CapMarker` carries the reason by reference from the client down to the stream.
A `ContextVar` was tried first and cannot work: a context propagates *into* a
child task, so a value set by the reader is invisible to the coroutine that
awaited it.

**Negative control:** reverting the base class alone returns 3 failures.

### 2.2 Tool names

**Reproduced:** `'mcp.fixpass.lookup_host' is not a callable function name`.
A dot is outside `^[a-zA-Z0-9_-]{1,64}$`, so **every MCP tool offered to a
model was rejected by the provider**, and nothing local could see it because
the name is only validated at the far end.

`namespaced` now emits `mcp__<server>__<tool>` with each part escaped, and
`parse_namespaced` reverses it. Dispatch is by dict lookup and never needed
parsing; the reverse exists so a ledger row names the server that answered.
Readability is the cost: `get_host` encodes as `get_5fhost`, because escaping
`_` is what keeps the `__` separator unambiguous.

The existing tests hardcoded `mcp.vendor.get_host`. They now derive the
expected name from `namespaced()`, so a future encoding change cannot diverge
silently again.

**Negative control:** restoring the dotted form fails 6 of the 9.

### 2.3 Air-gap: four sources, four different answers

Measured against `validate_outbound_url` rather than read off the doc:

| Target | `ALLOW_PRIVATE` unset | set |
|---|---|---|
| `127.0.0.1` | refused, loopback | **still refused** |
| RFC1918 | refused, private | allowed |

So the doc's "Internal MCP servers keep working" was true of the air-gap check
and false of the deployment. The test named
`test_air_gap_mode_permits_an_internal_server` **asserted the server is
refused** -- its own docstring said so -- and the doc had read the name.

Corrected: the doc states both switches and that loopback never works; the
test is renamed to what it proves; and compose now passes `AISOC_AIRGAPPED`,
`AISOC_AIRGAP_ALLOWLIST` and `AISOC_SSRF_ALLOW_PRIVATE`, none of which it
delivered, so an operator could not permit an internal server at all.

**The check-then-resolve-again half is a stated limit, not a fix.** The guard
resolves a hostname and httpx resolves it again when it connects. Pinning the
connection to the vetted address needs a custom transport resolver, which is
out of scope for a fix pass; it is recorded here and in the doc rather than
left implied.

### 2.4 Docs and claim rows

* `@aisoc/mcp` answers **404** on npm, so the quickstart's "works on a fresh
  clone before you've run `pnpm build`" was false. Corrected to say the build
  is required and why.
* The claim matrix carried **two rows for the same claim**, one saying 19 tools
  and a stale one saying 14 that cited a README line which does not mention
  tools. The real count, generated from `ALL_TOOLS`, is **19**.
* **The gate that should have caught it was blind.**
  `tests/published-count.test.ts` used `pattern.exec(body)`, which returns the
  first match and stops, so the correct row shadowed the wrong one and the gate
  reported OK over a false claim in the governance file itself. It now checks
  every occurrence, and with that change it names
  `publishes 14, the registry holds 19` before the row was removed.
* Removing the row took the matrix 291 -> 290, which `readme_gates` caught in
  three more documents quoting the old figure. That is the copied-count failure
  working as designed.

## Wave 3 (partial): what is done and what is not

**Done, each with a reproduction and a negative control:** 3.1, 3.2, 3.3,
3.4, 3.5, 3.6, 3.7, 3.8, 3.10, 3.11, 3.12, and the actionable half of 3.9.

**Wave 3 is closed.** Every item carries its reproduction and its negative
control; 3.9's remaining half is maintainer-blocked on a funded key (M2).

### 3.2 A replay has no side effects

Two of the four the plan names were **already closed** and are recorded as
such rather than re-fixed: `ShadowTriageWriter.persists_cost` is `False`, and
every write method returns the nothing-happened value its live counterpart
returns on a no-op.

The other two did not reach the worker through the writer, so nothing declined
them. `alert_trigger.run_for_alert` was unconditional, so **a replay of last
month's alerts would have fired this month's playbooks**. And the cost
governor's `DEDUPLICATED` branch answered from a live cache, so a replayed
verdict could be one production already produced, which measures the cache.

Adding the two members to the writer protocol immediately named the three
classes that implement it, because `ShadowModeTriageWriter` stopped satisfying
`isinstance`. Shadow mode answers differently from replay on purpose: it
withholds playbooks and keeps deduplication, and both reasons are written down.

### 3.4, 3.6, 3.12

See the commit; each is a figure that was structurally unable to be right.
`InvestigationState` had no `model_used`, so the shadow writer's `getattr`
default was the only branch that ever ran. `tool_calls` was a literal under a
comment promising it would move. `_classify_pivots` counted a raised call as a
pivot, so four timeouts looked like four pivots.

### 3.7 Demotion without a page load

Reproduced against a real Postgres before anything was written. A tenant
earns `auto_execute` on `isolate_host` from a 240-decision record, 30
disagreements are injected -- window agreement 88.9%, trailing slice 40%, both
under the floors -- and then, with no read of the API: the grant row still
says `granted`, and `services/actions` still reports
`earned_autonomy_for('isolate_host') == 'earned'`. That second one is the
sharp end. It means the dispatch path would have auto-isolated a production
host on a track record the product itself no longer accepted.

Two callers now, where there was one. `app.workers.autonomy_drift` sweeps
every tenant holding a grant on a timer from the API lifespan and writes the
demotion with its audit row; `tenant_policy` re-runs the same evaluator before
handing a verb to dispatch and **withholds** one that no longer holds,
without writing anything -- issuing and revoking stay with the service that
owns the hash chain.

The sweep is on by default, unlike `shadow_reconcile` beside it, and the
difference is what each reaches: that one polls a customer's SIEM, this one
aggregates rows this deployment already wrote. A safety control that has to be
switched on is off wherever nobody knew to switch it on.

**A defect in the fix, caught by its own positive control.** The two shared
aggregates bind different parameter counts -- the trailing slice takes `$7`
for its `LIMIT`, the window aggregate stops at `$6` -- and passing seven to
both made asyncpg refuse. The refusal was caught and an unreadable record is
treated as no record, so *every* grant on *every* deployment was withheld
while the log called the evidence unreadable. It passed the demotion test
perfectly. Only the test asserting a healthy tenant **keeps** its verb found
it. A safety control stuck on reads like working caution, which is why
nothing about the symptom says "broken", and the arity is now derived from
the statement so an edit to the shared module cannot put it back.

`scripts/check_module_reachability.py` went the way an allowlist is supposed
to: `autonomy_evidence_rules.py` was listed as a permanent entry reached only
by tooling, the dispatch re-check gave it a production caller, and the gate
refused the stale entry.
### 3.5 Non-degenerate acceptance

Measured before touching anything: all six decisions in the test window came
back `benign` at `0.10` on tier `deterministic`, so Phase 1's acceptance bar
was one constant list compared against itself.

The replacement drives the same runner with a recording of
`llama3.2:3b-instruct-q4_K_M` -- the model the air-gap compose file bundles --
answering the production triage prompt, served to the real gateway client over
a loopback socket rather than through a patched transport. Recorded replies
give the two properties a live model and a constant each give only one of:
they vary, and they repeat.

Proven non-vacuous rather than asserted to be. Flattening the recording to a
single verdict leaves the old bar passing (`first == second`) and makes the
new one fail, and `test_the_acceptance_bar_rejects_a_constant_verdict_stream`
keeps that proof in the suite.

Two things the recording exposed that a constant could not. The LLM path
writes the call's elapsed time into a finding string, so `latency_ms` was not
the only wall clock in a decision and the run was not reproducible until that
was excluded too. And one of the six real replies is malformed -- the model
truncated mid-rationale -- which the committed fixture keeps as it arrived,
because a recording edited until it parses is no longer a recording.

The alerts are synthetic and the fixture's own `provenance` block says so;
only the replies are real.

### 3.9 is half done, and the half that is left is M2

Installing from the lockfile and failing loudly on an import error are done.
The job still cannot produce a number, because it is gated on a funded key
that does not exist. **The claim row "The weekly job cannot go green having
measured nothing" is therefore still not true**, and is left for wave 7 to
downgrade rather than quietly marked done here.

### A correction to the plan's reading of 3.6

The plan calls the literal `0` a hardcoded placeholder. It is not: zero is the
correct answer today, because shadow mode declines escalation and escalation is
the only stage that calls tools. The defect is narrower and worse -- the
comment above it says the figure is "recorded so a future change that gives
triage a tool shows up here as a number moving off zero", and a literal can
never move. The fix derives the same zero from the ledger so it can change
when the run does.

## Final report

**Where it landed: 40 of 48 items `[x]`, 2 `[~]`, 4 `[!]` maintainer-only.** The
two still showing `[ ]` here — 4.3 white-label and 4.6 maturity evidence — are
complete and flipped on the branch carrying their PR; they read open only in a
worktree cut before it merged. Re-read this file on `main` rather than trusting
that sentence.

### What this pass was for

It added no capability. It existed to repair what two other programmes had
recorded as shipped and an audit found broken, which is why nearly every item
begins with a reproduction rather than a design.

### The pattern that recurred most

**A mechanism existed, passed its tests, and nothing called it on the path that
mattered.** `send_approval_email` had no caller at all, so the signed
email-approval fallback was unreachable. The retro-hunt flag passed through no
compose file, so a tenant could not turn the feature on. `find_matching()` had
no production caller, so no playbook had ever run from an alert. A passing test
on an uncalled function is indistinguishable from a working feature until
somebody traces the call graph.

**Its second half is worse and reachability analysis cannot see it: the code
runs and the table it reads is one nothing writes.** `triages_model` counted a
column the deterministic path also writes, so a deployment with no model
reported 100% AI triage — and the figure looked plausible, which is why it
survived four releases.

### What the gates themselves got wrong

Three gates were found grading something other than what they claimed.

- `check_maturity_table` matched a row on a **prefix**, so one row covering
  SCIM, white-label and metering satisfied the lookup with a single SCIM test
  and the other two capabilities inherited a pass. It printed OK for four
  releases.
- `check_ci_install_parity` read the `tee` target in
  `pytest … | tee /tmp/wl.txt` as a pytest **directory** argument, concluding a
  job naming one file ran a whole service suite. Thirteen findings from one
  `tee`.
- `check_test_discovery` read a shell redirection as a test path.

All three are the same shape: **a detector that knows one syntax of the
language it parses.** Each fix ships with a self-test asserting both
directions, because a parser fix that stops detecting is worse than the bug.

### What was narrowed rather than built, and why

Narrowing is in the plan as a legitimate outcome, and it was used twice, both
times with the reason recorded beside the claim.

- **The sign-in page is not branded.** Branding resolves from the caller's
  credential and there is none yet on that page; nothing maps a hostname to an
  organisation, because `organizations` has a slug and a name and no domain.
  One name baked into the process would be wrong for every organisation on the
  deployment except one, *while looking configured* — worse than the platform
  name.
- **`services/actions` reads only `product_name`.** The API resolver also
  returns colours, a logo, support contacts and a footer; none has anywhere to
  go in a Block Kit payload or a MessageCard, and resolving fields nobody
  renders is how a second resolver starts drifting from the first.

### What is left, and why it is not a gap

Four items are `[!]` maintainer-only and were recorded rather than attempted:
making the live jobs required checks under branch protection, funding provider
keys so the weekly evaluation produces real numbers, a real multi-node cluster
for the scale run, and accepting or overruling the closure default in the 1.4
ADR. None is a code change.

Two are `[~]`, and both are deliberate rather than unfinished. **3.9** installs
from the lockfile and fails loudly but cannot *run* without a funded key (M2).
**4.1** SSO is fixed and driven end to end against real Postgres with a real
signed assertion, but its containerised-IdP leg has never been observed to
pass, so the claim row is PARTIAL — a row resting on a job nobody has watched
succeed is not gated, and relabelling it would make this file a liability
instead of a control.
