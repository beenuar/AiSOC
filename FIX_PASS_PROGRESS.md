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

- [ ] **3.1** Frozen context, not empty context
- [x] **3.2** No side effects from a replay
- [ ] **3.3** Input shapes: per-source adapters for Elastic and Defender
- [x] **3.4** Model attribution: `model_used` is set from the call that answered
- [ ] **3.5** Non-degenerate acceptance for the reproducibility test
- [x] **3.6** Tool calls recorded from the ledger, not hard-coded to 0
- [ ] **3.7** Demotion without a page load
- [ ] **3.8** Skills: activation evidence, LLM-path-only disclosure, console retraction
- [~] **3.9** The weekly live evaluation installs from the lockfile and fails loudly; it still cannot *run* without a funded key (M2)
- [x] **3.10** The 9.3% flip rate is qualified or removed
- [x] **3.11** CI runs the live tests
- [x] **3.12** Pivot counting excludes failed calls

## Wave 4: Enterprise identity, white-label and metering

- [ ] **4.1** SSO completes in the console
- [ ] **4.2** Console MFA
- [ ] **4.3** White-label reaches every surface it claims
- [ ] **4.4** Metering counts what happened
- [ ] **4.5** SCIM live coverage and the console token claim
- [ ] **4.6** Maturity evidence names tests that exercise the row

## Wave 5: Hunting, intel, sandbox and operations wiring

- [ ] **5.1** Retro-hunts can be turned on
- [ ] **5.2** KEV exposure gets data
- [ ] **5.3** Hunts over the lake
- [ ] **5.4** Sandbox and air-gap settings reach the API
- [ ] **5.5** Release channel does not cross a major
- [ ] **5.6** Upgrade fixture does not insert into the renamed `cases` table
- [ ] **5.7** Chaos and HA run live in CI
- [ ] **5.8** Performance honesty

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

- [ ] **7.1** Re-run every claim row this pass touched
- [ ] **7.2** Update `GAP_CLOSURE_PROGRESS.md` and `PARITY_PROGRESS.md`
- [ ] **7.3** One `[Unreleased]` entry in `CHANGELOG.md`
- [ ] **7.4** Final report in this file

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

**Done, each with a reproduction and a negative control:** 3.2, 3.4, 3.6,
3.10, 3.11, 3.12, and the actionable half of 3.9.

**Not started:** 3.1 (frozen context), 3.3 (per-source input adapters),
3.5 (non-degenerate acceptance), 3.7 (demotion without a page load),
3.8 (skills activation evidence and the console retraction).

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
