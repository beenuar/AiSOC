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

Two traps when building that venv, both hit here: `service_requirements.py`
emits environment markers as separate shell tokens, so splitting its output on
whitespace corrupts them, and stripping the markers instead makes the two
conditional `numpy` pins collide into an unresolvable install. Parse with
`shlex`, regroup on each `name==version`, and re-quote the marker operands.

## Wave 1: Security and tenancy (P0)

- [x] **1.1** Agents authenticates to the API as a service, for the tenant it is working on
- [ ] **1.2** Federated search authenticates to the connectors service
- [ ] **1.3** Vendor reads match the connector types tenants actually save
- [ ] **1.4** Earned auto-close grants are honoured, and the closure default is decided
- [ ] **1.5** The hunting agent returns its findings, for the right tenant, with a ledger

## Wave 2: The MCP client works over a real connection

- [ ] **2.1** Transport: `_CappedStream` is a real `httpx.AsyncByteStream`
- [ ] **2.2** Tool names match the function-name pattern
- [ ] **2.3** SSRF re-resolution and air-gap: code, test and doc agree
- [ ] **2.4** Docs and claim rows: generated tool count, unpublished package, stale counts

## Wave 3: Replay, shadow mode and evaluation measure the real thing

- [ ] **3.1** Frozen context, not empty context
- [ ] **3.2** No side effects from a replay
- [ ] **3.3** Input shapes: per-source adapters for Elastic and Defender
- [ ] **3.4** Model attribution: `model_used` is set from the call that answered
- [ ] **3.5** Non-degenerate acceptance for the reproducibility test
- [ ] **3.6** Tool calls recorded from the ledger, not hard-coded to 0
- [ ] **3.7** Demotion without a page load
- [ ] **3.8** Skills: activation evidence, LLM-path-only disclosure, console retraction
- [ ] **3.9** The weekly live evaluation can actually run
- [ ] **3.10** The 9.3% flip rate is qualified or removed
- [ ] **3.11** CI runs the live tests
- [ ] **3.12** Pivot counting excludes failed calls

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

- [ ] **6.1** The v16 detection lifecycle
- [ ] **6.2** Enterprise IAM
- [ ] **6.3** Overclaims in `apps/docs/docs/intro.md`
- [ ] **6.4** The phishing playbook's fleet-wide retraction
- [ ] **6.5** Two broken detection-tuning routes

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
  **Needs:** a maintainer decision on the ADR.

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
