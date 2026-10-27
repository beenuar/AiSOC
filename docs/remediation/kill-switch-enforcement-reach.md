# The kill switch stopped one of the four things it claimed to stop

`services/api/app/api/v1/endpoints/kill_switch.py` described the platform's
emergency stop as

> one boolean with a mandatory reason, checked first and separately by
> everything that acts: closure in the triage worker, the actions
> dispatcher, playbook dispatch and the MCP write tools.

One of those four was true.

This matters more than an inaccurate comment. An operator who engages a
control described as the platform-wide stop, watches automatic closure
halt, and concludes the platform is frozen, **stops looking for another way
to halt it** — while the actions dispatcher carries on isolating hosts and
disabling accounts at their vendors. A safety control that stops less than
it claims is worse than one that plainly does not exist. This repository's
own standard is that a mechanism nothing calls is treated as not existing;
the same standard applied to a *claim* means an unenforced enforcement point
is a false statement, not an aspiration.

## The verified inventory

Measured on `origin/main` at `3802d0dc`, before any change.

| Claimed enforcement point | Real? | Evidence |
|---|---|---|
| Closure in the triage worker | **yes** | `auto_triage_agent.py:558` calls `closure.decide()`, which calls `resolve_closure_policy`, which calls `kill_switch_engaged` before anything else |
| The actions dispatcher | **no** | `git grep -i 'kill.?switch' -- services/actions` returned zero matches, in any form |
| Playbook dispatch | **no** | zero matches in `services/agents/app/playbook/` and in `services/api/app/services/playbook_step_dispatch.py`. The single hit in `case_postmortem.py:223` is the string `"kill switch"` in a containment-phrase keyword list, unrelated |
| The MCP write tools | **no, and there is no such surface** | `services/mcp` exposes one tool touching the response surface, `aisoc_preview_action`. It is dry-run only; `DRY_RUN_PATH` is a module constant and `tests/actions.test.ts` asserts `/dispatch` appears nowhere in `src/` |

So: one of four enforced, two absent, and one that could not be enforced
because it does not exist.

### The per-tenant switch has the same reach, and a different second problem

The reader is one function, `kill_switch_engaged(pool, tenant_id)`, and it
resolves both scopes in a single query. Both scopes therefore had **exactly
the same reach** — closure only — and no scope-specific gap in enforcement.

They differ on the write side rather than the read side. On `main` the
tenant switch is engageable through `POST /api/v1/kill-switch/engage`. The
global switch has no engage route at all, and would not work if it had one:

```
INSERT ... (tenant_id = NULL) as aisoc_app, no tenant bound   -> ERROR: new row violates row-level security policy
INSERT ... (tenant_id = NULL) as aisoc_app, tenant bound      -> ERROR: new row violates row-level security policy
INSERT ... (tenant_id = <t>)  as aisoc_app, tenant bound      -> INSERT 0 1
```

`aisoc_kill_switch` carries `WITH CHECK (tenant_id = current_tenant_id())`.
For the global row `tenant_id` is `NULL`, and `NULL = NULL` is `NULL`, not
true, so the check refuses it for every session the runtime role can open.
This was reproduced here independently and is **not fixed in this change**:
[#1534](https://github.com/beenuar/AiSOC/pull/1534) owns it and carries the
migration. It is recorded because the two halves compound — before both land,
the platform-wide stop could neither be set nor, if set, obeyed by dispatch.

### Other documented-but-absent enforcement, in the same family

* **The claim-to-gate matrix cites a document that does not carry the
  claim.** `docs/audit/CLAIM_TO_GATE_MATRIX.md` points at
  `apps/docs/docs/operations/shadow-mode.md` for "Autonomous closure and
  dispatch can be stopped without a restart". That file contains zero
  occurrences of the string "kill".
* **There is no operator documentation for the switch anywhere.** No page
  under `apps/docs/`, no console surface under `apps/web/src/`. An operator
  cannot find out what it does except by reading the module that was wrong
  about it. Still open; the product surface is #1534's.

## What was implemented, and what was corrected

Two routes were available per point. The choice was made per point.

### Implemented — the actions dispatcher

`services/actions/app/live_actions/dispatcher.py::dispatch()` now reads the
switch **before** translating credentials and before looking up an executor.
This is the point that touches a customer's estate, so enforcement is the
only honest answer: correcting the claim here would have meant publishing
"the stop button does not stop response actions".

Checked first and separately from the autonomy policy, for the reason the
closure path already records: it is what somebody reaches for at 3am and it
must not depend on tier rows, capability contracts or a registered executor
being correct. It also closes a gap the autonomy gate has by construction —
that gate runs only `if not request.dry_run and (action_type is not None or
capability in CAPABILITY_CONTRACTS)`, so a capability with neither is
ungoverned. The switch has no such condition.

### Implemented — playbook dispatch, at the same line

Deliberately **not** a second check inside `playbook_step_dispatch.py`.
Playbook steps reach a vendor through exactly one chain:

```
action_bridge.py:159  POST /api/v1/playbook-steps/dispatch
  -> playbook_step_dispatch.dispatch_step()
  -> actions_client.dispatch_live_action()
  -> POST /api/v1/live-actions/dispatch
  -> live_actions_router.py:176  dispatch(request)
```

There is no second path. `playbook_step_dispatch.py` already states the
principle in its own docstring — "A policy mirrored in two services is a
policy that is off in whichever one is more generous" — and a second check
would be a second thing to forget. The same chokepoint also covers the
`/dry-run` sibling route, the agent loop, phishing purge and the phishing
report intake worker, because all of them terminate at `dispatch()`.

A test drives the HTTP route itself rather than only the function, because
"the function refuses" and "the route every caller actually uses refuses"
are different claims.

### Corrected — the MCP write tools

There are none, so there was nothing to enforce, and enforcement would have
meant inventing a surface in order to gate it.

The sentence was worse than an unenforced claim. It told a reader the MCP
server could perform actions. That was the more alarming half, and it was
never true: the server's action tool is preview-only and a test asserts the
dispatch path appears nowhere in its source. The docstring now says what the
switch stops, what it does not, and states plainly that this point was
removed because the surface does not exist.

### Decided — dry runs are stopped too

A preview is only credentials-free while the strip list in
`live_actions/builtins.py` matches what each client factory reads, and
`services/actions/app/executors/siem.py` records a release where it did not:

> "the factory still builds a client and a 'dry run' calls the customer's
> production SIEM. That is exactly what happened."

During a declared freeze that is not a risk worth carrying for the
convenience of a preview, and an operator who pressed the stop button did
not mean "stop, except for previews". The cost is real and is stated here
rather than hidden: while the switch is engaged, the console's "preview what
this would do" button and the MCP preview tool both return `blocked`.

## The fail-open / fail-closed trade-off

An unreadable switch **refuses**. A control that reads "I cannot tell" as
"nobody pressed it" is not a stop control.

The cost of that choice is that a database outage stops automated response
on deployments that have a database. That is a real cost and it is bounded
three ways, deliberately rather than by assumption:

1. **A deployment with no DSN configured is not affected at all.** No
   database means no switch table, which is a configuration and not a read
   failure — the same line `resolve_tenant_policy` already draws for the
   autonomy tier. Failing closed here would brick every single-tenant
   install in order to guard a row that cannot exist on it.
2. **A deployment that has a database is already degraded by the same
   outage.** `resolve_tenant_policy` falls to its notify-only floor (L1) on
   an unreadable read, so unattended execution has already stopped. Failing
   closed on the switch is consistent with the posture next door rather than
   a new outage mode.
3. **Humans are unaffected.** `BLOCKED` is a refusal to act automatically.
   Analysts keep triaging, the console keeps working, and an operator can
   still act directly at the vendor.

Two further bounds in the implementation: the connection carries a five
second timeout so a hung database becomes a refusal rather than a dispatch
that never returns, and **only successful reads are cached** — caching a
failure would turn one refused connection into seconds of refused dispatch
after the database came back.

The refusal names the read failure, not the switch:
`blocked_by: kill_switch_unreadable`, with a summary saying the state is
unreadable. Reporting it as "kill switch engaged" would send an operator to
look for a switch nobody pressed, which is the failure mode where a
diagnostic names the wrong subsystem — worse than a vague one.

## What an operator should now expect

With the switch engaged, in either scope:

* no response action reaches a vendor, from any caller — the REST route, the
  agent loop, a playbook step, phishing purge, or a preview;
* no alert is closed automatically;
* every refused action comes back **`blocked`**, not `failed`. `failed`
  invites a retry and the retry is refused identically; `blocked` carries
  `blocked_by: kill_switch`, the scope, and the operator's own reason, so a
  console can say which control stopped it rather than leaving a reader to
  guess between the switch and the tier ladder;
* `executed` — the platform's single word for "a vendor was touched" — is
  never reported, because the executor is not looked up, let alone called.

With the switch released, everything dispatches as before. That direction is
asserted too: a stop control stuck on is as broken as one stuck off, and
this repository has a recorded case where a fail-closed fix withheld every
grant on every deployment and passed its drifted-tenant test perfectly,
caught only by the healthy-tenant control.

## Still unenforced, and stated rather than implied

* **There is no console control for the kill switch in either scope.** Both
  are API-only. An operator at 3am needs `curl`.
* **The global switch cannot be written by the runtime role.** Reproduced
  above; owned by #1534.
* **No operator-facing documentation page exists** for the switch.
* **The agents service and the actions service read the switch with two
  separate functions.** They cannot share one — both name their top-level
  package `app`, so importing one into the other shadows it. The duplication
  is deliberate and is the same shape as `autonomy_evidence_rules`, which
  `services/api` carries byte-identical to `services/actions`. The DSN
  resolution *is* shared, through `tenant_policy.resolve_dsn`, with a test
  asserting both readers use the same function: two resolvers could disagree
  about whether a deployment has a database and the generous one would win.
* **The matrix row** that #1534 rewrites states "An engaged switch stops
  closure and not dispatch". This change falsifies the second half.
  Whichever of the two pull requests lands second has to correct it; it is
  not edited here, because editing a row another open branch is rewriting
  produces a conflict rather than a correction.

## Proof

Three commits in order, each run and recorded.

**1. The test fails on the unfixed tree**, driven through the real
`dispatch()` against real Postgres 16 with all 121 migrations applied, read
by the `aisoc_app` runtime role under `FORCE ROW LEVEL SECURITY`. Only the
vendor is replaced, by a recorder that counts calls:

```
8 failed, 4 passed
FAILED ... test_a_global_switch_stops_dispatch
FAILED ... test_a_tenant_switch_stops_that_tenants_dispatch
FAILED ... test_the_reason_names_the_switch_even_when_policy_would_also_refuse
FAILED ... test_a_dry_run_is_stopped_too
FAILED ... test_blocked_is_not_reported_as_failed
FAILED ... test_the_route_every_caller_reaches_is_governed_too
FAILED ... test_an_unreadable_switch_blocks_rather_than_permits
FAILED ... test_unreadable_does_not_claim_somebody_pressed_it
```

The four that pass are the positive controls — released switch, no row, no
database, and one tenant's switch not stopping another. They pass trivially
on a tree that never checks, which is exactly why they are there: they
cannot prove the defect, only catch a fix that stops everything forever.

**2. The fix**: `12 passed`.

**3. Negative controls**, each removing one line and requiring red:

| Control | Result |
|---|---|
| `if switch.engaged:` → `if False:` | `8 failed, 4 passed`; restored → `12 passed` |
| unreadable returns `_RELEASED` instead of refusing | `2 failed, 1 passed`; restored → `3 passed` |

Both are wired as steps in `action-durability-live.yml`, which already
provisions this exact stack, so they run on every pull request rather than
having been demonstrated once. Each control refuses to run if it cannot find
the line it removes, so a reshaped gate fails loudly instead of silently
proving nothing.

One caveat, stated rather than buried: the **seeding** connection is the
owner's, declared inline with `aisoc-db-role: owner` and a reason, because
`check_runtime_db_role.py` correctly refuses an undeclared superuser DSN on
a live surface — seeding as owner is exactly the workaround that hid the
global row's unwritability. It is used here for one reason and the reason is
narrow: until migration 123 lands, no runtime session can put the global row
in place at all, and these cases grade the *reader*. The dispatcher under
test still connects as `aisoc_app` under `FORCE ROW LEVEL SECURITY`. Once
#1534 lands, the seed DSN can be the runtime role and the marker deleted.

A note on the chosen `search_siem` capability: `isolate_host` is HIGH blast
and the autonomy gate refuses it at every tier, so a test watching it stop
would have passed on the unfixed tree for a reason unrelated to the switch.
`search_siem` is contracted `AUTOMATIC` and really does execute, so "it
stopped" can only mean the switch stopped it. `isolate_host` still appears,
asserting that the *reason* names the switch — two controls that both refuse
are one control an operator cannot release.
