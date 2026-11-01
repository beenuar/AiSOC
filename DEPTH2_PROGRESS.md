# AiSOC depth plan, wave 2: progress

Mirrors `plans/aisoc_depth_wave2.plan.md`, which is locked and is the source of
truth. This file is the mutable half. The only permitted edit to the plan file
is flipping a todo's `status` in its front matter; every deviation is recorded
here.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done, `[!]` blocked (with
exactly what is needed).

An item is `[x]` only when all three of these are recorded against it: the test
or gate that failed on the pre-change tree for the stated reason, the change,
and the negative control showing that reverting it fails again.

- **Base commit:** `152c6d5f` (`origin/main`, v21.0.0).
- **Plan captured at:** `152c6d5`. Figures in the plan body are hints at that
  commit; Phase 0.2 below re-derives each one and the tree wins.
- **Predecessor:** `DEPTH_PROGRESS.md` tracks the first depth plan. Items that
  plan left open are carried here (see "Hand-over" below) and are never ticked
  in both files.

## Hand-over from the first depth plan

Recorded once, at kickoff, as the plan's precondition requires. These items
move from `plans/aisoc_depth_plan.plan.md` to this plan and are tracked here
from now on; `DEPTH_PROGRESS.md` gains a cross-reference rather than a tick.

| First depth plan item | Carried to | Note at hand-over |
|---|---|---|
| 0.3 `make up-full` baseline | wave 2 Phase 0.3 | `DEPTH_PROGRESS.md` D2 records why it was not captured there |
| 2.6 effective permissions | wave 2 Phase 1.1 | wave 2 adds usage overlay, computed tags, AWS semantics |
| 3.6 content depth | wave 2 Phase 2.1 | wave 2 adds the scenario families |
| 3.7 detection engineering agent | wave 2 Phase 2.5 | unchanged scope |
| 4.4 cloud-hardware run | wave 2 Phase 8.4 | maintainer-blocked at hand-over |
| 4.5 managed-cluster run | wave 2 Phase 8.4 | maintainer-blocked at hand-over |
| 5.5 verb breadth | wave 2 Phase 6.1 | wave 2 raises the floor to 150 arms |
| 5.6 plain-language playbooks | wave 2 Phase 6.2 | wave 2 adds the bounded model step |
| 6.3–6.6 AI estate | wave 2 Phases 7.1, 7.3, 7.4, 7.5 | wave 2 adds hosted agents and repo skills (7.2) |
| 8.1 sub-item 4.5 operator pages | wave 2 Phase 9.5 | unchanged scope |
| 8.1 sub-item 4.6 internationalisation | wave 2 Phase 9.3 | unchanged scope |
| 9.4 Teams half | wave 2 Phase 9.4 | maintainer-blocked at hand-over |
| 9.6 remainder (device evidence) | wave 2 Phase 9.2 | maintainer-blocked at hand-over |
| Phase 10 close | wave 2 Phase 10 | wave 2's Phase 10 closes both |

## Migration and ADR numbers claimed

Claim a number here, push the claim, then write the file. Two lanes once
claimed the same migration number simultaneously and one had to renumber.

| Number | Kind | Lane / item | Claimed | File |
|---|---|---|---|---|
| 0015 | ADR | Wave 0 / Phase 0.4 | 2026-11-01 | `docs/decisions/0015-siem-replacement-scope.md` |
| 142 | migration | Lane D / Phase 6.3 | 2026-11-01 | tenant response schedule (business hours, on-call) |
| 143 | migration | Lane D / Phase 6.3 | 2026-11-01 | approval timeout outcomes on the durable pause |
| 144 | migration | Lane D / Phase 6.4 | 2026-11-01 | reserved — ticket-sync state, if 6.4 reproduces a gap |
| 145 | migration | Lane D / Phase 7.5 | 2026-11-01 | reserved — AI containment state, if needed |
| 0020 | ADR | Lane D | 2026-11-01 | reserved |

Highest at kickoff: migration `123`, ADR `0014`. Next free: migration `124`,
ADR `0016`.

Pre-allocated exclusive blocks, claimed at lane start so two lanes cannot pick
the same number: Lane D holds migrations **142–145** and ADR **0020**. A
reserved number that is not used is released by striking it here at lane
close, never by a second lane assuming it is free.

## Phase 0: Kickoff

- [x] **0.1** This file exists, modelled on `DEPTH_PROGRESS.md`, with the
      hand-over recorded above.
- [x] **0.2** Every figure re-derived against the base commit. See below.
- [x] **0.3** Baseline artefacts committed under
      `docs/audit/depth2-baseline/` with hardware, date and commit.
- [x] **0.4** ADR-0015 (SIEM-replacement scope) written as **proposed**:
      AiSOC federates to the SIEM rather than replacing it, so the README's
      "Not a drop-in SIEM replacement" is now a decided position with its
      cost argument recorded. Nothing is built from it in this plan.

### 0.2 Re-derived figures

Measured on `152c6d5f` (the base commit) on 2026-11-01, Apple M-series
(arm64, macOS), from the generators the plan names. Captured values are the
plan body's; measured values are this tree's. The tree wins.

| Figure | Captured | Measured | Source | Verdict |
|---|---|---|---|---|
| Executable detections | 2,530 | **2,530** | `scripts/project_stats.py` | matches |
| Detection rules on disk | 7,015 | **7,015** | `scripts/project_stats.py` | matches |
| Threat-and-anomaly family | 24 | **24** | `scripts/project_stats.py` | matches |
| Windowed rules | 76 | **76** | `services/fusion/app/data/windowed_ruleset.json` | matches |
| Longest window | 86,400 s | **86,400 s** | same file | matches |
| Registered connectors | 87 | **87** | `scripts/generate_connector_count.py --check` | matches |
| Connector type ids | 98 | **98** | `packages/types/src/generated/connector-types.json` (`members`) | matches |
| Executor arms (strict) | 89 | **89** | `capability = "..."` declarations under `services/actions/app/live_actions/` | matches |
| Distinct verbs | 39 | **39** | same, deduplicated | matches |
| Executor arms (loose grep) | 111 | **111** | same pattern without the line anchor, counting `reverse_capability` | matches — and is still not the figure |
| Claim-to-gate matrix | 334 / 329 / 5 | **334 / 329 / 5** | `scripts/check_claim_gate_matrix.py` | matches |
| Verdict best balanced accuracy | 0.357 | **0.357** (`llama3.1:8b-instruct-q4_K_M`) | `apps/docs/docs/benchmark.md` | matches |
| Constant-answer floor | 0.250 | **0.250** | same | matches |
| Hosted model rows | not measured | **not measured** | same | matches |
| Auto-close precision range | 0.091–0.571 | **0.091–0.571** | same | matches |
| Alert reduction (production key) | 33.3 % | **33.3 %** | same | matches |
| Alert reduction (detection-shaped) | 24.5 % | **24.5 %** | same | matches |
| Highest migration | 123 | **123** | `services/api/migrations/` | matches |
| Highest ADR | 0014 | **0014** | `docs/decisions/` | matches |
| Cloud/identity/SaaS/code conditions | ~358 | **344** by the method below | compiled rulesets | **moved — see D1** |

Every figure the plan named reproduces exactly except the last, which the plan
itself flagged as approximate ("about 358 ... record why it moved").

### D1 — The cloud/identity/SaaS/code condition count has no formal rule yet

The first depth plan's 3.6 counts "executable cloud, identity, SaaS and code
conditions (native rules, windowed rules and threat-and-anomaly conditions
together)", by `log_source` product. No script in the tree implements that
sentence, so every published value of it — 461 at the first plan's capture,
395 at its re-derivation, "about 358" in this plan — was counted by hand with
a slightly different product set. That is the defect this plan's Phase 2.1
fixes by requiring a `make stats` line held by a `--check` gate.

Measured here, stating the method so the next reader can reproduce it: native
compiled rules whose `product` falls in the cloud (`aws`, `gcp`, `azure`,
`kubernetes`, `docker`, `cloudflare`), identity (`okta`, `identity`,
`active-directory`, `entra`, `auth0`, `jumpcloud`, `ping`, `onelogin`, `duo`),
SaaS (`google-workspace`, `m365`, `slack`, `salesforce`, `snowflake`, `box`,
`dropbox`, `1password`, `atlassian`, `jira`, `confluence`, `zoom`,
`servicenow`, `notion`, `hubspot`) and code (`github`, `gitlab`, `bitbucket`,
`npm`, `pypi`) sets: **344**.

Top contributors: `aws` 73, `azure` 46, `kubernetes` 37, `gcp` 35, `okta` 33,
`identity` 33, `active-directory` 17, `google-workspace` 10, `docker` 9,
`m365` 8, `github` 7, `slack` 7.

Windowed rules contribute **0** to that figure, and the reason is a finding in
itself: `windowed_ruleset.json` entries carry `category` but **no `product`
field at all**, so a product-keyed count cannot see them and a category-keyed
count would be counting a different thing. Phase 2.1's gate has to decide this
explicitly — either windowed rules gain a product, or the published figure
says "native only" — and whichever it picks, the number moves again. Recorded
here so that move reads as a definition being fixed rather than as content
disappearing.

The gap between 344 and "about 358" is therefore a difference of product sets,
not of content: nothing was removed from the tree between the plan's capture
commit and this one (they are the same commit, `152c6d5`).

### 0.3 Baseline artefacts

Committed under `docs/audit/depth2-baseline/` with hardware, date and commit
on each. These are the "before" for every later delta.

| Artefact | Status |
|---|---|
| Re-derived figures | captured (the table above) |
| Executor arm count | captured (89 strict / 39 verbs / 111 loose) |
| Cloud/identity/SaaS/code conditions | captured (344, method recorded in D1) |
| Verdict scorecard | the published matrix is the baseline; re-running it needs a local model pulled (see below) |
| Alert-reduction suite | captured |
| `make up` + `make smoke` | captured |
| `make up-full` | captured — closes the first depth plan's D2 |

## Deviations

Recorded as they are found. D1 is above.

### D2 — `make up-full` failed its first run on a port bind, and what that does and does not prove

The baseline host had nine unrelated containers running from other projects,
one of them `lodestone-postgres-1` published on `0.0.0.0:5432`. That is the
exact condition the port resolver was built for, and it is a more honest
baseline host than a clean one.

What happened, in order:

1. `make up` succeeded. CORE came up, an administrator was created, and
   `make smoke` passed 10 of 10 stages. No `docker-compose.ports.yml` was
   written during this run.
2. `make up-full` recreated `postgres` (the `full` profile changes its
   environment) and the recreate failed:
   `Bind for 0.0.0.0:5432 failed: port is already allocated`.
3. Running `python3 scripts/resolve_port_conflicts.py` by hand detected the
   conflict immediately and wrote the overlay:
   `postgres 5432 → 15432 (5432 is held by container lodestone-postgres-1)`.
4. `make up-full` then succeeded: 22 AiSOC containers, postgres published on
   15432.

Both `up` and `up-full` declare `_ports` as a prerequisite, and `COMPOSE` is
a recursively-expanded variable whose `$(shell test -f ...)` re-runs on every
reference, so the overlay is picked up by both targets once it exists. The
unexplained step is (1): the resolver ran as a prerequisite of `make up` and
did not write an overlay, while the same script three minutes later did.

**What this does not prove.** Step 1 ran against a tree where an earlier
backgrounded `make up` had been killed mid-pull, so the container and
network state at that moment is not reconstructable, and the two obvious
hypotheses — a probe that reads a held port as free (the `SO_REUSEADDR`
class, recorded as fixed) versus a resolver that correctly saw AiSOC's own
already-running postgres — cannot be separated from this evidence. A grep is
not a reproduction and neither is a sequence I cannot replay.

**Carried as a follow-up, not claimed as a defect:** reproduce on a clean
host by starting a foreign Postgres on 5432 first, then `make up` from a tree
with no overlay present, and record whether the overlay is written. If it is
not, that is a real first-run defect for the most common conflict there is
and belongs in its own fix with a negative control. Until that run exists,
this is an observation with its evidence attached.

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

### 6.1 Verb breadth — done

**What failed before.** `scripts/check_executor_arm_count.py --check` on the
pre-change tree:

```
executor-arm-count: FAIL
  89 executor arms over 39 verbs; the plan's floor is 150. Counted by the
  declared rule (class-level `capability = "..."`), not the looser grep that
  also matches reverse_capability arguments.
```

That is the reproduction, and it is also the fix for a second defect: the
figure had been published three ways. The loose grep reports 111 because it
counts `reverse_capability=` arguments, which are declarations *about* a verb
rather than arms of it.

**The change.** 62 new arms across AWS, GCP, Entra, Google Workspace, Okta,
GitHub, Slack, Salesforce, Snowflake, 1Password, Cloudflare Gateway, Zscaler
and Netskope, with 20 new verbs in the `Capability` enum and the
`KNOWN_CAPABILITIES` mirror, a capability contract each, and nine new or
extended vendor clients. Every endpoint was verified against the vendor's
current public reference and every URL committed in a module docstring was
fetched and required to answer 200 first — which caught two errors before any
code was written: `admin.users.setInactive` does not exist (404), so Slack
containment is removal plus `admin.users.assign`; and
`developer.salesforce.com` answers 403 to every non-browser request, so the
Salesforce citations are the `help.salesforce.com` pages carrying the same
semantics.

**Measurement.** 89 arms / 39 verbs → **151 arms / 60 verbs / 34 vendors**,
by the plan's declared rule, read from the generated artefact
`docs/audit/executor-arms.json`.

**Negative controls, all five run and recorded.**

1. Dropping `NetskopeAllowDomain` from `CLOUD_SAAS_EXECUTORS` while leaving
   the class in place: the gate exits 1 naming it as a declaration that "counts
   towards the arm total and answers executor_not_found at dispatch" — the
   padding shape the cross-check exists for.
2. Raising `REQUIRED_ARMS` to 152: the gate exits 1 on the floor.
3. Making `_run` call the client factory on the dry-run path: 62 of 62
   `test_dry_run_never_constructs_a_client` cases fail.
4. Renaming a keyword in one arm's client call (`user_name=` → `username=`):
   the autospec'd double raises `missing a required argument: 'user_name'` and
   the signature test fails — which is the defect class that shipped twice
   (`SearchSIEMExecutor`, `CreateNotableEventExecutor`) because simulation mode
   never constructs the client.
5. Adding the Authorization header to GitHub's credential-revocation call:
   `test_github_credential_revocation_sends_no_authorization` fails. GitHub
   documents that an authenticated request there returns 403, so without this
   the leaked token stays live while an operator debugs a missing scope.

**Wiring, per the seven-point rule.** Enum member and `KNOWN_CAPABILITIES`
mirror for all 20 new verbs (`check_action_contract.py` compares them);
contract per verb, declared on the verb and not the vendor; executor wired to
a real client method with a `create_autospec` signature test covering every one
of the 62; credential tuple per arm re-derived from the factory's source by
`ast` and graded behaviourally; verification recorded as a gap with its reason
rather than claimed (see below); rollback where the vendor allows it and the
limitation recorded where it does not; `KNOWN_ORPHANS` unchanged at 7 and not
raised — no new verb was added to it.

**The verification gap, recorded rather than papered over.**
`PostActionVerifier` is keyed on `ActionType`, and these are live-action
capabilities with no `ActionType`, so the probe registry cannot be reached for
them — the same gap `unisolate_host` has carried since it was built. Every one
of these clients *does* implement its read-back, and those read-backs ship as
dispatchable read verbs (`get_cloud_identity`, `get_oauth_grants`,
`get_secret_scanning_alerts`), so a playbook can read the effect even though
governance does not treat the verb as self-verifying. The consequence is
enforced rather than assumed: a test asserts no new verb above `read_only` is
`AUTOMATIC`, because unverifiable means not autonomous.

**Vendor limitations recorded, not worked around.**

- Microsoft 365 application passwords: Graph publishes no endpoint for them,
  so there is no M365 arm for that half of the plan's "Workspace and M365
  OAuth-grant and app-password revocation". The Workspace half ships
  (`asps.delete`); the M365 half is absent because the API is.
- 1Password: no `revoke_token` arm. The SCIM bridge sees no user-issued API
  tokens, and the Connect and Service Account tokens that exist are managed
  outside it with no documented revocation endpoint. Suspension stops sessions.
- GitHub deploy keys: deletion is not platform-reversible, because the host
  stores only the public half and re-adding needs key material AiSOC never
  holds.

### 6.2 Plain-language playbooks and a bounded model step — done

**Reproduced first, and half of it did not reproduce.** Depth 5.6's
drafter already exists: `services/agents/app/playbook/nl_drafter.py` turns a
sentence into a playbook, validates it against both the Pydantic model and
`schemas/playbook.schema.json`, falls back to a deterministic substrate when
no model is configured, and lands it with `enabled=false` so the editor is
the gate. `POST /playbooks/draft-from-nl` wraps it. Nothing there needed
building. The one part of 5.6 that does not exist is "previews it against a
chosen past alert" — see D3.

What this plan **adds** did reproduce: there was no step type that asks the
model a bounded question, and `StepType` had 26 members with no way to
express a decision the author did not want to make themselves.

**The change.** `ask_model`: a closed answer set written by the author, a
required `on_invalid` fallback branch, and a branch id taken from the
author's own map rather than from the model's text. Five surfaces in sync,
held by `scripts/check_playbook_schema_parity.py`, which reports
`schema 27 | StepType 27 | runnable 27 | packages/types 27` and scans every
`.ts`/`.tsx` file for a sixth vocabulary rather than naming the files it
knows about.

**"Cannot call a verb" is pinned by a test that tries.** Three layers: the
step is routed through `_CONTROL_FLOW` rather than `_HANDLERS` (which is
where `action_bridge` is reached); an AST test asserts the module imports
nothing that can dispatch; and `test_the_step_cannot_dispatch_a_verb` makes
the model answer with the name of a containment verb, replaces the bridge
with a tripwire that fails the test if called, and asserts the step decided
nothing — because a verb name is just an invalid answer here.

**Negative controls.** Removing `ask_model` from `_CONTROL_FLOW` fails three
branch tests; deleting the enum-membership check in `parse_answer` fails
three answer-validation tests.

### 6.3 Time gates and timeouts — done

**Reproduced.** `approval_rules.evaluate()` took impact, declared approval,
confidence and tier, and nothing else — there was no way for a tenant to say
"not at three in the morning". And `pause.expire_due` had exactly one
behaviour: mark the pause `expired` and log it, so every approval in the
product behaved identically at its deadline.

**The change.** `ResponseSchedule` + `apply_schedule` in `approval_rules.py`
(vendored byte-identically into the API), migration 142 for the per-tenant
schedule and its windows with RLS, and migration 143 for the pause row's
declared timeout outcome.

**The direction is the property, and it is asserted rather than described.**
`test_it_never_produces_an_automatic_decision` sweeps every `ActionImpact` ×
`ApprovalRequirement` pair and asserts the schedule never lowers one. The
positive control (`test_inside_business_hours_leaves_it_automatic`) is the
one that catches a gate stuck closed, which reads as working caution.

**One statement, not two.** The first cut read the declared outcomes in a
separate cross-tenant sweep before `expire_due`. That was a second statement
racing the first and would have taken the tenant-predicate ratchet from 80
to 81 — which the gate refuses, correctly. Collapsing both into one
`UPDATE ... RETURNING` removes the race, removes the ordering hazard, and
moves the ratchet entry rather than adding one.

**Negative controls.** Letting `apply_schedule` touch a non-automatic
decision, or emit AUTOMATIC, fails six tests; treating `on_call_now = None`
as cover fails the one test named for it.

### 6.4 Ticket sync — verified, and one direction was broken

**The outbound direction already works and needed no change.** Driven end to
end for the first time — the production `push_case` and `push_status_change`
routes, the production Jira and ServiceNow connectors, and a mock HTTP
server returning recorded vendor shapes — all five assertions passed on the
first run: a case mints an issue carrying the `aisoc-case-<id>` label the
return leg resolves by, a ServiceNow incident carries its correlation id, a
status change patches the existing ticket rather than minting a second one,
a vendor refusal is a 502 that does not forward the vendor's body, and a
connector without the capability is refused.

**The inbound direction had a defect that four correct unit tests could not
see**, because each mocks the next layer: `case_fanout` patches
`httpx.AsyncClient`, the connectors push routes are exercised by nothing,
`test_push_capabilities.py` patches `httpx.AsyncClient` with a `MagicMock`,
and the inbound test mocks the database session. A chain of four correct
unit tests is not a loop.

The defect: the idempotency check was `new_status == ref_row.status`, an
exact equality. Jira `Done` maps to the **intermediate** `resolved`, so a
case a human had closed in AiSOC was moved backwards out of its terminal
state by an ordinary redelivery — and Jira retries up to five times while
ServiceNow retries until it gets a 2xx. No unusual sequence was needed, only
a close followed by a retry.

**The fix** refuses an inbound status that would move a case out of a
terminal state, scoped to terminal states only: an ITSM moving a ticket from
Resolved back to In Progress is a real transition this product should
mirror, and only at `closed` is a retry indistinguishable from a reopen.

**Negative control.** Reverting the guard fails two tests, including the
redelivery test that found it.

### 7.5 AI containment — done

**Reproduced.** `ai_inventory.py` scores a provider key's exposure and
`llm_usage` reads OpenAI and Anthropic audit logs. Zero arms could act on
any of it, so a provider key found in a public repository was a finding with
a recommendation and no verb.

**The change.** 14 arms across OpenAI, Anthropic and an AI gateway: key
revocation, role demotion, workspace removal, spend caps, and the reads
behind them. Arms **151 → 165** over **64 verbs across 37 vendors**.

**The property this phase turns on: three providers, three different answers
to "can this be undone", carried honestly.** OpenAI deletes a project key,
so that arm declares no rollback. Anthropic deactivates one, so it has a
real platform reverse and is the reason `restore_token` exists as a verb at
all. A gateway block is a documented pair. One `revoke_token` contract
claiming a platform rollback because Anthropic can would have given the
rollback path a route back it does not have on the other two.

**Two things deliberately not duplicated, each pinned by a test.** AI OAuth
grant revocation reuses the Workspace, Entra and Okta arms from 6.1, because
an AI application's grant is an ordinary consent and a fourth arm would be a
second code path to the same vendor endpoint. Agent process kill reuses the
EDR `kill_process` arms, because the agent is a process on a host.

**A recorded vendor limitation.** Neither OpenAI's nor Anthropic's public
admin API exposes a budget this platform can set, so `set_spend_cap` has
exactly one vendor arm and `test_no_spend_cap_arm_exists_for_a_provider_that_has_no_budget_api`
says so.

**The kill-switch playbook** ships `enabled: false`, asks the bounded
question *before* the approval rather than after it, and the approval
declares its timeout outcome: if nobody answers within two hours the gateway
key's spend cap goes to zero, which is the narrow containment rather than
the wide one. It is not `services/actions/app/services/kill_switch.py`,
which is the platform-wide autonomy stop and is not an agent control.

### D3 — Depth 5.6's "preview against a chosen past alert" is still open

The drafter produces a schema-valid draft and lands it disabled, and
`alert_trigger.py` previews playbooks when an alert fires. What does not
exist is the affordance 5.6 names: pick a past alert, and see what this
draft *would* have done against it. `POST /playbooks/draft-from-nl` takes a
prompt and nothing else.

Recorded rather than built here because it needs a surface this lane does
not own — the draft endpoint would have to resolve a historical alert into a
trigger context, which is the console's alert reader rather than the
playbook engine. The bounded-step half of 6.2, which is what this plan adds
to 5.6, is complete.

### D4 — The new verbs carry a recorded verification gap, not a probe

Every client added in 6.1 and 7.5 implements its read-back, and none of them
is reachable from `PostActionVerifier`, because that registry is keyed on
`ActionType` and these are live-action capabilities with no `ActionType` —
the same gap `unisolate_host` has carried since it was built.

Closing it properly means either adding 24 `ActionType` members (each of
which the contract gate then requires a legacy executor for, by design) or
re-keying the verifier on capability strings. Both are larger than this
lane's scope and neither should be done by widening an exemption list.

The consequence is enforced rather than left implicit: a test asserts no new
verb above `read_only` is `AUTOMATIC`, so unverifiable means not autonomous,
and the read-backs ship as dispatchable read verbs (`get_cloud_identity`,
`get_oauth_grants`, `get_secret_scanning_alerts`) so a playbook can read the
effect even though governance does not treat the verb as self-verifying.

### D5 — The kill-switch playbook is recorded as outside the benchmark corpus

`test_playbook_completion_rate.py` requires every shipped playbook to match
at least one incident in the 200-case synthetic corpus, and every pack
category to cover at least one — "a category that matches no incidents is
dead weight". The AI-agent kill switch matches nothing, because the corpus
contains **no AI-estate template at all**.

Two wrong fixes were available and both were refused. Tagging the playbook
`supply-chain` would make it match `github-pat-leak`, which is exactly the
"matches by tag only" case the gate's own docstring says it exists to
prevent: blocking a gateway key does nothing about a leaked GitHub PAT.
Adding an AI-estate template to the corpus moves a published measurement
and belongs to the lane that owns detection content.

What shipped instead: one entry in the existing
`_PLAYBOOKS_NOT_IN_BENCHMARK_DATASET` list with the reason, the category
gate's exemption **derived** from that list rather than kept as a second
hand-written one (so the two cannot disagree), and a new ratchet —
`test_the_not_in_benchmark_list_is_a_ratchet` re-runs the evaluation with
the exemption emptied and fails if an entry would no longer be an orphan.
It uses the evaluator's own definition rather than a second predicate,
because a ratchet with its own idea of "covered" is a ratchet that drifts.
Proven by adding a covered playbook to the list and watching it fail.

**To close this:** an AI-estate incident template in
`services/agents/tests/eval_data/synthetic_incidents.json`, with the
scorecard and alert-reduction suite re-run, after which the entry must be
removed or the ratchet fails.
