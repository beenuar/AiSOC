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
| 124 | migration | Lane A / 1.1 | 2026-11-01 | `services/api/migrations/124_identity_privilege_facts.sql` |
| 125 | migration | Lane A / 1.2 | 2026-11-01 | `services/api/migrations/125_access_review_findings.sql` |
| 126 | migration | Lane A / 1.4 | 2026-11-01 | `services/api/migrations/126_sub_principal_baselines.sql` |
| 127 | migration | Lane A / 1.5 | 2026-11-01 | reserved — `1.5` change timeline, if a table is needed |
| 128 | migration | Lane A / 3.1 | 2026-11-01 | `services/api/migrations/128_identity_links.sql` |
| 129 | migration | Lane A | 2026-11-01 | reserved |
| 0016 | ADR | Lane A / 1.1 | 2026-11-01 | `docs/decisions/0016-privilege-context-in-scoring.md` |
| 0017 | ADR | Lane A / 3.1 | 2026-11-01 | reserved — identity-resolution confidence model |

Highest at kickoff: migration `123`, ADR `0014`. Lane A holds migrations
`124`–`129` and ADRs `0016`–`0017`; next free outside that block: migration
`130`, ADR `0018`.

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

### D3 — the queue has never read identity privilege, contrary to the plan

The plan's 1.1 says "Prioritisation already reads identity privilege (v16)
and must read this". It does not. `score_alert_priority` has taken an
`identity` argument and carried a `_PRIVILEGE_FACTOR` table since v16, and
its **only** production caller — `alert_queue.build_queue` — passed
`identity=None` at `alert_queue.py:570`. `queue_priority()`, the one other
function that would pass one, has no production caller at all.

So the privilege factor was unreachable from the only surface where
prioritisation changes anything. Recorded here because it changes 1.1's
scope: the item is not "make the existing reader read a better source", it
is "wire the reader", which is the repository's defining defect found again
inside a module whose own docstring explains why an ordering nobody can
interrogate stops being trusted.

Closed by Lane A's 1.1: `resolve_identity_contexts()` resolves each alert's
actor against the privilege version covering that alert's own event time,
one batched query per page, and `build_queue` passes it.

### D4 — the container clock runs ahead of the host's, and a live
point-in-time test trips over it

`identity_privilege_facts.valid_from` defaults to Postgres `now()`. On this
machine the Docker Postgres container's clock measured ~17 ms **ahead** of
the host's Python clock, so a row written and immediately read back at
`datetime.now(tz=UTC)` landed *before* its own `valid_from` and the
point-in-time select correctly returned nothing.

That is the store behaving exactly as specified — an event predating a
collection has no posture — so the fix is in the test, which now reads one
minute ahead. Widening `valid_from <= :at` to absorb the skew would have
answered historical questions with newer snapshots, which is precisely the
defect migration 103 is versioned to prevent. Recorded because the symptom
("the row is there and the point-in-time read cannot see it") reads as a
query bug and is not one.

### D5 — the verdict baseline in the plan is for a model this host cannot run

The published best balanced accuracy of 0.357 is
`llama3.1:8b-instruct-q4_K_M`. The only model pulled on this host is
`llama3.2:3b-instruct-q4_K_M`, so a run here is not comparable to that row.

Rather than quote the 8B figure as a baseline it did not measure, Lane A ran
the **same 3B model on both trees** — `origin/main` at `152c6d5ff` and the
lane branch — so the comparison has one variable. Both numbers are recorded
in the item log below, and neither is published as the project's headline:
the scoreboard row for the 8B model is untouched.

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

### 1.1 Effective permissions everywhere — shipped

**Reproduced first.** `services/api/tests/test_identity_privilege_reproduction.py`
and `services/agents/tests/test_identity_privilege_tool_reproduction.py`
failed on the pre-change tree: 15 of 20 api assertions and all 3 agents
assertions. The 5 api assertions that passed are the *negative* arms of the
condition-operator matrix, and they passed for the wrong reason — the
resolver denied every operator it could not evaluate, so "correctly refuses"
and "under-reports real access" were indistinguishable until the operators
were modelled.

**What shipped.**

- `effective_permissions/iam_conditions.py`: 24 condition operators plus the
  `IfExists` suffix and the `ForAnyValue:` / `ForAllValues:` qualifiers, with
  a **three-valued** result. Undecidable is resolved per effect — an
  undecidable `Allow` does not grant, an undecidable `Deny` still denies —
  so both arms refuse to over-report access.
- `effective_permissions/aws.py`: `NotAction` and `NotResource` invert their
  sets; session policies cap the identity arm (intersected across several,
  never unioned) and not the resource-policy arm; withheld actions are
  reported in `deny_actions` with the reason in `notes`.
- `identity_privilege.py`: tier derived from what an identity can *write*,
  never from the name of the role it holds, plus `can_escalate`,
  `data_access`, `third_party`, `cross_account`, each with its evidence.
- Migration **124**: `identity_privilege_facts` (versioned on the same
  interval as the snapshot it came from, one live row per principal enforced
  by a partial unique index) and `identity_permission_usage` (the runtime
  overlay), both under RLS.
- `identity_usage_collector.py`: the overlay from the lake, returning
  `measured=False` with a reason whenever the lake cannot be asked.

**Wiring — the production callers.**

| Surface | Caller |
|---|---|
| Fusion, per alert | `fusion_engine.process()` step 2.7 → `IdentityPrivilegeResolver.resolve()`, stamped at the alert's **event time** |
| Confidence | `ConfidenceScorer.score()` factor `identity_privilege`, weight 0.06, the eight existing weights scaled by 0.94 so the total is still exactly 1.0 |
| Console queue | `alert_queue.build_queue()` → `resolve_identity_contexts()` → `score_alert_priority(identity=...)` (see D3) |
| Typed pivots | `investigation_tools.TOOLS["identity_effective_permissions"]`, reachable from `POST /graph/investigate/query` |
| Agent tool registry | `tools/registry.py::default_registry`, so the model is offered it and the call lands in the ledger |
| Triage prompt + `confidence_basis` | `fused_alert_consumer._attach_privilege_context()` → `context/privilege.py`, through the same `/investigate/query` door the registered tool uses |

**Negative controls.** Ten live-Postgres tests, each with one: the
point-in-time read is contrasted against the live-row read it replaced and
the two disagree; the unchanged-rederivation test is paired with a changed
one that *does* open a version; the queue test reverts the context and the
score collapses to the unknown baseline.

**Gates.** `test_tool_result_channel.py` caught the new tool missing from
`AGENT_TOOL_NAMES` and `test_investigation_tools.py` caught it missing from
the dispatch-coverage table. Both were the gate working, and both are fixed
rather than relaxed.

**Measurements.**

Alert reduction, `services/fusion/tests/test_alert_reduction_real.py`:

| Measure | Before | After |
|---|---|---|
| Production correlation key | 1000 → 667 = **33.3 %** | 1000 → 667 = **33.3 %** |
| Detection-shaped cohort | 1000 → 755 = **24.5 %** | 1000 → 755 = **24.5 %** |

Verdict scorecard, `scripts/run_verdict_eval.py`, same corpus and the same
model on both trees (see D5), Apple M-series arm64 / macOS, 2026-11-01,
`llama3.2:3b-instruct-q4_K_M` served by Ollama, 72 live model calls on each
run, 0 errored:

| Metric | Before (`152c6d5ff`) | After | Delta |
|---|---|---|---|
| Balanced accuracy | 0.2604 | 0.2715 | +0.0111 |
| Malicious recall | 0.1944 | 0.1944 | 0.0000 |
| Abstention rate | 0.0139 | 0.0139 | 0.0000 |
| Auto-close precision | 0.4286 (3/7) | 0.3750 (3/8) | −0.0536 |

**Both movements are run-to-run variance, not an effect of this change, and
the reason is structural rather than a judgement call.** The verdict harness
sets no service token, so `fetch_privilege_context` returns empty,
`render_privilege(None)` returns `""`, and the prompt the model receives is
byte-identical on both trees. The auto-close figure moved because its
denominator moved from 7 to 8 — one additional item crossed the
consideration threshold — which is the smallest denominator on the
scorecard and the one most sensitive to a single sampled token.

Nothing here is published to the scoreboard: the project's headline row is
`llama3.1:8b-instruct-q4_K_M` at 0.357, which this host cannot run.
