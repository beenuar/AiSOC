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

## Lane B status (sources: 1.3, 1.6, 8.1 to 8.4)

| Item | State | Where |
|---|---|---|
| 1.6 Anonymizer and hosting classes at ingest | **done**, in review | PR #1586 |
| 1.3 HR and device context | **done for three of six connectors**, in review | PR #1589 |
| 8.1 CNAPP depth | not started, gap reproduced | item log |
| 8.2 NDR connectors | not started; ExtraHop buildable, Corelight blocked | item log |
| 8.3 Enrichment per tenant, cited | not started, gap reproduced | item log |
| 8.4 Scale and deployment evidence | **blocked, recorded with exactly what is needed** | item log |

Every row above has its reproduction recorded in the item log as a command
or a failing test, including the ones that were not built: a gap nobody
reproduced is a rumour, and the three not-started items are written up so
the next lane starts from evidence rather than from the plan's prose.

## Migration and ADR numbers claimed

Claim a number here, push the claim, then write the file. Two lanes once
claimed the same migration number simultaneously and one had to renumber.

| Number | Kind | Lane / item | Claimed | File |
|---|---|---|---|---|
| 0015 | ADR | Wave 0 / Phase 0.4 | 2026-11-01 | `docs/decisions/0015-siem-replacement-scope.md` |
| 151–158 | migration | Lane F (analyst: 3.2, 3.3, 4.x, 5.x, 9.x) | 2026-11-01 | reserved block, see below |
| 0022 | ADR | Lane F | 2026-11-01 | reserved |

Highest at kickoff: migration `123`, ADR `0014`. Next free: migration `124`,
ADR `0016`.
| 142 | migration | Lane D / Phase 6.3 | 2026-11-01 | tenant response schedule (business hours, on-call) |
| 143 | migration | Lane D / Phase 6.3 | 2026-11-01 | approval timeout outcomes on the durable pause |
| 144 | migration | Lane D / Phase 6.4 | 2026-11-01 | reserved — ticket-sync state, if 6.4 reproduces a gap |
| 145 | migration | Lane D / Phase 7.5 | 2026-11-01 | reserved — AI containment state, if needed |
| 0020 | ADR | Lane D | 2026-11-01 | reserved |
| 124 | migration | Lane A / 1.1 | 2026-11-01 | `services/api/migrations/124_identity_privilege_facts.sql` |
| 125 | migration | Lane A / 1.2 | 2026-11-01 | `services/api/migrations/125_access_review_findings.sql` |
| 126 | migration | Lane A / 1.4 | 2026-11-01 | **released unused** — 1.4 lives in the existing fusion baseline store (Redis), as the plan requires; no table was needed |
| 127 | migration | Lane A / 1.5 | 2026-11-01 | **released unused** — 1.5 reads `posture_snapshots` (103) and the lake; no new table |
| 128 | migration | Lane A / 3.1 | 2026-11-01 | `services/api/migrations/128_identity_links.sql` |
| 129 | migration | Lane A | 2026-11-01 | **released unused** |
| 0016 | ADR | Lane A / 1.1 | 2026-11-01 | `docs/decisions/0016-privilege-context-in-scoring.md` |
| 0017 | ADR | Lane A / 3.1 | 2026-11-01 | **released unused** — the confidence model is a table of eight rules in `identity_resolution.py`, each with its reasoning beside it, and the merge threshold's justification is in the module docstring. An ADR restating them would be a second place for them to drift |
| 146 | migration | Lane E / 7.1 | 2026-11-01 | AI provider coverage + chat compliance (labels and bounded snippet only) |
| 147 | migration | Lane E / 7.2 | 2026-11-01 | hosted agents and repository AI artefacts as asset kinds |
| 148 | migration | Lane E / 7.3 | 2026-11-01 | agent identities and per-agent baselines |
| 149 | migration | Lane E / 7.3 | 2026-11-01 | reserved: agent baseline observations |
| 150 | migration | Lane E / 7.4 | 2026-11-01 | reserved: AI rule-pack supporting state |
| 0021 | ADR | Lane E / 7.1 | 2026-11-01 | AI-chat compliance-log minimisation |

Highest at kickoff: migration `123`, ADR `0014`. Lane E holds the exclusive
block migrations `146`–`150` and ADR `0021`.

Pre-allocated exclusive blocks, claimed at lane start so two lanes cannot pick
the same number: Lane D holds migrations **142–145** and ADR **0020**. A
reserved number that is not used is released by striking it here at lane
close, never by a second lane assuming it is free.
| 0018 | ADR | Lane B / 1.6 | 2026-11-01 | `docs/decisions/0018-ip-class-dataset-provenance.md` |
| 130 | migration | Lane B / 1.6 | 2026-11-01 | `services/api/migrations/130_alert_ip_class.sql` |
| 131 | migration | Lane B / 1.3 | 2026-11-01 | `services/api/migrations/131_workforce_context.sql` |
| 132 | migration | Lane B / 8.3 | 2026-11-01 | `services/api/migrations/132_tenant_enrichment_providers.sql` |
| 133 | migration | Lane B / 8.1 | 2026-11-01 | `services/api/migrations/133_cloud_security_findings.sql` |

Lane B holds an exclusive pre-allocated block: migrations `130`-`137` and ADR
`0018`. Numbers `134`-`137` are reserved and unused unless an item below
claims one here first.

Highest at kickoff: migration `123`, ADR `0014`. Next free outside Lane B's
block: migration `124`, ADR `0016`.

Highest at kickoff: migration `123`, ADR `0014`. Next free sequential number:
migration `124`, ADR `0016`. Outside that sequence, Lane E holds the exclusive
block migrations `146`–`150` and ADR `0021`, and Lane F holds `151`–`158` and
ADR `0022` (below).

### Lane F block (exclusive, pre-allocated)

Lane F holds migrations `151`–`158` and ADR `0022`. The block is pre-allocated
rather than taken from the next-free counter so that Lane F's many items cannot
collide with lanes A, B, D and E, which take theirs sequentially. Files as they
land:

| Number | File | Item |
|---|---|---|
| 151 | `services/api/migrations/151_alert_occurrences.sql` | 3.3 linked occurrences |
| 152 | `services/api/migrations/152_root_cause_findings.sql` | 3.3 cross-vendor root cause |
| 153 | `services/api/migrations/153_attack_stories.sql` | 3.2 stories |
| 154 | `services/api/migrations/154_triage_questions.sql` | 4.3 questions |
| 155 | `services/api/migrations/155_hunt_source_reports.sql` | 5.1 source reports |
| 156 | `services/api/migrations/156_software_inventory.sql` | 5.4 inventory |
| 157 | unused | — |
| 158 | unused | — |
Highest at kickoff: migration `123`, ADR `0014`. Lane A claimed migrations
`124`–`129` and ADRs `0016`–`0017`, and **used 124, 125, 128 and 0016**.
The rest are released: a claimed-and-unused number is kept in this table
rather than deleted, so a later lane reading it can see the number is free
without having to prove the claim was abandoned rather than forgotten.
Next free outside the block: migration `130`, ADR `0018`.

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
## Phase 7: AI agent security (Lane E)

- [x] **7.1** Provider coverage (depth 6.3) plus enterprise AI-chat
      compliance logs stored as labels and bounded snippets only.
      [#1585](https://github.com/beenuar/AiSOC/pull/1585).
- [x] **7.2** Hosted agents and repository AI artefacts as new asset kinds.
      [#1585](https://github.com/beenuar/AiSOC/pull/1585).
- [!] **7.3** Agent identity and per-agent baselines (depth 6.4 / parity 6.7)
      — not delivered; reproduced gap and what is needed recorded below.
- [~] **7.4** AI rule pack — four of the listed targets shipped and replayed
      ([#1585](https://github.com/beenuar/AiSOC/pull/1585)); the rest need a
      producer or 7.3's baselines, each recorded below.
### D5 — Lane F did not reach eleven of its sixteen items, and this is where they stand

Recorded rather than left implicit. Lane F covered 4.2–4.6, 5.1–5.5, 9.1–9.5
and 3.2–3.3. Five landed (3.2, 3.3 first half, 5.2, 4.6, 9.2/9.4 records);
eleven did not. The reproduction work for each was done before the lane ran
out of time, so what follows is **measured state, not a guess**, and is worth
more to whoever picks them up than a fresh grep would be.

| Item | Measured state on this tree | What is actually left to build |
|---|---|---|
| **3.3** second half | first half shipped | Cross-vendor root-cause collapse (migration 152 is claimed and unused). `alerts.external_id` is the natural anchor; `parent_alert_id` / `child_alert_ids` / `is_merged` have existed since migration 042 with **no writer**, so check that vocabulary before minting a new one. |
| **4.2** reviewer pass | not started | The decision contract is assembled by `reflex_observability.decision_contract` and is **not persisted** — absent from `persist_auto_triage`'s 24 kwargs. A reviewer pass needs it durable first. Closure is chokepointed at `closure/authorization.authorize_auto_closure`, so a reviewer cannot reach closure by accident. Ship only if it moves balanced accuracy or auto-close precision without lowering malicious recall. |
| **4.3** questions + rules | not started | Both engines are in grammar lockstep today. Operators are `eq/ne/lt/lte/gt/gte/contains/startswith/endswith/in/not_in/exists/not_exists`; **`neq` is not one** and a rule using it silently never matches. Migration 154 is claimed and unused. |
| **4.4** precedent + re-triage | **verified, not built** | See D3. Precedent reaches triage by two routes but matches only on exact fingerprint or rule/entity string; `semantic_memory.py` is a complete Qdrant recall with provenance that the triage path never touches. Re-triage is genuinely absent, and `run_id` is `uuid5(alert_row_id:WORKFLOW_VERSION)` with `ON CONFLICT (run_id, seq) DO NOTHING`, so a naive re-triage writes **nothing** — it needs a re-triage discriminator in the run id, and seq 0/1 are taken. |
| **4.5** vendor evidence | **verified, not built** | See D3. `investigation_reads.py` exists with 5 verbs over 7 vendors. Two real gaps: no GuardDuty finding-read verb (the alias resolves GuardDuty to a CloudTrail read), and `run_auto_triage` has **no tool channel at all** and says so in a comment, so a vendor alert that auto-triages never pulls vendor evidence. A deterministic context fetch, like `_attach_identity_context`, is a better shape than a tool channel: the ledger citation is then real because the fetch happened. |
| **5.1** hunt from a report | not started | Every piece exists separately: `ssrf_guard.validate_outbound_url` (**a validator, not a fetcher — it does not bound response size**, so 5.1 must add its own `max_bytes` and timeout), `EvidenceEnvelope.wrap` for nonce fences (use it, not `wrap_untrusted`), and the closed hunt schema in `hunt/plan.py` with `hunt_plan_sql.py` binding every value as a parameter. Migration 155 is claimed and unused. |
| **5.3** explorer | **partly exists** | The Data Explorer exists and already shows the generated query; `/graph?entity=` pivot exists. Missing: CSV export, cross-filters and a per-entity view. One latent bug to fix while there: `ExploreView.tsx` assigns `res.esql` into a field labelled `SQL` and runs it through `lakeApi.sql` (ClickHouse). |
| **5.4** software inventory | **absent** | No connector reads a code-platform SBOM API. `packs/aisoc-inventory-baseline.yaml` queries `deb_packages`, `rpm_packages` and `homebrew_packages` — but **not** the Windows `programs` table — and **nothing consumes the results**. `assets` and `asset_vulnerabilities` are host-level; there is no package-level table. Migration 156 is claimed and unused. |
| **5.5** retro-hunt at scale | **absent** | The retro-hunt subsystem is substantial and sweeps two stores with honest failure states. `scripts/perf/` is ingest/throughput oriented; nothing measures sweep cost against indicator volume. Needs recorded hardware. |
| **9.1** voice | **absent** | `voice.ts` is an interface with no recogniser and no screen (see D4). `expo-local-authentication` is already installed and `app/approval/[id].tsx` already names the exact action in its biometric prompt, which is the 9.1 requirement. `@react-native-voice/voice` is **already denied** by `check_no_audio_egress.py` as cloud-capable — an on-device package must be added *and* allowlisted, with the self-test extended, since the self-test is what makes that gate non-vacuous. |
| **9.3** i18n | **absent** | Nothing at all: no library, no `messages/`, no RTL, no gate. Scope is the five surfaces gap-closure 13.4 names (~690 strings), not the whole console (~72k lines). Note parity 4.7's axe-core extension targets the **same five surfaces**, so the two share a blast radius. |
| **9.5** operator pages | **2 of 6 built; the matrix row is stale** | SCIM tokens **is built** (`ScimTokensPanel.tsx`, wired at `SettingsView.tsx:424`) and organisation members is built, but the claim row at `CLAIM_TO_GATE_MATRIX.md:299` still lists both as not built. Branding, retention, rule packs, delegations and the console over-limit state are genuinely absent. The enforcement bullet of parity 4.5 is already GATED and done. |

### D3 — Four Lane F items did not reproduce as the plan describes them

Recorded under the "reproduce before building" rule: a grep is a hint, and
four of Lane F's gaps turned out to be narrower than the plan's wording, or
already closed. Nothing was rebuilt on the strength of the plan's sentence.

| Item | Plan says | Measured on this tree |
|---|---|---|
| 4.4(a) | analyst reclassifications do not reach triage | **They do, by two independent routes.** `human_priors.record_human_prior` writes `author: "human"`, `confidence: 1.0` into `aisoc_institutional_memory` under `outcome:<evidence_fingerprint>`, and `context/dispositions.py` renders the last five analyst decisions into the triage preamble. The real gap is narrower: matching is **exact fingerprint** (SHA-256 over 18 canonical fields) or rule-id/entity string, never similarity. `services/api/app/services/semantic_memory.py` is a complete Qdrant-backed vector recall with tenant filtering and provenance — and the triage path never touches it; its only consumers are `/kb/query` (opt-in), `remember_closed_case` and its own router. |
| 4.5 | read verbs "in `investigation_reads.py`" are to be added | **The file exists**, at exactly that path, 987 lines, 5 read verbs across 7 vendors with contracts, executors, a closed agent allowlist, a parameter allowlist and autospec'd signature tests. Defender/EDR evidence pulling is fully built. The two real gaps: no GuardDuty finding-read verb (only an alias that resolves GuardDuty to a CloudTrail read), and reads are reachable **only from the escalation path** — `run_auto_triage` has no tool channel at all, and says so in a comment, so a vendor-originated alert that auto-triages never pulls the vendor's evidence. |
| 5.2 | the hunt scheduler is "Elasticsearch only" | **Splunk is a live registered provider.** `SUPPORTED_PROVIDERS` held two drivers, and backend choice is driven by what the tenant connected rather than by the translation. Separately, the plan's "scheduled hunts resolved their SIEM from process settings that were never declared fields" defect is **already fixed** and documented at length in `event_warehouse/credentials.py`. The real gap was the half that fix could not reach: a tenant who has connected nothing. |
| 5.2 tail | "add the missing link from a hunt into the governed detection-proposal flow" | **The link exists.** `hunt_scheduler._propose_detection_from_hunt` inserts a DRAFT into `detection_rule_proposals` with `source='hunt-finding'`, gated by `AISOC_HUNT_TO_DETECTION` (default on), since wave 1. |

### D4 — The mobile README claimed voice input that does not exist

Not a plan defect; a tree defect found while reproducing 9.1/9.2. The
capability table read *"Voice input — **Transcription is on-device by
construction**"*, which is true of the module and reads as a working
feature. `apps/mobile/src/lib/voice.ts` has **no recogniser behind it and no
screen importing it**: the only file in the repository that mentions it is
that README. Corrected to say so, and the `mobile.yml` README-honesty guard
extended to pin both the voice row and the handset row, with the guard's
own vacuous-pass case (an empty README) asserted.
### D3 - Three of the five anonymizer classes have no redistributable source

Item 1.6 names five classes and anticipates that one of them (residential
proxies) may have no redistributable source. Measured, **three** do not.

The widely cited community list of VPN and datacentre ranges was the obvious
candidate and was refused on the licence, not on the data: its repository
carries no licence file at all. Recorded as a command rather than as a claim,
because this is the kind of statement that goes stale:

    $ curl -s -o /dev/null -w "%{http_code}" \
        https://raw.githubusercontent.com/X4BNet/lists_vpn/main/LICENSE
    404

An MIT-licensed repository cannot redistribute data whose terms nobody can
read. Commercial anonymizer feeds exist and are licensed per deployment,
which makes them a per-tenant credential rather than something to commit.

So `vpn`, `public_proxy` and `residential_proxy` ship with zero records and
are tenant-supplied only; `tor_exit` and `hosting_provider` ship populated.
The docs page says this in a table and in prose, the ADR records the
alternatives, and the claim-matrix row leads with it.

### D4 - Tenant-supplied class lists are designed and not built

The fallback the plan names for an uncovered class is a tenant-supplied
list. It is **not implemented**, and three classes are therefore unavailable
rather than empty-by-choice. Said plainly in
`apps/docs/docs/operations/ip-classification.md` under "What is not here
yet" rather than implied to exist.

The design, recorded so the next lane does not re-derive it:

* the stamper is in Go at ingest and has no per-tenant database access, so
  the per-tenant layer belongs in fusion, where the tenant is known;
* `services/fusion/app/services/tenant_overlay.py` is the extension point.
  It already loads per-tenant rows from Postgres with hot reload and already
  exposes exactly this shape in `derived_allowlist_fields(event)` and
  `derived_identity_fields(event)`: per-tenant derived fields applied at
  match time;
* it needs a tenant-scoped table (CIDR, class, author, reason) with RLS, a
  third source in `TenantOverlay._fetch` (whose signature is a 2-tuple
  today and would become a 3-tuple), an `ip_class` applied only where the
  global dataset had no answer, and an API route plus a settings surface so
  something writes the table. A table fusion reads and nothing writes is the
  same defect as a table the console writes and nothing reads.

Not done because landing 1.6 and 1.3 unblocks Lane C, and a half-wired
per-tenant path would have been worse than an honest gap. Nothing shipped
depends on it; the three classes simply carry no records.

### D5 - Workday and Kandji are blocked; three of the six named sources are built

Item 1.3 names six connectors. Three are built against public references
verified on 2026-11-01 and cited by URL in each module: BambooHR, Rippling
and Microsoft Intune. Three are not, for different reasons.

**Workday.** `community.workday.com/sites/default/files/file-hosting/restapi/`
answers 200, but the Staffing REST surface a tenant actually exposes is
per-tenant and the report-as-a-service shape most deployments use is defined
by the customer's own report definition, not by a fixed schema. There is no
public response document from which an honest mock payload can be written.
**Needed:** a Workday sandbox tenant, or one recorded (redacted) response
from `Get_Workers` or from a customer's staffing RaaS report.

**Kandji.** `api-docs.kandji.io` answers 200 and the landing page documents
the base URL, the token header, the rate limit and the response codes. The
device-list response's field names are rendered client-side and could not be
extracted. **Needed:** one recorded (redacted) `GET /api/v1/devices`
response, or the field list from the vendor's device-detail page.

**Jamf Pro.** `developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory`
answers 200 and the field names *are* verified -- `general.name`,
`operatingSystem.version`, `operatingSystem.fileVault2Status`,
`diskEncryption.fileVault2Enabled`, `userAndLocation.username`,
`userAndLocation.email`, `security.firewallEnabled` -- so unlike the other
two this one is **not blocked on the vendor**. It is not built in this pass
for time, and `plugins/jamf-mdm` stays a manifest without a connector class.
The promotion is a known quantity: one module in the shape of
`microsoft_intune.py` reading `GET /v1/computers-inventory` with
`section=GENERAL&section=OPERATING_SYSTEM&section=DISK_ENCRYPTION&section=USER_AND_LOCATION&section=SECURITY`.

Recorded rather than built against an invented shape, which is the plan's own
rule for exactly these vendors.

### D6 - HR and MDM connectors get no ingest profile, and the first evidence for that was the wrong test

**Corrected after CI.** The conclusion held; the evidence did not, which is
the half worth recording.

These three connectors publish no events at all. `fetch_alerts` returns an
empty list on each by design: an HR system reports slowly-changing state,
not security events, and their output is context the scheduler writes to
`workforce_members` and `workforce_devices`, never to ingest. A
`connectorProfiles` entry would be an entry nothing can reach.

What was wrong was the check behind it. The original entry said `go test
./internal/normalizer/` passed and cited
`TestConnectorTypeCanonicalTargetsAreDeclaredAndUnshadowed`, which asserts
that every *alias target* is declared and asks nothing about a connector
having a profile. The test that does ask is
`TestEveryDeclaredConnectorHasAnOCSFDecision`, and it failed in CI:

    connector "bamboohr" has no entry in connectorOCSFClass: its events
    take the 2001 default, which is always promoted, and nothing records
    that as a decision

`connectorOCSFClass` exists precisely to separate "decided to take the
generic path" from "nobody looked", and a connector with no entry reads as
the second. All three now carry a `genericReason` naming what they are.

The lesson is the one this programme keeps paying for: a local suite
passing is not evidence that the specific question was asked. The original
entry named a test by title and did not read what it asserted.

### D7 - Zero check runs was a conflicted PR, not a saturated pool, and the two look identical from outside

**Corrected.** This entry first recorded the wrong cause, and the
correction is worth more to the next lane than the original observation
was.

What was true: the head commit of each Lane B branch returned
`total_count: 0` check runs. What was wrong: attributing that to the shared
runner pool because 19 runs were queued and 18 in progress at the same
moment. The pool had in fact drained to a single queued run.

**The real cause.** Wave 0 was squash-merged into `main`, so `main` and the
Lane B base `depth2/wave0-kickoff` each carried `DEPTH2_PROGRESS.md` and
`plans/aisoc_depth_wave2.plan.md` by different histories - an add/add
conflict. Both pull requests were therefore `mergeStateStatus: DIRTY`, and
**GitHub cannot compute a merge ref for a conflicted pull request, so it
creates no check runs at all**. Zero runs was the conflict, not the queue.

**The one call that tells the two apart**, which is the durable half of
this entry:

```bash
gh pr view <n> --repo beenuar/AiSOC --json mergeStateStatus -q .mergeStateStatus
```

* `DIRTY` - the merge ref cannot be computed. **Nothing can be graded**,
  and no amount of waiting or re-pushing will change that. Merge the base
  in and the runs appear.
* `BLOCKED` or `UNSTABLE` with `total_count: 0` - the pull request is
  gradeable and the runs have genuinely not started. That is the pool.

A queue snapshot alone cannot distinguish them, because a busy queue is the
ordinary state of this repository and is true at the same moment either way.
Checking the queue first is what produced the wrong answer here.

**Standing rule for this lane from now on:** after any push, read
`mergeStateStatus` before concluding anything about the pool.

Resolved by merging `origin/main` into both branches, keeping both sides of
the tracker. Measured immediately afterwards: 108 check runs on
`depth2/lane-b-sources` and 109 on `depth2/lane-b-workforce`, against zero
before.

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
### 8.1 CNAPP depth - Lane B - NOT STARTED, gap reproduced

**Reproduced, recorded as commands rather than asserted.**

`services/connectors/app/connectors/wiz.py` declares exactly one GraphQL
operation, `query IssuesTable`. There is no vulnerability query, no
configuration-finding query, no secrets query and no runtime-detection
query. The four sibling cloud-security connectors each read one endpoint
and it is their alert stream in every case:

| Connector | The one read it makes |
|---|---|
| `orca` | two `GET`s against the alerts API |
| `prisma_cloud` | two `POST`s against the search API |
| `lacework` | `GET /api/v2/Alerts` |
| `sysdig` | `GET /api/v1/secureEvents` |

So the gap is real on all five and is as the plan describes it.

**What remains, scoped:** extend the Wiz connector to vulnerabilities,
configuration findings, secrets and runtime detections where the vendor API
offers them; record the same depth check for the other four; surface the
findings as **triage context keyed on the resource the alert touched**,
not as alerts by default. The triage-context half is the part that needs a
design decision rather than a read: a CNAPP finding on a resource is an
input to a verdict about an event on that resource, which means a lookup
keyed on resource identity at triage time, in the shape
`services/agents/app/context/identity.py` uses for principals.

**Risk the plan already names:** Wiz's newer GraphQL surfaces are behind a
customer tenant. Verify each field against the vendor's current public
reference before writing it, and record BLOCKED rather than inventing a
payload shape, exactly as D5 does for Workday and Kandji.

### 8.2 NDR connectors - Lane B - NOT STARTED, one half blocked

**Reproduced.** `ls services/connectors/app/connectors/ | grep -iE
"extrahop|corelight"` returns nothing. The two network connectors that
exist are `zeek_suricata` and `darktrace`.

**Reference availability, measured 2026-11-01:**

| Vendor | Public reference | Verdict |
|---|---|---|
| ExtraHop RevealX 360 | `https://docs.extrahop.com/current/rest-api-guide/` answers **200** | buildable |
| Corelight | `https://docs.corelight.com/` answers **401** | **BLOCKED** |

So ExtraHop is a build and Corelight is not. **Corelight needs** either a
documentation account, or one recorded (redacted) detection payload plus the
endpoint and auth shape, before an honest mock can be written. Corelight's
*Zeek output* is open and is already covered by the `zeek_suricata`
connector, which is a different thing from the sensor's own detection API
and must not be passed off as it.

### 8.3 Enrichment per tenant, cited - Lane B - NOT STARTED, gap reproduced

**Reproduced, and the gap is wider than the plan states.**

`services/enrichment` is a **Go** service, not Python. Measured on this
tree:

  * `grep -c tenant` over `internal/enricher/enricher.go` and
    `internal/config/config.go` returns **0** and **0**. There is no
    per-tenant dimension anywhere in the service, so per-tenant opt-in is
    absent rather than partial.
  * No reference to the credential vault anywhere under
    `services/enrichment/`. Keys are per-deployment environment variables.
  * `RATE_LIMIT_RPS` and `RATE_LIMIT_BURST` are parsed in `config.go` lines
    59-60, assigned to struct fields at lines 92-93, and **read by nothing
    else in the service**. The plan's "reads and never enforces" reproduces
    exactly.
  * `URLSCAN_API_KEY` is a config field (`config.go:71`) with no client.
  * No enrichment result is cited in the ledger.

**What remains, and the one design decision it needs.** The per-tenant
opt-in is a console settings surface with the tenant's own key in the
credential vault, which `services/api` owns the write path for. A Go
service cannot hold that write path, so either the enrichment service
learns to read vault tokens through a vendored read-path `decrypt_dict`
(the pattern `services/connectors` already uses), or the fan-out moves
behind an API route that resolves the tenant's credentials first. That
choice should be made explicitly rather than discovered during
implementation.

The rate limiter needs a test that proves it **refuses**, per the brief: a
limiter asserted only on the allowed path is indistinguishable from no
limiter.

### 8.4 Scale and deployment evidence - Lane B - **BLOCKED**, which is the correct outcome

The plan's own text allows for this: "published with hardware, date and
commit, **or recorded as blocked with exactly what is needed**". Both halves
are blocked on hardware nobody here has, and neither is blocked on code.

**4.4, the cloud-hardware run.** Already stated honestly on
`apps/docs/docs/operations/performance.md` under "No cloud-hardware run
exists yet, and that is a gap", re-read on 2026-11-01 and still accurate.
Every figure on that page comes from an 18-core Apple-silicon laptop, a
6-CPU Linux VM on it, or a kind cluster on the same machine. The target is
a sustained 5,000 events/s through detection at p95 under 2 s on one
documented instance size.

**Needed:** a cloud account and one named instance type. Nothing else. The
harness already records the hardware fingerprint, the load shape and the
commit into every result file, and `scripts/check_perf_results.py` already
refuses a result that drops any of them. The command that produces the row
is published on that page and is reproduced here so this entry stands alone:

```bash
python3 scripts/perf/load_harness.py \
    --target compose --events 500000 --workers 32 --batch 100 \
    --alert-every 100 --target-eps 5000 --drain-timeout 1800 \
    --assert-benign-alert-rate-max 0.001 \
    --out docs/perf/results/<date>-<instance-type>-realistic-mix.json
```

**4.5, the managed-cluster run.** The only cluster evidence in the tree is
the three-node **kind** run of 2026-09-27, and the page already says what
that does and does not prove: "kind nodes are containers on the same
kernel, so this is not two machines' worth of anything". A kind run is not
a managed-cluster run and must not be published as one.

**Needed:** a managed Kubernetes cluster (EKS, GKE or AKS) with at least
three worker nodes and a load balancer, plus permission to install the
chart into it. The first depth plan recorded the same requirement as
maintainer action M3; this entry carries it forward rather than restating
it as new.

**What was deliberately not done:** no figure was produced by extrapolation
from the laptop runs. A laptop VM's disk, network and CPU scheduling are not
an instance type's, and a number derived that way becomes a promise nobody
can keep. "Not measured" with the exact requirement is the honest record,
and it is the record this item asks for.

### 1.3 HR and device context - Lane B

**Reproduced.** On the current tree:

    ModuleNotFoundError: No module named 'app.connectors.bamboohr'

and the state behind it, measured rather than asserted: 88 connectors in
`_CONNECTOR_CLASSES`, none HR and none MDM; `import_context` with exactly
one production caller, the manual POST at
`services/api/app/api/v1/endpoints/graph.py:725`.

**Shipped.**

| Piece | Where |
|---|---|
| HR connectors | `bamboohr`, `rippling` |
| MDM connector | `microsoft_intune` |
| Capabilities | `PULL_WORKFORCE`, `PULL_DEVICE_INVENTORY` |
| Context store | `services/connectors/app/workforce.py`, migration `131` |
| Scheduler caller | `ConnectorScheduler._sync_workforce_context`, on every poll |
| CORE read | `services/api/app/services/workforce_context.py`, merged into `/graph/identity-context` |
| Triage derivations | `derive_employment_facts` and `_render_device_line` in `services/agents/app/context/identity.py` |
| Citations | `identity.basis` names departed, departing, contractor and device counts |
| Marketplace | three `plugins/<id>/plugin.yaml`, index regenerated |
| Docs | three pages generated, all three in the sidebar |
| Count | regenerated, not edited: 87 -> **90** |

**Negative control.** Removing the `_sync_workforce_context` call from
`_poll_one` fails `test_the_scheduler_calls_a_workforce_sync_on_every_poll`
with the reason stated: the connector would be registered, configured,
polled and silently ignored. Removing each derived fact from
`render_for_prompt` fails its paired prompt assertion, and removing it from
`basis` fails its paired citation assertion, which is why both halves are
asserted for all four facts.

**Numbers, from the generators.**

| Figure | Value | Source |
|---|---|---|
| Registered connectors | 87 -> **90** | `generate_connector_count.py --check` |
| Connector docs | 90 documented, 41 generated / 49 hand-written | `generate_connector_docs.py --check` |
| Marketplace plugins | 80 -> **83** | `build_marketplace.py` |
| Claim matrix | 335/330/5 -> **336/331/5** | `check_claim_gate_matrix.py` |

**One trap avoided and worth recording.** `generate_connector_docs._slug`
writes the hyphenated filename for a connector with no existing page, so
`microsoft_intune` documents at `/docs/connectors/microsoft-intune`. The
connector's `docs_url` was written with the underscore first and would have
404'd; corrected before commit and verified against the generated sidebar
entry.

**Deviations:** D5 (Workday and Kandji blocked, Jamf deferred with its shape
recorded), D6 (no ingest profile, with the reason and the check).

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

### 1.2 Access review and right-sizing — shipped

**Reproduced first.** `services/api/tests/test_access_review_reproduction.py`
failed 7/7: no module in the tree compared granted with used, and a grep for
`access_review`, `right-sizing`, `best_fit_role` or `dormant_admin` across
`services/` and `apps/web/src` matched only Lane A's own 1.1 files.

**What shipped.** `access_review.py` (pure), `access_review_store.py`,
migration **125**, five routes behind `compliance:read`, and a console page
at `/access-review` with a sidebar entry. Six finding kinds, each with a
required `object_hint` and `recommendation` — a read-only review whose
findings do not name the object to change leaves the reviewer with the hard
half of the work, which is why reviews do not happen.

**The honesty property this item turns on.** Usage-dependent findings are
suppressed *wholesale* when `UsageOverlay.measured` is false, not emitted
with a caveat. A caveat on "revoke this" is read by nobody, and the finding
is wrong in the direction that costs an outage. `best_fit_role` returns
`None` for the same reason, and also when no built-in covers the used set —
recommending a role that does not cover something a principal actually used
is a recommendation to cause an outage, which is the one error a
right-sizing feature must not make.

Three distinct empty states, because only one of them is good news:
`never_run`, `nothing_reviewed` (a review over zero principals) and
`no_findings` (a review over a real inventory). Rendering all three as
"0 findings" presents an estate nobody looked at as an estate with nothing
wrong.

**Negative controls.** Eight live-Postgres tests: unmeasured usage suppresses
the usage findings *and then the same principal with measured usage produces
them*; three runs produce one row *and the run table proves three runs
happened*; a finding that stops reproducing is retired; an acknowledgement
survives the next run; another tenant's finding cannot be acknowledged
(404, not 403, so the route is not an existence oracle).

**Defect found while building.** The retire query hit the recorded
`:name::type` bind-cast trap — SQLAlchemy's regex backtracks one character
over a Postgres cast, so `:principals::text[]` declared a parameter named
`principal`. Seven of eight live tests failed with a syntax error. Spelled
`CAST(:principals AS text[])`; `check_text_bind_casts.py` stays green.

### 1.4 Sub-principal baselines — shipped

**Reproduced first.**
`services/fusion/tests/test_sub_principal_baselines_reproduction.py` failed
7/7. `baselines.py` kept a baseline per *principal* plus one volume
baseline per OAuth app; a token, a service account and an AI agent were all
folded into the human's baseline, which is backwards for the case these
baselines exist to catch.

**What shipped.** In `baselines.py` itself, as the plan requires — not a new
store. `api_token`, `oauth_app`, `service_account` and `ai_agent` become
subjects of their own, with four signals: acting outside its own baseline, a
machine cadence turning interactive, a new ASN within an hour of the token
first appearing, and reactivation after 60 days idle. All seven new fields
are in `DERIVED_FIELDS`, so a rule can clause on them.

**`classify_cadence` tests interactive first, and the order is the
classifier.** A person working 09:00–17:00 produces consecutive active hours
whose gaps are almost all 1, which is indistinguishable from an hourly cron
by regularity alone. What separates them is that a person calls several
times within one hour and a timer does not, so the repeat count has to be
consulted before the regularity is. The first implementation checked
regularity first and classified a human as `scheduled`.

**The cross-language contract, and the second defect it caught.** The GitHub
join key is written by Go (`session.go`, `strings.TrimSpace`, no case
folding) and consumed by Python, whose general field helper lowercases —
correct for a username, wrong for a base64 digest, and the obvious
implementation is the broken one. Both sides now read one committed fixture,
`services/ingest/internal/activity/testdata/github_token_key.json`, and it
immediately found a *second* divergence nobody had looked for: Go requires a
string type, while the Python side coerced a numeric `hashed_token` into
`"12345"` — a baseline key Go never writes. Go: 8 subtests pass. Python: 9
assertions pass, including a negative control that fails if the resolver
ever starts folding case.

**Gate caught drift.** `check_detection_fields.py` keeps its own mirror of
`DERIVED_FIELDS` and `test_baselines.py` compares the two in both
directions; it failed on the seven new fields, which is the gate working.

### 1.5 What changed before this alert — shipped

**Reproduced first.**
`services/api/tests/test_change_timeline_reproduction.py` failed 5/5.

**What shipped.** `change_timeline.py` joins versioned posture (what the
estate looked like, complete for collected providers) with audit events (who
did it, complete for ingested sources). Both are kept because a timeline
from one alone is missing either the attribution or the coverage. Six change
kinds over a closed action vocabulary — an unfamiliar action is not returned
rather than guessed into a kind, because a reader cannot tell a guessed
classification from a known one.

`ChangeTimeline.measured` distinguishes "read both sources and found
nothing" from "could not read either". An empty list with no such field
turns a lake outage into evidence of a quiet week.

**Wiring.** Registered as the typed pivot `changes_before_alert` and in the
agents tool registry, reaching the API through the same `/investigate/query`
door the privilege tool uses. The lake table is `aisoc.raw_events`, already
declared ClickHouse-owned in `check_raw_sql_columns.py`'s `UNMIGRATED_TABLES`,
so no new declaration was needed — verified by running the gate.

### 3.1 Identity resolution — shipped

**Reproduced first.**
`services/api/tests/test_identity_resolution_reproduction.py` failed 7/7.

**What shipped.** `identity_resolution.py` (pure) over all six sources the
plan names, `identity_resolution_store.py`, and migration **128**. Eight
rules, each carrying its own confidence, the evidence that produced it, and
a `merged` flag derived from one threshold.

**The failure mode designed against is a wrong link, not a missing one.** A
wrong merge makes the identity look *richer*, not broken, and nothing
downstream can detect it. The three canonical wrong merges are refused and
each has a test: `alice@example.com` against `alice@contoso.com` (stored as
a visible weak link, never merged), `admin` against `admin` (not even
returned as weak — it would fill a review page with noise that reads as
near-misses), and a shared role mailbox (demoted rather than treated as a
verified address match).

`MERGE_THRESHOLD` is 0.90 because the two errors are asymmetric: a missed
link costs an analyst one pivot by hand, a wrong link silently attributes
one person's alerts to another.

**Both stores, one read interface.** Postgres for CORE per ADR-0010,
`SAME_PERSON` edges mirrored to the graph for `full`, and reads come from
Postgres only — a read that preferred the graph would answer differently on
the two profiles for reasons no operator could see. Only merge-strength
links are mirrored, because a weak edge in the graph gets walked by every
traversal whose author did not know to filter it.

**Negative controls.** Seven live-Postgres tests. The ordered-pair CHECK is
exercised with a deliberate out-of-order insert that must be refused by the
database; the weak-chain test is paired with a strong link proving the walk
works at all; the bounded walk is compared at two depths; a human decision
is tested in *both* directions (confirm promotes a weak link, reject demotes
a strong one, neither touches `confidence`).

### Measurements for 1.2, 1.4, 1.5 and 3.1

Alert reduction re-run after all four: **33.3 %** (1000 → 667) and
**24.5 %** (1000 → 755) — identical to the Phase 0 baseline.

The verdict scorecard was **not** re-run for this batch, and the reason is
stated rather than skipped: none of these four changes what the triage
prompt contains on the eval corpus. 1.2 is a separate console surface with
no triage caller; 1.4 adds fields to fusion's derived namespace that no
corpus alert carries; 1.5 and 3.1 add tools the model may call, and the
harness places no service token, so both return "could not read" exactly as
the privilege tool did in the 1.1 measurement — where the prompt was proved
byte-identical. A re-run would re-measure the same sampling noise at ~17
minutes per pass. If a later lane wires any of these into the prompt by
default, the scorecard has to move with it.
### 7.1 — Provider coverage and AI-chat compliance logs

Landed early because Lane D's 7.5 depends on the provider work.

**What already existed, and was therefore not rebuilt.** Verified before
writing anything: the AI estate inventory (`services/api/app/services/
ai_inventory.py`, one `score_risk`, six asset kinds, tri-state `sanctioned`),
migration 110 and its RLS, the fusion recorder with its three discovery
sources, endpoint discovery, the `ai_gateway` connector, the two OCSF 6003
webhook templates, `packages/aisoc-ai-sdk`, the AI estate console page, and
**sixteen** executable AI rules — eight `llm-*` on the OpenAI/Anthropic
control plane (`det-application-071`…`078`) and eight `ai-*` on runtime and
guardrail findings (`079`…`086`). None of that was touched.

**Reproduced gap A.** `LlmUsageConnector` accepted `openai` and `anthropic`
and nothing else. Six of seven tests in
`services/connectors/tests/connectors/test_llm_usage_provider_coverage.py`
fail on the base commit; four of them drive the real HTTP path against a
mock server and get a `ValueError` from the constructor.

**Reproduced gap B**, found while wiring A and the more interesting one.
`test_ai_asset_recorder.py` writes `finding.evidence.scopes` into a
hand-built OCSF event and asserts the recorder reads
`finding.evidence.scopes`. Both halves are the test's own invention: no
connector produces that path and ingest does not synthesise it, so the
assertion held whether or not the production path worked. Driven through the
shape ingest really produces — the connector's dict as a JSON string under
`raw_data` — an Entra consent grant reached the inventory with **no scopes at
all**, so an AI notetaker consented into every mailbox scored identically to
one granted nothing.

**Reproduced gap C.** No table anywhere held AI-chat compliance data; the
migration sweep for one returned nothing.

**What shipped.** Four more providers on the existing connector
(`google_gemini`, `github_copilot`, `microsoft_copilot`, `entra_consent`),
each against the vendor's current public reference, every URL fetched and
200 before committing. `_from_provider_audit` now reads through
`_connector_fields`, so scopes reach the one existing `score_risk`; an OAuth
grant is keyed on the application rather than the audit record. Migration
146 with five RLS'd tables, ADR-0021, a classifier, a client, three API
routes and a console panel.

**Wiring proof.** One `score_risk` path, unchanged — the new providers feed
the existing `oauth_grant` and `provider_key` kinds and add no second
scorer. Minimisation is schema-enforced (no column can hold a message;
`VARCHAR(280)`; CHECK-constrained label vocabulary; no client method returns
text) rather than promised in prose. Erasure and retention come from the
`tenant_id` column name that `discover_tenant_tables` selects on, asserted
per table.

**Negative controls.** (1) Reverting only the `fields.get("scopes")` read
fails both recorder tests again with `KeyError: 'scopes'`. (2) Adding a
`transcript` `Text` column to `AiChatContentLabel` and changing nothing else
fails the forbidden-column and unbounded-TEXT sweeps.

**Measurement delta.** No change to the executable-detection figure: this
item adds no rules. Rules reading these feeds are 7.4.

**Deviation D3 — one provider, not several, for the compliance half.** The
plan says "where a provider offers a compliance API". Exactly one does with
a complete public reference: Anthropic's, at
`platform.claude.com/docs/en/manage-claude/compliance-*`, whose pages were
fetched and returned 200. OpenAI's equivalent is behind a Cloudflare
challenge that answers 403 to every non-browser request, including its
ordinary audit-log reference, so no honest mock can be written from it. The
`provider` column is a CHECK constraint with one value today; adding a
second is a one-line migration. **Blocked, with exactly what is needed:** a
reachable public reference for the OpenAI Compliance API, or a recorded
payload from a customer tenant.

### 7.2 — Hosted agents and repository AI artefacts

**What already existed, and was therefore not rebuilt.** The whole asset
table, the one `score_risk`, the tri-state `sanctioned`, the console page and
its "not learned" rendering, and the recorder's three discovery sources. 7.2
widened two constraints and added two producers; it changed no scoring.

**Reproduced gap.** `.laneE/repro_7x.py` against the base commit:
`AI_ASSET_KINDS` held six values, `hosted_agent present: False`,
`repo artefact kind present: False`. Migration 110's CHECK constraint rejected
a seventh kind deliberately, so this is that refusal answered by a reviewed
migration rather than by dropping the constraint.

**What shipped.** Migration 147 (two kinds, two discovery sources, a
repository expression index), `ai_repo_scan.py`, `hosted_agents.py`, the
generated `_vendor/ai_instruction_rules.py` with its sync gate wired into
`ci.yml`, and the console's kind list and source-limitation copy.

**Wiring proof — the single scorer.** `score_risk` gained three signals
(`unvetted_mcp_server`, `instruction_injection`, `unpinned_skill_source`) and
both producers emit `attributes` keyed to what it already reads (`tools`,
`mcp_servers`, `skills`), so neither needs a special case and no second
scorer exists. `DEVICELESS_KINDS` is shared between the model and the scorer
so the four kinds with no device are not charged for lacking one.

**Wiring proof — the injection channel.** Repository instruction text and a
hosted agent's system prompt both pass `scan_instruction_text` at capture.
The patterns are generated from the agents guard's own `_RULES` table, so the
scanner and the triage guard cannot disagree about the same text; only
pattern *names* are stored, never the matching span. Proven in both
directions: a hostile instruction file is flagged and scores higher, an
ordinary one is flagged by nothing and scores exactly 0 with an empty reason
list.

**Negative controls.** Clean twins on every signal (clean instruction file,
clean hosted agent, vetted MCP server, every deviceless kind) each score 0
with no reasons, so every delta is attributable to one field. The vendored
rule table's `--check` fails against a stale copy, and the generator fails if
an excluded rule name leaves the guard.

**Two defects found while building it, both recorded rather than quietly
fixed.** `path.lstrip("./")` strips the leading dot of a dotfolder, which
would have turned most of the scan off silently — caught because the
classification test enumerates real paths instead of two examples. And a
committed JWT-shaped literal in the 7.1 test, which the repository's secret
scan correctly refused.

**Measurement delta.** No change to the executable-detection figure.

### D4 — One hosted-agent provider, for the same reason as D3

`GET /v1/agents` is the one provider hosted-agent list with a complete public
reference. The GitHub Copilot coding agent is reachable only through its
audit events (`copilot.swe_agent_*`), which 7.1 now ingests but which are
events rather than an inventory; `docs.github.com/en/rest/copilot/copilot-agents`
is a 404. **Blocked, with exactly what is needed:** a published REST reference
for a second provider's hosted-agent list, or a recorded response from one.

### 7.4 — AI rule pack (PARTIAL, four of the listed targets)

**What already existed.** Sixteen executable AI rules: eight `llm-*` on the
OpenAI/Anthropic control plane and eight `ai-*` on runtime and guardrail
findings. Not rebuilt.

**Reproduced gap.** `.laneE/repro_7x.py` showed no rule anywhere clausing on
a Copilot audit action, a consent scope or an assistant's resource-access
volume, because until 7.1 no connector emitted any of them.

**What shipped.** Four rules on the feeds 7.1 added:
`llm-copilot-content-exclusion-changed` (critical),
`llm-copilot-agent-mcp-config-changed` (high),
`llm-ai-app-granted-write-scope` (high),
`llm-copilot-bulk-resource-access` (medium).

**Replay proof.** `services/fusion/tests/test_ai_rule_pack_replay.py` drives
the real `DetectionEngine` over the real compiled ruleset against fixtures
that are the committed output of `LlmUsageConnector.normalize()` — not
synthesized from the rules. Each negative twin differs in exactly one
decisive field, and a test asserts that property on the fixtures rather than
trusting it.

**Negative control.** Rewriting one rule's clause to the unprefixed vendor
action — the exact shape of the measured GitHub failure where 1 of 12 rules
fired on real output — and re-exporting fails that rule's positive replay
while the other three stay green.

**Measurement delta.** Executable detections **2,530 → 2,534**; on disk
7,015 → 7,019. Re-derived with `python3 scripts/project_stats.py` and
propagated by the generators to the README, `ROADMAP.md`, the truth table,
`corpus-stats.json`, both marketplace indexes and the packaged API copy. No
figure was hand-typed; `test_readme_figures_gate.py` passes (23).

**Not delivered, and why — the remaining targets each need a producer that
does not exist yet.** Recorded rather than shipped as rules clausing on
fields nothing emits, which is the failure this plan's replay rule exists to
prevent:

| Target | What is missing |
|---|---|
| Provider key used from a new ASN | No provider audit log read here carries a source IP, so there is no address to resolve to an ASN. Needs 1.6's anonymiser/ASN dataset plus a provider feed that emits the IP. |
| Agent invoking a *new* high-risk tool | "New" is a per-agent baseline, which is 7.3 and is not built. The stateless engine can see the tool, not its novelty. |
| Rise in guardrail violations | A rate over a window per agent; same dependency on 7.3. |
| Token-spend anomalies per key and per agent | `cost_telemetry.py` records per-call cost and the dashboard aggregates it, but neither writes a per-agent baseline the engine can read. Wiring a second meter was explicitly refused. |
| Secrets or personal data labelled in AI chats | The labels exist (7.1, migration 146) but live in Postgres, not on the event stream the engine evaluates. Needs a promoter from `aisoc_ai_chat_content_labels` to an event, which is a design decision rather than a rule. |
| Agent process reading browser cookie or credential stores | Endpoint discovery sees AI processes; nothing emits a file-access event scoped to cookie or credential stores. Needs an osquery/EDR producer. |

### 7.3 — Agent identity and baselines: NOT DELIVERED

**Reproduced gap, recorded for whoever picks it up.** Two halves, both open:

- *Agent identity.* No module in the tree defines an identity for AiSOC's own
  agents: `grep -rln "agent_identity\|AgentIdentity\|agent_principal"` across
  `services/` returns nothing. Parity 6.7 asks for short-lived credentials and
  least-privilege tool scopes visible in the audit log.
- *Per-agent baselines.* `services/fusion/app/services/baselines.py` defines
  **zero** `baseline_*` functions; the only AI-adjacent signal is
  `baseline_oauth_app_volume_z`, emitted inside `BaselineStore` and keyed on
  the OAuth application, not on an agent. Nothing keys a baseline on an agent
  identity, and `cost_telemetry.py` has no baseline writer at all.

**Why it is not started rather than half-built.** It is the dependency under
four of 7.4's six remaining targets, so a partial version would have produced
rules that cannot fire — and 7.5 (Lane D) depends on 7.1, which landed first
as instructed. Starting a per-agent baseline store without the agent identity
half would key it on whatever field happened to be present, which is how
`baseline_oauth_app_volume_z` came to be the only one.

**What is needed:** the full item, in order — agent identities with
short-lived credentials and least-privilege tool scopes first, then baselines
keyed on them (tools, resources, volume, token spend, hours) reading the
existing `cost_telemetry.py` rather than a second meter.
| Date | Item | Entry |
|---|---|---|
| 2026-11-01 | 3.3 | Reproduced: 5 of 7 cases in `services/fusion/tests/test_alert_occurrences.py` fail on the pre-change tree with "no statement touched alert_occurrences". A repeat's only residue was a `source_event_ids` append — capped at 200 and shared with multi-event correlation, so its length is not a repeat count — and `alerts.first_seen`/`last_seen` have had no writer since `001_init.sql`. Shipped migration 151 (`alert_occurrences`, a rollup keyed `(tenant_id, alert_id)`: exact count including the survivor, real window, newest-first bounded payload-id window), the sink write, and the measurement as **its own labelled row**: 28.4 % repeat folding (1000 → 716, 284 folded) published beside 33.3 % and 24.5 % correlation and never added to either. **The reduction is identical before and after**, which the docs state: folding is not new, keeping what it folded is. Balance asserted four ways summing to the denominator (658 retained alone + 58 attached to a group + 284 folded + 0 pending), plus a resolvability assertion that each folded repeat maps to the retained alert's own id. **Writing the live suite found a defect in this item's own migration**: the conventional `WITH CHECK (tenant_id = current_tenant_id())` makes the row unwritable by fusion, which binds no tenant session — measured as `aisoc_app` (NOBYPASSRLS), the identical session inserts into `alerts` and is refused here, and because the write is best-effort it would have failed in silence (migration 123's shape). Negative controls, both measured: reverting the `WITH CHECK` fails all six live cases; removing the jsonb containment guard takes five redeliveries of one message from a count of 2 to 7. Baselines unmoved. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 4.6 | **Not measured, with the reproduction.** `make replay-eval` reads a window of closed findings somebody's analysts already labelled; no design partner has offered one, so false-positive reduction, time to verdict and escalation rate are recorded as *not measured* on the replay page with the exact two-command reproduction. `scripts/check_outcome_claims.py` is what makes the record worth anything: while the page says an outcome is unmeasured, no published surface may print a number for it — **including `0`**, which is the more damaging case because it reads as measured-and-reduced-nothing and looks like data. The prohibition is read off the page rather than hardcoded, so a real measurement retires it without editing the gate. Its first run flagged a true sentence (a table row naming `escalation rate` beside an unrelated "auto-refresh every 60s"), so the rule narrowed from same-line to same-clause with both that case and a real claim in the identical row shape pinned. 13 self-test cases; negative control names file and line. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 9.4 | **Blocked, verified rather than assumed.** The Teams war room is built and `POST /war-room` answers 501 naming each absent Microsoft Graph setting instead of falling back to the incoming webhook, because one shared channel per deployment puts the next incident's traffic in the last one's thread. Already pinned by `services/teams-bot/tests/test_war_room.py`. **Needs:** an Entra application registration with `Channel.Create`, `ChannelMessage.Send` and `Group.ReadWrite.All`, admin consent, and a team id. Recorded as a claim row so the honest refusal cannot quietly become a fallback. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 5.2 | Reproduced: `resolve_provider` required `connected_types.intersection(provider.connector_types)`, and `_execute_hunt` turns the resulting `UnsupportedTranslation` into a hit count of **zero** — not an error state, so no case opens, nothing logs above INFO, `last_run_at` moves, and it is indistinguishable from "your hunt found nothing". That was the answer on every deployment whose data lives in AiSOC's own lake. Added `LakeProvider` (no connector types; the registry now allows such a provider, checked **after** the connector-backed chain so a tenant's own SIEM always wins) with tenant binding through `compile_hunt`, an unreachable lake raising rather than returning zero, and dropped conditions logged by name. ADR-0015's **HUNTING OUTPUT** label did not exist anywhere outside the ADR — now in the banner, the page title and the mail subject, with a sentence saying what the document does not claim. Emailed delivery did not exist either (`aisoc_hunt_reports` and the report scheduler's `ReportArtefact` were never connected); it ships **off** behind `AISOC_HUNT_REPORT_RECIPIENTS`. Negative control: removing the empty-`connector_types` arm fails the reproduction and the scheduler-wiring case. API suite 5042 passed. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 9.2 | **Blocked, and the README was overstating.** See D4. Corrected the capability table and extended the `mobile.yml` honesty guard to pin both rows. **Needs:** 9.1's recogniser and screen first — nothing can speak to the app today — then an Apple developer account and provisioning profile for iOS, or a Google Play account for a store-signable Android build. The Android `assembleDebug` APK already installs on a handset, so once 9.1 lands the Android half becomes a device question rather than a credentials one. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 3.2 | Reproduced: the grouper chained on a shared host, user or source-IP **string**, first match wins in a fixed order, with nothing on the result saying which of the three had done it — so a NAT egress address welds two intrusions into one story; an alert carrying a `session_id` (written by fusion since migration 102, alongside `originating_human`) got no more weight than one carrying a hostname; and `ChainMember` carried a per-member severity that nothing aggregated, so "a member benign alone may be escalated by its story" had nowhere to happen. Built **on** the grouper: typed links with three strengths (session/human > hash/domain > host/user/ip), story severity raised by exactly one tier only when the story spans three or more kill-chain stages with the reason carried on the assignment, and actor mode held at `unknown` until Lane A's 1.4 supplies cadence — two tempting inferences rejected in code and pinned by test. **Measured:** story recall 100 % on all three labelled scenarios (4/4, 3/3, 2/2), purity 100 % (5/5), 0 cross-rule stories of 63 on a detection-shaped cohort. **The purity rule was found by the measurement, not reasoned out:** the first cut refused a weak link only across detection rules and the suite measured 75 % purity, because the scenario alerts carry no `rule_id` and an antivirus quarantine sharing the NAT address joined a phishing-to-exfiltration story. A weak link now also may not join a story anchored on strong evidence; the asymmetry (a strong link may still join a string-held pile) is deliberate and tested. Negative controls, both measured: removing either refusal fails two cases. Reduction baselines unmoved at 33.3 % and 24.5 %. **Open and recorded, not approximated:** stories are still Redis-only — the assignment reaches the Kafka envelope and the realtime socket and evaporates, so no API read or case can show one — and the resolved-identity link waits on Lane A's 3.1. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
### 1.6 Anonymizer and hosting classes at ingest - Lane B

**Reproduced.** A Go test driving the real `Normalize` entry point, not the
classifier in isolation, so that a classifier package with passing unit
tests and no caller could not satisfy it. On the pre-change tree:

    internal/normalizer/ipclass_stamp_test.go:68:20:
      act.Location.IPClass undefined (type activity.Location has no field)

Nothing in the tree classified an address, and no dataset existed to
classify from.

**Shipped.**

|---|---|
| Downloader | `scripts/fetch_ip_class_dataset.py` |
| Pinned snapshot | `services/ingest/internal/activity/ipclass/data/` (21,726 records) |
| Go classifier | `services/ingest/internal/activity/ipclass/ipclass.go`, embedded |
| Production caller | `activity.Project` -> `stampIPClass`, so every caller gets it |
| Python loader | `scripts/ip_class_dataset.py`, vendored to `services/fusion/app/services/ip_class.py` |
| Live -> matcher | `DetectionEngine._with_activity_location` lifts the nested stamp flat |
| Replay -> matcher | `ip_class_fields` in both copies of the derived-field lockstep |
| Lake | 3 columns, `001_init.sql` and lake migration `005_ip_class` in lockstep |
| Alert | migration `130`, fusion `RawAlert`, promoter, `_INSERT_SQL`, API `AlertResponse` |
| Console | `SourceAddressClassSection` on the investigation rail |
| Gate | `scripts/check_ip_class_dataset.py`, wired in `ci.yml` twice |
| Decision | ADR `0018` |
| Docs | `apps/docs/docs/operations/ip-classification.md`, in the sidebar |

**Negative control.** Removing the single `stampIPClass(&act.Location)` call
from `Project`, leaving the fields and the dataset in place:

    --- FAIL: TestNormalizeStampsAnonymizerClass/tor_exit_relay
        ip 2.56.10.36: ip_class = "", want "tor_exit"
    --- FAIL: TestNormalizeStampsAnonymizerClass/cloud_hosting_range
        ip 1.178.1.0: ip_class = "", want "hosting_provider"

Restored, the suite passes again.

**Numbers, from the generators.**

|---|---|---|
| Dataset records | 21,726 | `check_ip_class_dataset.py` |
| `tor_exit` records | 1,228 | same |
| `hosting_provider` records | 20,498 | same |
| Sources | 8 | same |
| Classes shipped | 2 of 5 | same (see D3) |
| Go/Python parity sample | 400 addresses, 0 disagreements | same |
| Claim matrix | 334/329/5 -> **335/330/5** | `check_claim_gate_matrix.py` |

**Scorecard and reduction suite.** Not re-run: this item adds a field that no
shipped rule matches on yet (Lane C's 2.1 is what will), changes no
correlation key, no confidence input and no priority input, and the fusion
suite's 1,065 tests pass unchanged. Recorded as a deliberate judgement
rather than an omission; Lane C's first rule reading `ip_class` is the PR
that has to carry the delta.

**Deviations:** D3 (three classes have no redistributable source), D4
(tenant-supplied lists designed, not built).


### 7.3 — Agent identity and per-agent baselines (depth 6.4 / parity 6.7)

[#1601](https://github.com/beenuar/AiSOC/pull/1601), base `main`.

**Reproduced gap.** `docs/audit/depth2-baseline/lane-e-phase73-reproduction.py`,
runnable from a bare checkout: no module under `services/agents` defines an
agent identity; `ToolRegistry.execute` takes no caller, declares no scope and
writes no audit row; `baselines.py` declares seven derived fields and none is
keyed on an AI agent.

**Half A.** Short-lived identity per run, least-privilege tool scope enforced
at `ToolRegistry.execute` — the one chokepoint every tool call passes
through, because a check an agent performs on itself is one a steered agent
can be talked out of. Identity is required, not optional. Nothing in the
scope table changes an estate; a test forbids it.

**Half B — one mechanism, built for Lane A.** `SUB_PRINCIPAL_FIELDS` replaces
the hardcoded OAuth-app block, with the dict key as the field prefix so
`baseline_oauth_app_volume_z` keeps its published name. Lane A's 1.4 adds
`token` and `service_account` as one entry each. Eight new derived fields.

**Negative controls.** Making identity optional fails one named test;
removing the `agent` entry fails eight baseline tests.

### 7.4 — four more targets shipped, two still blocked

Executable detections **2,530 → 2,534** on `main`'s base (and 2,534 again on
the landing branch, which carries the other four — the two PRs touch
different rules and the figure is regenerated in each).

Shipped and replayed through the real connector, the real `BaselineStore`
and the real engine: `ai-agent-new-high-risk-tool`,
`ai-agent-guardrail-violation-rate`, `ai-agent-token-spend-anomaly`,
`ai-gateway-key-spend-anomaly`.

### D5 — The 7.1 labels reach the engine as events, not as a query

Decided explicitly, as the brief requires, and **not yet implemented**.

The chat-content labels from 7.1 live in `aisoc_ai_chat_content_labels` in
Postgres; the detection engine evaluates a stream. Two options:

*The rule reads it where it lives* — refused. The engine is stateless and
evaluates per event with no database handle; giving it one would mean a
Postgres round trip per event on the hot path, and the one place that
pattern exists (the tenant tuning overlay) is a per-tenant cache loaded
once, not a per-event read.

*The label reaches the stream* — chosen. The collector emits one OCSF event
per newly labelled conversation, through the same ingest path a connector
uses, carrying the labels, the shape names and the bounded snippet it
already stores. A rule then clauses on `labels_has_any` exactly as every
other rule clauses on connector fields, with no new mechanism and no new
hot-path cost.

**What it needs:** the API service has no ingest client — `IngestClient`
lives in `services/connectors` — so this is either a small vendored client
in the API or a move of the collector into the connectors service. That is
a structural decision touching another lane's tree, which is why it is
recorded here rather than guessed at. Nothing is shipped clausing on
`labels` until it exists.

### D6 — The enrichment-decision gate judges reachability globally

Found while landing 7.1: `scripts/check_enrichment_decisions.py` asks
whether a retired rule's fields are resolvable against the **union of every
connector's** namespace. Promoting a field called `scopes` on Entra consent
events therefore made `ident-github-pat-classic-created-with-broad-scopes`
look reachable, and the gate demanded it be un-retired — while GitHub's
audit log still does not carry a created classic PAT's scopes, so the rule
could not fire.

Worked around correctly by renaming the field to `granted_scopes`, which is
more precise anyway. **The gate weakness is not fixed:** a rule's
reachability should be judged against the fields its own `log_source`
emits. Left recorded rather than changed, because it is a shared gate
several lanes depend on and a scoping change belongs with its owner.

### D7 — Lane A's Phase 1.4 had not landed when 7.3 was built

`origin/main` was fetched before starting and again before committing;
`baselines.py` on `main` still had no sub-principal mechanism. 7.3 therefore
built the shared one rather than waiting. It is additive — a dict entry per
kind, plus one name appended to `PRINCIPAL_FIELDS` — so if 1.4 lands first
the two combine rather than conflict. If both touch the file, combine; never
take one side.
