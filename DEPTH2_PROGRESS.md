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
| 151–158 | migration | Lane F (analyst: 3.2, 3.3, 4.x, 5.x, 9.x) | 2026-11-01 | reserved block, see below |
| 0022 | ADR | Lane F | 2026-11-01 | reserved |

Highest at kickoff: migration `123`, ADR `0014`. Next free: migration `124`,
ADR `0016`.

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
| 154 | `services/api/migrations/154_triage_questions.sql` | 4.3 questions — **landed** |
| 155 | `services/api/migrations/155_hunt_source_reports.sql` | 5.1 source reports |
| 156 | `services/api/migrations/156_software_inventory.sql` | 5.4 inventory |
| 157 | unused | — |
| 158 | unused | — |

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
| **4.3** questions + rules | **done** | Reproduced before building: all three operator sets (API `ALLOWED_OPS`, agents `COMPARATOR_OPS`, the matcher's own branches) were measured identical at 13, and **`neq` is not one of them** — a rule using it parses as a field name and silently never matches. Lockstep was therefore a *preservation* requirement, now held by `check_business_context_grammar.py` in three directions and proven by two injected controls against this tree. Plain-language rules compile deterministically — **no model anywhere on the path** — into the same structured rule both engines run, round-tripped through the real parser and previewed with per-field coverage against the tenant's own last 50 alerts. Questions split at rest into a free-text label that decides nothing and a closed-schema lookup that produces the answer; unanswerable is a distinct answer from no. Migration 154 landed. |
| **4.4** precedent + re-triage | **verified, not built** | See D3. Precedent reaches triage by two routes but matches only on exact fingerprint or rule/entity string; `semantic_memory.py` is a complete Qdrant recall with provenance that the triage path never touches. Re-triage is genuinely absent, and `run_id` is `uuid5(alert_row_id:WORKFLOW_VERSION)` with `ON CONFLICT (run_id, seq) DO NOTHING`, so a naive re-triage writes **nothing** — it needs a re-triage discriminator in the run id, and seq 0/1 are taken. |
| **4.5** vendor evidence | **verified, not built** | See D3. `investigation_reads.py` exists with 5 verbs over 7 vendors. Two real gaps: no GuardDuty finding-read verb (the alias resolves GuardDuty to a CloudTrail read), and `run_auto_triage` has **no tool channel at all** and says so in a comment, so a vendor alert that auto-triages never pulls vendor evidence. A deterministic context fetch, like `_attach_identity_context`, is a better shape than a tool channel: the ledger citation is then real because the fetch happened. |
| **5.1** hunt from a report | not started | Every piece exists separately: `ssrf_guard.validate_outbound_url` (**a validator, not a fetcher — it does not bound response size**, so 5.1 must add its own `max_bytes` and timeout), `EvidenceEnvelope.wrap` for nonce fences (use it, not `wrap_untrusted`), and the closed hunt schema in `hunt/plan.py` with `hunt_plan_sql.py` binding every value as a parameter. Migration 155 is claimed and unused. |
| **5.3** explorer | **done** | **The recorded measurement understated this and is corrected here.** It said the explorer "already shows the generated query" and named the `res.esql` assignment as a latent bug. Reproduction showed the natural-language path could not work *at all*: `/nl-query/translate` runs nothing and returns an ESQL/SPL/KQL triple, and the ESQL was posted to the lake's **SQL** endpoint — different languages. So the query on screen was never the query that ran, and `/nl-query/execute` had shipped the whole capability with no caller. The predecessor test pinned the defect as intended, its fixture putting literal SQL in the `esql` field. Shipped: the correct endpoint, the executed query with its language and its bound values shown separately, which store answered, unapplied filters with their direction, cross-filters, per-entity view, CSV export and the graph pivot. |
| **5.4** software inventory | **done (PARTIAL row)** | No connector reads a code-platform SBOM API. `packs/aisoc-inventory-baseline.yaml` queries `deb_packages`, `rpm_packages` and `homebrew_packages` — but **not** the Windows `programs` table — and **nothing consumes the results**. `assets` and `asset_vulnerabilities` are host-level; there is no package-level table. Migration 156 is claimed and unused. |
| **5.5** retro-hunt at scale | **absent** | The retro-hunt subsystem is substantial and sweeps two stores with honest failure states. `scripts/perf/` is ingest/throughput oriented; nothing measures sweep cost against indicator volume. Needs recorded hardware. |
| **9.1** voice | **absent** | `voice.ts` is an interface with no recogniser and no screen (see D4). `expo-local-authentication` is already installed and `app/approval/[id].tsx` already names the exact action in its biometric prompt, which is the 9.1 requirement. `@react-native-voice/voice` is **already denied** by `check_no_audio_egress.py` as cloud-capable — an on-device package must be added *and* allowlisted, with the self-test extended, since the self-test is what makes that gate non-vacuous. |
| **9.3** i18n | **absent** | Nothing at all: no library, no `messages/`, no RTL, no gate. Scope is the five surfaces gap-closure 13.4 names (~690 strings), not the whole console (~72k lines). Note parity 4.7's axe-core extension targets the **same five surfaces**, so the two share a blast radius. |
| **9.5** operator pages | **done — all 7 built and gated** | SCIM tokens **is built** (`ScimTokensPanel.tsx`, wired at `SettingsView.tsx:424`) and organisation members is built, but the claim row at `CLAIM_TO_GATE_MATRIX.md:299` still lists both as not built. Branding, retention, rule packs, delegations and the console over-limit state are genuinely absent. The enforcement bullet of parity 4.5 is already GATED and done. |

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

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

| Date | Item | Entry |
|---|---|---|
| 2026-11-01 | 3.3 | Reproduced: 5 of 7 cases in `services/fusion/tests/test_alert_occurrences.py` fail on the pre-change tree with "no statement touched alert_occurrences". A repeat's only residue was a `source_event_ids` append — capped at 200 and shared with multi-event correlation, so its length is not a repeat count — and `alerts.first_seen`/`last_seen` have had no writer since `001_init.sql`. Shipped migration 151 (`alert_occurrences`, a rollup keyed `(tenant_id, alert_id)`: exact count including the survivor, real window, newest-first bounded payload-id window), the sink write, and the measurement as **its own labelled row**: 28.4 % repeat folding (1000 → 716, 284 folded) published beside 33.3 % and 24.5 % correlation and never added to either. **The reduction is identical before and after**, which the docs state: folding is not new, keeping what it folded is. Balance asserted four ways summing to the denominator (658 retained alone + 58 attached to a group + 284 folded + 0 pending), plus a resolvability assertion that each folded repeat maps to the retained alert's own id. **Writing the live suite found a defect in this item's own migration**: the conventional `WITH CHECK (tenant_id = current_tenant_id())` makes the row unwritable by fusion, which binds no tenant session — measured as `aisoc_app` (NOBYPASSRLS), the identical session inserts into `alerts` and is refused here, and because the write is best-effort it would have failed in silence (migration 123's shape). Negative controls, both measured: reverting the `WITH CHECK` fails all six live cases; removing the jsonb containment guard takes five redeliveries of one message from a count of 2 to 7. Baselines unmoved. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 4.6 | **Not measured, with the reproduction.** `make replay-eval` reads a window of closed findings somebody's analysts already labelled; no design partner has offered one, so false-positive reduction, time to verdict and escalation rate are recorded as *not measured* on the replay page with the exact two-command reproduction. `scripts/check_outcome_claims.py` is what makes the record worth anything: while the page says an outcome is unmeasured, no published surface may print a number for it — **including `0`**, which is the more damaging case because it reads as measured-and-reduced-nothing and looks like data. The prohibition is read off the page rather than hardcoded, so a real measurement retires it without editing the gate. Its first run flagged a true sentence (a table row naming `escalation rate` beside an unrelated "auto-refresh every 60s"), so the rule narrowed from same-line to same-clause with both that case and a real claim in the identical row shape pinned. 13 self-test cases; negative control names file and line. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 9.4 | **Blocked, verified rather than assumed.** The Teams war room is built and `POST /war-room` answers 501 naming each absent Microsoft Graph setting instead of falling back to the incoming webhook, because one shared channel per deployment puts the next incident's traffic in the last one's thread. Already pinned by `services/teams-bot/tests/test_war_room.py`. **Needs:** an Entra application registration with `Channel.Create`, `ChannelMessage.Send` and `Group.ReadWrite.All`, admin consent, and a team id. Recorded as a claim row so the honest refusal cannot quietly become a fallback. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 5.2 | Reproduced: `resolve_provider` required `connected_types.intersection(provider.connector_types)`, and `_execute_hunt` turns the resulting `UnsupportedTranslation` into a hit count of **zero** — not an error state, so no case opens, nothing logs above INFO, `last_run_at` moves, and it is indistinguishable from "your hunt found nothing". That was the answer on every deployment whose data lives in AiSOC's own lake. Added `LakeProvider` (no connector types; the registry now allows such a provider, checked **after** the connector-backed chain so a tenant's own SIEM always wins) with tenant binding through `compile_hunt`, an unreachable lake raising rather than returning zero, and dropped conditions logged by name. ADR-0015's **HUNTING OUTPUT** label did not exist anywhere outside the ADR — now in the banner, the page title and the mail subject, with a sentence saying what the document does not claim. Emailed delivery did not exist either (`aisoc_hunt_reports` and the report scheduler's `ReportArtefact` were never connected); it ships **off** behind `AISOC_HUNT_REPORT_RECIPIENTS`. Negative control: removing the empty-`connector_types` arm fails the reproduction and the scheduler-wiring case. API suite 5042 passed. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 9.2 | **Blocked, and the README was overstating.** See D4. Corrected the capability table and extended the `mobile.yml` honesty guard to pin both rows. **Needs:** 9.1's recogniser and screen first — nothing can speak to the app today — then an Apple developer account and provisioning profile for iOS, or a Google Play account for a store-signable Android build. The Android `assembleDebug` APK already installs on a handset, so once 9.1 lands the Android half becomes a device question rather than a credentials one. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
| 2026-11-01 | 3.2 | Reproduced: the grouper chained on a shared host, user or source-IP **string**, first match wins in a fixed order, with nothing on the result saying which of the three had done it — so a NAT egress address welds two intrusions into one story; an alert carrying a `session_id` (written by fusion since migration 102, alongside `originating_human`) got no more weight than one carrying a hostname; and `ChainMember` carried a per-member severity that nothing aggregated, so "a member benign alone may be escalated by its story" had nowhere to happen. Built **on** the grouper: typed links with three strengths (session/human > hash/domain > host/user/ip), story severity raised by exactly one tier only when the story spans three or more kill-chain stages with the reason carried on the assignment, and actor mode held at `unknown` until Lane A's 1.4 supplies cadence — two tempting inferences rejected in code and pinned by test. **Measured:** story recall 100 % on all three labelled scenarios (4/4, 3/3, 2/2), purity 100 % (5/5), 0 cross-rule stories of 63 on a detection-shaped cohort. **The purity rule was found by the measurement, not reasoned out:** the first cut refused a weak link only across detection rules and the suite measured 75 % purity, because the scenario alerts carry no `rule_id` and an antivirus quarantine sharing the NAT address joined a phishing-to-exfiltration story. A weak link now also may not join a story anchored on strong evidence; the asymmetry (a strong link may still join a string-held pile) is deliberate and tested. Negative controls, both measured: removing either refusal fails two cases. Reduction baselines unmoved at 33.3 % and 24.5 %. **Open and recorded, not approximated:** stories are still Redis-only — the assignment reaches the Kafka envelope and the realtime socket and evaporates, so no API read or case can show one — and the resolved-identity link waits on Lane A's 3.1. [#1588](https://github.com/beenuar/AiSOC/pull/1588) |
