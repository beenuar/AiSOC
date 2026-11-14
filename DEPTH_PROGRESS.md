# AiSOC depth plan: progress

Mirrors `plans/aisoc_depth_plan.plan.md`, which is locked and is the source of
truth. This file is the mutable half.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done, `[!]` blocked (with
exactly what is needed).

An item is `[x]` only when all three of these are recorded against it: the test
or gate that failed on the pre-fix tree for the stated reason, the change, and
the negative control showing that reverting it fails again.

- **Base commit:** `1b8bc2d4` (`origin/main`, v17.1.0).
- **Plan captured at:** `90ea2fd`. Figures in the plan body are hints at that
  commit; Phase 0.2 below re-derives each one and the tree wins.

## Reconciliation, 2026-10-09

Eleven items had merged to `main` and every one still read `[ ]` here. The
tracker is the mutable half of a locked plan, so a tick that lags the tree
makes it describe a repository that no longer exists -- the same failure the
plan exists to catch, one level up.

Reconciled against the tree rather than against the pull requests: each item
below was confirmed by the artefact it was supposed to produce being present
on `main` (the corpus file, the OCSF decision table, the event catalogue
directory, the scorecard fields, the notify arms, the report scheduler, the
step bounds, the access-conditions routes, the security pack), not by a merged
title. Each carries the reproduce, change and negative control the legend
requires in its own pull request body.

| Item | Landed in | Confirmed by |
| --- | --- | --- |
| 1.1 | #1205 | `services/agents/tests/eval_data/verdict/verdict_corpus_v1.json` |
| 1.2 | #1191 | nine scorecard fields in `aisoc_benchmark/replay.py` |
| 1.3 | #1197 | `scripts/check_verdict_corpus.py`, `prompting/tool_results.py` |
| 2.1 | #1195 | `internal/normalizer/ocsf_classes.go` |
| 2.2 | #1204 | `scripts/check_activity_projection.py` |
| 2.3 | #1209 | `schemas/event_catalog/` |
| 5.1 | #1203 | `live_actions/notify_arms.py` |
| 5.2 | #1211 | `app/workers/report_scheduler.py` |
| 5.3 | #1207 | `app/playbook/bounds.py` |
| 8.2 | #1206 | `endpoints/access_conditions.py` |
| 8.3 | #1210 | `docs/security/` |

Not started: phases 3, 4, 6, 7, 9 and the whole of 10, and
2.4--2.7. Those remain `[ ]` and are not claimed here.

Not started **as at 2026-10-09**: phases 3, 4, 6, 7, 9 and the whole of 10,
plus 1.4--1.6 and 2.4--2.7. That list was true on the day and is not
maintained -- lanes have landed items in several of those phases since. The
per-phase checklists below and the item log at the end are the live answer;
this paragraph is a dated snapshot and reading it as current is the exact
failure the reconciliation above was written to fix.

## Migration and ADR numbers claimed

Phases run in parallel lanes, so a number is claimed here **before** the file
is written. Next free at capture: migration `095`, ADR `0010`
(`docs/decisions/`, not `docs/adr/` -- the plan's wording; the directory is
`decisions/` and the highest is `0009-auto-close-without-an-earned-grant.md`).

> **Renumbered at the 2026-10-12 merge train.** Nineteen lanes merged at once and
> several had claimed the same free numbers before any of them landed — four lanes
> on migration `110`, three on `111`, three on ADR `0011`. First lane merged kept
> its number; the rest were renumbered in one commit, with every in-tree reference
> updated. The **file name in the Status column is authoritative**; the Number
> column records what the lane claimed at the time. Final ladder: migrations
> `102`–`118` contiguous, ADRs `0011`–`0013`. The `109` claimed by 9.6 for
> `109_push_devices.sql` was never written (9.6 shipped no migration), so `109`
> went to `109_mcp_access.sql`; a future 9.6 follow-up re-derives against `main`
> as the rule below already requires. The `111` claimed by 6.4 is likewise
> re-derived when that lane lands.

| Number | Claimed by | Status |
|---|---|---|
| ADR `0010` | 2.7 — entity and session context in CORE | **landed**, `docs/decisions/0010-entity-and-session-context-in-core.md`, accepted |
| migration `102` | 2.4 — `102_sessions.sql` | **landed**, `sessions` table plus three `alerts` columns |
| migration `103` | 2.5 — `103_posture_snapshots.sql` | claimed |
| migration `104` | 9.1 — `109_mcp_access.sql` | claimed |
| migration `105` | 9.2 — `105_semantic_memory.sql` | claimed |
| migration `106` | 9.3 — `106_case_depth.sql` | claimed |
| migration `107` | 9.4 — `107_case_war_rooms.sql` | claimed |
| migration `108` | 9.5 — `108_hunt_reports.sql` | claimed |
| migration `109` | 9.6 — `109_push_devices.sql` | claimed |
| migration `110` | 8.1 — `116_console_webauthn.sql` | claimed |
| migration `111` | 8.1 — `117_audit_retention.sql` | claimed |
| migration `112` | 8.1 — released, taken by another lane (D12) | **struck** |
| migration `113` | 8.1 — `118_entitlement_enforcement.sql` | claimed |
| ADR `0011` | 8.1 — truncating a hash-chained audit log | claimed |

| migration `104` | 5.4 stateful user/manager verification (verification requests, answers, tenant opt-in) | claimed |
| migration `105` | 5.6 plain-language playbook drafts (draft, preview, approval) | claimed |

Lane B claimed `102`/`103` and landed that claim on `main` first, so Lane C's
two moved to `104`/`105` and `102_playbook_verification.sql` was renamed with
it. Both lanes had claimed before writing, as the plan requires -- what the
rule cannot prevent is two lanes claiming the same free number before either
merges, so re-read `services/api/migrations/` **and** this table before
picking one.
| migration `110` | 6.1 — `110_ai_assets.sql` | claimed |
| migration `111` | 6.4 — `111_ai_agent_identities.sql` | claimed |
| ADR `0011` | 6.6 — AI containment arms off by default, and the rollback a kill-switch needs | claimed |
| — | 5.4 — `104_playbook_verification.sql` on `depth/5.4-5.6-lane-c`, and 7.1 — `104_phishing_campaigns.sql` on `depth/7.1-7.3-phishing` | **collision, unresolved here.** Both lanes wrote a `104` on a branch without a row in this table. Phase 9's `104` is the one with a claim, so these two need renumbering by their own lanes; recorded rather than renamed from outside, because renaming another lane's migration from here is how a branch comes back to a file that no longer exists |
| migration `110` | 7.1 — `111_phishing_campaigns.sql` | claimed |
| migration `111` | 7.2 — `112_phishing_message_analysis.sql` | claimed |
| ~~migration `110`~~ | ~~3.4 — `110_entity_baselines.sql`~~ | **released**, ADR-0011 put the baselines in the Redis fusion already runs, so there is no table |
| migration `111` | 3.7 — `111_detection_coverage.sql` | claimed |
| ADR `0011` | 3.4 — behavioural baselines in CORE | **landed**, `docs/decisions/0011-behavioural-baselines-in-core.md`, accepted |
| migration `110` | 4.2 — `110_stream_inputs.sql` (Kafka customer topics, TAXII collections) | claimed |
| migration `111` | 4.3 — `114_lake_query_jobs.sql` (cold-query cost estimate and progress state) | claimed |
| migration `112` | 4.5 — `115_scheduler_leases.sql` (connector-scheduler leader election) | claimed |
| ADR `0011` | 4.4 — partitioning fusion by entity rather than by alert | claimed |

Highest migration on `main` at claim time was `101_audit_immutable_nullify.sql`,
so `095`--`101` were taken by sibling lanes between the capture above and this
claim; re-read `services/api/migrations/` rather than trusting the capture row.

The same is true of this table: `104` was already written on two sibling
lanes' branches with no row here, which is how lanes collide. Phase 6's
numbers were picked after reading `services/api/migrations/` on `main` **and**
`git ls-tree` over every `origin/*` branch, not from the row above.

Phase 9 re-read `services/api/migrations/` on 2026-10-11 before claiming:
`101_audit_immutable_nullify.sql` was still the highest on `main`, and `102`
and `103` were already spoken for in the table above, so Phase 9 takes `104`
through `109`, one per item. A number left unused at the end of the phase is
released by striking its row rather than by silently leaving a gap.

Item 8.1 re-read `services/api/migrations/` on 2026-10-11 before claiming:
`105_semantic_memory.sql` was the highest on `main`, and `102`--`109` were
already spoken for above, so 8.1 takes `110`--`112` and ADR `0011`. The three
sub-items that need no schema — the containerised-IdP CI leg,
internationalisation and accessibility — claim no number. The same release
rule applies: an unused number is struck, not silently skipped.

**Phase 6 moved `105`/`106` to `110`/`111` on 2026-10-11**, because Phase 9's
claim for `104`--`109` reached this table on `main` first and a claim table
nobody defers to is not a coordination mechanism. The lesson is the one this
section already states and that three lanes still fell to: the table is
authoritative only for lanes that write to it **before** the file, and four
branches now carry a `104` or a `105` that was never claimed here. Reading
`main` is not enough; read `git ls-tree` over every `origin/*` branch as
well, which is what found this.
Phase 7 claimed `104` and `105` on the same day and **lost the race**: Phase 9
merged to `main` first, so Phase 7 renumbered to `110` and `111` rather than
leaving two files with one number each. Both lanes re-read the directory
before claiming and both read `101`, which is the shape a claim table cannot
prevent on its own — the table is the tiebreak, and whoever lands second
moves. Recorded because the next lane will hit it too: re-read
`DEPTH_PROGRESS.md` on `origin/main`, not only the migrations directory, and
expect to renumber if a sibling merged between the claim and the pull
request.
Phase 3 re-read `services/api/migrations/` on 2026-10-11 before claiming:
`101_audit_immutable_nullify.sql` was still the highest on `main` and `102`
through `109` were already spoken for above, so Phase 3 takes `110` for the
3.4 baseline store and `111` for the 3.7 coverage store. ADR `0011` is the
next free number in `docs/decisions/` after 2.7 landed `0010`.
Phase 4 (items 4.2--4.5) re-read the directory on 2026-10-11 immediately
before claiming: `101_audit_immutable_nullify.sql` is still the highest file
on `main`, `102`--`109` are spoken for above, so this lane takes `110`--`112`
and ADR `0011`. The numbers are claimed before any file is written, because
two lanes recently picked `102`/`103` within minutes of each other and one
had to renumber. Unused numbers are struck at the end of the phase.

## Carried to the wave-2 depth plan, 2026-11-01

This plan's open items were handed over to
`plans/aisoc_depth_wave2.plan.md` at its kickoff and are tracked in
`DEPTH2_PROGRESS.md` from that date. They are deliberately **not** ticked
here: a tick in both files is a double count, and the wave-2 plan's Phase 10
closes this plan's Phase 10 as well.

Carried: 0.3's `make up-full` baseline (recorded below as D2 — now captured,
see `DEPTH2_PROGRESS.md` 0.3), 2.6, 3.6, 3.7, the 4.4 cloud-hardware run,
the 4.5 managed-cluster run, 5.5, 5.6, 6.3 to 6.6, 8.1's sub-items 4.5 and
4.6, the 9.4 Teams half, the 9.6 remainder, and Phase 10. The hand-over
table in `DEPTH2_PROGRESS.md` names the wave-2 phase each one became.

## Phase 0: Kickoff

- [x] **0.1** `DEPTH_PROGRESS.md` exists (this file), modelled on
  `PARITY_PROGRESS.md`.
- [x] **0.2** Every figure re-derived against the base commit. See below.
- [~] **0.3** Baselines captured. Four of five recorded; `make up-full` and the
  hosted-model matrix are noted under Deviations. **`make up-full` was
  captured on 2026-11-01 under the wave-2 plan's Phase 0.3** — 22 containers
  on the `full` profile, recorded in `docs/audit/depth2-baseline/README.md`.
  This item stays `[~]` here and is closed in `DEPTH2_PROGRESS.md`.

### 0.2 Re-derived figures

Measured on `1b8bc2d4`, 2026-10-07, each by the generator or gate the plan
names. Where the captured and measured values differ, **the measured value is
the one later phases are graded against**.

| Figure | Captured in plan | Measured | Note |
|---|---|---|---|
| Executable detections | 2,603 | **2,603** | `generate_corpus_stats.py --check` |
| On disk | 6,991 | **6,991** | same |
| Quarantined | — | **4,388** | same |
| Unreachable native rules | 119 | **119** | `check_detection_fields.py`; `MAX_UNREACHABLE = 119` |
| … needing a windowed evaluator | 74 | **74** | the family Phase 3.1 translates |
| … identity enrichment | 24 | **24** | Phase 3.3 |
| … fields nothing emits | 8 | **8** | Phase 3.3 |
| … first-seen / age | 8 | **8** | Phase 3.3 |
| … other | 6 | **6** | |
| … behavioural baseline | 2 | **2** | Phase 3.4 |
| Windowed rules | 18 | **18** | `services/fusion/app/data/windowed_ruleset.json` |
| Executor arms | 73 | **74** | classes declaring `capability = "…"` under `services/actions/app/live_actions/`. **33 distinct capability verbs.** Phase 5.5 counts arms, so its target is measured from 74 |
| Claim-to-gate matrix | 290 rows, all GATED | **290 rows, 290 GATED, 0 PARTIAL, 0 NO GATE** | `check_claim_gate_matrix.py` |
| CORE / full services | 16 / 22 | **16 / 22** | `check_profile_service_counts.py` (production stack: 16 / 21) |
| Next migration | 095 | **095** | highest is `094_user_delete_fk.sql` |
| Next ADR | 0010 | **0010** | in `docs/decisions/`, highest `0009` |

**Cloud, identity, SaaS and code executable rules: captured 461, measured
395.** The gap is a definition the plan does not pin, not a change in the
tree, so it is recorded here rather than reconciled silently. Measured by
`log_source` on executable entries in `marketplace/index.json`, grouping:

| Group | Count | `log_source` values counted |
|---|---|---|
| cloud | 225 | aws 76, azure 50, gcp 40, kubernetes 36, docker 10, cloud 8, multi-cloud 5 |
| identity | 123 | identity 47, okta 35, active-directory 22, auth0 5, duo 5, ping 5, keycloak 4 |
| saas | 34 | google-workspace 8, m365 7, slack 6, email 3, salesforce 3, + 7 others |
| code | 13 | github 12, gitlab 1 |
| **total** | **395** | |

Phase 3.6 must therefore raise **395 → 800** and ship the `make stats` line
with a `--check` gate that fixes this grouping in code, so the figure stops
being re-derivable two ways.

**Two measurement caveats found while re-deriving, both worth carrying:**

1. **1,724 of the 2,603 executable rules live under
   `detections/sigma-imports/_quarantine/`.** "Executable" and "quarantined"
   overlap, because the Sigma compiler began translating rules in place
   without moving them. Any later statement of the form "N executable rules"
   must not be read as "N rules outside quarantine".
2. **The plan's "1,798 of 2,603 are Windows (69%)" does not reproduce from
   the index.** Only 111 executable entries carry `log_source: windows`, and
   218 are Windows by path or log source (8%). The 1,770 Sigma imports carry
   **no `log_source` at all**, which is where the difference lives: the
   captured figure counted the Sigma corpus as Windows, which is
   approximately but not exactly true. Phase 3.6's gate should classify by a
   field that exists rather than by corpus membership.

### 0.3 Baseline artefacts

Hardware: Apple M5 Max, 18 cores, 128 GiB host; Docker 29.5.2 in a 6-CPU /
15.6 GiB Linux VM. Date 2026-10-07. Commit `1b8bc2d4`.

| Baseline | Result | Artefact |
|---|---|---|
| `make up` (CORE) | **PASS** -- 16 services healthy, administrator created | — |
| `make smoke` | **PASS 10/10 stages** -- event traversed ingest → Kafka → fusion → alert, severity and source attribution survived | — |
| Behavioural injection suite | **19 passed.** Overall flip rate **0.2593**, unsafe-action rate **0.037** over 27 cases | `services/agents/tests/eval_data/behavioural_injection.json` |
| Live-agent model matrix | **0 of 2 models measured** -- "no live LLM key configured", reported as *not measured* rather than zeros | — |
| Load harness, 20,000 events | **pipeline 130.3 alerts/s**, ingest accepted 397.6 events/s, p50 **54.9 s**, p95 **100.2 s**, p99 103.9 s, delivery ratio **1.0**, duplicates **0**, dead letters **0** | `docs/perf/results/2026-10-07-compose-depth-baseline.json` |

Per-family injection flip rates at baseline, from the artefact above:

| Family | Cases | Flip rate | Guard catch rate |
|---|---|---|---|
| command_line | 4 | 0.25 | 0.75 |
| email_subject | 3 | 0.3333 | 0.6667 |
| fake_analyst_note | 2 | 0.0 | 1.0 |
| **fake_tool_output** | — | **1.0** | **0.0** |
| file_path, process_name, url, username | — | 0.0 | — |
| persona | — | 0.67 | — |

`fake_tool_output` at 1.0 flip / 0.0 catch is the figure Phase 1.3 must bring
to **at or below 0.10 on tuned *and* held-out payloads**.

The load-harness row is the "before" for Phase 4.4, whose target is a
sustained 5,000 events/s at p95 under 2 s on documented cloud hardware. The
measured p95 of 100 s is a *drain* latency under a 20,000-event burst on a
6-CPU laptop VM, not a steady-state figure, and must be labelled that way
wherever it is quoted.

## Deviations

Recorded as they happen. A deviation is not a failure; an unrecorded one is.

### D1 -- The load harness could not run from a clean checkout (fixed here)

`scripts/perf/load_harness.py` invoked `go run ./services/demo-producer` with
`cwd=` the repository root. There is no `go.mod` at the root -- the producer
is its own module at `services/demo-producer/go.mod` -- so the subprocess
failed before starting:

```
producer failed (1): go: go.mod file not found in current directory or any
parent directory; see 'go help modules'
```

The harness has therefore never produced a run on the path it documents; the
published laptop figures must have come from a prebuilt `--producer-bin`,
which needs no module context. Fixed in the Phase 0 commit by running `go run
.` from the producer's own directory, which is what produced the baseline
above. Phase 4.4 extends this harness and inherits the fix.

### D2 -- `make up-full` not captured on this host

Deferred rather than claimed. The `full` profile is 22 services at ~12 GiB
against a 15.6 GiB VM that is already running the 16 CORE services, and a
baseline taken under memory pressure would describe the host rather than the
stack. Recorded as unmeasured; Phase 4.5 (`helm install` brings up all of
CORE) and Phase 3.4 (baselines in CORE) are the items that need it, and both
will re-take it on a sized host.

### D3 -- Hosted model rows are maintainer-blocked (M2)

`scripts/run_model_matrix.py` reports **0 of 2 models measured** with "no live
LLM key configured". This is the gate behaving correctly: it refuses to
publish `0.000` where it means "not measured". Phase 1.4 has since measured
two local candidates, which need no key: see the verdict-quality table on the
benchmark page and the 1.4 note below. The hosted rows stay `[!]` until the
maintainer funds a key, and still read "not measured" rather than zero.

### D4 -- Not all 74 "windowed" rules need a window

The reachability gate attributes a rule to the windowed family by matching
its field names against `_count$|^count_|_per_|time_window|_window_|_5min|_ratio$`.
Eight of the 74 are per-event properties the pattern misreads: `row_count` is
the size of one export record, `answer_count` the number of records in one DNS
response, `insecure_registries_count` the length of a list in one daemon
config event, `subdomain_hex_ratio` a property of one query name, and
`active_keys_per_account` the state of an account at one moment. They are
refused under the `not-windowed` kind rather than translated, and the family
label in `check_detection_fields.py` is left as it is: changing the classifier
would move the published family counts that Phase 0.2 recorded, for no gain
now that each rule carries an individual reason.

### D5 -- Five windowed rules that predate this work group by a field nothing emits

`wd-secret-enumeration` (`distinct_by=secret_name`), `wd-windows-password-spray`,
`wd-sysmon-remote-thread-fanout`, `wd-sysmon-dns-query-fanout` and
`wd-sysmon-process-spawn-burst` name entity fields outside the statically
recovered namespace. Four of the five are Windows `EventData` keys the
`windows_event` connector lifts wholesale, so the namespace under-approximates
and the rules are probably fine; `secret_name` has no such explanation. The
new gate **reports** these rather than failing on them, because failing would
be a false alarm about working rules, and the entity question is answered by
replay rather than by a name lookup. Not fixed here: changing a shipped
rule's `group_by` is a content decision with its own blast radius.

### D6 -- The windowed engine ran a narrower field namespace than the stateless one

`WindowedDetectionEngine._fields` carried a docstring saying it matched the
stateless engine's namespace "exactly". It did not: the stateless engine then
applies `derived_fields.enrich()` and the per-tenant allowlist overlay, and
the windowed engine applied neither. Two of the rules translated here carry an
`<x>_in_allowlist` clause, so without fixing this they would have moved from
one engine that could not fire them to another. Both passes are now applied in
`evaluate()`, which takes the overlay the consumer had already resolved for
the stateless engine.

### D7 -- There is no "existing watermark" in fusion to order sequences by

Item 3.2 says to order sequences "by event time with the existing
watermark". No watermark exists anywhere in the detection path: the only two
in the tree belong to `services/actions`' shadow-reconcile router and the
dead-letter replay, which are unrelated subsystems. Rather than invent one or
quietly order by arrival, the engine orders strictly by event time and
declares its own bound,
`SEQUENCE_REORDER_TOLERANCE_SECONDS = 300`, for how late an event may arrive
and still be stitched into a sequence. The bound is stated in the module
rather than inherited from something that does not exist.

Ordering by arrival would have been the easy implementation and is wrong
here: almost every connector in this tree **polls**, so a batch arrives in
the vendor's order and the event that starts a sequence routinely lands after
the one that finishes it. `test_a_batch_delivered_out_of_arrival_order_still_fires`
is the regression test for that, and reverting the event-time read makes it
and two others fail.

### D11 -- Semantic recall measured *worse* than the full-text baseline on every embedding backend reachable from here

Parity 6.5 asks for the accuracy delta. It is measured, by
`scripts/score_memory_recall.py` over 12 hand-authored probes against a
12-item corpus, and the delta is negative:

| metric | lexical | semantic (`qwen2.5:0.5b`) | delta |
|---|---|---|---|
| recall@1 | 0.667 | 0.333 | **-0.333** |
| recall@3 | 0.750 | 0.417 | **-0.333** |
| recall@5 | 0.750 | 0.667 | -0.083 |
| MRR | 0.708 | 0.465 | **-0.243** |

The honest reading is not "semantic recall does not work". It is that
**no embedding model is reachable from this project without a funded key**.
The two models served locally are *generative* models used as embedders,
which is a known-poor substitute; `nomic-embed-text` was attempted and the
pull did not complete in ten minutes. Hosted embedding rows are blocked by
the same thing as D3 (maintainer item M2).

Three things follow, and all three are in the tree rather than in this note:

1. **The default did not move.** `POST /kb/query` stays full-text; semantic
   recall is `recall_memory: false` and strictly additive, so a caller that
   does not ask for it gets byte-identical behaviour. Putting a measurably
   worse retriever in front of the ranker would have made analyst search
   worse on exactly the deployments that cannot pay for an embedding model.
   The field's docstring carries the number and says to move the default when
   the measurement does.
2. **The measurement found a real defect in the first implementation.** The
   3,072-dimension model initially scored 0.167 at recall@1 — and that was
   measuring `_fit()` *truncating* the vector to the collection's 1,536, not
   measuring the model. Padding a short vector is harmless under cosine;
   truncating a long one discards most of what the model said. Truncation is
   now refused with a message naming both dimensions, which is a
   configuration an operator can fix rather than a silently worse retriever
   they cannot see.
3. **What is still not measured, stated plainly:** the downstream effect of
   memory recall on *verdict* quality, which is what the Phase 1 scorecard
   grades. That needs an agent run per corpus item against a model worth
   grading, and no such model is funded or locally servable here. The
   retrieval delta above is the part that can be measured honestly today,
   and it is the part that is actually about what 9.2 builds.

### D12 -- Migration `112` was claimed here and taken by another lane first

The claim table above reserved `110`--`112` for 8.1 after re-reading
`services/api/migrations/` against `main`, which is the documented procedure
and was not enough. Sequentially-numbered migrations are a **first-come
namespace across branches, not across `main`**: by the time 8.1 came to write
its third file, `115_scheduler_leases.sql` existed on another lane's pushed
branch. `110` and `111` had three and three other claimants respectively and
survived only because this item pushed first.

Re-derived immediately before committing by scanning the migration directory
of **all 259 remote branches**, not just `main`, which put the first free
number at `113`. The `112` row is struck rather than silently reused, per the
release rule at the top of that table.

The general lesson is that "re-read `main` before claiming" understates the
problem. `main` is the one place a number cannot yet be taken.

### D13 -- Two honest gates disagreed about the claim matrix, and the older one was wrong

`scripts/check_claim_gate_matrix.py` read the matrix as 300 GATED / 2 PARTIAL
while `readme_gates._matrix_counts` read 299 / 3, so the summary block was
reported as stale against a table that was correct.

`readme_gates` classified a row by scanning the **whole line** for `NO GATE`,
then `PARTIAL`, then `GATED`. A row's Notes cell is prose, so the first GATED
row to record *why* it had been PARTIAL -- which is exactly what a row should
say when a gate is built and the status earned -- counted as PARTIAL.

The cheap fix was to reword the row and lose the history. It now reads the
cell the column header names, refuses a table whose Status column cannot be
located rather than counting it as empty, and both properties are pinned by
tests that fail against the previous parser.

### D14 -- 4.6 is not started, and 4.5 is half done. Neither is claimed

Stated plainly rather than folded into a tick.

**4.6 internationalisation** (gap-closure 13.4) is **not started**. It asks
for a Next.js i18n library, externalised strings on five surfaces, a locale
switcher, RTL, locale-aware dates and numbers, a pilot locale and a CI gate
for missing and unused keys. Nothing of it exists: there is no `i18n`
directory, no message catalogue and no i18n dependency in `apps/web`. It is
the one sub-item of 8.1 with no code behind it, and the honest record is a
`[ ]`, not a partial credit for the parts that are easy.

**4.5** asks for two things. The opt-in limit enforcement the depth plan
names by file is built, wired to two routes and gated (#1332). The **six
console pages** -- branding, SCIM tokens, retention, organisation members and
grants, rule packs, delegations -- are not. Its claim row says so in the row
itself rather than relying on this note, because a reader of the matrix does
not read this file.

Neither is blocking 8.1's stated "Done when": a CI test signs in through OIDC
and SAML with MFA enforced for the role, an elevation expires on schedule
(8.2, merged), and the security pack passes the competitor-name and
comment-path gates. All three hold. The item is `[~]` rather than `[x]`
because the spec lists more than its own done-when.

### D8 -- No upstream Sigma correlation rule exists in this tree to import

`detections/sigma-imports/` holds 3,132 rule documents and **not one carries
a `correlation:` block**, so the missing importer and the missing corpus hid
each other: there was nothing for an importer to have failed on. There is
also no fetcher for the upstream corpus (`scripts/` has `compile_sigma_ruleset.py`,
`sigma_compiler.py` and `sigma_proof_event.py`, none of which downloads
anything).

So the importer is built and exercised against **first-party** correlation
documents hand-authored in the upstream format under
`detections/sigma-correlations/`, four accepted and two refused. The figure
they contribute is first-party content and is labelled that way in the truth
table and in the corpus README; it is not imported coverage. Vendoring the
upstream correlation corpus needs a fetcher and a licence review, and is not
attempted here.

One standard is weaker here than for the stateless Sigma imports, and stays
weaker: those are replayed through the real connector `normalize()` by an
out-of-process worker, and these are replayed through the real **windowed
engine** only. The connector step is not applied, because importing
`services/connectors` into a fusion test process shadows fusion's own `app`
package — the documented reason `compile_sigma_ruleset.py` uses a subprocess.
Instead, every selector field, `group-by` and `distinct_by` is checked
against the emitted-field namespace with **no ceiling**, which caught three
invented fields on the first run of the gate.

### D15 -- A durable `wait` suspended the run and then carried on

Found while building 5.4 on 5.3's pause, and fixed here because 5.4 inherits
it. `_control_wait` writes a pause row and returns `StepStatus.PENDING` with
`paused: True`, and the run loop broke out only for `StepType.APPROVAL` --
so a `wait` long enough to become durable, or any `wait` with
`until: callback`, wrote its row and then ran every step after it. When the
callback or the sweeper later resumed from `step_index + 1`, those steps ran
a **second** time.

Nothing caught it because the two tests that exercise the durable path assert
on the pause row and on the resume, not on what the first half of the run did
afterwards -- and the shipped packs contain no `wait`, so no replay exercised
it either. The run loop now stops on any step that returns PENDING with a
`pause_id`, keyed on the result rather than on the step type, because the same
control step both sleeps in process (no pause) and suspends (a pause) and the
type cannot tell those apart.

Negative control: reverting that break fails
`test_a_durable_pause_stops_the_run` plus two others, recorded in the pull
request.

### D16 -- The manager comes from SCIM only, and the lookup is three sources deep

The plan says "from SCIM or IdP data". Implemented as the step's own
`manager` parameter, then the run context (where identity enrichment puts one
when the alert carried it), then `aisoc_scim_users.manager_ref` -- the
enterprise extension's `manager.value`, which the column was missing
entirely, so every sync delivered the attribute and every sync dropped it.

**A live per-request lookup against Entra or Okta is not implemented**, and
is named here rather than left to be inferred: it needs a vendor credential
in the agents service, which today holds none, and the escalation runs on a
sweeper with no tenant session. A tenant that provisions through SCIM has the
data; a tenant that does not will see `no_manager` and the run resumes with
that outcome rather than hanging.

`context_import.py` writes a `manager_id` edge into Neo4j, which would be a
fourth source. Not used: the agents service has an asyncpg pool and no Neo4j
driver, and adding one for an escalation is a dependency the item does not
justify.
### D17 -- The plan says `valid_to`; this schema says `valid_until`

Item 2.5 asks for versioned snapshots with `valid_from` / `valid_to`. The one
existing table in this database that bounds a fact in time is `identity_edges`
(migration 018), and it spells the closing column `valid_until`. Adopting the
plan's spelling would put two names for one concept in one schema, and the
next person to write a point-in-time query would have to know which table
they were in before they could write a `WHERE`. The existing spelling wins;
`posture_snapshots` uses `valid_from` / `valid_until`, and the deviation is
recorded here rather than made silently.

### D18 -- Eleven API tests are already failing on `main`, and nothing grades them

The full `services/api` suite run for 2.5 reported 4,774 passed and 11 failed.
All eleven are in `test_alert_list_priority_sort.py` and
`test_alert_tiles_cover_the_whole_result_set.py`, neither of which this branch
touches, and all eleven fail identically on a clean `git archive origin/main`
export with the same error: `list_alerts() missing 1 required positional
argument: 'http_request'`. The handler grew a `Request` parameter; the two
test files call it directly and were not updated.

What makes this worth a deviation rather than a footnote is why it is still
open on a branch-protected `main` with twenty-eight required checks. Both
files open with "Run against live Postgres: the defect is an `ORDER BY`, and a
fake session that answers any query cannot tell one ordering from another" --
and their fixture skips when no database answers. The only job that runs them
is `Python — Tests`, which sets `DATABASE_URL` to a host with no Postgres
behind it, so the fixture skips and the job is green. Neither file is named by
any workflow in `.github/workflows/`, so no live-Postgres job runs them
either. The suite that exists to prove the priority ordering has therefore
never graded it, and the signature break has been invisible since it landed.

Fixing them belongs to item 2.6, which wires the priority score and the queue
ordering these very tests cover; the fix lands there together with a workflow
that actually runs them against a database, because repairing the assertions
without that would restore a test nothing executes.
### D9 -- Five of the 45 "unreachable" rules were never unreachable

`scripts/check_detection_fields.py` carries its own copy of the matcher's
operator suffixes, under a comment saying it mirrors
`detection_matcher.OPERATORS`. It did not. `neq` had been added to the
matcher and not to the gate, so `approver_role_neq: "codeowner"` — which the
engine reads correctly as `approver_role` with `!=` — was reported as a rule
naming a field called `approver_role_neq`. Five rules were counted against
the ratchet for a defect that had already been fixed.

The same comparison in the other direction found a worse one: the gate
listed `not_startswith_any` and `not_endswith`, which the **matcher** did not
implement. Three shipped rules use `path_not_startswith_any`, so the matcher
read the whole string as a field name and all three could never fire — while
the gate, stripping a suffix nothing implemented, reported them reachable.
Both operators are now implemented in the vendored matcher and the canonical
one, the fixture synthesiser knows them, and
`test_the_gate_and_the_matcher_agree_on_every_operator` compares the two
lists in both directions.

### D10 -- 18 rules are retired rather than fixed, and why each one is

The plan says of one family: "build them where cheap, otherwise quarantine
with a reason". Applied to all three families, that leaves 18 rules that need
work belonging to another item, recorded individually in
`scripts/enrichment_decisions.py`:

| kind | n | needs |
|---|---|---|
| `needs-connector-field` | 9 | a field the vendor has and no connector surfaces — depth plan 2.2 |
| `needs-external-source` | 6 | a registry, a credential report or a factor record — 2.5 and beyond |
| `needs-inventory` | 3 | an inventory this platform does not hold (DC machine accounts, privileged OAuth scopes) |

`scripts/check_enrichment_decisions.py` is what stops this being a way to
move the ratchet: it fails if a retired rule's fields are all resolvable.
Proved by retiring a working rule and watching it fail.

The line that mattered most was refusing a plausible substitute.
`domain_age_days` wants a domain's registration age from a registry; the
first-seen store could have answered "when this deployment first saw it" and
the number would have looked right in a diff. It would also have fired the
rule on most of the internet. Five such age-of-a-thing fields are named in a
test that forbids the first-seen store from ever growing them.

### D19 -- Identity privilege reads a table a tenant must populate

The `*_priv` booleans resolve from `identity_nodes.privilege_tier >= 2`, the
column migration 018 created for the question. The table's only writer is
`POST /api/v1/identity-graph/nodes`, so a tenant that has imported no
directory gets **no key at all** and those 18 rules stay silent — they are
reachable "when the tenant has identity data", the same standard this gate
already applies to a vendor-payload field. That is weaker than "reachable on
any deployment" and is stated rather than glossed. Depth plan 2.5's posture
collectors are what will populate it automatically.

Four booleans in the same family are deliberately **not** computed —
`scope_priv`, `act_as_user_priv`, `gpo_link_priv` and `account_is_dc` — and
are among the 18 above. Each has no subject field any source emits, and
guessing a subject would produce a boolean that is confidently wrong rather
than absent.

### D20 -- The "behavioural baseline" family named the wrong piece of work

`check_detection_fields.py` classified an unreachable field into a family so
the headline number would be actionable. Its behavioural pattern was
`_baseline|_deviation|^active_|_is_first_`, and `^active_` is not a
behavioural shape at all. It matched the only two rules left on the ratchet:

| rule | field | what it actually needs |
|---|---|---|
| `det-endpoint-146` | `active_state` | a systemd unit state from a host agent |
| `det-identity-015` | `active_p0_or_p1_incident` | the tenant's ITSM incident queue |

So the gate reported "2 rules need depth plan 3.4" when the true answer was
**zero**, and building 3.4 exactly as specified would not have moved the
number by one. A gate pointing at the wrong piece of work is worse than one
pointing at none, because the named thing gets built and the next reader
concludes the fix failed.

The pattern now matches the shape `baselines.py` actually produces
(`^baseline_|_baseline$|_deviation$`), and a new `external system context`
family carries the ITSM rule. `MAX_UNREACHABLE` stays at **2** — this is a
reclassification and not a fix, and lowering a ceiling on the strength of
relabelling is the move this file exists to refuse.

Two consequences worth stating. The behavioural family is now genuinely
empty, so 3.4 closes no unreachable rule and is not credited with any; it
earns its place by making 3.5's rules possible, which is a different claim.
And D9's lesson repeated one level up: a gate that keeps its own description
of another component drifts from it, and here the drift was in the
classifier rather than in the operator list.

### D21 -- D9, D10 and D19 were written, merged, and lost on `main`

PR #1226 (depth 3.3) added three deviation sections. None of them is on
`main`. The item log still cites "(gate operator drift, D9)" and "18 retired
with a reason (D10)", so the tracker has spent two days pointing at
explanations a reader could not find, and the same merge truncated 3.2's
checklist paragraph mid-sentence and left a stale unchecked duplicate
beneath it.

Nothing was wrong with the branch; the loss happened in a conflict
resolution that took `main`'s side of this file wholesale. That is the
documented failure mode for a file several lanes write to at once, and the
documented remedy — keep both sides' paragraphs, never take one side whole —
is the one that would have prevented it.

All three are restored here verbatim from the merge commit rather than
rewritten from memory. At restoration the trio kept its numbers; the 2026-10-12
merge train renumbered them D19/D20/D22 because parallel lanes had taken D11-D14 on `main` first.

### D22 -- A rule of this lane's own was a bare anomaly, and its own gate caught it

Depth plan 3.5 is explicit that an anomaly is *"a typed signal, not an alert
on its own"*. `ta-saas-oauth-app-volume-spike` was written with
`baseline_oauth_app_volume_z_gte` as its entire clause -- an alert on an
anomaly, which is the one thing the item says not to build. It passed
`generate_detections --check`, the truth table, the reachability gate and
the generic fixture replay, because every one of those asks whether a rule
is well-formed and can fire, and it was and it could.

What caught it was the family's own gate asserting that each rule reads a
threat condition *as well as* a baseline. The rule now also requires
`event_type: oauth_token_event`.

The reusable half is that the generic gates could not have caught it. A
corpus-wide gate checks the properties every rule shares; a property that
belongs to one family has to be asserted by that family, and writing that
assertion is part of adding the family rather than a later tidy-up.

## Phase 1: Verdict quality you can publish

- [x] **1.1** Balanced, labelled verdict corpus
- [x] **1.2** Scorecard: balanced accuracy, MCC, per-class precision/recall,
  Wilson interval, false negatives, auto-close precision, escalation rate,
  time to verdict
- [x] **1.3** Close `fake_tool_output` structurally (≤ 0.10 tuned and held-out)
- [x] **1.4** A 7--8B local model in the matrix, chosen by score
- [x] **1.5** `make replay-eval` design-partner kit
- [x] **1.6** Published "Verdict quality" table with a `--check` drift gate

### 1.4 -- five local models measured; the winner is generation, not size

All five graded the same corpus digest through the production triage path,
72 model calls each, zero provider errors.

| Model | Balanced acc. | MCC | Malicious recall | Malicious prec. | ECE | Auto-close prec. |
|---|---|---|---|---|---|---|
| `llama3.1:8b-instruct-q4_K_M` | **0.357** | **0.209** | 0.583 / 36 | **0.724** | **0.349** | 0.111 (9) |
| `llama3.2:3b-instruct-q4_K_M` (CPU default) | 0.285 | 0.047 | 0.250 / 36 | 0.500 | 0.442 | 0.571 (7) |
| `llama3:8b` | 0.279 | 0.113 | **0.639** / 36 | 0.657 | 0.421 | 0.091 (11) |
| `qwen2.5:7b-instruct-q4_K_M` | 0.260 | 0.032 | 0.083 / 36 | 0.750 | 0.594 | 0.243 (37) |
| `mistral:7b-instruct-v0.3-q4_K_M` | 0.210 | 0.202 | **0.639** / 36 | 0.657 | 0.366 | 0.143 (14) |

Four classes: a constant answer scores **0.250** balanced accuracy, and
always guessing the majority class scores **0.500** plain accuracy.

**Decision, strictly by balanced accuracy:** `llama3.1:8b-instruct-q4_K_M`
becomes the default on `docker-compose.gpu.yml` and
`docker-compose.host-llm.yml`. It also leads on MCC, malicious precision and
calibration, and is the only row with ECE below 0.40. The 3B stays the
default for CPU `make up`, where a ~5 GB model does not fit the 8 GB CORE
budget -- a deployment constraint, not a score.

**Size is the wrong unit.** The previous-generation `llama3:8b` scores
*below* the 3B it would replace, so "upgrade to an 8B" is not advice that
survives measurement. An earlier revision of this file recorded exactly that
conclusion from `llama3:8b` alone and was wrong; the LiteLLM config's hint
now carries all five numbers instead.

**Two findings outrank the ranking.** Every model measured is far closer to
chance than to useful -- the best is 0.357 against a 0.250 floor, and three
of five fall below the 0.500 plain accuracy of guessing the majority class.
And auto-close precision is poor across the board (0.091-0.571 on 7-37
candidates), so **nothing measured here supports autonomous closure**. That
is a finding about the auto-close gate, not about which model to pick.

Caveats published rather than smoothed over:

- **Latency is excluded from the comparison.** The 3B ran CPU-bound inside
  the stack container and the four 7--8B rows GPU-accelerated on the host,
  so the figures measure different machines. All are still printed.
- **Per-decision model attribution is unverified.** Every call was placed
  and answered -- each decision carries reasoning specific to its alert --
  but `resolved_models` came back empty on every run, so the scorecard shows
  that 72 calls happened and not which model served each.
- **Auto-close precision rests on 7 to 37 candidates.** Small denominators;
  read the column as a warning sign, not a ranking.

**Writing the winner into the GPU overlay broke the GPU overlay, and CI
caught it.** Adding the model default left the
`deploy.resources.reservations.devices` block nested under `litellm`
instead of `ollama`. The file still parsed, `docker compose config` still
resolved, and `make up-gpu` would still have come up -- with the card
reserved by a proxy that runs no inference while generation fell back to
the CPU. There is no error anywhere in that sequence, which is why the
existing `test_it_touches_only_ollama` was the only thing between it and a
release.

Its companion assertion failed for a legitimate reason at the same time:
the overlay now *must* touch three services, since the measured default
needs a pull instruction on `ollama-pull` and routing on `litellm`. The
assertion was re-expressed rather than relaxed, and two properties added --
a device reserved on any service but `ollama` fails, and the model pulled
must be the model routed to. That second one guards the quiet failure: the
gateway 404s on a model nothing pulled, triage swallows it into the
deterministic fallback, and the stack looks healthy while measuring no
model at all. Each was proven by injecting the defect it names.

### 1.5 -- run end to end against a live stack, not a mock

`make replay-eval` / `make replay-eval-verify` drove a real run through the
API against a mocked Splunk ES holding 200 recorded closed notables: 200
read, 60 replayed in the test window, 240 production writes intercepted, a
signed bundle written and verified, and a wrong key refused with exit 1.

The live run is what found the three defects the unit tests could not: the
decisions route answers a bare array and the kit assumed an envelope; a
machine named only in the agent's reasoning survived redaction; and the
prose and identifier passes named their counter namespace in different
cases, so one host could take two tokens. All three are fixed with
regression tests, each proven to fail against the pre-fix tree.

Known gap: the run abstained on all 60 decisions because the stack's triage
reached no model, so the kit has been exercised on a deterministic run end
to end but **not yet on a run with real model verdicts in it**.

### 1.6 -- the section it replaced was wrong, not merely stale

`apps/docs/docs/benchmark.md` said verdict accuracy was not measured here
and could not be. Item 1.1's corpus made that false. The reasoning is kept
(it is why `score_replay_set.py` still refuses this tree's two all-malicious
corpora) and the conclusion is replaced by the measurement.

`scripts/check_verdict_quality.py --check` is wired into `ci.yml` and fails
on drift between the committed scorecard and the published block, proven by
reverting a number and watching it red. It also refuses five scorecard
shapes that would each publish a score-shaped cell with no measurement
behind it -- the load-bearing one being a row claiming a live measurement
that placed zero model calls, which is precisely what a run against a dead
endpoint produces once triage falls through to its deterministic scorer.

## Phase 2: A semantic layer and live posture

- [x] **2.1** OCSF classes beyond five
- [x] **2.2** Activity projection on every event
- [x] **2.3** Event classification catalogue
- [x] **2.4** Sessions per principal — one producer in the activity
  projection, three consumers (Postgres, ClickHouse, Neo4j), held by
  `check_session_projection.py`
- [ ] **2.5** `__posture_snapshot__` collectors (AWS, Azure, GCP, Workspace, GitHub)
- [ ] **2.4** Sessions per principal
- [x] **2.5** `__posture_snapshot__` collectors (AWS, Azure, GCP, Workspace, GitHub)
- [ ] **2.6** Use the posture everywhere
- [x] **2.7** Entity context in CORE (ADR first) — ADR-0010 accepted;
  Postgres in CORE, Neo4j stays in `full`

## Phase 3: Detection depth for cloud, identity and SaaS

- [x] **3.1** Translate the 74 windowed `det-*` rules — 50 translated, 24
  refused with a reason. `MAX_UNREACHABLE` 119 → 45.
- [x] **3.2** Ordered sequences and Sigma correlations — the windowed engine
  stages ordered and unordered sequences (`SequenceRule` in
  `services/fusion/app/services/windowed_detection.py`, loaded by
  `load_sequence_rules` from the same artefact the counting rules use); all
  four translatable Sigma correlation types compile through
  `scripts/sigma_correlation.py`, held by `scripts/check_sigma_correlations.py`,
  with seven refusal reasons recorded rather than approximated. No upstream
  Sigma correlation rule exists in this tree to import (D8), so the corpus is
  first-party and labelled as such.
- [x] **3.3** Enrichment inputs (parity 5.5) — identity privilege (18 rules)
  resolved from the Phase 2.5 posture and SCIM attributes, and a per-tenant
  first-seen store keyed by principal and attribute
  (`services/fusion/app/services/first_seen.py`, Redis with a lake backstop)
  closing 2 more. 5 rules were never unreachable — the gate kept its own copy
  of the matcher's operator list and had drifted from it (D9) — and 18 were
  retired with a reason rather than given fields nothing emits (D10).
  `MAX_UNREACHABLE` 45 → 2, and the two that remain both need the 3.4
  baseline, so they are named rather than hidden. Two matcher operators that
  three shipped rules already used were implemented.
- [x] **3.4** Behavioural baselines in CORE — the scoring core moved into
  fusion as `services/fusion/app/services/baselines.py` rather than UEBA
  moving into CORE, measured and recorded in ADR-0011: the UEBA image is
  145.4 MB on disk with a 63.3 MiB import floor, against zero new
  containers and a measured 2,412 bytes of Redis per principal (200
  principals over 10,000 events, `used_memory` read before and after
  against a real Redis 7). All three families the plan names are there —
  per-principal rarity of actions, resources, client families and
  locations; peer-group deviation; volume per principal and per OAuth app —
  each a typed `AnomalySignal`, never an alert on its own. Wired into
  `DetectionEngine.evaluate_async` beside the 3.3 first-seen store, so a
  CORE install computes them with no `full` service running. 22 tests,
  one of which caught this work's own worst defect: the first draft
  resolved client-family rarity from three field names **no connector
  emits**, so that signal could never have been computed anywhere. Every
  subject chain is now held against the gate's own emitted-field
  namespace, proved by reinstating the broken chain. The
  reachability gate's "behavioural baseline" family was **narrowed**: it
  matched `^active_`, which swept in a systemd unit state and an ITSM
  lookup and reported both as blocked on a baseline that would never have
  helped either (D20). `MAX_UNREACHABLE` stays at 2, now with accurate
  reasons.
- [x] **3.5** Threat-and-anomaly condition rules — 24 in a new
  `threat-anomaly` category (`scripts/detection_specs_part4_threat_anomaly.py`),
  each pairing a threat condition with a 3.4 baseline score, across AWS 6,
  Okta 4, Workspace 3, Azure/Entra 2, GitHub 2, Kubernetes 2 and one each
  of M365, Slack, Salesforce, GitLab and generic identity. Executable
  2,511 → **2,535** (`generate_corpus_stats.py --check`), on disk 6,991 →
  7,015, counted as its own `make stats` line because the claim differs: a
  rule here also needs a warmed baseline, so a day-one install has the
  rule before it has the signal. **Every fixture is hand-authored** and
  every negative is the benign twin of its positive — the same threat
  action by a principal for whom it is routine — so the pair differs only
  in the clause the rule is about. `test_threat_anomaly_replay.py` (147
  assertions) drives the real `DetectionEngine` and holds four properties
  a synthesised fixture cannot: the twin moves a baseline field, no
  negative uses the `not-` sentinel, stripping the baseline from a
  positive silences the rule, and one rule fires **end to end in CORE on a
  baseline earned from replayed traffic** with no `full` service running —
  the phase's second "Done when", as an assertion. The decorative-clause
  control caught a rule of this lane's own that was a bare anomaly (D22).
- [ ] **3.6** 395 → at least 800 cloud, identity, SaaS and code conditions
- [ ] **3.7** Detection engineering agent (gap-closure Phase 9 / parity 6.2)

## Phase 4: Collection and scale

- [ ] **4.1** Cloud-native collection (S3+SQS org trail, Pub/Sub, Event Hubs)
- [x] **4.2** Standard inputs (syslog, OTLP, Kafka, TAXII 2.1). **All four
  bullets closed.** The syslog bullet landed earlier (its entry is below
  and is unchanged); the three that were open are done here.

  **OTLP logs.** `POST /v1/logs` in `services/ingest/internal/otlp`,
  reading `ExportLogsServiceRequest` in both encodings the specification
  defines and gzip bodies, because real collectors emit both and a
  receiver that reads one of them is a receiver half the estates cannot
  use. The path is not ours to choose: an exporter appends `/v1/logs` to
  its endpoint. The partial-success contract is implemented rather than
  skipped — a partly unprojectable batch answers 200 with
  `rejected_log_records`, and a publish failure answers 503 with
  `Retry-After`, because a blanket 200 tells the collector records it
  never delivered have landed and a 400 makes it discard them.

  **Kafka input.** `services/ingest/internal/kafkainput`, one source per
  tenant, the tenant from a minted token and from nothing in the record.
  The failure handling is the whole of it, and it is the shared
  `streamhealth` table rather than a second copy: a rebalance is
  transient and the loop continues, a `TopicAuthorizationFailed` stops it
  naming the operator action, and an undecodable record is poison —
  skipped *and* committed, because a poison record that is not committed
  is re-read forever. A publish failure is the one case that must not
  commit, Kafka being the only input here that can withhold an
  acknowledgement.

  **TAXII 2.1.** A real server at `/api/v1/taxii2/` over
  `threat_intel_iocs` (migration `110`), serving discovery, API root,
  collections, objects, manifest and `added_after` pagination. A
  collection is a filtered view, never a copy. The API root is a fixed
  string because a tenant in the path is a segment any caller can retype,
  on an endpoint whose purpose is to be pointed at by a third party.
  Writes are refused with a 403 that names the posture.

  **The refactor that came first**, because it decides whether the Kafka
  input is a second copy of a table or a second user of one: the
  permanent/transient/poison classifier, the stuck-after escalation and
  the kafka-go reader-error bridge were private to `graph_ws`. They moved
  to `services/ingest/internal/streamhealth`, parameterised by the two
  genuinely per-subsystem things — the published metric stem, which keeps
  its name, and the environment variables the advice tells an operator to
  edit. `graph_ws` keeps its API through aliases and its 555-line test
  passes unchanged.

  Gated by `scripts/check_standard_inputs.py` (self-test: nineteen
  injected violations, one per rule, plus a refusal on both an absent and
  an empty tree) wired into `ci.yml :: python-lint`, and by
  `taxii-live.yml` against real Postgres. **49 new Go tests** (27 OTLP,
  22 Kafka input), **37 Python projection tests**, **15 live TAXII
  tests**. Three claim rows added; the matrix reads 305 rows, 302 GATED.

  **Four defects found by writing this, recorded rather than quietly
  fixed.** A well-formed empty OTLP batch answered 400, because an
  `ExportLogsServiceRequest` with no fields set encodes to zero protobuf
  bytes and the body reader called that unreadable. The partial-success
  path had no reachable trigger, so the contract was a mechanism with no
  caller; a record carrying nothing of its own is now refused and
  counted. `otlp-logs` was absent from `ALLOWED_TEMPLATE_IDS`, so no
  operator could mint a token the receiver accepts — the receiver, its
  route, its template and its readiness entry were all correct and the
  feature was unusable. And the gate's own media-type rule matched the
  error message that names JSON rather than the case arm that accepts it,
  so a receiver that had stopped reading JSON entirely passed.

  **Three verification gaps, stated rather than implied.** No live
  OpenTelemetry Collector, no live Kafka broker and no third-party TAXII
  client has been exercised against any of this. The OTLP bodies are
  built with the vendor's own protobuf types, the Kafka loop is driven
  through a scripted reader so what is proven is the failure handling
  rather than kafka-go's wire protocol, and TAXII conformance is asserted
  against the specification's shapes rather than against a client's
  behaviour.

  **One thing found and left.**
  `GET /api/v1/threatintel/stix/taxii/collections` is a demo-gated stub
  returning a fixed sample list under the description "TAXII 2.1
  collections for server compatibility". Removing a published operation
  is a breaking OpenAPI change, so it stays; its docstring now says
  plainly that it is not the server, and so does the new page.
- [~] **4.2 (historical)** The syslog bullet, closed earlier. `services/ingest`
  accepts UDP and TCP and reads RFC 5424, RFC 3164, CEF and LEEF, with the
  tenant taken from a minted token because syslog carries nothing a sender
  does not control. Gated by `scripts/check_syslog_listener.py` (self-test:
  one injected violation per rule, including each of the three Go syntaxes
  a tenant could leak through) wired into `ci.yml :: python-lint`. 33 new
  Go tests. At the time this was written three bullets were open and were
  named here rather than left to be inferred: an OTLP logs receiver, a
  Kafka input for customer topics, and a TAXII 2.1 server over the tenant
  IOC store. All three are now closed; see the `[x]` entry above. This
  paragraph is kept as the record of what the syslog bullet alone
  covered, not as a live statement of what is missing.
- [x] **4.1** Cloud-native collection (S3+SQS org trail, Pub/Sub, Event Hubs).
  Three connectors (`aws_cloudtrail_s3`, `gcp_pubsub`, `azure_event_hubs`),
  each resumable and each declaring a bounded `collection_budget` that says
  where the overflow goes. Gated by
  `scripts/check_cloud_native_collection.py` (self-test: one injected
  violation per rule, plus a refusal on both an absent and an empty tree),
  wired into `ci.yml :: python-lint`. 83 new tests, connectors suite 1014 ->
  1098. **One verification gap, stated rather than buried:** no Azure
  subscription is reachable from here, so the Event Hubs capture fixture was
  synthesised from the Avro specification rather than recorded from a live
  hub, and the Data Lake Gen2 listing path has never run against a real
  storage account. The claim row is `PARTIAL` for exactly that reason.
- [ ] **4.2** Standard inputs (syslog, OTLP, Kafka, TAXII 2.1)
- [x] **4.3** Retention the tenant chooses. **All three bullets
  closed.** The lake TTL is now a 400-day ceiling rather than a fixed 90
  days, in `001_init.sql`, in the tiering DELETE and in a `MODIFY TTL`
  migration so an existing volume converges; `MAX_LAKE_DAYS` bounds what a
  tenant may choose and the three numbers are held equal. Legal hold now
  blocks the purge, through `may_purge` so the decision has one home, with
  unreadable hold evidence withholding rather than proceeding, and the run
  reporting what it withheld. Gated by
  `scripts/check_retention_window.py` (self-test: eight injected
  violations, one per rule) wired into `ci.yml :: python-lint`. 13 new
  tests, api suite 4,569 -> 4,582.

  **The third bullet is now closed too.** `/lake/sql`'s `cost` was the
  rate limiter's token price — a number about how often you may ask, not
  about how much the asking will read — and there was no progress state
  at all: a cold query either returned inside the published 30-second
  bound or raised a bare timeout.

  Every figure in the new estimate is ClickHouse's own: rows and parts
  from `EXPLAIN ESTIMATE`, the warm/cold split from `system.parts`
  joined to the storage policy's volumes (a part is cold because the
  server says it is on the cold volume, not because of its age — those
  disagree whenever a move is in flight), and progress from
  `system.processes` keyed on a query id we set. There is deliberately
  **no invented throughput constant**: a predicted duration needs a
  bytes-per-second figure and the only honest source is a measurement on
  the deployment's own hardware, so the routing rule is structural — a
  query goes to a job when the estimate says it must read the cold
  volume.

  `estimated_usd` is **null** unless the deployment configures
  `AISOC_LAKE_COLD_RETRIEVAL_USD_PER_GB`.
  `docs/decisions/storage-cost-model.json` prices residency, not reads;
  quoting it for a scan would be the wrong number stated confidently.
  `null` means "we do not know what this costs" and `0.0` means "this
  costs nothing", and a test pins that they are never confused.

  Jobs are rows (migration `111`), not an in-process registry: the API
  runs more than one replica, and that shape has been shipped and
  regretted three times here. 26 pure tests, 12 live ones against real
  Postgres, eight new rules in `check_retention_window.py`, and
  `lake-query-jobs-live.yml`.

  **The test that had to be rewritten, because the first one proved
  nothing.** The claim race originally gathered five concurrent claims
  and asserted one winner — and it passed under a SELECT-then-UPDATE
  implementation as well, measured by subverting the claim and watching
  it stay green. It is now two explicitly interleaved transactions, and
  that version goes red when the predicate is removed.

  **Two of the eight new gate rules were wrong in the same direction**
  and were caught by their own injections: the terminal-state rule
  matched a status string `list_stuck_jobs` legitimately also uses, and
  the routing rule matched a response *field name* rather than the
  branch, so an endpoint that reports `touches_cold` and ignores it
  passed.

  **Not measured, and why: no ClickHouse was exercised.** There is none
  in CI and none on the machine this was written on, so `EXPLAIN
  ESTIMATE`, the `system.parts` join and the `system.processes` read are
  asserted against ClickHouse's documented shapes with the parsing
  tested on recorded rows. What is proven live is the job lifecycle,
  which is where the concurrency defects are.

  **Two limits on what is closed**, recorded rather than left to be found:
  the lake half is gated statically — no test in CI watches a row survive
  past day 90 on a real ClickHouse, so what is proven is that the numbers
  agree and the migration exists; and a hold stops the whole tenant's sweep
  rather than only its own subjects, because both purges are bulk
  statements. Narrowing that needs a per-subject predicate on each store
  and is follow-up.
- [~] **4.4** Throughput (parity 6.9) and a cloud-hardware run. **Every
  parity 6.9 bullet is closed; the cloud-hardware run is not, and cannot
  be from here.**

  **Rules indexed — on required fields, not log source.** The engine ran
  every rule against every event, and its own docstring already recorded
  why a log-source index could not be the fix: connector product names
  do not line up with spec products, a product-based pre-filter was
  tried once and reverted for silently dropping real matches, and a
  mapping table leaves every new connector one missing entry away from a
  detection that stops firing. `match_when` is an AND at the top level,
  so a rule that requires a field the event does not carry cannot match
  it — strictly more selective than log source and provably lossless.
  "Required" is decided by **running the real matcher against an empty
  event**, which is how writing the test found that `neq` requires its
  field in this matcher despite reading like a negation; a hand-written
  operator list would have been wrong in the direction that drops
  detections. Measured: 2,511 rules, 1,751 indexed (69.74%), 797
  candidates for a routine cloud event (68.3% fewer), 2.760 → 1.066
  ms/event over 2,000 iterations.

  **Ordering per entity.** Ingest keyed every message `tenant:event_id`,
  unique per event, so nothing about one entity was ordered relative to
  anything — while fusion correlates on `{tenant}:{entity}:{tactic}`.
  Now `tenant:entity` in the same precedence the correlation key uses,
  held equal by a test, because a partition key disagreeing with the
  correlation key routes an entity's events to a partition and then
  correlates them under a different name.

  **Concurrent triage.** Auto-triage awaited one LLM call at a time.
  Concurrency is per entity, not global: alerts about one host are the
  ones most likely to be one incident and triage reads memory earlier
  triages of that entity wrote, so racing them turns a deterministic
  verdict into a coin toss. Offsets commit only after the in-flight
  window drains, with a time bound as well as a count.

  **Lag hints.** `GET /scale-hint` publishes the backlog and a suggested
  replica count. AiSOC does not act on it — ADR-0012 records why — and
  the per-replica budget is derived from the published realistic-mix run
  rather than chosen, with a test that reads the committed result file
  and fails if the two drift.

  **Realistic mix.** `--alert-every N` sends one alerting event every
  Nth and routine telemetry in between. Published run: 6,000 events
  saturating at 1-in-100, **0 of 5,940 routine events raised an alert**,
  0 missing, 0 duplicates, p95 event-to-alert 1,195 ms, ingest 122.6
  events/s.

  **The first attempt at that run measured a routine alert rate of
  1.00** — every "benign" event became an alert. Not the corpus firing:
  the load path sends an undeclared connector type, the ingest
  normalizer's generic fallback files it as class 2001 Security Finding,
  and the promoter promotes OCSF category 2 unconditionally. **Eight of
  the twelve declared profiles are category 2**, so on those connectors
  no event can be routine whatever it contains. Also fixed: "missing
  events" was counted against every accepted event, so a perfect mix run
  reported losing 99% of its traffic.

  ADR `0011`. 51 new tests (12 index, 8 partition key, 18 entity lanes,
  13 scale hint). Three claim rows; matrix 309 rows, 306 GATED.

  **`[~]` and not `[x]`, for one reason: there is no cloud-hardware
  run.** No cloud instance has been provisioned for this project, so
  every figure on the performance page comes from a laptop or from a
  kind cluster on it. The plan's 5,000 events/s at p95 under 2 s target
  is therefore an aim rather than a result, and the page says so, with
  the exact command that would close it once an instance exists. A
  second, smaller caveat recorded there too: the published mix run went
  through the **published images**, not a build of this branch, so it is
  not a measurement of the rule index — that is measured separately and
  in process.
- [~] **4.5** Deployment completeness (parity 6.8). **Three of four
  bullets closed; the managed-cluster run is maintainer-blocked.**

  **The chart installs CORE.** `infra/helm/aisoc/values.yaml` declared
  **seven** application services against CORE's sixteen: no response
  execution, no connector polling, no threat-intel store, no LLM
  gateway, no local model, no vector store. `helm install` produced a
  deployment that could not act, could not collect and could not triage
  — and reported success, because nothing compared the two files.
  `actions`, `connectors` and `threatintel` are now entries in
  `.Values.services`; `litellm`, `ollama` and `qdrant` are deliberately
  not, because that map defaults every image tag to
  `.Chart.AppVersion` and tagging a third-party image with AiSOC's
  version renders perfectly and pulls a tag that does not exist. Two of
  them need storage, so they are StatefulSets with volume claims.

  **Restore covers backup.** The two scripts already agreed on all six
  components; nothing held them that way, and a component added to one
  and not the other is discovered during an incident. Now compared in
  both directions.

  **Leader election.** The scheduler adds one job per connector
  instance in process, so two replicas each polled every vendor on every
  cycle — and on a rate-limited API the second replica's poll is the one
  that gets throttled, which looks exactly like expired credentials. A
  Postgres lease (migration `112`), not a Kubernetes Lease: the
  scheduler also runs under Compose and systemd, and an election that
  only works on Kubernetes is off wherever most first runs happen. The
  mechanism is `UPDATE ... WHERE expires_at < now()`, proved by two
  **explicitly interleaved** transactions rather than a race — a race
  between coroutines on one loop passes under a SELECT-then-UPDATE too,
  which this phase measured on its own lake-job claim. A follower
  *removes* its poll jobs rather than declining to add more.

  Gated by `scripts/check_deployment_completeness.py` (self-test: nine
  injected violations, one per rule, plus a refusal on both an absent
  and an empty tree) wired into `ci.yml :: python-lint`, and by
  `scheduler-lease-live.yml`. 13 live lease tests; matrix 311 rows, 308
  GATED.

  **`[~]`, for three things that could not be verified from here**,
  named rather than implied:

  1. **No managed-Kubernetes run.** The plan already says this one waits
     on the maintainer providing a cluster. No managed cluster is
     reachable from this machine, so `docs/perf/` gains no row.
  2. **`helm install` has not been run on a cluster.** `helm lint` is
     clean and `helm template` renders 14 workload components, which is
     static evidence that the chart is well-formed — not evidence that
     it comes up. The kind install the plan's "Done when" names is the
     open half of this item.
  3. **`scripts/check_published_images.py` could not reach GHCR**
     ("ghcr.io unreachable: The read operation timed out") and correctly
     refused a vacuous pass rather than reporting the tree clean. So the
     three new third-party image references and the three new
     first-party ones are **not** confirmed to resolve in the registry.

## Phase 5: Response that finishes

- [x] **5.1** Steps that act (parity 5.3)
- [x] **5.2** Delivery (parity 5.7)
- [x] **5.3** `wait`, `parallel`, `loop` with idempotency keys
- [x] **5.4** Stateful user and manager verification. A `verify_user` step
  suspends the run on a `verification` pause (migration 102, a third `kind`
  on `aisoc_playbook_pauses` rather than a second table), asks the affected
  person over the configured Slack, Teams or email destination through the
  5.1 `notify` arms, escalates to their manager from
  `aisoc_scim_users.manager_ref` when the stage deadline passes, and
  resumes the run with the signed answer in the context so an ordinary
  `condition` step branches on it. Five outcomes a playbook can read:
  `acknowledged`, `denied`, `unsure`, `timed_out`, `no_manager`. The answer
  is HMAC-signed over `(token, answer, stage)` — the token alone would make
  a guess yield three working links, and without the stage the subject's own
  link still answers after the question has moved to their manager. The
  contract's caution is enforced in `may_auto_send` in that order: a
  confirmed true positive is never asked, with no opt-out and no exception
  for a human-initiated run, and everything else needs a row in
  `aisoc_verification_policies` — default-deny, with a writer at
  `PUT /api/v1/verification-policies` so the control can actually be
  switched on. Ships off: `AISOC_PLAYBOOK_VERIFY_EXECUTE` previews and names
  who *would* be asked. Gated by `scripts/check_stateful_verification.py`
  (self-test: eleven injected violations, one per rule) wired into
  `ci.yml :: python-lint`, plus `verification-live.yml` driving the real SQL
  against real Postgres. 20 new offline tests, 12 live, 5 SCIM; shipped
  playbook `user-verification-containment.playbook.json`. Deviation D15
  records the `wait` defect this item found and fixed.
- [ ] **5.5** Executor arms 74 → at least 150
- [ ] **5.6** Plain-language playbooks

## Phase 6: AI agent security

- [x] **6.1** AI asset inventory. Reproduced:
  `scripts/check_ai_asset_inventory.py` on the unmodified tree reported nine
  problems across five of its eight rules — no migration creates the table,
  no model maps it, no route reads it, no writer exists, and the graph
  vocabulary has no label for an AI asset. Implemented `aisoc_ai_assets`
  (migration `110`, tenant-scoped, `FORCE ROW LEVEL SECURITY`, granted to
  `aisoc_app`), the ORM model, `GET /ai-assets`, `GET /ai-assets/{id}` and
  `POST /ai-assets/{id}/sanction` behind a new `ai_estate:read` /
  `ai_estate:write` pair held by five roles and mintable into an API key,
  `AiAssetRecorder` in the fusion consumer's raw-events branch, the `AIAsset`
  graph label with `OPERATES` and `HOSTS` edges emitted at ingest (schema
  `v1.2 -> v1.3`), and the `/ai-estate` console page. 21 new fusion tests
  (suite 662 -> 683), 8 new Go tests in `internal/graph`, 5 live-Postgres
  cases in `tests/isolation/test_ai_estate_live.py`.

  **The writer is the whole item**, and the gate says so rather than the
  prose: the `WRITER` rule requires the consumer to call the recorder *and*
  `main.py` to construct it, because an unconstructed recorder is a `None`
  every call site skips in silence and the page would render "no AI estate"
  to a tenant that has one — the second half of this repository's recurring
  defect, the half module reachability cannot see.

  Two negative controls, both re-injecting a real defect rather than an
  invented one, both run against a real PostgreSQL 16 with every migration
  applied and the suite connected as the DML-only `aisoc_app` role: reverting
  the identity constraint from `UNIQUE NULLS NOT DISTINCT` to plain `UNIQUE`
  turns one provider-key row into **three**, each claiming to be first seen
  now (measured, not predicted — a provider key has no device, so under the
  default NULL semantics every sighting inserts); and a tenant policy of
  `USING (true)` lets tenant A read tenant B's estate. Each fails the suite
  and each is a step in `ai-estate-live.yml`. The gate's own self-test
  injects one violation per rule and found two blind spots in the gate while
  being written — it read its own component's docstring as a fabrication, and
  a `NodeAIAsset,` substring match would have passed on a commented-out
  `// NodeAIAsset,`.

  **Two limits, stated rather than left to be found.** Phase 2.5 is open, so
  `effective_permissions` is a column with a resolver behind it and nothing
  writing it yet; the risk scorer returns `False` for an absent snapshot
  rather than treating unknown as privileged, and the console says in words
  that permissions did not contribute. And the three discovery sources see
  genuinely different things — runtime telemetry never carries a device, a
  provider audit log never carries either — so `discovery_source` is stored
  per row and the page prints what each source can and cannot see, because
  an unlinked device and an unlinkable one are different facts.
- [x] **6.2** Endpoint discovery with no new agent. Reproduced:
  `services/fusion/tests/test_ai_endpoint_discovery.py` was written first and
  **13 of its 16 cases failed** on the tree as 6.1 left it, driving payloads
  in the shapes `windows_event`, `auditd`, `fleetdm` and `osctrl` actually
  emit — read out of each connector's own `normalize()` rather than invented.

  **The root cause is the one this repository keeps paying for, in its second
  form.** 6.1's endpoint branch read `process.name` off the OCSF event. The
  canonical OCSF profile maps `title`, `external_id` and the identity aliases
  and *nothing else*; all four endpoint connectors put their process fields in
  the connector payload, which `services/ingest` stores as a JSON string under
  `raw_data`. So the branch resolved `None` on every real source and could
  never have produced one row — and its own unit tests passed throughout,
  because they built events in the shape the module expected. The recorder now
  reconstructs the same flat namespace `DetectionEngine._raw_fields` does, and
  `PROCESS_FIELDS` / `COMMAND_LINE_FIELDS` name each connector's own spelling.

  Built: `packs/aisoc-ai-estate.yaml` (5 queries — coding-agent processes, MCP
  server processes, MCP client configuration files, AI IDE extensions,
  provider key files; loaded through the real `pack_loader`, 5 packs -> 6),
  `SOURCE_CAPABILITIES` declaring what each of the five discovery sources sees
  *and* cannot see, `apps/docs/docs/concepts/ai-estate-discovery.md`, and
  `scripts/check_ai_endpoint_discovery.py` (6 rules, self-test injects one
  violation each). Fusion suite 683 -> 700.

  Negative controls: an ordinary process (`falcon-sensor`, `osqueryd`,
  `nginx`, `chrome`, `MsMpEng.exe`, `node`), an unrelated IDE extension
  (`esbenp.prettier-vscode`) and an unrelated `package.json` each produce no
  asset, and an endpoint sighting is asserted to carry no model or provider —
  because filling those from a default would make the inventory assert
  something no source observed. The gate's own self-test re-injects the
  original defect (`fields = _connector_fields(ocsf)` -> `fields = dict(ocsf)`)
  and requires NAMESPACE to catch it; writing it found the same
  read-your-own-docstring blind spot a second time, now fixed by stripping the
  docstring before matching.

  **Honest limit, and the reason the claim row is PARTIAL:** `crowdstrike`,
  `sentinelone` and `azure_defender` poll the vendor's own **detections**, not
  process telemetry — `crowdstrike.py` reads `/detects/queries/detects/v1` —
  so they cannot supply a process start, and the plan's wording that endpoint
  discovery comes from them is not satisfiable with the connectors this tree
  has. The documentation says so in a callout rather than leaving a reader to
  assume their EDR covers it. Separately, no osquery agent runs in CI: the
  pack is asserted to load and to select the columns the recorder reads, but
  no test has watched a real `osqueryd` execute one of its queries.
- [ ] **6.3** Provider coverage beyond OpenAI and Anthropic
- [ ] **6.4** Agent identity and baselines (parity 6.7)
- [ ] **6.5** AI rule pack
- [ ] **6.6** AI containment and kill-switch

## Phase 7: Phishing operations

- [x] **7.1** Intake to purge (gap-closure Phase 10 / parity 6.4)
- [x] **7.2** Header, URL and attachment analysis
- [x] **7.3** Adversary-in-the-middle session reuse

## Phase 8: Enterprise gates

- [~] **8.1** Identity and administration. Five of six sub-items done, each
  in its own pull request; the shortfall is itemised in D14 below.
  - [x] parity 4.1 — a containerised Keycloak signs somebody in over **OIDC**
    and **SAML**, both legs **observed to pass** (#1327). The SSO claim row
    moves PARTIAL → GATED on that evidence, not on a relabel.
  - [x] 4.2 — WebAuthn as a console second factor and MFA enforced **per
    role** (#1328), on top of the TOTP, recovery codes and per-tenant
    enforcement fix pass 4.2 already shipped.
  - [x] 4.4 — the audit retention window is enforced and a truncated chain
    still verifies (#1329). Export already existed on `AuditLogView.tsx`.
  - [~] 4.5 — opt-in limit enforcement in `entitlements.py` (#1332). The
    **six console pages** 4.5 also names are not built: see D14.
  - [ ] 4.6 — internationalisation. Not started: see D14.
  - [x] 4.7 — axe covers the case list and case workspace, the two views
    4.7 left out, and the four defects it found are fixed (#1331).
- [x] **8.2** ABAC, elevation and workload identities
- [x] **8.3** Buyer security pack

## Phase 9: Analyst surfaces

- [x] **9.1** MCP over streamable HTTP (parity 6.6). All six bullets of
  parity 6.6 closed. `services/mcp/src/http.ts` serves the SDK's
  `StreamableHTTPServerTransport` at `POST /mcp` with an unauthenticated
  `GET /healthz`; `docker-compose.yml` gains an `mcp` service under its own
  profile and `infra/helm/aisoc` an `mcp` component, both off unless an
  operator asks for them. The credential is per request and there is no
  environment fallback — the transport is **stateless with a fresh server
  per request**, so revoking a key ends the conversations it opened rather
  than leaving a session id that outlives it. Every call goes through
  `POST /api/v1/mcp/tool-calls/authorize`, which resolves the tool's
  required permission from a catalogue generated from the TypeScript
  registry, checks it through the principal's **own** `require_permission`
  (not a second copy of the logic), consults the tenant's grant, and writes
  an `mcp:tool_call` audit row **before** the tool runs — reads included,
  which was the whole gap. The outcome is a second `mcp:tool_result` row
  because `audit_log` refuses UPDATE by trigger. A tool whose registry entry
  says `readOnlyHint: false` cannot run on a bearer token: it queues an
  approval fingerprinted over its exact arguments, the requester cannot
  approve it, and the approval is spent by the call it authorised. Gated by
  `scripts/check_mcp_over_http.py` (self-test: one injected violation per
  rule across all seven, plus the empty-tree refusal) wired into
  `ci.yml :: python-lint`. 32 new tests — 16 API, 16 over a real socket
  against a real API stub. Live end-to-end against a real Postgres 16 and
  the real API recorded in the PR: 19 tools advertised, a read allowed, an
  out-of-scope tool denied, the write tool refused at the tenant switch and
  then at the approval, approved by a second principal, allowed, and spent.
  18 of 18 audit rows hash-chained, and `DELETE FROM audit_log` refused by
  the trigger while the run was in progress.
- [x] **9.2** Semantic memory (parity 6.5). All three bullets of parity 6.5
  closed, and the third one — "replay shows the accuracy delta" — produced a
  result that changed the design rather than confirming it. `aisoc_memory_items`
  (migration `105`) is the store of record for past cases, runbooks and
  institutional memory; Qdrant is an index over it, reached through its REST
  API so this service gains no dependency and its lockfile does not move.
  Every item carries an author, a source, a scope, an expiry and a state, and
  the author is the **authenticated principal**, never the body — provenance a
  caller can set is not provenance. Two claims about one subject suspend
  **both** sides and recall returns neither until an analyst settles it;
  preferring the newer one silently restores a bad entry the next time the job
  that wrote it runs, which is the case the feature exists for. Recall is
  tenant-scoped in the Qdrant filter itself and `search()` **raises** rather
  than offering an unscoped branch. With no embedding backend recall is 503
  with the reason, never an empty list. `kind='case'` is written automatically
  by the case-closure path, so the half of the "exists unwired" family that
  reachability analysis cannot see — a table every surface reads and nothing
  writes — does not apply. Measured by
  `scripts/score_memory_recall.py` (12 hand-authored low-overlap probes,
  mean lexical overlap 0.166, `is_synthetic: true`); its self-test is wired
  into `ci.yml :: python-lint`. 17 new tests, api suite +17. Live end to end
  against real Postgres 16, real Qdrant v1.7.0 and a real embedding backend,
  recorded in the PR. **The measurement is published as it came out, and it is
  unflattering:** see D11.
- [x] **9.3** Case depth (parity 5.6 remainder). All four open bullets.
  **Alert merge needed no schema at all**: `is_merged`, `parent_alert_id` and
  `child_alert_ids` have been on `alerts` since migration 001 with the ORM
  model as their only mention anywhere — the repository's recurring defect,
  and worth naming so "new" means something. Merge keeps every row: a
  duplicate is marked and pointed at its parent, the survivor's children are
  **appended** not replaced, re-merging and merging into a merged alert are
  both refused because each would orphan or cycle the chain, and the
  survivor inherits the case a duplicate was already on. Case merge (migration
  `106`) repoints the alerts and keeps both case rows, because deleting loses
  the audit chain, the custody entries and any vendor ticket already naming
  that id. Bulk triage is new in the route **and** the console: a checkbox per
  row, a select-all that selects this page only, and a bar whose Apply
  performs a real write and surfaces the preflight 409 with the real matched
  count instead of silently retrying. `closed` is deliberately unreachable
  there — `bulk-close` snapshots every row first and a weaker second path to
  one destination is how the weaker one wins. Tenant custom fields are two
  tables rather than a JSONB blob so a field can be enumerated, rendered,
  validated at write time and retired cleanly; values are canonicalised on
  write. Workload is counted per request over rows the query selected, a
  merged-away case is not counted as work, and **a mean over nothing is
  `null`, never `0.0`** — with the count it was taken over beside it. Graded
  by `.github/workflows/case-depth-live.yml` against a real Postgres with
  three negative controls, because every statement here is Postgres-only and
  a SQLite stand-in would be a different query. 29 new tests (23 API live, 6
  web). The live suite earned its keep immediately: it caught that
  `aisoc_cases.alert_ids` is `uuid[]` while the two columns beside it are
  JSONB, which a stand-in would have accepted.
- [ ] **9.4** War rooms

- [ ] **9.3** Case depth (parity 5.6 remainder)
- [~] **9.4** War rooms. **Slack is complete; Teams is built and
  maintainer-blocked, and the block is stated in the product rather than
  here.** One action (`POST /war-rooms/cases/{id}`, and a console panel on
  the case) creates the channel, invites the assignees, posts the case
  header and records the room; a sweep worker posts the timeline and
  verdicts as they change; a decision taken in the channel comes back onto
  the case through a service-token-only route. Idempotency is the design
  rather than a refinement: every post is keyed by a fingerprint of the
  *event value*, unique per room, so a retry is a no-op, two replicas cannot
  double-post, and a case that goes `open → closed → open` posts three times
  because a re-opened case is news. The sweep derives its events from the
  case row rather than a cursor, so a missed tick cannot lose one. Opening
  fails **loudly** (502 carrying the vendor's own sentence) because an
  analyst pressed a button; syncing fails **soft** and records `last_error`,
  which the console renders — a room that has silently stopped mirroring is
  worse than one that was never opened, and "never synced" renders
  differently from "synced with nothing to say". A chat button reaches four
  verbs and **`close` is not one of them**. 37 new tests (17 slack-bot, 9
  teams-bot, 11 API). **Open and stated, not inferred:** creating a Teams
  channel needs Microsoft Graph with an Entra application registration and
  admin consent, which no maintainer has provisioned, so that route answers
  **501 naming all four missing settings** and deliberately does not fall
  back to the incoming webhook — one shared channel per deployment would put
  the next incident's traffic in the last one's thread. The Graph calls
  themselves have therefore never run against a real tenant. Neither has the
  Slack path against a real workspace: it is covered by 17 tests against a
  fake client, and no Slack token exists here.
- [ ] **9.5** Hunt to report
- [x] **9.5** Hunt to report. A natural-language hunt or a retro-hunt
  sighting becomes a stored report answering what, how, where and when, with
  ledger citations, readable as JSON or HTML and exportable as PDF through
  the **same WeasyPrint path and the same unavailability error** the weekly
  digest uses — one renderer, because two drift and the PDF stops matching
  the page somebody approved. Three refusals carry the item: a hunt that has
  never run is refused (a report about an unexecuted query is a statement
  about the query, not the estate), an **uncited report is refused at
  persist time** (an uncited report is an assertion), and a section that
  cannot be derived stays **empty** and renders as "not recorded" rather
  than as a confident sentence about nothing. The retro-hunt builder
  computes the gap between when intelligence arrived and when the estate
  first saw the indicator, which is the number a retro-hunt exists to
  produce and which a reader would otherwise get by subtracting two
  timestamps. Graded by `.github/workflows/hunt-report-live.yml` against a
  real Postgres with three negative controls. 14 new tests. The live suite
  earned its keep three times on its first run: `alerts` has no singular
  `affected_host` (it is `affected_hosts`, a JSONB array, and `entities` is
  what fusion actually writes), `investigation_events` has **no `case_id` at
  all** so the ledger is only reachable by joining `investigation_runs`, and
  that table's `case_id` is TEXT rather than UUID so binding a UUID raises
  in asyncpg instead of coercing. Each would have shipped under a SQLite
  stand-in, and the middle one would have cited an empty set on every
  report.
- [ ] **9.6** Native responder
- [~] **9.6** Native responder. **Two of three bullets closed; the third is
  maintainer-blocked and the block is in the product, not in this note.**
  *Device build:* `mobile.yml` gains an Android job that runs
  `expo prebuild` and Gradle `assembleDebug`, asserts the APK really
  contains `classes.dex` (a green build that produced nothing is a shape
  this repository has shipped) and uploads it — an APK that installs and
  runs on a handset. Not store-signable (a Google Play account) and not a
  *release* build: `:app:createBundleReleaseJsAndAssets` dies inside
  Metro's asset hashing on the runner, Node 20 fixes it, and
  `scripts/check_toolchain_pins.py` correctly refuses a second Node version
  because 20 left security support in April 2026 and no image ships it.
  Lowering that gate to make this job pass would have been the wrong trade,
  so the limit is stated instead. iOS
  compiles **and links** for the simulator on a macOS runner — the Expo
  config generates a valid Xcode project, the pods resolve and every native
  module builds. It deliberately does not run Metro's bundle phase, which
  dies on that runner inside one of expo-router's PNGs for a Metro/Node
  reason unrelated to this app; the Android job bundles, so that half is
  still graded. A device build needs an Apple developer account. *Voice:* `apps/mobile/src/lib/voice.ts` takes a recogniser that
  returns a **string**, so no audio type appears anywhere in the module and
  there is nothing for a later edit to upload; a device with no offline
  model is **refused** rather than silently using the platform's cloud
  recogniser; the transcript is shown before it is sent, because on-device
  recognition is worse and a security question misheard is a question
  answered about the wrong host. Gated by `scripts/check_no_audio_egress.py`
  (self-test: six checks, including that a *comment* saying the app does not
  record is not mistaken for the app recording), wired into both `ci.yml`
  unconditionally and `mobile.yml`. *Push:* `services/realtime` sent every
  subscription through `web-push`, which signs a VAPID JWT and POSTs to the
  endpoint **URL** — a bare APNs device token is not a URL, so a
  subscription saved by the mobile app was accepted, counted and failed on
  every send, which is the worst of the three states because the count
  looked healthy. `native-push.ts` speaks APNs and FCM HTTP v1 and
  distinguishes delivered, device-gone and **not-configured**, the last
  naming each missing variable and never reporting a delivery. 19 new tests
  (11 realtime, 8 mobile); mobile suite 34 → 42. **Open and stated:** no
  APNs `.p8` and no FCM service account exist here, so nothing has been
  delivered to a real handset, and no microphone has exercised the voice
  path. The README's claim table was inverted rather than deleted — it now
  has to keep saying that an iPhone *device* build and a real-handset push
  have **not** happened, and `mobile.yml` fails if it stops.

## Phase 10: Close the books

- [ ] **10** Re-run touched claim rows, update sibling progress files, one
  `[Unreleased]` entry per phase, final report here

## Item log

| Date | Item | What happened |
|---|---|---|
| 2026-10-11 | 9.3 | Reproduced: the alert merge columns had zero writers outside the ORM model; `grep -rn custom_field services/api` and `grep -rn workload` (excluding workload *identities*) both counted zero; and `grep -rn bulk apps/web/src/components/alerts` found only unrelated comments, so the only bulk verb in the product was `POST /alerts/bulk-close` with no console surface at all. The two-case-table trap named in the brief was already closed by migration 083 and `check_one_case_table.py` reports OK, so `aisoc_cases` is the table this item deepens. Three negative controls recorded in the PR and wired into the live workflow. The live suite found a real defect on its first run: `aisoc_cases.alert_ids` is `uuid[]` while `ioc_ids` and `artifact_ids` beside it are JSONB, and the merge statement had assumed JSONB. |

| 2026-10-11 | 9.1 | Reproduced: on `origin/main` the greps for `StreamableHTTP` in `services/mcp/src/`, for `aisoc-mcp` in `docker-compose.yml` and `infra/helm/`, for a per-tenant tool grant in `services/api/app/`, and for an `mcp:` audit action all counted **zero**, and `check_mcp_over_http.py` reported seven problems. Built the HTTP transport, the authorize/complete pair, the tenant grant table, the approval queue bound to a call's arguments, and the generated tool catalogue held in parity with the TypeScript registry. Four negative controls recorded in the PR; one of them found a hole in the new gate itself, which reported `http.ts` for reading the process-wide API key when the only mention was a comment saying it deliberately does not — the detector now strips comments before matching, and refuses a `{...cfg}` spread as well, because a spread is correct today and a credential fallback the day somebody reorders the literal. |
| 2026-10-11 | 9.4 | Reproduced: `grep -rn 'conversations.create|channels.create|war_room'` across every service and the console returned four hits, all prose — a playbook template describing a "Notify war-room" step and an eval fixture quoting the phrase. Both bots could only answer: slack-bot had one outbound route (an approval card) and teams-bot posts to a hand-configured webhook. Built the channel creation, the keyed sweep, the decision route and the console panel. Teams is 501 with its four missing settings named, which is the honest state and the one a stock install is in. |
| 2026-10-11 | 9.5 | Reproduced: `grep -n hunt` across `app/services/report_builder.py` and `app/api/v1/endpoints/reports.py` returned nothing — the report surface and the hunt surface did not know about each other, so a hunt produced rows and a retro-hunt produced a sightings row and neither produced anything a person could read or forward. Built the four-section report, the citation rule, the two builders and the JSON/HTML/PDF export. Three negative controls in the live workflow: allowing an uncited report, filling an empty section with a sentence, and reporting a hunt that never ran each have to turn the suite red. The live run found three schema facts a stand-in would have hidden, recorded in the item above. |
| 2026-10-11 | 9.6 | Reproduced: `grep -c 'eas build|gradlew|xcodebuild|expo prebuild' .github/workflows/mobile.yml` returned **0** and the workflow actively *required* the README to say no device build had happened; `grep -rni 'speech|voice' apps/mobile/src apps/mobile/app` returned **0**; and `services/realtime/src/push.ts` sent every record through `webpush.sendNotification`, so a native token was accepted and could never be delivered to. Built the Android APK job, the simulator job, the on-device voice module and the APNs/FCM sender. Negative control: removing the on-device refusal so the cloud recogniser could be used fails two of the eight voice tests. The README guard was inverted rather than deleted — "we added a build so the honesty check is no longer needed" is how an ungated claim comes back. |
| 2026-10-11 | 9.2 | Reproduced: `knowledge_base.py` searched with `to_tsvector`/`plainto_tsquery` and nothing else; `grep -rn qdrant services/api/app/` found only the migration runner and the tenant-deletion sweep, no recall path; and no memory row anywhere carried an author, a source, a scope, an expiry or a state. Built the store of record, the Qdrant index over it, the conflict state machine, the case-closure writer and the recall scorer. Two negative controls recorded in the PR: restoring last-write-wins on a contradiction fails three tests, and restoring vector truncation fails one. The measurement is negative and is published as such — see D11, which also records that it caught the truncation defect. |
| 2026-10-07 | 0.1 | This file created at base commit `1b8bc2d4`. |
| 2026-10-07 | 0.2 | Every figure re-derived. Two matched exactly (detections, unreachable families); executor arms measured 74 against a captured 73; the cloud/identity/SaaS/code figure measured 395 against a captured 461 on a grouping the plan does not pin, recorded above. Two measurement caveats found: executable and quarantined overlap by 1,724 rules, and the "69% Windows" figure does not reproduce from the index. |
| 2026-10-10 | 2.7 | Reproduced: ADR-0007 closed by naming this decision and declining to make it, so the question was open and nothing in the tree answered it. Measured rather than estimated, on a running CORE stack: 16 services idle at 3,649.8 MiB, and `ollama` measures 2.96 GiB under inference against a 140.6 MiB idle, so CORE's working peak is 6,540 MiB and the headroom under 8 GiB is **1,652 MiB** — which is what either option is spent out of, and is the number the estimate-based version of this decision would have missed. Neo4j 5.15-community with the `full` profile's own settings, loaded with 20,000 sessions, 500 users and 20,000 edges and then read with the aggregation 2.4 needs: **696.8 MiB** resident, 42.2% of the headroom. The same rows in a tenant-scoped Postgres table with the three indexes the store needs: **+10.9 MiB** marginal resident in a container CORE already runs, 8,288 kB of relation, aggregation in 5.148 ms — 0.7% of the headroom and 64× less memory for the same data. Accepted: Postgres in CORE, Neo4j keeps the Session nodes in `full`. The ADR states what it does **not** decide — ClickHouse stays in `full`, so CORE still has no event lake. |
| 2026-10-10 | 2.4 | Reproduced: `check_session_projection.py` against `origin/main` reports all three declarations missing and exits 1 — there was no session concept in the tree at all, in any of the three stores. Fixed by deriving the key in exactly one place (`services/ingest/internal/activity/session.go`) and reading it in three (`sessions.py` for Postgres, `lake_writer.py` for ClickHouse, `graph/session.go` for Neo4j), on ADR-0010's condition that the arrangement is held by a gate rather than a comment. The id is a deterministic `uuidv5` of tenant, source and key, so the three stores agree without any of them coordinating at write time. Negative controls: reverting the `cloudTrailSession` reordering fails three subtests plus `TestAnAnonymousAssumeRoleNamesNobody`; shrinking the closed set in either the Python tuple or the SQL `CHECK` is caught; a second deriver and an invented fallback key are each caught, performed as the exact edit a contributor would make. Writing the tests found the defect that mattered: the chain edge back to the originating human was being dropped on precisely the two calls that carry it, because `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` have no `userIdentity` at all (the caller is not yet an AWS principal) and the early return on a missing identity skipped the issued-session read. Pointing the new gate at the pre-fix tree also found a defect **in the gate**: it died with `FileNotFoundError` instead of naming which declaration was missing, so a fourth self-test case now asserts a missing declaration produces a sentence rather than a traceback. Ingest suite green (12 packages); fusion 677 passed, 2 skipped. |
| 2026-10-09 | 4.3 | Reproduced: `check_retention_window.py` on the unmodified tree reported six problems — the lake deleting at 90 days against a 3,650-day cap, no `MODIFY TTL` migration, tiering deleting at 90, and the purge worker calling neither `alerts_under_legal_hold` nor `may_purge` and reporting nothing withheld. Fixed all but the cold-query bullet. Four negative controls recorded in the PR, including the positive control: a purge stuck closed withholds every tenant and fails four of the eight hold tests, which is the only thing that separates a working control from commendable caution. One pre-existing test (`test_storage_tiering.py`) pinned the 90-day tiering DELETE and now reads the shared constant; `test_retention_worker.py`'s session double could not answer the new holds query, so the worker failed closed and five of its cases failed — the double was taught the query rather than the fail-closed behaviour relaxed. |
| 2026-10-09 | 4.2 | Reproduced: `check_syslog_listener.py` against `origin/main` reported "no Go sources under services/ingest/internal/syslog", and the only syslog path was `POST /v1/inbox/cef`, which needs a forwarder that already speaks HTTP. Implemented `services/ingest/internal/syslog` (UDP + TCP, both RFC 6587 framings, four wire formats, token-derived tenant, batched publish, `/readyz` subscription). Five negative controls recorded in the PR; one of them found a hole in the new gate itself, which reported OK while the tenant came from `msg.Hostname` through a struct field — the detector now knows all three Go syntaxes and the self-test exercises each. Writing the tests also found a shutdown deadlock: `Stop` waited on goroutines watching a context the caller had not cancelled yet. Ingest suite green, `internal/syslog` 33 cases. |
| 2026-10-07 | 0.3 | `make up` and `make smoke` (10/10) pass. Injection suite and load-harness baselines committed. `make up-full` deferred (D2) and hosted model rows blocked (D3). Fixing D1 was a precondition for the load-harness baseline. |
| 2026-10-09 | 3.3 | Identity privilege (18 rules) and a per-tenant first-seen store (2) built; 5 rules were never unreachable (gate operator drift, D9); 18 retired with a reason (D10). `MAX_UNREACHABLE` 45 → 2, the two remaining both needing the 3.4 baseline. Two matcher operators three shipped rules already used were implemented. |
| 2026-10-09 | 3.2 | Ordered and unordered sequences in the windowed engine; all four translatable Sigma correlation types compile, seven refusal reasons recorded. No upstream correlation rule exists in this tree to import (D8), so the corpus is first-party and labelled as such. |
| 2026-10-11 | 4.5 | Three of four bullets closed. Reproduced: `check_deployment_completeness.py` on the pre-fix tree reported six CORE services the chart renders no workload for. Added them (three in `.Values.services`, three as their own templates because a third-party image must not inherit `.Chart.AppVersion` and two need volumes), compared restore against backup in both directions, and built Postgres leader election for the connector scheduler (migration `112`). Negative control: removing the lease's expiry predicate makes both interleaved transactions lead and three live cases go red. **Not verified here:** no managed-cluster run, no `helm install` on a cluster, and `check_published_images.py` could not reach GHCR and refused to pass vacuously. |
| 2026-10-11 | 4.4 | Every parity 6.9 bullet closed; the cloud-hardware run is not possible from here and is recorded as unmeasured rather than implied. Rule index on required fields (lossless, proven by replaying every fixture both ways; 68.3% fewer candidates, 2.6x on evaluation), entity partition key held equal to the correlation key, per-entity concurrent triage, lag-based scale hint derived from the published run. The realistic mix found that eight of twelve connector profiles are category 2 and are promoted unconditionally, so on those connectors no event can be routine — the first run measured a routine alert rate of 1.00. ADR-0012; matrix 309 rows, 306 GATED. |
| 2026-10-11 | 4.3 | Third bullet closed. Reproduced: `check_retention_window.py` with the new rules reported no cold-query estimator, no job surface and no job table on the pre-fix tree. Built `lake_cold_query.py` (EXPLAIN ESTIMATE + system.parts + system.processes, no invented throughput or price), `lake_query_runner.py` and migration `111`. Negative control: removing the `status = 'queued'` predicate makes both interleaved transactions claim one job and the live suite goes red. The first version of that test — five gathered claims — passed under the broken implementation and was replaced. 26 pure + 12 live tests; matrix 306 rows, 303 GATED. |
| 2026-10-11 | 4.2 | Reproduced: `check_standard_inputs.py` against the pre-fix tree reported no OTLP package, no Kafka input and no TAXII server — the only TAXII-shaped route being a demo-gated sample list. Built all three, after moving the consumer-health classifier out of `graph_ws` into `streamhealth` so the new Kafka consumer shares the table rather than copying it. Negative controls recorded in the PR: a timestamp-only TAXII cursor loses an indicator in the single-row pagination walk (measured — 3 of 4), and nineteen gate injections each go red. Writing it found four defects, including an OTLP template nobody could mint a token for and a gate rule that read an error message instead of the behaviour. Ingest Go suite green; api projection suite 37; live TAXII suite 15. |
| 2026-10-09 | 4.1 | Reproduced: `check_cloud_native_collection.py` on the unmodified tree reported all three collection paths absent. Implemented `aws_cloudtrail_s3` (SQS-notified S3 objects; management events, data events and VPC flow logs; delete-after-emit), `gcp_pubsub` (REST pull on a log-sink subscription; ack-after-read) and `azure_event_hubs` (Capture blobs over the Data Lake Gen2 JSON API, with a focused Avro OCF reader). Negative controls recorded in the PR: deleting the SQS message before the object is read, acknowledging the Pub/Sub batch before it is built, ignoring the Avro union branch index, and ignoring the flow-log header line each fail a named test, and all were restored. Connectors suite 1014 -> 1098 passed. |
| 2026-10-11 | 5.4 | Reproduced: `check_stateful_verification.py` against `origin/main` reported eight problems — no `verification.py` at all, `verify_user` absent from the control-flow table, no resume path, no escalation, no `timed_out`, no sweep, no migration and no writer for the opt-in table. Built the stage machine on the existing pause row rather than a second table. Three negative controls recorded in the PR: reverting the run-loop break fails three tests including the `wait` regression (D15), removing `manager_ref=_extract_manager(body)` fails three SCIM tests, and removing `ENABLE ROW LEVEL SECURITY` from migration 102 fails the live tenancy test with "tenant B read tenant A's verification policy". Two pre-existing tests pinned the old shape and were widened rather than relaxed: the control-flow table's membership (still an equality, now of four) and the sweeper's return dict. Writing the gate found a hole in the gate: its first block extractor matched `\n\n\n`, which finds nothing for the *last* function in a module, so the ordering rule was skipped entirely over an injected violation. |
| 2026-10-11 | 6.2 | Reproduced: 13 of 16 new cases failed, driving the shapes the four endpoint connectors actually emit. Root cause was 6.1's endpoint branch reading `process.name` off OCSF, which the canonical profile never populates — it found `None` on every real source while its own tests passed. Fixed by reconstructing the connector namespace. Shipped the osquery pack (5 queries, packs 5 -> 6), the source-capability table, the operator doc and a 6-rule gate. Fusion suite 683 -> 700. Claim row is PARTIAL: no osquery agent runs in CI, and the EDR connectors return vendor detections rather than process telemetry, so the plan's "CrowdStrike, Defender, SentinelOne" wording is not satisfiable with these connectors. |
| 2026-10-11 | 6.1 | Reproduced: the new gate reported nine problems across five of eight rules on the unmodified tree. Built `aisoc_ai_assets` (migration 110), its routes behind a new `ai_estate:*` permission pair, the fusion recorder that writes it on the default profile, the `AIAsset` graph label with `OPERATES`/`HOSTS` edges, and the `/ai-estate` page. Two negative controls against a real PostgreSQL: reverting `NULLS NOT DISTINCT` turns one provider-key row into three, and a `USING (true)` policy leaks across tenants. Claim matrix 302 -> 303 rows, 300 GATED. Writing the gate found two blind spots in the gate itself. |
| 2026-10-09 | 3.1 | All 74 decided. 50 translated into `wd-*` rules derived from each original's own clauses and replayed through the real engine (162 assertions); 24 refused with a reason across five kinds. `MAX_UNREACHABLE` 119 → 45, published executable 2,603 → 2,529, windowed 18 → 68. Three findings recorded as D4–D6 below. |
| 2026-10-11 | 8.1 | parity 4.1's containerised-IdP leg **observed to pass**, both halves: `keycloak-oidc` verifies a real `id_token` against Keycloak's published JWKS with an audience-mismatch negative control, and `keycloak-saml` walks the whole SP-initiated flow to the real ACS and signs `alice@example.com` in as `infosec`, with an untrusted-key control answering 400. Run `38124780886`, as `ENVIRONMENT=test` against the DML-only `aisoc_app` role. The SSO claim row moves PARTIAL → GATED on that evidence. Building it found two shipped defects no self-authored provider could expose: `resolve_saml_connection` bound `:i` untyped so `:i IS NULL` raised on asyncpg, and Keycloak's default role-list mapper emits one `<Attribute Name="Role">` per role, which python3-saml refuses. |
| 2026-10-11 | 8.1 | WebAuthn as a console second factor and MFA enforced per role. Fixing the branch's own gates found three `passkey_credentials` reads scoped by user id alone on a tenant-scoped table, and a permission-model violation where the MFA policy route imported `ROLE_PERMISSIONS` directly; the role *vocabulary* now has one owner in `role_grants.known_roles()`. 23 of 23 live cases pass against real Postgres, and deleting the login integration fails 14 of them — measured, where the workflow had said eight. |
| 2026-10-11 | 8.1 | An enforced audit retention window with a re-anchored checkpoint, ADR-0013, and 12 live cases. Writing them found that migration `111` declared `ON DELETE CASCADE` on the checkpoint table and then made the cascade impossible; and, separately, that `audit_log`'s own trigger from migration `101` blocks `DELETE FROM tenants` for every tenant that has written a row, so tenant deletion is impossible on `main`. Reproduced and filed as #1330 rather than fixed here. |
| 2026-10-11 | 8.1 | Opt-in per-tenant limit enforcement (migration `113`, D12), wired to `POST /connectors` and `POST /tenants/me/users` through one helper, with `GET`/`PUT /usage/enforcement` as the operator surface. Nine live cases, half of them positive controls: a guard that never refuses fails 1, a guard stuck closed fails 4. |
| 2026-10-11 | 8.1 | axe extended to the case list and case workspace, the two of parity 4.7's five views that were left out. Four real defects found and fixed: two `<select>` controls with no accessible name (one of them the control that writes a case's status), two indistinguishable `<aside>` landmarks, and panel headings at `h3` directly under the page's `h1`. |


| 2026-10-11 | 7.1 | Reproduced: against the unmodified tree, `registry.list_vendors_for_capability` returned `[]` for all five mailbox verbs and `dispatcher.dispatch` answered `executor_not_found` for `purge_email` over 79 registered builtin arms -- a phishing response that could block the sender's domain at the firewall and could not remove the message it arrived in. Added the five verbs to both halves of the vocabulary, two mail clients (Graph, Gmail with per-mailbox domain-wide delegation), ten vendor arms, migration `104`, three intake adapters, campaign grouping, the governed fan-out and a report-mailbox worker. Only documented vendor APIs: purge is a soft delete on both and `restore_email` is a real reverse; there is no tenant-wide sender block because neither vendor exposes one through these APIs, and the per-mailbox scope is in the summary an analyst reads rather than only in a docstring. Everything ships off. Negative controls recorded in the PR: defaulting the feature flag on reds four tests, inverting the verification probe's polarity reds two, reading the envelope sender instead of the preserved headers reds four adapter tests including the one asserting the report mailbox is not proposed for purge, incrementing `recipient_count` instead of recomputing it reds the grouping test, and dropping `recipient_count` from the per-mailbox dispatch reds the fan-out test -- which is the quiet way a SEVERE action becomes a MODERATE one. Gates: `check_action_contract` 86 -> 97 executors, `check_module_reachability` 981 -> 986 of 1014, `check_route_authz` 262 -> 265 authorizing with both ceilings unmoved, matrix 302 -> 303 rows. Actions suite 1158 -> 1228; api 44 new cases, 17 of them against a real Postgres with the full chain. Recorded as **PARTIAL**, not GATED: no Microsoft 365 or Google Workspace tenant was exercised (D-7.1). |
| 2026-10-11 | 7.2 | Reproduced: `grep -rl "authentication-results" services/` returned no match on the unmodified tree, so nothing in the product read a sender-authentication header and a message whose SPF and DMARC had both failed produced a verdict that had never looked. Built header analysis with a three-valued result, URL submission through the existing sandbox contract, the attachment hash lookup the submit path already had, and `evidence_cited` citations into the investigation ledger. Migration `111` stores the headers on the submission so a retriage replays them rather than re-fetching a message the purge has usually removed. `analysed` and `unanalysed` are counted separately in three places and summed in none. Negative controls: treating `none`/`neutral` as passes reds two tests; silently skipping an unanalysable URL reds three. **That second control is the finding worth keeping** -- it failed to fail on the first attempt, because every test built its own `ArtefactResult` list and never ran the producer, so five cases were added that drive `analyse_message` with the registry patched empty. A second finding came from the ledger suite's teardown: deleting a run cascades to its events and migration 008's trigger refuses, so the fixture was dropped rather than the append-only control defeated. Gates: matrix 303 -> 304 rows (300 GATED), `check_text_bind_casts` and `check_raw_sql_columns` clean over 6 new columns, `check_route_authz` unmoved. 45 new api cases, 6 of them against a real Postgres with the full chain. |

### D-7.1 -- No Microsoft 365 or Google Workspace tenant was exercised

Every mailbox verb in 7.1 is built against the vendors' documented request
shapes and asserted with a recorded `respx` mock: the Graph `$filter` on a
bracketed `internetMessageId`, the `move` to `recoverableitemsdeletions`, the
inbox `messageRules` body, Gmail's `rfc822msgid:` operator, `trash`/`untrash`
and the settings filter. **Nobody has watched either vendor accept any of
them.** The maintainer-only list already carries "provide cloud and SaaS test
tenants"; this is the same block, named here so the claim row's PARTIAL has a
reason a reader can find.

Two specific consequences, stated rather than implied. A decoder and a fixture
that share an author share a misreading, so a field Graph spells differently
from the reference would pass every test here. And the Gmail filter body and
the Graph inbox-rule body were written from the API reference rather than
taken from a working call, which is the half of `block_sender` least likely
to be right first time.

The claim row returns to GATED when a live tenant is available. Nothing was
weakened to accommodate this: the row says PARTIAL, the operations page says
"treat the first run against your own tenant as the first run", and the
CHANGELOG entry says it too.
| 2026-10-11 | 2.5 | Reproduced: `test_posture_snapshot_coverage.py` on the unmodified tree asserted the *gap* — every resolver in `effective_permissions/` was pure and the only production snapshot source returned `{}`, so every live call 412'd and the subsystem had never answered a question about a real estate. Five collectors now exist under `services/connectors/app/connectors/posture/`, reached by a `__posture_snapshot__` sentinel through each connector's `get_resource_config`, and the coverage test is inverted: it now fails when a registered resolver has no declared collector. Building it found three things worth recording. (a) `BaseConnector.get_resource_config` declares `at_ts: str | None = None` while AWS, Okta and GitHub each required a positional `ts`, so a caller written against the base class raised `TypeError` on three of the connectors — standardised, with `test_every_implementation_matches_the_base_signature` holding it. (b) Google Workspace's directory read needs scopes the audit-log credential is not consented for, so the JWT is now built per scope: asking for both in one assertion would have broken alert polling on every tenant that had not pre-consented the new ones. (c) A snapshot is only an answer if you know *when* it was true — an alert is triaged minutes to days after the event, and a single mutable "current posture" row answers "what can this identity do now" while appearing to answer "what could it do when it acted", which is the worse failure because the number looks right. Migration 103 therefore versions snapshots on `valid_from`/`valid_until` (`valid_to` in the plan; `valid_from`/`valid_until` is the existing spelling in migration 018 and two spellings of one concept in one schema is worse than a recorded deviation — D17). Negative controls, both run against live Postgres and both restored: dropping `posture_snapshots_live_idx` leaves `test_a_second_live_row_is_refused_by_the_database` reporting `DID NOT RAISE IntegrityError`, and defeating the content-hash comparison in `save_snapshot` fails `test_unchanged_recollection_does_not_open_a_version` with two distinct row ids — without that comparison an unchanged estate re-collected hourly writes a version an hour and "when did this posture last change" becomes unanswerable because every row is a change. Evidence: 12 posture-store tests against live Postgres with the migration chain applied, 65 across the posture and effective-permission suites, 1,145 connector tests, 4,774 API tests. Eleven API failures are pre-existing on `main` and unrelated — recorded as D18. |
| 2026-10-11 | 7.3 | Reproduced: `OktaConnector.normalize()` returned `None` for `session_id`, `src_asn`, `user_agent`, `client_browser` and `mfa_satisfied` on a System Log row carrying all five, so the family had nothing to group by and could not have been written. Same shape as the `outcome` hoist in #1279 -- the engine flattens `raw_event` one level and `authenticationContext` arrives as a dict. Hoisted the session, network and client fields on Okta and Entra, then wrote four rules grouping by **session** rather than by user: three distinct-value rules at threshold 2 and one ordered sequence at critical. Fixtures hand-authored from an Okta System Log row and a Graph `signIn` resource; the negative twin inverts only the clause each rule is about. Windowed 72 -> 76; executable detections unchanged at 2,511, because a windowed rule is not in that corpus. Negative controls: removing the `session_id` hoist reds 4 connector tests; switching one rule's `group_by` to `actor_email` reds 2 engine tests. Two findings recorded as D-7.3a (the threshold engine windows by arrival and only sequences window by event time) and D-7.3b (the reported-message link is deferred with a reason). |

### D-7.3a -- The threshold engine windows by arrival, not by event time

Found by a test that failed. An earlier version of
`test_a_replay_outside_the_sequence_window_does_not_fire` fed two events whose
`event_time` fields were two hours apart and expected the threshold rules to
stay quiet. They fired, because `_evaluate_thresholds` scores each Redis
member with `time.time()` while `_evaluate_sequences` reads
`parse_event_time`. Both events arrived in the same second, so the window
never moved.

This is recorded rather than patched. Arrival-time scoring is what makes a
threshold cheap, and a connector polling a vendor every five minutes delivers
a burst whose arrival order is the only clock fusion has for it. The
consequence is specific and worth knowing: **the one-hour figure on the three
`wd-aitm-*` threshold rules is a budget on ingestion, not on the vendor's
timestamps.** A replay that happened an hour ago and is polled now lands in
the same window as the sign-in. For this family that direction is the safe
one -- it widens rather than narrows -- but a future rule whose correctness
depends on the vendor's clock needs a sequence, not a threshold.

### D-7.3b -- The reported-message half of 7.3 is deferred, with the reason

The plan's 7.3 asks for the session-reuse family "plus the link from a
reported message whose URL precedes that sign-in". The session half is
implemented and gated. The link is not, and inventing it would have been
worse than deferring it.

The obstacle is not effort, it is that nothing can feed it today. The
reported-message URLs live in `aisoc_phishing_submissions` in `services/api`
(depth 7.1), and the windowed engine consumes Kafka events in
`services/fusion`; fusion has no read of the API's tables and should not grow
one for a detection. The alternative -- staging a *gateway's* phishing
verdict instead of AiSOC's own reported-message corpus -- was examined and
refused: the one secure-email-gateway connector in the tree, `proofpoint`,
fetches `/v2/siem/messages/blocked` only, so it never sees a click, and its
`normalize()` emits neither the recipient nor the URL. Hoisting fields for an
event the connector does not fetch is a rule that cannot fire wearing a rule
that can.

What would close it, in the order it has to happen: `proofpoint` (or a
`netskope` / `zscaler` web arm) fetching click events and emitting
`recipient`, `url` and the gateway's classification; then a sequence rule
staging that click and the MFA-satisfied sign-in by the same principal. The
AiSOC-authored half -- joining a tenant's *own* reported-message URLs to a
sign-in -- belongs in the API beside the campaign store rather than in
fusion, as an enrichment on the alert the session rules raise.
