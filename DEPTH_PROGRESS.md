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

## Migration and ADR numbers claimed

Phases run in parallel lanes, so a number is claimed here **before** the file
is written. Next free at capture: migration `095`, ADR `0010`
(`docs/decisions/`, not `docs/adr/` -- the plan's wording; the directory is
`decisions/` and the highest is `0009-auto-close-without-an-earned-grant.md`).

| Number | Claimed by | Status |
|---|---|---|
| (none yet) | | |

## Phase 0: Kickoff

- [x] **0.1** `DEPTH_PROGRESS.md` exists (this file), modelled on
  `PARITY_PROGRESS.md`.
- [x] **0.2** Every figure re-derived against the base commit. See below.
- [~] **0.3** Baselines captured. Four of five recorded; `make up-full` and the
  hosted-model matrix are noted under Deviations.

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
publish `0.000` where it means "not measured". Phase 1.4 adds local 7--8B
candidates, which need no key and *can* be measured here; the hosted rows stay
`[!]` until the maintainer funds a key.

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

### D11 -- Identity privilege reads a table a tenant must populate

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

## Phase 1: Verdict quality you can publish

- [ ] **1.1** Balanced, labelled verdict corpus
- [ ] **1.2** Scorecard: balanced accuracy, MCC, per-class precision/recall,
  Wilson interval, false negatives, auto-close precision, escalation rate,
  time to verdict
- [ ] **1.3** Close `fake_tool_output` structurally (≤ 0.10 tuned and held-out)
- [ ] **1.4** A 7--8B local model in the matrix, chosen by score
- [ ] **1.5** `make replay-eval` design-partner kit
- [ ] **1.6** Published "Verdict quality" table with a `--check` drift gate

## Phase 2: A semantic layer and live posture

- [ ] **2.1** OCSF classes beyond five
- [ ] **2.2** Activity projection on every event
- [ ] **2.3** Event classification catalogue
- [ ] **2.4** Sessions per principal
- [ ] **2.5** `__posture_snapshot__` collectors (AWS, Azure, GCP, Workspace, GitHub)
- [ ] **2.6** Use the posture everywhere
- [ ] **2.7** Entity context in CORE (ADR first)

## Phase 3: Detection depth for cloud, identity and SaaS

- [x] **3.1** Translate the 74 windowed `det-*` rules — 50 translated, 24
  refused with a reason. `MAX_UNREACHABLE` 119 → 45.
- [x] **3.2** Ordered sequences and Sigma correlations — the windowed engine
  stages ordered and unordered sequences; all four translatable Sigma
  correlation types compile. See D7 and D8.
- [x] **3.3** Enrichment inputs (parity 5.5) — identity privilege and a
  per-tenant first-seen store built; 18 rules retired with a reason.
  `MAX_UNREACHABLE` 45 → 2. See D9–D11.
- [ ] **3.4** Behavioural baselines in CORE
- [ ] **3.5** Threat-and-anomaly condition rules
- [ ] **3.6** 395 → at least 800 cloud, identity, SaaS and code conditions
- [ ] **3.7** Detection engineering agent (gap-closure Phase 9 / parity 6.2)

## Phase 4: Collection and scale

- [ ] **4.1** Cloud-native collection (S3+SQS org trail, Pub/Sub, Event Hubs)
- [ ] **4.2** Standard inputs (syslog, OTLP, Kafka, TAXII 2.1)
- [ ] **4.3** Retention the tenant chooses
- [ ] **4.4** Throughput (parity 6.9) and a cloud-hardware run
- [ ] **4.5** Deployment completeness (parity 6.8)

## Phase 5: Response that finishes

- [ ] **5.1** Steps that act (parity 5.3)
- [ ] **5.2** Delivery (parity 5.7)
- [ ] **5.3** `wait`, `parallel`, `loop` with idempotency keys
- [ ] **5.4** Stateful user and manager verification
- [ ] **5.5** Executor arms 74 → at least 150
- [ ] **5.6** Plain-language playbooks

## Phase 6: AI agent security

- [ ] **6.1** AI asset inventory
- [ ] **6.2** Endpoint discovery with no new agent
- [ ] **6.3** Provider coverage beyond OpenAI and Anthropic
- [ ] **6.4** Agent identity and baselines (parity 6.7)
- [ ] **6.5** AI rule pack
- [ ] **6.6** AI containment and kill-switch

## Phase 7: Phishing operations

- [ ] **7.1** Intake to purge (gap-closure Phase 10 / parity 6.4)
- [ ] **7.2** Header, URL and attachment analysis
- [ ] **7.3** Adversary-in-the-middle session reuse

## Phase 8: Enterprise gates

- [ ] **8.1** Identity and administration
- [ ] **8.2** ABAC, elevation and workload identities
- [ ] **8.3** Buyer security pack

## Phase 9: Analyst surfaces

- [ ] **9.1** MCP over streamable HTTP (parity 6.6)
- [ ] **9.2** Semantic memory (parity 6.5)
- [ ] **9.3** Case depth (parity 5.6 remainder)
- [ ] **9.4** War rooms
- [ ] **9.5** Hunt to report
- [ ] **9.6** Native responder

## Phase 10: Close the books

- [ ] **10** Re-run touched claim rows, update sibling progress files, one
  `[Unreleased]` entry per phase, final report here

## Item log

| Date | Item | What happened |
|---|---|---|
| 2026-10-07 | 0.1 | This file created at base commit `1b8bc2d4`. |
| 2026-10-07 | 0.2 | Every figure re-derived. Two matched exactly (detections, unreachable families); executor arms measured 74 against a captured 73; the cloud/identity/SaaS/code figure measured 395 against a captured 461 on a grouping the plan does not pin, recorded above. Two measurement caveats found: executable and quarantined overlap by 1,724 rules, and the "69% Windows" figure does not reproduce from the index. |
| 2026-10-07 | 0.3 | `make up` and `make smoke` (10/10) pass. Injection suite and load-harness baselines committed. `make up-full` deferred (D2) and hosted model rows blocked (D3). Fixing D1 was a precondition for the load-harness baseline. |
| 2026-10-09 | 3.3 | Identity privilege (18 rules) and a per-tenant first-seen store (2) built; 5 rules were never unreachable (gate operator drift, D9); 18 retired with a reason (D10). `MAX_UNREACHABLE` 45 → 2, the two remaining both needing the 3.4 baseline. Two matcher operators three shipped rules already used were implemented. |
| 2026-10-09 | 3.2 | Ordered and unordered sequences in the windowed engine; all four translatable Sigma correlation types compile, seven refusal reasons recorded. No upstream correlation rule exists in this tree to import (D8), so the corpus is first-party and labelled as such. |
| 2026-10-09 | 3.1 | All 74 decided. 50 translated into `wd-*` rules derived from each original's own clauses and replayed through the real engine (162 assertions); 24 refused with a reason across five kinds. `MAX_UNREACHABLE` 119 → 45, published executable 2,603 → 2,529, windowed 18 → 68. Three findings recorded as D4–D6 below. |
