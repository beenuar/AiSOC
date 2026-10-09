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

- [ ] **3.1** Translate the 74 windowed `det-*` rules
- [ ] **3.2** Ordered sequences and Sigma correlations
- [ ] **3.3** Enrichment inputs (parity 5.5)
- [ ] **3.4** Behavioural baselines in CORE
- [ ] **3.5** Threat-and-anomaly condition rules
- [ ] **3.6** 395 → at least 800 cloud, identity, SaaS and code conditions
- [ ] **3.7** Detection engineering agent (gap-closure Phase 9 / parity 6.2)

## Phase 4: Collection and scale

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
| 2026-10-09 | 4.1 | Reproduced: `check_cloud_native_collection.py` on the unmodified tree reported all three collection paths absent. Implemented `aws_cloudtrail_s3` (SQS-notified S3 objects; management events, data events and VPC flow logs; delete-after-emit), `gcp_pubsub` (REST pull on a log-sink subscription; ack-after-read) and `azure_event_hubs` (Capture blobs over the Data Lake Gen2 JSON API, with a focused Avro OCF reader). Negative controls recorded in the PR: deleting the SQS message before the object is read, acknowledging the Pub/Sub batch before it is built, ignoring the Avro union branch index, and ignoring the flow-log header line each fail a named test, and all were restored. Connectors suite 1014 -> 1098 passed. |
