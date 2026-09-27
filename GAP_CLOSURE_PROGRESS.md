# Gap-closure program progress

Mirrors [`plans/aisoc_gap_closure_plan.plan.md`](plans/aisoc_gap_closure_plan.plan.md),
which is a locked plan and is never edited. This file is the mutable half: it
records what has shipped, what is in flight, what is blocked and on whom, and
every place the plan and the tree disagreed.

**Legend:** `[ ]` open · `[~]` in flight · `[x]` shipped · `[!]` blocked, with
the exact request recorded.

**Program started:** 2026-09-26 against `main` at `2ad20dd7`, v11.2.0.

---

## Pre-existing state, captured before any code was written

The plan requires a baseline so this program is never blamed for a failure it
did not cause. Captured on the worktree at `2ad20dd7` with no gap-closure
changes applied.

### Test suites: zero pre-existing failures

Every suite was run the way `ci.yml` runs it (per service, from the service
directory, `PYTHONPATH=.`).

| Suite | Result |
|---|---|
| `tests/` (root, excluding `tests/isolation`, which needs live containers) | 1014 passed |
| `services/agents` | 1252 passed, 3 skipped, 2 xfailed |
| `services/api` | 2791 passed, 33 skipped |
| `services/actions` | 737 passed |
| `services/connectors` | 880 passed |
| `services/fusion` | 341 passed |
| `services/ueba` | 112 passed |
| `services/threatintel` | 86 passed |
| `packages/aisoc-benchmark` | 35 passed |
| `packages/aisoc-cli` | 40 passed, 1 skipped |

**Total: 6388 passed, 37 skipped, 2 xfailed, 0 failed.**

Nine suites initially reported collection errors. Every one was a dependency
absent from the local virtualenv rather than a defect: `sqlalchemy`,
`aiokafka`, `PyJWT`, `neo4j`, `bcrypt`, `sqlglot`, `strawberry-graphql`,
`apscheduler`, `aiosqlite`, `qdrant_client`. CI installs each from the service
lockfiles. They were installed locally and all ten suites then passed, so the
figures above are measured rather than excused. This is recorded because a
collection error reads like a failure in a log, and a future session that skips
the install would otherwise attribute ten red suites to this program.

### Gates: zero pre-existing failures

All 46 `scripts/check_*.py` gates were run. 43 pass outright. The three that did
not return zero are invocation or credential artifacts, not findings:

| Gate | Result | Why it is not a finding |
|---|---|---|
| `check_attribution.py` | exit 2 with no argument | Refuses to run without a scan target, by design. With `--all`: **OK, 12376 tracked files scanned, no attribution found.** |
| `check_codeql_alerts.py` | exit 2 with no token | Needs `security-events: read`. With `--offline`: **OK, workflow wiring sound**, and it correctly reports the alert count as NOT VERIFIED rather than clean. |
| `check_mypy_baseline.py` | exit 1 | Interpreter skew, and the gate predicts it in its own output. See below. |

`check_mypy_baseline.py` reports `scripts/run_evals.py: 15 index findings,
baseline records 13`. The gate's own note in the same run reads: *"this run is
on python 3.12 and the baseline was recorded on 3.11 ... PEP 701 changed how
f-string sub-expressions are attributed to source lines in 3.12, which splits
some findings that 3.11 reports once. Measured: 2 findings in
`scripts/run_evals.py` out of ~990."* The delta is exactly 2, in exactly the
file named. `ci.yml` pins `python-version: '3.11'` at all seven setup steps, so
CI compares like with like. Not a regression, and not something this program
introduced.

**How a regression will be told apart from the above:** any new failure in a
suite listed as passing, any gate moving off `OK`, or any mypy delta in a file
other than `scripts/run_evals.py` or larger than 2 findings, is this program's
and gets fixed before the PR merges.

### Reference points measured at baseline

- Claim-to-gate matrix: **147 rows, 139 GATED, 8 PARTIAL, 0 NO GATE**, ratchet ceiling `MAX_NO_GATE=0`.
- `README.md`: **249 lines** against a 250 cap. There is one line of headroom, so new claims link rather than add.
- Ruff pin read from the tree: `ruff>=0.16.8,<0.17` (`ci.yml`, `ai-sdk.yml`, `python-detections.yml`). Local runs use 0.16.9.
- Latest migration: `063_cost_provenance.sql`. Next free number is **064**.

---

## Deviations: where the plan and the tree disagree

The plan was captured against v11.2.0 and is locked. Where it names something
that has moved, already exists, or works differently, the code wins and the
difference is recorded here.

### D1. `services/api/app/services/llm_safety.py` exists, and the plan is right to name it

The kickoff brief for this session stated that this module does not exist, that
`services/api` has no LLM input contract at all, and that only
`services/agents/app/llm/contract.py` is real. **That is no longer true.** The
module is present at `2ad20dd7`, is 130 lines, is fail-closed, and validates
before the network call rather than after.

The correction is itself a stale reading of an older audit. The module's own
docstring records the history: the repository notes claimed it existed, it did
not, and it was subsequently written. It now re-exports `LLMInputContract`,
`LLMContractViolation`, `classify_message`, `is_contract_enforced` and
`validate_messages` from `app/_vendor/llm_contract_rules.py`, which
`scripts/sync_vendored_llm_contract.py --check` keeps byte-identical with the
agents service so the two halves cannot disagree about what counts as a raw log.
`CLAIM_TO_GATE_MATRIX.md` carries a GATED row for it.

**Resolution:** follow the plan as written. Prompts raised in `services/api` go
through `app.services.llm_safety`; prompts raised in `services/agents` go
through `app.llm.contract`. Neither is a substitute for the other, and
`test_llm_contract_no_bypass.py` plus the api job's `test_llm_safety.py` both
already enforce it. Nothing to build here.

### D2. Migration 063 is the latest, as the plan says

Verified against `services/api/migrations/`. `063_cost_provenance.sql` is the
highest number present. Phase 1's tables take **064**.

### D3. `POST /api/v1/evaluations/replay` must not be built on the existing `replay.py`

`services/api/app/api/v1/endpoints/replay.py` already exists and is unrelated
work: it publishes a redacted investigation ledger to a public share link at
`/r/{slug}`. Phase 1.4's evaluation job is a different noun that happens to
share a word. It gets its own module so the two surfaces never collide, and so
a reader looking for share-link publishing is not handed replay evaluation.

### D4. The tracker the plan's ancestors pointed at is gone, and its replacement is committed

`docs/audit/PROGRESS.md` is in `.gitignore` and was never committed.
`docs/audit/DEFERRED_SUBPHASES.md` replaced it and carries the six lettered
deferrals (3.5+, 5b, 7b+, 9b, 10b, 11b). This file follows that precedent and
is committed for the same reason: a tracker that is not in the repository is a
tracker that does not exist.

### D5. No history-reader or replay-evaluation code exists anywhere in the tree

Checked before writing anything, because the repository's most repeated lesson
is that a "missing" capability often already exists unwired. Searched
`services/`, `packages/` and the five SIEM clients for closed-finding readers,
replay runners and evaluation scoring. None of the five clients
(`splunk_client.py`, `sentinel_client.py`, `elastic_client.py`,
`qradar_client.py`, `defender_client.py`) has a list-closed-findings method.
Phase 1.1 is genuinely new work, and the writeback direction it mirrors
(`disposition_writeback.py`) already exists and supplies the taxonomy.

### D6. No two services can be imported into one process, so the connector `normalize()` is reached over HTTP

The plan says "normalize each finding with the same connector `normalize()`
production uses", and it is right to. Grading the agent on an input shape the
product never produces measures a pipeline nobody runs.

It cannot be done by importing. `services/agents`, `services/connectors` and
`services/actions` all package their code as top-level `app`, so one Python
process can hold exactly one of them, and no path manipulation changes that.
The two remaining options were a copy of every vendor's field mapping inside
the agents service, kept in step by discipline, or a round trip to the service
that owns the mapping.

**Resolution:** a round trip, through a new `POST /connectors/{id}/normalize`.
This is the same reasoning that already put organisation memory and SIEM
writeback behind HTTP calls to the API service rather than behind a second copy
of their SQL. The handler builds the connector with `__new__` and never runs
`__init__`, so the route holds no credential and cannot call a customer's SIEM;
a connector whose `normalize` does reach for instance state gets a 422 naming
itself rather than returning a half-mapped envelope. Eleven of the 84
registered connectors take that path today, and a parametrised test asserts
every connector either normalizes or says why.

The runner keeps a `FindingNormalizer` port with **no fallback**. A replay that
cannot reach the production mapping raises `NormalizerUnavailable` and names
what is missing, because a "close enough" mapping written in the agents service
would be invisible in the report: its output has the same shape as the real
thing.

### D7. What a replay measures is triage, not the pipeline

The plan's chain is connector `normalize()` then triage. Production's chain has
`services/ingest` and `services/fusion` in between, and fusion is where an
alert gains correlation across related events, its fused confidence score, the
deterministic narrative and entity resolution.

A replayed finding carries none of those. Reproducing them in the agents
service would be the reimplementation the plan forbids, one layer down.

**Resolution:** the gap is published rather than closed. `ENVELOPE_LIMITS` in
`app/replay/normalize.py` lists the four missing enrichments and travels in
every report's method section, and `confidence_score` is deliberately left
unset rather than invented, since a fabricated fusion confidence would enter
the prompt that decides the verdict being graded.

### D8. Phase 1.4 has to be orchestrated by the API, and the "Done when" decomposes

Recorded before building it, because the obvious design does not work and the
reason is structural rather than a matter of taste.

**No process can hold two of these services.** `services/actions` owns the SIEM
credential path and the history readers. `services/agents` owns triage.
`services/connectors` owns `normalize()`. All three package their code as
top-level `app`. A CLI that imported the reader and the runner would import two
modules called `app` and get one of them.

**So the API orchestrates.** It is already the service that does this: it holds
the vault and the tenant session, and it already proxies
`/cases/{id}/investigate` to agents and dispatches live actions to actions. The
job is `POST /api/v1/evaluations/replay` (new module, **not**
`endpoints/replay.py`, which is share-link publishing and unrelated - see D3),
calling actions for history and agents for the shadow triage, and scoring with
`packages/aisoc-benchmark`. The benchmark package is a distribution rather than
a service, so the API can import it directly; that is the one link in the chain
with no round trip.

What remains, in dependency order:

1. An internal route on `services/actions` returning `ClosedFinding` rows for a
   connector instance and a window. The readers exist; nothing exposes them.
2. An internal route on `services/agents` accepting findings plus a context
   snapshot and returning `ReplayDecision` rows. `ReplayRunner` exists; nothing
   exposes it.
3. Migration **064** for a tenant-scoped `aisoc_replay_evaluations` table, with
   an RLS policy satisfying `check_rls_policy_shape.py` and `aisoc_app` grants.
4. The two API routes, default-deny, tenant from the credential.
5. `aisoc replay` in `packages/aisoc-cli`, driving the API. The CLI already
   discovers a repo root for `serve` and `db upgrade`.
6. The console page and the PDF export, on the existing report pipeline.

**The phase's "Done when" decomposes into four links, and three are already
proven.** It reads: the CLI, against a mocked Splunk ES holding 200 recorded
closed notables, produces a report that reproduces byte for byte on a second
run with the deterministic model path.

| Link | Status |
|---|---|
| Mocked Splunk to 200 closed findings | Proven in `services/actions/tests/test_alert_history.py` (Phase 1.1), against vendor-shaped payloads on the real HTTP path |
| Findings to decisions, reproducibly | Proven in `services/agents/tests/test_replay_runner.py::test_two_runs_over_one_history_produce_identical_decisions`, identical on every field but wall-clock latency |
| Decisions to a byte-identical report | Proven in `packages/aisoc-benchmark/tests/test_replay_metrics.py::test_scoring_the_same_decisions_twice_gives_the_same_report`; the bootstrap seed and resample count travel in the report |
| CLI to API to report, end to end | **Not built, therefore not proven** |

Three proven links are not the same claim as one end-to-end run, and the phase
must not be recorded as done until the fourth exists. Note also that a true
end-to-end run spans three services, so its home is an integration test with
containers rather than any service's unit suite.

Deviations D9 onward were recorded after the phase sections below and sit
at the end of this file. The numbering is one sequence; only the placement
differs, because two phases were in flight at once.

---

## Phase 1: Replay evaluation on a customer's own history

- [x] **1.1 History readers.** Shipped in [#903](https://github.com/beenuar/AiSOC/pull/903). Five readers on the clients in `services/actions`, which already own the credential path and already hold the writeback going the other way: `SplunkClient.list_closed_notables`, `SentinelClient.list_closed_incidents`, `ElasticClient.list_closed_signals`, `QRadarClient.list_closed_offenses`, `DefenderClient.list_resolved_alerts`. One taxonomy module (`app/services/alert_history.py`) rather than five that could disagree. 30 tests drive each reader's real HTTP path against vendor-shaped payloads; the `services/actions` suite goes 737 to 767. Claim-to-gate row added, matrix 147 rows to 148, GATED 139 to 140. Two vendor decisions recorded in `apps/docs/docs/evaluation/replay.md`: Elastic ships no disposition field so an untagged deployment yields no labels, and QRadar "Non-Issue" is `benign` not `benign_true_positive` because it makes no claim about whether the rule was right.
- [x] **1.2 Replay runner.** Shipped in [#904](https://github.com/beenuar/AiSOC/pull/904). `services/agents/app/replay/` holds the split, the shadow sinks and the runner; it holds no triage. Persistence is injected through `app/workers/triage_persistence.py`, whose default is `LiveTriageWriter` doing exactly what the worker did inline, so the measured path is the production one rather than a copy. `CostTracker` gained a `persist` flag so a replay measures spend without billing it. Normalisation reaches the real connector through a new `POST /connectors/{id}/normalize`, because both services package their code as top-level `app` and one process can hold one of them. Verdict, confidence, evidence, tool calls, model id, tokens, measured cost and latency are all recorded per decision. See D6 and D7 below for the two places the plan and the tree disagreed.
- [x] **1.3 Scoring.** Shipped in [#904](https://github.com/beenuar/AiSOC/pull/904). `packages/aisoc-benchmark/aisoc_benchmark/replay.py` reuses the existing `_INDICATOR_PATTERNS` for hallucination so there is one definition, and adds per-class precision and recall with malicious recall first, a confusion matrix, abstention rate, reliability bins with an expected calibration error, per-rule and per-source breakdowns, and seeded bootstrap intervals. Below 30 malicious cases the headline accuracy is withheld with the count and the reason. A rate with no denominator reads "not measured".
- [x] **1.4 Surfaces.** Shipped in [#907](https://github.com/beenuar/AiSOC/pull/907). Built to the shape D8 records: the API orchestrates, driving two new internal routes (`POST /replay/history` on actions, `POST /replay/run` on agents) and scoring in process through a byte-identical mirror of `packages/aisoc-benchmark` under `services/api/app/_vendor/`, since the API image's build context excludes `packages/`. `aisoc replay` drives the API and renders nothing of its own; progress goes to stderr so `aisoc replay ... > report.md` is the report and nothing else. The console page shows every rate beside the count it was computed over, and prints the withheld-headline sentence in place of a number rather than a dash or a zero. Export reuses `format_replay_report` and `ReplayScore.as_dict` from 1.3 and serves the stored artefact rather than re-rendering it; the PDF is that same Markdown through WeasyPrint, and answers 503 naming the native libraries when they are absent rather than serving an empty file. Migration **065**, not the 064 D8 names: `064_sandbox_upload_policy.sql` landed from Phase 11 while this was in flight, which is exactly why D8 says to check the directory. See D16 for the defect the end-to-end run found.
- [x] **1.5 Gates and docs.** Recorded vendor payload tests per reader shipped with 1.1. The leakage test shipped in [#904](https://github.com/beenuar/AiSOC/pull/904) (`services/agents/tests/test_replay_leakage.py`), covering all three stores a test-window decision can travel back through, each with a sensitivity half that runs the unprotected configuration and asserts it leaks. Three claim-to-gate rows added, matrix 148 rows to 151, GATED 140 to 143. `apps/docs/docs/evaluation/replay.md` covers the method, the limits and the privacy position, and now the three surfaces as well: a "Running one" section for the console, the CLI and the API, and a "Reproducibility, stated precisely" section that names what is excluded and why. Its "what exists today" note no longer hedges, because nothing on the page is unbuilt. Three more claim-to-gate rows added for 1.4, all GATED. The absolute tally moves with whatever else lands, so recount it with `scripts/check_claim_gate_matrix.py` rather than reading a number off this line.

**Done when:** the CLI, run against a mocked Splunk ES holding 200 recorded
closed notables, produces a report that reproduces byte for byte on a second run
with the deterministic model path.

**Met.** `tests/e2e/test_replay_cli_end_to_end.py` is the fourth link, and it
runs exactly that: a mock Splunk ES serving 200 closed notables over the two
REST endpoints `SplunkClient.run_search` actually calls, four services started
from the working tree with uvicorn, a real administrator created by the
deployment's own bootstrap script and signed in through the real login route
(the dev-mode bypass would have skipped the `connectors:write` and
`reports:read` checks these routes declare), and the CLI invoked twice. The two
reports are identical as bytes. Measured on this worktree: 200 findings read,
200 carrying an analyst label, 60 replayed and graded, 40 malicious, headline
printed rather than withheld.

Two things stop that from being a vacuous pass. A second assertion fetches both
reports **without** the latency exclusion and fails if more than that one line
differs, so a stripped artefact cannot hide a field that quietly stopped
reproducing. And further assertions require the report to carry the 200 findings
read, the 60-finding graded window and a printed headline, because a withheld
headline reproduces just as reliably while printing far fewer numbers, so a run
that was accidentally thin would weaken the proof without failing it.

Wall-clock latency is the only excluded field, and the exclusion lives beside
the renderer that emits the line rather than in the CLI, so the producer and the
remover cannot drift. The claim is therefore "byte for byte apart from the two
latency figures, over a pinned window, on the deterministic model path", and
each of those qualifiers is load-bearing: an unpinned window is a different
window on a second run, and a hosted model may legitimately differ.

## Phase 2: Live shadow mode and evidence-gated autonomy

- [x] **2.1 Shadow mode**, per tenant and per alert class. Shipped in [#906](https://github.com/beenuar/AiSOC/pull/906), and its second closure path in [#912](https://github.com/beenuar/AiSOC/pull/912), which closes D15. The seam is Phase 1.2's: `FusedAlertTriageWorker` already routes every write through the `TriageWriter` port, so shadow mode is a wrapper around the tenant's live sink rather than a second code path. Chosen per alert, not per worker, because the class is not known until the alert is in hand; the constructor sinks are untouched, which is what keeps the Phase 1.2 AST test true. Migration **066** adds `aisoc_shadow_mode` and `aisoc_shadow_decisions`. Analyst closures now arrive from both routes the plan names: a bounded sweep over alerts closed in this console, and a scheduled sweep over each measuring tenant's own SIEM on the five Phase 1.1 readers unchanged. See D9 for the one property everything else rests on, and D15 for what the second path cost.
- [x] **2.2 Rolling agreement** per alert class, rule, source and model, on the operations dashboard and the autonomy scorecard. Shipped in [#906](https://github.com/beenuar/AiSOC/pull/906). The metrics are Phase 1.3's and "uses the Phase 1 metrics" is now a gate rather than a sentence: `check_replay_contract_parity.py` went from three trees to four and compares `GRADED_DISPOSITIONS`, `ABSTENTION_VERDICTS`, `MALICIOUS` and `UNLABELED` in both directions, proven capable of failing by drifting each collection in turn. Agreement is computed over *answered* decisions only so abstaining cannot inflate it, malicious recall counts an abstention as a miss, a rate with no denominator reads "not measured", and every rate travels with its count. Matrix 156 rows to 159, GATED 148 to 151.
- [x] **2.3 Promotion gate**, with automatic demotion on drift and every transition written to the hash-chained audit log. Shipped in [#908](https://github.com/beenuar/AiSOC/pull/908). Migration **067** adds `aisoc_autonomy_grants`. The gate is pure and lives in the vendored rules module so `services/actions` enforces the same arithmetic at dispatch that `services/api` decides on at promotion time. Wired into all three modules the plan names: `unified_autonomy.unified_decision` gained an `earned_grant` argument that can only widen the reversible MEDIUM-blast branch, `tenant_policy.TenantPolicy` carries the earned verbs and never issues one, and `autonomy_policy.py` gained `GET`/`POST`/`DELETE /grants`. One of those three was never reachable: `DELETE /{action}` is declared several hundred lines earlier in the same router and FastAPI matches in registration order, so every revocation request was taken by the threshold-reset handler, answered 204 and deleted a row from `aisoc_autonomy_thresholds`. A tenant could earn a grant and had no working way to hand it back, which is this phase's safety control failing one way. Fixed by constraining `{action}` with a path convertor that excludes the router's literal sub-resources, so the exclusion sits in the matching regex rather than in the order of the file. The gate written for this bug class had never seen a route (it read `app.routes`, which `include_router` does not populate on the pinned FastAPI); it now takes its corpus from `app.openapi()` and decides reachability by sending a request, refuses an empty corpus, and is joined by `check_route_shadowing.py` across all thirteen services. Matrix 173 rows to 175, GATED 165 to 167. The dispatcher was also wired, because `unified_decision` turned out to have no production caller at all (see D12). The "Done when" runs against a real Postgres in `integration.yml`. See D13 for why the ceiling stops at L3.

**Done when:** on recorded data, a test tenant cannot enable auto-close for a
class with 20 shadow decisions, can once the thresholds are met, and is demoted
when injected disagreements cross the drift threshold.

**Met.** `tests/isolation/test_autonomy_promotion_live.py`, 13 tests against
`postgres:16` with the full API migration chain applied: refused at 20 with
`insufficient_sample` and `insufficient_malicious` and nothing written, granted
at 150 with the full snapshot, demoted after 30 injected disagreements with
`recent_drift` among the reasons, and the promotion and demotion replayed
through `audit_hash.verify_chain`.

## Phase 3: Prompt-injection evaluation suite

- [x] **3.1 Corpus** of injected incidents paired with clean twins, generated deterministically and labelled synthetic. Shipped in [#913](https://github.com/beenuar/AiSOC/pull/913). `services/agents/tests/adversarial/injection_incidents.py`, 65 pairs (54 adversarial, 11 benign controls) across the six surfaces the plan names. Payloads are written to fit the field they arrive in, which is what makes this corpus harder than the payload corpus beside it rather than a restatement of it. The prose payloads are **imported** from `injection_corpus.py`, not copied, so the two cannot drift. Determinism is a hashed base-incident choice with no RNG and no clock, pinned by a digest. See D17 for the property the twins had to gain before any metric was attributable.
- [x] **3.2 Metrics**: verdict flip rate, unsafe action proposal rate, tool-call deviation, guard detection rate. Shipped in [#913](https://github.com/beenuar/AiSOC/pull/913). `injection_metrics.py` defines all four once, so the suite and the gate that publishes them cannot hold two definitions of "detected". A flip counts only in the attacker's direction and only against the clean twin's verdict; an unsafe action counts only when the injected run proposes containment the clean run did not, because an incident whose correct response *is* to isolate a host would otherwise score as an attack succeeding every time. See D18 for the measurement error this found in itself.
- [x] **3.3 Runs and publishing**: deterministic floor in CI, live rates in the weekly wet eval or "not measured", both on the benchmark page. Shipped in [#915](https://github.com/beenuar/AiSOC/pull/915). `scripts/check_injection_eval.py` is the single entry point for both halves, so the CI gate and the wet eval cannot hold two definitions of "detected". `ci.yml :: p1-eval` runs it with `--check` and `--benchmark-md`, which fails when the published page and a live measurement disagree; `wet-eval.yml` runs it with `--live` inside the preflight-gated job. Four claim-to-gate rows added across the two PRs and the existing prompt-injection row corrected.

**Done when:** CI enforces the guard floor on the corpus, the wet eval emits
live rates or "not measured", and `apps/docs/docs/benchmark.md` shows both.

**Met, with one number deliberately absent rather than filled in.** CI
enforces the floor and the ratchet, and both were proven capable of failing
rather than merely observed passing: the gate is driven red by a guard that
detects nothing, by one silenced payload outside the ratchet, by a ratchet
entry that has gone stale, and by a benign control being flagged. The
benchmark page carries both halves and CI fails when the page and the
measurement disagree.

The wet eval emits "not measured", and that is the honest state rather than a
shortfall: **no funded key exists, so the three behavioural rates have never
been measured on any model.** What was verified is that they cannot be
reported as anything else. An unmeasured `Rate` carries no `value` key, so no
formatter can round it to zero; a live run with no key and a live run whose
every dispatch failed both report the same; and the weekly job is gated on
its preflight, so an unconfigured repository shows *skipped* rather than
passed. That last property is now asserted by a test, and the test was proven
by deleting the `if:` and watching it go red.

**The guard's measured rate against this corpus was 66.7% (36 of 54)** when
the corpus was built, where the prose payload corpus measured the same guard
at 0.852. Both were published with the distinction stated. The gap was a
finding rather than a regression, and 3.4 below is the work it made possible.

- [x] **3.4 Close the field-native gap, and measure whether closing it generalised.** Shipped in [#916](https://github.com/beenuar/AiSOC/pull/916). The guard now reads a **segmented view** of every string in which identifier punctuation is a word separator, so a rule written for an email body reaches a DNS label without being rewritten, and each rule declares which views it is valid on. Containment aimed at a *named target* is matched by the argument's shape rather than by a noun list, on the literal view only, because segmentation is what makes an identifier readable and also what destroys the target's shape. Corpus detection **66.7% to 98.1% (53/54)**, prose corpus **0.852 to 0.96** with false positives still at 0.00, benign controls flagged **2/11 to 1/11** like for like. The offboarding script that cost an analyst automation on every true positive is fixed: tool names match on token boundaries, which `\b` could not do because `_` is a word character. Seventeen of the eighteen ratchet entries are closed and the last is refused with its reason. **The generalisation result is the important one and it is bad: 7.1% (2/28) on held-out payloads (D20).**

**Done when (3.4):** the field-native families are closed on the corpus, the
offboarding false positive is gone, and the change is graded against payloads
authored after it.

**Met, and the held-out grading is the part worth reading.**
`services/agents/tests/adversarial/injection_holdout.py` is 28 adversarial
payloads and 6 benign controls in the same seven surfaces, written after the
guard was committed and never consulted while its patterns were written. The
guard scores **7.1% (2/28)** on it against 98.1% on the corpus it was
hardened against, and the guard *before* this change scores 3.6% (1/28). The
hardening moved the tuned corpus by 31 points and unseen payloads by one
payload. That corpus carries no floor and never will, for the reason stated
in D20.

## Phase 4: Let the investigation agent reach the customer's tools

- [ ] **4.1 Federated search tool** as a typed agent tool; the model never writes SPL, KQL or ES|QL.
- [ ] **4.2 Vendor read tools**, plus new read verbs for SentinelOne, Microsoft Entra ID, Google Workspace, AWS CloudTrail and Microsoft Defender.
- [ ] **4.3 Tool handling**: advertise only configured backends, project and cap results, mark them untrusted, and surface a read failure as "could not check".
- [ ] **4.4 Strategies** updated so `check_investigation_depth.py` still holds.
- [x] **4.5 CORE decision**: measured, decided in [ADR-0007](docs/decisions/0007-connectors-and-actions-in-core.md), implemented. Both services join CORE. Measured with images pulled fresh from GHCR and `docker stats`, the same method as ADR-0006: `actions` 539 MB image / 45.99 MiB cold-start / 48.3 MiB at 40 hours, `connectors` 586 MB / 71.45 MiB / 76.51 MiB, together **124.8 MiB against an 8 GB budget, 1.5%**. Cross-checked against `litellm` at 471 MiB on the same host, which ADR-0006 measured at 451 MiB. ADR-0006's misleading-idle trap was checked for and is absent: neither moves more than 0.6 MiB under 100 requests, because both are network front ends with no model and no index. Both verified to boot and serve with zero configuration. The decision turned on something stronger than a feature gap, recorded as D17: CORE was already *configured* for both and started neither. The README's ~8 GB figure is deliberately not moved, and the lake and graph deliberately stay in `full`.

## Phase 5: MCP client

- [x] **5.1 Client** on the official MCP Python SDK, pinned, streamable HTTP only by default. `services/agents/app/mcp/`, on `mcp==1.30.0` exact-pinned. The 1.x line rather than 2.x deliberately: mcp 2.x depends on `httpx2`, a second HTTP client alongside the `httpx` this service already pins, and two TLS stacks inside the one service that reaches third-party servers is a cost with no return. Exact rather than ranged because the version is the behaviour: this library parses replies from third parties straight into the prompt, and a change in what `readOnlyHint` and `destructiveHint` mean would move what `policy.py` decides.
- [x] **5.2 Registry** in `services/api`: migration **069**, `/api/v1/mcp-servers`, credential in the existing `CredentialVault` under the connector convention rather than a bespoke column. The console never sees a credential (`has_credential: bool`); the agents service reads it over one internal route that is **service-token only with no session fallback**, unlike every other dual-mode route in this service, because a console user who can read their tenant's alerts must not thereby be able to read their operator's vendor token. See D21 for why the credential travels at all.
- [x] **5.3 Read-only by default.** A tool is callable only if the tenant allowlisted it *and* the server did not annotate it `destructiveHint: true` or `readOnlyHint: false`. Both halves, because they are different assertions: the allowlist is the tenant's, the annotation is the vendor's, and either saying no is a no. The allowlist defaults empty, so a newly registered server offers nothing. A destructive tool is refused outright and the refusal names governed dispatch; see D22 for why "or not at all" is the honest half of the plan's sentence today.
- [x] **5.4 Untrusted by default.** Socket-level byte cap, per-run nonce fence, injection guard, an inline first-party boundary sentence, and a ledger row for every call, refusal and failure. The SSRF guard and air-gap policy run immediately before the socket, not at save time; see D23.
- [x] **5.5 Tests and docs.** 40 tests across three files against a real `FastMCP` server over the SDK's memory transport, so nothing mocks `ClientSession` or `McpClient`. `apps/docs/docs/operations/mcp-client.md` marks all five vendor servers unverified against a live vendor, and says the tool names given are examples to be replaced with what the vendor's own `tools/list` publishes.
- [x] **5.6 AiSOC's own MCP server.** Extended, not duplicated: `services/mcp` goes from 13 tools to 18. **The ledger half already existed** (`aisoc_list_investigations`, `aisoc_get_investigation`, `aisoc_replay_decision`, `aisoc_explain_step`), which is recorded rather than re-implemented. New: `aisoc_get_triage_verdict`, `aisoc_list_replay_reports`, `aisoc_get_replay_report`, `aisoc_list_actions` and `aisoc_preview_action`. The preview is dry-run only and cannot become anything else; see D24. Every tool now publishes MCP behaviour annotations, and the published tool count is gated for the first time; see D25.

**Done when:** against a mock MCP server, an investigation calls an allowlisted
read tool, refuses a destructive one, and the ledger records both.

**Met.** `services/agents/tests/test_mcp_investigation.py::test_done_when_an_investigation_calls_a_read_tool_and_refuses_a_destructive_one`
runs exactly that: a real `FastMCP` server publishing `get_detections`
(read-only) and `isolate_host` (destructive), both allowlisted by the operator
**on purpose** so the annotation is what refuses rather than the allowlist; the
real tool loop `deep_investigation` drives; a scripted model that asks for both.
The read tool returns the server's data fenced with the run nonce, the
destructive tool was never bound so the loop's own registry refuses it, and the
real `_LedgerWriter` produces one `mcp_tool_call` row and one
`mcp_tool_refused` row carrying the run id, the resolved tenant and the
classification.

Three things stop that from being a vacuous pass. The destructive tool is
asserted absent from the schemas handed to the provider, not merely absent from
the trace, so "the model did not call it" and "the model was never offered it"
are told apart. The ledger is captured at the **database boundary**
(`ledger.record_event`) rather than by replacing the writer, so the sequence
numbers, the tenant resolution and the payload shape are the ones that would
reach Postgres, and a separate test asserts the sequence numbers are monotonic
and above the graph range, because `ON CONFLICT (run_id, seq) DO NOTHING` drops
a collision silently. And a refusal is separately proven to cost **no network
call at all**, by handing the invoker a session factory that raises the moment
anything asks it for a session.

Not proven: a row landing in a real Postgres, which is the live-container
suites' job, and anything at all against a live vendor MCP server.

## Phase 6: Tenant skills and better triage context

- [ ] **6.1 Tenant-authored skills** in YAML in the console editor, validated against the tenant's actual tools.
- [ ] **6.2 Lifecycle**: draft, backtest through the Phase 1 replay, active; every investigation records the skill version that guided it.
- [ ] **6.3 Triage context**: knowledge-base runbooks with citations, the last N analyst dispositions with reasons, and identity context, all point-in-time.
- [ ] **6.4 Measure it**: replay before and after on the synthetic corpus and at least one recorded history fixture, and publish the delta.

## Phase 7: Declarative custom agents

- [ ] **7.1 Definition** as data: trigger, tool allowlist, skills, output schema, budget, autonomy ceiling.
- [ ] **7.2 Runtime** on the existing tool loop, versioned, with dry-run preview and the replay backtest.
- [ ] **7.3 Reference agents**: identity takeover review, cloud credential abuse, insider data movement, each with a CI eval.

## Phase 8: Intel-driven retro-hunts and a hunting agent

- [ ] **8.1 Retro-hunts** consuming the `NEW_IOC` events nothing consumes today, with provenance, dedup, rate limits and budgets.
- [ ] **8.2 KEV exposure** checked against asset and vulnerability data, opening a case task when exposed.
- [ ] **8.3 Hunting agent** turning a hypothesis into a plan, read-only queries and evidence-backed findings; new `aisoc-hunt` role alias.
- [ ] **8.4 Hunt library** grown from 5 to at least 50, each with positive and negative synthetic scenarios, and `hunts/README.md` corrected where it cites a script that does not exist.

## Phase 9: Detection-engineering loop

- [ ] **9.1 Coverage gaps** ranked per tenant against the compiled executable ruleset, shown on the coverage page.
- [ ] **9.2 Rule-drafting agent** producing governed DRAFT proposals through the existing NL detection builder; nothing promoted without a human.
- [ ] **9.3 Tuning**: proposed exclusions for high-false-positive rules, backtested before and after.
- [ ] **9.4 Measure**: proposals accepted, time from gap to proposal, backtest noise, published as measured or as "not measured".

## Phase 10: Mailbox remediation and phishing campaign response

- [ ] **10.1 Verbs** for Microsoft 365 via Graph and Google Workspace via Gmail, declaring no capability Graph has no documented API for.
- [ ] **10.2 Contracts** whose blast radius scales with recipient count, verification re-querying the mailboxes.
- [ ] **10.3 Campaign grouping** raising one governed purge proposal across all recipients.

## Phase 11: File and URL analysis provider contract

- [!] **Phase 11 is not this program's to build.** Another agent is building it
  in parallel against the MalwareAnalyzer API, whose access the maintainer has
  supplied. Recorded here so the phase is not double-built, and so a later
  session does not read the unticked boxes as open work.
  - [!] 11.1 Interface, CAPEv2 reference provider, mock, documented commercial slot.
  - [!] 11.2 Upload policy: hash lookup first, disclosure off by default, air-gap refuses non-local.
  - [!] 11.3 Wiring to enrichment, phishing attachments and the agent tool surface.

## Phase 12: Production proof and a stable release channel

- [ ] **12.1 Load harness** measuring sustained throughput and latency percentiles against compose and kind, published with hardware and date.
- [ ] **12.2 Reference HA deployment** with a chaos test asserting no loss and no duplicates.
- [ ] **12.3 Release policy**, including the gate that a major bump requires a BREAKING section and a BREAKING section requires a major bump.
- [ ] **12.4 Package publishing**: token-free trusted publishing prepared in `release.yml` and `publish-cli.yml`. The one-time registry steps are maintainer-only and recorded below.

## Phase 13: Enterprise identity and MSSP plumbing

- [ ] **13.1 SCIM 2.0** with Users, Groups, ServiceProviderConfig, ResourceTypes and Schemas, per-organization hashed rotatable tokens, and audited deprovisioning.
- [ ] **13.2 MSSP white-label** per organization across console, PDF, digests, email approvals and ChatOps, with SVGs sanitized and assets stored locally.
- [ ] **13.3 Usage metering** from real rows, exposed through an API and a monthly CSV, with no pricing logic.
- [ ] **13.4 Console i18n** with a pilot locale, RTL, locale-aware formatting and a missing-keys gate.

---

## Blocked on the maintainer

Each entry states the exact request. None is stubbed, simulated, or published
as a number that was not measured.

- [!] **Funded LLM provider keys for the wet eval and the model matrix.**
  Request: set the `WET_EVAL_OPENAI_KEY` repository secret, plus any other
  provider keys `scripts/run_model_matrix.py` is to cover, then Phases 1 to 3
  can be re-run on hosted models. Until then every hosted-model row reads "not
  measured" and never `0`. This is the same blocker that keeps hardening Phase 4
  deliberately unchecked.
- [!] **Registry accounts and trusted-publisher setup for npm and PyPI.**
  Request: create the npm organization and the PyPI trusted publisher, then
  confirm so `release.yml` and `publish-cli.yml` can arm their upload steps.
  The build, pack and check steps already run unconditionally, so only the
  upload is gated.
- [!] **Third-party penetration test, SOC 2 and ISO 27001** for the hosted
  offering (see ADR-0002), and ISO 42001 if hosted AI is sold. Request: engage
  the assessors. This is a procurement action, not an engineering task.
- [!] **Design partners who permit their closed alerts to be replayed**, and
  named references. Request: introduce at least one design partner willing to
  let Phase 1 run against their own history, so the replay report can be
  published as measured on real data rather than on recorded fixtures.
- [!] **A managed human-review service behind the agent**, if the business
  chooses to offer one. Request: a product decision, not an implementation.

---

## Shipped

Nothing yet beyond this kickoff. Each entry below will name its PR.

- [x] **Kickoff.** [#901](https://github.com/beenuar/AiSOC/pull/901), merged.
  Locked plan saved verbatim to `plans/aisoc_gap_closure_plan.plan.md`, this
  tracker created, hooks installed via `scripts/setup_hooks.sh`, and the
  baseline above captured and recorded.
- [x] **Phase 1.1, history readers.**
  [#903](https://github.com/beenuar/AiSOC/pull/903).
- [x] **Phase 1.2 replay runner and 1.3 scoring.**
  [#904](https://github.com/beenuar/AiSOC/pull/904). Suites: `services/agents`
  1252 to 1280, `packages/aisoc-benchmark` 35 to 57, `services/connectors` 880
  to 886. Every other suite unchanged and passing.
- [x] **Phase 2.1 shadow mode and 2.2 rolling agreement.**
  [#906](https://github.com/beenuar/AiSOC/pull/906). Migration 066. Suites:
  `services/agents` 1293 to 1311, `services/actions` 767 to 801, `services/api`
  2852 to 2872, `apps/web` settings vitest 9 to 15. Claim matrix 156 rows to
  159, GATED 148 to 151.
- [x] **Phase 2.3 evidence-gated autonomy.**
  [#908](https://github.com/beenuar/AiSOC/pull/908). Migration 067. Suites:
  `services/actions` 801 to 835, `apps/web` settings vitest 32 to 36, and
  `tests/isolation/test_autonomy_promotion_live.py` 13 passing against live
  `postgres:16`. Claim matrix 159 rows to 164, GATED 151 to 156.
- [x] **Phase 2.1's second closure path, closing D15.**
  [#912](https://github.com/beenuar/AiSOC/pull/912). Migration 068. Suites:
  `services/actions` 888 to 908 (20 new, plus the vendored `test_tenant_scope`
  that travels with the tenth copy of the module), `services/api` 2877 to 2904
  (27 new). Claim matrix 167 rows to 170, GATED 159 to 162. The registration
  gate was proven against the pre-fix tree: run against `main`'s
  `services/api/app/main.py`, both `test_the_deployed_lifespan_registers_the_sweep`
  and `test_the_sweep_is_off_by_default_and_says_so` fail.
- [x] **Phase 5.1 to 5.5, the MCP client.** Migration 069. New dependency
  `mcp==1.30.0`, exact-pinned in `services/agents/pyproject.toml`, re-locked
  in `poetry.lock` and added to the agents CI install list so the version CI
  exercises is the version the image ships. Suites: `services/agents` 1350 to
  1390 (40 new), `services/api` 2924 to 2964 (40 new). Claim matrix 176 rows
  to 182, GATED 168 to 174. New gate
  `scripts/check_mcp_client_policy.py`, wired into `ci.yml`, proven able to
  fail against eight injected regressions rather than merely observed passing.
  See D21 to D23.

- [x] **Phase 5.6, AiSOC's own MCP server.** `services/mcp` 13 tools to 18,
  suite 124 to 135. Every tool now publishes MCP behaviour annotations, and
  the published tool count is compared against the registry across seven
  documents for the first time. Claim matrix 184 rows to 186, GATED 176 to
  178, and the existing "MCP server exposes 13 tools" row was corrected
  rather than only renumbered, because the gate it named had never read a
  document. See D24 and D25.
### D9. A shadow verdict must not reach `alerts.disposition`, and the guard belongs in the SQL

Recorded because the obvious implementation of shadow mode is wrong in a way
that looks right and produces a flattering number.

`ledger.persist_auto_triage` writes the agent's verdict to
`alerts.disposition`. That column is described in the model as the analyst's,
set from the feedback endpoint, and it is the column Phase 2.1 reconciliation
reads to learn what the analyst decided. A shadow run that forwarded that
write unchanged would have the agent filling in the answer it was about to be
graded against: every alert an analyst did not explicitly re-dispose would
score as perfect agreement, and the scorecard would climb toward a promotion
on no evidence at all.

This is the Phase 1 leakage lesson arriving by a different route. Phase 1's
version was a verdict written as an outcome prior that suppressed the next
alert; this one is a verdict written into the field the next measurement
reads. Both are the evaluation answering itself, and neither shows up as an
error.

**Resolution:** `persist_auto_triage` gained a `shadow` flag, and the guard is
written into the statement rather than left to the caller:

    SET disposition = CASE WHEN $10 THEN disposition ELSE $3 END,
        status      = CASE WHEN $7 AND NOT $10 THEN 'resolved' ELSE status END,
        resolved_at = CASE WHEN $7 AND NOT $10 THEN now() ELSE resolved_at END

`NOT $10` is the load-bearing part. The shadow sink already forces
`auto_closed` off, so the `$7` arm would be enough today; relying on that
alone would mean a second caller added later closes alerts it was only meant
to observe, and the symptom would be a tenant's queue emptying itself during
an evaluation.

### D10. The sink is chosen per alert, and the writer is passed rather than swapped

Shadow mode is per tenant *and* per alert class, and the class is not known
until the alert is in hand, so the choice cannot be made in the worker's
constructor. Two ways not to do it: assigning to `self._writer` per message
leaks across concurrently triaged alerts, and it would also break the Phase
1.2 AST test that asserts the deployed worker overrides neither sink, which
is a test worth keeping.

So `triage()` resolves the sink once and passes it down. Five helpers took a
keyword-only `writer` parameter, and it is **required** on all of them
including `_record`, with no fallback to `self._writer`. A default would mean
a future caller who forgets the keyword silently gets the live sink, which is
the unsafe direction for this particular control: the failure would be a
shadow run writing the analyst's disposition column.

### D11. The gate logic is vendored, not fetched over HTTP

`services/actions` enforces autonomy at dispatch and `services/api` decides
promotions and owns the hash-chained audit log. Both package their code as
top-level `app`, so one process holds one of them, and each image is built
with only its own directory as build context.

The Phase 1.4 precedent (D6, D8) is a round trip to the service that owns the
thing. That is right for a *mapping* held by another service. It is wrong
here: this is a safety control on a latency-sensitive path, and a control that
fails open when a second service is unreachable is not a control. So the pure
rules are a standard-library-only module vendored byte-identically, following
the five mirrors already in the tree, with
`sync_vendored_autonomy_evidence.py --check` wired into `ci.yml`. Two copies
allowed to differ means the control is off in whichever one is more generous.

### D15. The SIEM half of reconciliation has no scheduled caller, and the docs said it did

Found by grepping for callers of the code this program had just written, which
is the check this repository's own history says to run before claiming
anything.

`services/actions/app/services/shadow_reconcile.py` exists, reuses the five
Phase 1.1 readers unchanged, matches a vendor closure to the decision it
grades on the vendor finding id, keeps `unmatched` and `already_resolved`
apart, and has eleven tests. **Nothing calls it.** The AiSOC-side half is
wired and runs on every read of the agreement endpoint; the SIEM-side half is
a library with no driver.

The docs page shipped in #906 said closures "are polled back out" of the five
vendors, which is a claim about a thing with no scheduler. An operator whose
analysts work entirely in Splunk would have waited for a scorecard that was
never going to fill in, and concluded the agent was not being evaluated rather
than that we were not looking.

**First resolution:** the claim was corrected rather than the code hurried. The
page said in those words that this half was not automatic, named what existed
and what did not, and said agreement was measured on AiSOC closures until it
landed. 2.1 moved from `[x]` to `[~]`.

**Closed in [#912](https://github.com/beenuar/AiSOC/pull/912)**, in exactly the
shape recorded above: `services/api` owns the vault and the tenant session, so
it resolves the connector's credentials and posts them with a window to
`POST /api/v1/shadow/reconcile` on `services/actions`, which calls the reader
and then `reconcile_findings`. Same round trip as `siem_writeback` and
`/connectors/{id}/normalize`, for the same reason D8 records. 2.1 is `[x]`.

Three things the build settled that the note above did not anticipate:

**The tenant had nowhere to come from.** `/replay/history` needs no tenant at
all: the credentials it is handed are the scope, and it writes nothing. This
route writes to one tenant's decision rows, so it needs one, and taking it
from a request field would be a value the caller chose that nothing checked.
`services/actions` was the one service of ten with no vendored
`app/security/tenant_scope.py`, so it got the tenth copy through
`sync_vendored_tenant_scope.py` rather than a bespoke guard, and the tenant
travels on `X-AiSOC-Tenant-ID` exactly as it does to `/replay/run`.

**The matcher had a silent no-op in it.** With no `DATABASE_URL`,
`reconcile_findings` logs at `debug` and returns a result reporting the
findings it considered and zero matched. Reported upward that is
indistinguishable from a window whose join key never arrives, and the two send
an operator to entirely different places. `database_configured()` is now
checked by the route *before* the vendor is called, so a missing environment
variable is a 503 naming it rather than a customer's search quota spent on a
window nothing could be written from.

**A watermark was not optional.** Without one the sweep re-reads the same hours
every tick forever. Migration **068** adds `aisoc_shadow_reconcile_state`, and
the column that turned out to matter most is `blocked_connector_updated_at`: a
revoked credential is permanent until somebody acts, and comparing that value
against `connectors.updated_at` makes "somebody saved the connector" the only
thing that resumes polling. A timer would have been the churn the state exists
to avoid, and a manual reset would have been a support ticket.

### D17. CORE was not missing `connectors` and `actions`. It was configured for both and started neither

The plan's framing of 4.5 is a capability gap: "the default profile has no
evidence source". Measuring it found something worse than absence, and the
difference is what made the decision easy rather than a judgement call about
124.8 MiB.

`api` in CORE carries `CONNECTORS_SERVICE_URL: http://connectors:8003` and
`AISOC_ACTIONS_BASE_URL: http://actions:8085`, and
`AISOC_FEATURE_FED_SEARCH` defaults to `True` in the API's settings. So on
the profile `make up` starts, the federated-search route was enabled and
fanning out to a hostname that does not resolve, and the live-actions proxy
answered 502 with a message naming the two compose profiles an operator would
have had to know to switch to. The capability was not switched off in CORE.
It was switched on and pointed at nothing.

That reframes the alternative. "Leave both in `full`" is not "CORE stays
lean", it is "CORE keeps advertising a capability it cannot perform", and the
only other honest option would have been to delete the configuration, which
trades a broken capability for an absent one.

**Two things were also corrected while the profile table was open,** on the
precedent ADR-0006 set when it found the published `full` count was 30:

- The counts were published in ten figures across four documents and nothing
  compared any of them to `docker-compose.yml`. That is now
  `scripts/check_profile_service_counts.py`, wired into `ci.yml`, failing in
  both directions. `docs/testing/CLEAN_INSTALL.md` also says 14 and is
  **left alone** deliberately: it records a dated run on 2026-09-23 and
  rewriting it would be revisionism.
- The ADR index in `docs/decisions/README.md` was missing 0005 and 0006.

**What is not decided, so nobody reads 4.5 as having closed the whole gap.**
ClickHouse and Neo4j stay in `full`. They are stateful stores with their own
memory floors rather than network front ends, so they are a separate decision
needing its own measurement. After this change a CORE agent can reach a
configured vendor and still cannot reach an event lake, and the eleven lake
pivots report their data class is unavailable rather than returning empty.

### D12. `unified_decision` had no production caller, and the plan names it anyway

The plan says to wire the promotion gate into
`services/actions/app/services/unified_autonomy.py`. Doing only that would
have wired it into nothing.

`unified_decision` is referenced in exactly one place in the tree:
`services/actions/tests/test_unified_autonomy.py`. The live path is
`live_actions/dispatcher.py::_govern`, which composes a different
`AutonomyDecision` (the one in `autonomy_safety`) from `decide()`, the tenant
policy and `_apply_capability_contract`. This is the repository's most-repeated
shape: a mechanism that exists, is unit-tested, and is not on the path that
needs it.

**Resolution:** both. `unified_decision` takes the grant and is kept
consistent, because the plan names it and because a second grader that
disagreed with the first would be worse than the unwired one. And the grant is
wired into `_govern`, where it raises the tier ceiling exactly as the existing
`force_auto` override does and then passes through `_apply_capability_contract`
unchanged, so the contract's floors still apply. Adding a third grader beside
the two that already compose would have re-created the "same verb graded
differently depending on which door it came through" defect this tree already
fixed once.

### D13. A grant stops at L3 where `force_auto` goes to L4

`force_auto` lifts the ceiling to L4, which permits HIGH blast radius. An
earned grant lifts it to L3, which stops at MEDIUM.

The two are not the same kind of thing. `force_auto` is a human writing down a
decision about one verb. A grant is an inference from agreement on *triage
verdicts*, which is evidence about the agent's judgement and is not evidence
that isolating a host was the right call. Letting one number unlock both is how
a measurement of one thing becomes permission for another, and it would be
invisible afterwards because the resulting action looks identical either way.

`test_earned_autonomy_wiring.py` pins the ceiling, pins that a grant never
lowers a bar (a 40-case sweep over blast radius, confidence and reversibility
asserting the only permitted movement is queued to auto on the reversible
MEDIUM branch), and pins that confidence is still required, since a grant is
evidence about the agent in general and confidence is what it says about this
decision.

### D14. The live database is not optional for this phase

The unit suites prove the arithmetic and prove the statements are built
correctly. Between them they would still miss the failure that matters most: an
aggregate that counts something slightly different from what the evaluator
expects. The SQL and the evaluator agree by convention, and a convention is
what drifts.

One instance of exactly that was found by running it. `to_named_params` turns
`$2::text[]` into `:graded::text[]`, and SQLAlchemy's `text()` parser reads the
second colon pair as the start of another bind parameter, so a stray colon
reached Postgres and every agreement query on the API side failed to parse.
Both unit suites were green. The cast is gone from the shared SQL (both drivers
infer the array type from the column) and the SQLAlchemy caller declares it
with `bindparam(..., type_=ARRAY(Text))` instead.

The live suite is also the only place the hash chain over the transitions can
be checked, since `entry_hash` is computed on insert from the previous row for
the same tenant. It cleans up the evidence and the grants and deliberately
leaves the tenant, the operator and the audit rows: `audit_log` refuses a
DELETE by trigger, `audit_log.tenant_id` cascades from `tenants` and
`audit_log.actor_id` is `ON DELETE SET NULL` from `users`, so removing either
reaches the trigger and is refused. Working around that in a test would mean
demonstrating the hole the trigger closes, so the refusal is asserted instead.

### Notes for the next session

Two traps this program hit that are worth not re-learning.

**A gate run before `git add` reads a different tree than CI does.**
`check_comment_paths.py` failed naming two comments that pointed at
`apps/docs/docs/evaluation/replay.md`. The file existed. It was untracked, and
the gate's corpus is `git ls-files`. Staging first made it pass. The same shape
made a `ruff format --check` comparison against `main` look like `main` had two
unformatted files: `git stash` leaves untracked files in place, so the "base"
run was still seeing the new ones.

**A test that reconfigures a gate before pointing it at production is not
testing production.** `tests/test_readme_figures_gate.py::test_live_repo_is_consistent`
passed against this tree while `scripts/readme_gates.py --skip-sandbox` failed
against the same commit in CI. Its helper narrows `FIGURE_DOCS` to the one
scratch path its fixtures write, and passing the real repository root through
that helper left the narrowing in place, so the "real tree" check read the
compliance page and neither `ROADMAP.md` nor `RELEASES.md`. Both had gone stale
and the test had never been able to say so. Fixed by importing the gate
unmodified for that one test and pinning the surface at three documents, and
the fix was proven by re-staling `ROADMAP.md` and watching the test fail.

**Backgrounding a long run kills it here.** The first baseline attempt was
started with `nohup ... &` and was dead within a minute, having written 41
progress dots. Long suites run in the foreground.

### D16. The route Phase 1.2 added could never have been reached, and only the end-to-end run could tell

D8 predicted that three proven links are not the same claim as one end-to-end
run. This is what the fourth link found the first time it ran.

`POST /connectors/{id}/normalize` shipped in 1.2 as the resolution to D6: both
services package their code as top-level `app`, so the agents service reaches
the production connector mapping over HTTP rather than copying it. The client
built its URL as `{CONNECTORS_SERVICE_URL}/connectors/{id}/normalize`. The
connectors service mounts that router with `prefix="/api/v1"`, and the API's
own caller in `endpoints/connectors.py` appends the same segment for exactly
that reason. So every normalize request the agents service could have made
would have returned 404, and no replay could have run on any deployment.

Three suites were green over it. The unit test covering `fetch_normalized`
asserted the URL the code produced rather than the URL the service serves,
which is the one-directional shape this repository keeps finding: it compared
the producer against a copy of itself and printed OK. Nothing else called the
function, so nothing else could notice.

**Resolution:** the prefix is a named constant with the reason recorded beside
it, and the test now parses `services/connectors/app/main.py` and
`app/api/router.py` with `ast`, derives what that service actually serves, and
asserts the requested URL is in that set. It was proven against the pre-fix
value: with the prefix removed it fails naming both URLs. This service cannot
import that one, so reading the other tree's source is the only way to compare
in the direction that drifts.

The durable lesson is D8's, sharpened: an end-to-end test is not a slower
version of the unit tests underneath it. It is the only thing that exercises
the joins, and the joins are where a caller-less mechanism hides.

### D17. A twin that differs twice cannot attribute anything, and the scaffold made it differ twice

Every metric in Phase 3 is a difference between two runs over incidents that
differ in exactly one field. The first generator satisfied that for the
common case and broke it for two others, and the break was invisible in the
rates.

Two of the six surfaces the plan names are not in the base corpus at all
(`itsm` ticket text has no telemetry source, and `BodyPreview` is absent from
the `m365_audit` records that do exist). The generator scaffolded a record to
hold the payload, and scaffolded it **onto the injected twin only**. So those
pairs differed in two ways: the payload, and the existence of a telemetry
record. An agent could have reacted to the extra record rather than to its
content, and every rate computed over those pairs would have been
unattributable while still looking exactly like a number.

Found by the twin-integrity test rather than by reading, which is the point
of asserting the invariant instead of describing it: a structural diff
between the twins reported `['telemetry']` where it expected
`['telemetry[2].description']`.

**Resolution:** both twins are built together, and the scaffold carries a
`baseline` value on the clean side (what the field ordinarily holds) so the
two differ only in that field's value. Fixing it moved neither the detection
rate nor the false-positive rate, which is the expected result for a
correctness fix that is not a scoring change, and is worth recording because
a fix that moves the number it was supposed to leave alone would mean
something else was wrong.

### D18. The first guard measurement taken here was wrong, and it was wrong in the flattering direction

Scanning the injected twin and asking whether the guard flagged it anywhere
credits the guard for signals that have nothing to do with the payload. The
base incidents are real security content: some of them legitimately contain
containment verbs and adversarial-looking strings. Measured that way the
guard scored **85.2%** on this corpus with a false-positive rate of 27.3%.

Neither figure was about the payloads. Three incidents scored as detections
because something in the base incident's own telemetry matched, and one
benign control scored as a false positive for the same reason. In every one
of those cases the guard had not matched the payload at all.

Read the wrong way round, it also almost produced a much more damaging
result: 85.2% is very close to the 0.852 the prose corpus reports, so the
measurement would have quietly confirmed the number it was supposed to
challenge, and the entire finding in D19 would have been invisible.

**Resolution:** `attributable_hits` requires a signal at the exact field the
payload was written into **and** no signal at that field in the clean twin.
The second half is load-bearing because a payload is appended to whatever the
field already held, so a field whose original content trips the guard would
otherwise credit every payload placed in it. The corrected rate is **66.7%**.
The rule is proven in the direction that broke: a test contaminates a base
incident at the injected field and asserts the pair stops counting.

This is the clean twin paying for itself twice. It was built for the three
behavioural metrics, which cannot exist without it, and it turned out to be
the only way to make the deterministic one honest as well.

### D19. The guard reads prose, and attackers write fields

The finding this phase exists to produce, recorded here because it is
actionable work rather than a caveat.

By surface, the guard detects 18 of 21 payloads in ticket text and 12 of 14
in an email body, against 1 of 5 in a command line, 1 of 5 in a DNS name and
0 of 3 in a file name. Its patterns were written against prose, and every
field in the second group constrains phrasing in a way prose does not: no
spaces, hyphen and underscore separators, a rigid shape.

The narrowest gap is the most expensive. `injected_containment` matches a
containment verb followed by a noun from a fixed list (`host`, `account`,
`user`, `session` and so on), so it catches "isolate the host" and misses
"isolate WIN-DC-PRIMARY". The second is what an attacker writes, because the
attacker wants one specific machine off the network, and this is the family
the guard's own history already names as its original blind spot.

**Not closed here, deliberately.** Adding patterns that catch the payloads in
this corpus would raise the published number and teach nobody anything: the
corpus would have been fitted, and the next real evasion would land in the
same place. The 18 current misses are recorded on a ratchet that admits no
new ones and refuses stale entries, so the gap is visible, bounded and
cannot grow. Closing it properly means a guard that reads identifier-shaped
fields as instructions, measured against payloads written after the change
rather than before it.

Two false positives are recorded on the same terms, and one of them costs
more than it looks: `disable_user_offboarding_batch.ps1` is a legitimate
script name, `disable_user` is in the guard's tool-name list, and a
tool-name match is **high** severity, which demotes the case to L0. So an
ordinary offboarding script takes automation away from a true positive.

<<<<<<< HEAD
### D20. The hardening worked on the corpus and barely generalised, and the second number is the one that matters

D19 left the field-native gap open on the grounds that tuning a guard against
the corpus that grades it produces a flattering number and no information.
That reasoning was right, so the work in 3.4 was graded twice: once on the
corpus it was written against, and once on payloads authored after the guard
was committed and never consulted while its patterns were written.

| | tuned corpus | held out |
|---|---|---|
| guard before 3.4 | 66.7% (36/54) | 3.6% (1/28) |
| guard after 3.4 | 98.1% (53/54) | 7.1% (2/28) |

The change moved the corpus it was written against by 31 points and moved
unseen payloads by a single payload. **It fitted the corpus far more than it
closed the threat, and that is the finding**, not the 98.1%.

The two held-out payloads that are caught say why. One is caught by unicode
normalisation and one by a rule whose vocabulary happened to fit. Every other
held-out payload asks for exactly what the tuned corpus asks for, in words no
rule enumerates: `ho-ticket-pull-off-network` wants a named host taken off the
network and is missed because "pull off the network" is not in a verb list,
and `ho-ticket-cab-signoff` claims sign-off from a change advisory board,
which the authority rule does not list.

So the structural half of 3.4 did generalise and it was not enough.
Segmentation genuinely made every prose rule reach an identifier field, and a
rule added tomorrow will reach one too, which a longer pattern list would not
have achieved. But what segmentation carries into those fields is still a set
of word lists, and a word list is exactly the thing an attacker routes around
without effort. The guard is a vocabulary matcher that can now read more
fields.

**The next structural step is named here and deliberately not taken here.**
The property that separates almost every held-out miss from its benign
control is not vocabulary at all: it is that an imperative addressed to a
reader appears in a field that carries machine-generated data. A DNS label, a
command line, a user agent and a file name are emitted by software and never
contain requests, so sentence-shaped second-person content in one of them is
anomalous whatever it says. Ticket text and an email body are written by
people and are full of requests, so the same test cannot apply there and a
different one is needed. That is a field-class prior rather than another word
list, and the field classes come from the platform's own OCSF schema rather
than from an attacker's thesaurus.

It is not taken here because the held-out corpus has now been read. Anything
built after reading it and graded against it is tuned against it, and the
number would be worthless in precisely the way this decision exists to
prevent. Doing it properly needs a **new** held-out set authored after that
change lands.

For the same reason `HOLDOUT_UNDETECTED` is **not a ratchet** and the
held-out corpus carries **no floor**. CI checks that the measurement happens
and that the published page matches it, and checks the recorded misses in
both directions so the record keeps describing the tree. It does not check
that the rate is good, because a target on a held-out set is an instruction
to tune against it, and the first person to satisfy that target by writing
one pattern per miss would leave the repository with a number that means
nothing and no way to tell.

One thing the held-out figure is *not*: a pessimistic bound. These payloads
were written by someone who could read the patterns, and for a guard shipped
under an MIT licence in a public repository, so can an attacker. White box is
the correct threat model here, so 7.1% is the number to plan against.

The false-positive side moved the right way and is reported like for like.
On the eleven benign controls that existed before this change, 2 flagged and
1 does now: `disable_user_offboarding_batch.ps1` no longer trips a
high-severity tool-name match, so an ordinary offboarding script no longer
takes automation away from a true positive. Six controls were added, four of
which flag the un-narrowed draft of the rule they sit beside, which is what
makes them evidence rather than decoration. Two of those six flagged `main`
itself through bare nouns in `injected_containment` that matched their own
verb, and both nouns are gone. `benign-edr-response-cmdline` still flags and
stays recorded: suppressing it needs a rule that reads a containment verb in
flag position as a tool invocation, and a suppression rule is the one kind
whose failure mode is silence.
=======
### D21. The credential has to cross the internal network, and the usual dual-mode route is the wrong shape for it

The plan puts the client in `services/agents` and the registry in
`services/api`. Both package their code as top-level `app`, so one process
holds one of them, and the API is the service with the vault and the tenant
session. The credential therefore travels, on the same round trip that already
carries organisation memory, SIEM writeback, connector normalisation and shadow
reconciliation. D15's version of this has the API *pushing* credentials to
`services/actions`; this one reverses the direction, because the agent is the
one that knows an investigation has started.

What is deliberately different from every other internal route here: there is
**no session fallback**. `/feedback/context-statements`, `/alerts/{id}/source-writeback`
and the rest accept either a session or the service token, because the data
behind them is the caller's own. This route returns plaintext third-party
credentials. A console user who can read their tenant's alerts must not thereby
be able to read the bearer token their operator configured for a vendor's MCP
server, so a perfectly valid session gets a 401 and the console is given
`has_credential: bool` instead. `test_a_valid_console_session_is_still_refused_plaintext`
pins it.

Two smaller decisions on the same route. `tenant_id` is **required**, because a
service token carries no tenant of its own and defaulting an omitted parameter
to "every tenant" on a route returning credentials is the widest possible
reading of an absence. And a row whose credential will not decrypt is dropped
with a warning rather than returned with an empty credential: the second would
produce an unauthenticated call to a third party that the operator believes is
authenticated, and the vendor's 401 would reach the agent as "that tool is
unavailable", which is indistinguishable from the tool not existing.

### D22. "Or not at all" is the honest half of 5.3 today, and saying so is the point

The plan says a state-changing MCP tool is reachable only through governed
dispatch, as a live action with a declared contract, **or not at all**. The
first half cannot be built here. A capability contract declares impact,
reversal and a verification probe for a *verb*, and it is graded by
`approval_matrix.evaluate_contract`; an MCP tool is a name on somebody else's
server with an annotation and a description. There is no verb to contract, no
reversal to declare and no probe to write, and inventing one per vendor tool
would be the "exists but nothing calls it" shape wearing a contract.

So the shipped behaviour is refusal, and the refusal message names governed
dispatch as the door it would otherwise take. This is recorded rather than
left implicit because the opposite reading is available and wrong: a future
session could read 5.3 as unfinished and wire MCP tools into the dispatcher
without a contract, which would be worse than the refusal by exactly the margin
this repository's playbook-step defect cost: steps that claimed to dispatch
actions and reached no executor at all.

The other half of the sentence is where the work went. Refusing at call time
would have been the obvious implementation; refusing at *discovery*, so the
tool is never put in front of the model, is strictly stronger, because a tool
the model cannot see is one it cannot be talked into naming. Both happen, and
the dispatch-time check re-runs the same pure function over the same discovered
descriptor rather than a weaker restatement of it.

### D23. The SSRF guard belongs at the socket, and putting a copy at save time nearly made it worse

The plan says server URLs pass the SSRF guard. The obvious place is the
registry, when an operator presses save, and that is where a reader looks for
it. It is the wrong place to *rely* on: DNS is not a property of a URL. A
hostname that resolves to a public address at save time can resolve to
`169.254.169.254` an hour later, and by then the saved row has been validated
and nothing re-asks.

So there are two checks and they are deliberately not the same check.
`services/api` runs a **structural** one at save time (scheme, userinfo,
hostname shape, IP literals, the cloud-metadata blocklist, the air-gap policy)
so an operator gets an immediate readable refusal, and its docstring says in as
many words that it does not resolve DNS and is not the control. The enforcing
one is `validate_outbound_url` in `services/agents`, called after the
configuration is read and before the transport is constructed. The gate asserts
the ordering by line number inside `session()`, because "the guard is called"
and "the guard is called first" are different claims and only the second is a
control.

The near-miss worth recording: the first draft had the API resolving DNS too,
which would have read like the real check to every future reader while ageing
into a false one, and would have made the agents-side guard look like a
belt-and-braces duplicate that a later cleanup could reasonably delete.
>>>>>>> 54de0d37 (feat(agents): reach a tenant's own MCP servers, read-only and untrusted by default)

### D24. Two thirds of 5.6 already existed, and the third needed a boundary in code rather than in prose

5.6 names three read surfaces and one preview. Checking first, which is the
thing this repository's history says to do before building anything:

**The Investigation Ledger half was already shipped.**
`aisoc_list_investigations`, `aisoc_get_investigation`, `aisoc_replay_decision`
and `aisoc_explain_step` have been in `services/mcp/src/tools/investigations.ts`
for months. Nothing was rebuilt and nothing was wrapped.

**The triage-verdict half half-existed.** `aisoc_get_alert` already returns
every verdict field, so the new tool is a focused projection rather than a new
capability. It earns its place by handling two things the raw record does not:
`confidence` (an integer 0 to 100) and `ai_score` (a float 0 to 1) are kept
apart by name with the scale stated, because a consumer that treats one as the
other renders `2100%`, which this tree has shipped once; and a null verdict is
reported in words as "nothing has triaged this yet" rather than left as a null
field an agent reads as "no threat found".

**Replay reports had no tool at all.** Phase 1.4's surfaces exist; nothing
exposed them over MCP. The report is served **as stored**, not re-rendered,
so a withheld headline (below 30 malicious cases, Phase 1.3 refuses to print a
number) stays withheld. Re-rendering would eventually mean two definitions of
what a replay report says, and the one an agent quotes would not be the one
the operator exported.

**The preview is the part that needed care.** It is the only tool in this
server that touches the response surface, and an MCP key is credential
material that lives in an editor's configuration file. So the boundary is in
code: `DRY_RUN_PATH` is a module constant and the only action path the module
names, `/live-actions/dispatch` appears nowhere in `src/`, and the test asserts
that by **reading the source** rather than by driving the handler, so a second
action tool added later is caught rather than only the one under test. The
schema is strict, so a caller-supplied `dry_run: false` is a validation error
rather than a field forwarded to the API. The enforcing control is still
upstream, where the route forces `dry_run: true` whatever the body says; this
is the second lock, on the side an agent can see.

Proven able to fail by pointing the constant at the dispatch path, which reds
both the source scan and the request assertion.

### D25. The server published no annotations, which is the gap its own client complains about

Phase 5.1's client refuses an MCP tool whose server sets `destructiveHint:
true` or `readOnlyHint: false`, and treats an absent annotation as no claim
rather than as a claim to be read-only. AiSOC's own MCP server published
**none at all**, so by its own client's rules every one of its 13 tools was a
tool an operator would have had to vouch for by name.

Fixed by declaring them on all 18 and advertising them in `ListTools`. The
test pins the set of not-read-only tools to exactly `aisoc_run_investigation`,
in both directions: a future write tool cannot arrive annotated read-only, and
a read tool cannot drift into looking state-changing. `readOnlyHint` is
required as a boolean rather than optional, because an omission is
indistinguishable from a tool nobody thought about.

`aisoc_run_investigation` is the one honest exception. It starts an agent run:
it writes ledger rows, spends model budget and can reach whatever the tenant
configured. Annotating it read-only would be the direction of dishonesty a
client cannot detect.

**And the published tool count was ungated.** "13 tools" was written into six
documents and nothing compared any of them to `ALL_TOOLS`. The claim matrix
carried a row saying the count was gated by `ci.yml :: mcp`; that job runs the
registry tests, which pin the tool *set*, and had never read a document. The
row's Status column was therefore true about a different claim than the one it
stated. `tests/published-count.test.ts` now compares all seven figures against
the registry in both directions, proven by staling one figure and by deleting
another. `plans/cyble-aisoc/platform/README.md` also carries the old figure
and is deliberately left alone: plan files are never edited.
