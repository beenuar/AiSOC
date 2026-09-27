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

---

## Phase 1: Replay evaluation on a customer's own history

- [x] **1.1 History readers.** Shipped in [#903](https://github.com/beenuar/AiSOC/pull/903). Five readers on the clients in `services/actions`, which already own the credential path and already hold the writeback going the other way: `SplunkClient.list_closed_notables`, `SentinelClient.list_closed_incidents`, `ElasticClient.list_closed_signals`, `QRadarClient.list_closed_offenses`, `DefenderClient.list_resolved_alerts`. One taxonomy module (`app/services/alert_history.py`) rather than five that could disagree. 30 tests drive each reader's real HTTP path against vendor-shaped payloads; the `services/actions` suite goes 737 to 767. Claim-to-gate row added, matrix 147 rows to 148, GATED 139 to 140. Two vendor decisions recorded in `apps/docs/docs/evaluation/replay.md`: Elastic ships no disposition field so an untagged deployment yields no labels, and QRadar "Non-Issue" is `benign` not `benign_true_positive` because it makes no claim about whether the rule was right.
- [x] **1.2 Replay runner.** Shipped in [#904](https://github.com/beenuar/AiSOC/pull/904). `services/agents/app/replay/` holds the split, the shadow sinks and the runner; it holds no triage. Persistence is injected through `app/workers/triage_persistence.py`, whose default is `LiveTriageWriter` doing exactly what the worker did inline, so the measured path is the production one rather than a copy. `CostTracker` gained a `persist` flag so a replay measures spend without billing it. Normalisation reaches the real connector through a new `POST /connectors/{id}/normalize`, because both services package their code as top-level `app` and one process can hold one of them. Verdict, confidence, evidence, tool calls, model id, tokens, measured cost and latency are all recorded per decision. See D6 and D7 below for the two places the plan and the tree disagreed.
- [x] **1.3 Scoring.** Shipped in [#904](https://github.com/beenuar/AiSOC/pull/904). `packages/aisoc-benchmark/aisoc_benchmark/replay.py` reuses the existing `_INDICATOR_PATTERNS` for hallucination so there is one definition, and adds per-class precision and recall with malicious recall first, a confusion matrix, abstention rate, reliability bins with an expected calibration error, per-rule and per-source breakdowns, and seeded bootstrap intervals. Below 30 malicious cases the headline accuracy is withheld with the count and the reason. A rate with no denominator reads "not measured".
- [ ] **1.4 Surfaces.** CLI `aisoc replay`, async API job with tenant-scoped tables, the "Evaluate on your history" console page, and JSON, Markdown and PDF export. Markdown rendering already ships with 1.3 (`format_replay_report`).
- [~] **1.5 Gates and docs.** Recorded vendor payload tests per reader shipped with 1.1. The leakage test shipped in [#904](https://github.com/beenuar/AiSOC/pull/904) (`services/agents/tests/test_replay_leakage.py`), covering all three stores a test-window decision can travel back through, each with a sensitivity half that runs the unprotected configuration and asserts it leaks. Three claim-to-gate rows added, matrix 148 rows to 151, GATED 140 to 143. `apps/docs/docs/evaluation/replay.md` covers the method, the limits and the privacy position. What remains is the documentation of the 1.4 surfaces once they exist.

**Done when:** the CLI, run against a mocked Splunk ES holding 200 recorded
closed notables, produces a report that reproduces byte for byte on a second run
with the deterministic model path.

## Phase 2: Live shadow mode and evidence-gated autonomy

- [ ] **2.1 Shadow mode**, per tenant and per alert class.
- [ ] **2.2 Rolling agreement** per alert class, rule, source and model, on the operations dashboard and the autonomy scorecard.
- [ ] **2.3 Promotion gate**, with automatic demotion on drift and every transition written to the hash-chained audit log.

## Phase 3: Prompt-injection evaluation suite

- [ ] **3.1 Corpus** of injected incidents paired with clean twins, generated deterministically and labelled synthetic.
- [ ] **3.2 Metrics**: verdict flip rate, unsafe action proposal rate, tool-call deviation, guard detection rate.
- [ ] **3.3 Runs and publishing**: deterministic floor in CI, live rates in the weekly wet eval or "not measured", both on the benchmark page.

## Phase 4: Let the investigation agent reach the customer's tools

- [ ] **4.1 Federated search tool** as a typed agent tool; the model never writes SPL, KQL or ES|QL.
- [ ] **4.2 Vendor read tools**, plus new read verbs for SentinelOne, Microsoft Entra ID, Google Workspace, AWS CloudTrail and Microsoft Defender.
- [ ] **4.3 Tool handling**: advertise only configured backends, project and cap results, mark them untrusted, and surface a read failure as "could not check".
- [ ] **4.4 Strategies** updated so `check_investigation_depth.py` still holds.
- [ ] **4.5 CORE decision**: measure the memory cost of `connectors` and `actions` in CORE, decide in an ADR, implement the decision.

## Phase 5: MCP client

- [ ] **5.1 Client** on the official MCP Python SDK, pinned, streamable HTTP only by default.
- [ ] **5.2 Registry**: per-tenant server registry with vault credential, tool allowlist, timeout and response-size cap.
- [ ] **5.3 Read-only by default**; a state-changing MCP tool is reachable only through governed dispatch.
- [ ] **5.4 Untrusted by default**: contract boundary markers, injection guard, ledger, SSRF guard and air-gap policy.
- [ ] **5.5 Tests and docs** against an in-process MCP test server, plus `apps/docs/docs/operations/mcp-client.md` marking each vendor server unverified until someone runs it.
- [ ] **5.6 AiSOC's own MCP server** gains read tools for triage verdicts, the ledger and replay reports, plus a dry-run-only action preview.

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
