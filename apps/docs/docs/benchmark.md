---
sidebar_position: 4
title: Public Eval Harness
description: AiSOC's open, deterministic regression harness. 200 synthetic incidents, four CI gates over the substrate (extractors, fusion, templates, judges). Honest about what it measures — and what it doesn't.
---

# AiSOC Public Eval Harness

> **An open, deterministic regression harness over the AiSOC substrate.**
>
> This page is _not_ a leaderboard for AI SOC agents. It is a CI-gated harness
> that exercises the deterministic substrate underneath AiSOC — the keyword
> extractors, the fusion pipeline, the report and response templates, and the
> offline judges that grade them. The dataset, the harness, and the CI gate are
> all in the repo. You can reproduce every number on this page in under
> 10 seconds on a laptop.

[![MITRE Accuracy](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-mitre.json)](#latest-results)
[![Alert Reduction](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-reduction.json)](#latest-results)
[![Investigation Completeness](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-completeness.json)](#latest-results)
[![Response Quality](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-quality.json)](#latest-results)

:::warning Read this first
This harness does **not** exercise the live LLM agent (`services/agents`
LangGraph orchestrator). It runs **deterministic substrate code** against
**synthetic data** so we can gate every commit in milliseconds. Three of the
four metrics on this page measure the **internal consistency** of that
substrate — not agent accuracy. We explain exactly what each suite measures —
and doesn't — below.
:::

## Why this exists

The AI SOC market is full of unfalsifiable claims:

- *"90% alert reduction"* — measured on **whose** alerts, against **what** baseline?
- *"10× analyst throughput"* — what's the dataset, the rubric, the failure mode?
- *"Detects MITRE ATT&CK"* — across how many tactics? With what accuracy?

You cannot deploy a black-box vendor in a regulated environment and tell your
auditor "we trust their internal QA." AiSOC takes the opposite tack: rather
than claim a number we can't substantiate, we publish a small, honest harness
and call out exactly which numbers are real and which are mostly substrate
self-checks.

1. **The dataset is in the repo.** [`services/agents/tests/eval_data/synthetic_incidents.json`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json) — 200 cases, deterministic, regenerable.
2. **The harness is in the repo.** Four pytest suites under [`services/agents/tests/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/tests).
3. **The CI gate runs on every commit.** [Latest run](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml).
4. **Historical numbers are queryable.** Every successful build pushes its `eval_report.json` to the [`eval-results`](https://github.com/beenuar/AiSOC/tree/eval-results) branch as `eval/results/<commit_sha>.json`.

## Latest results

The four numbers below are produced by `scripts/run_evals.py` against the
200-incident synthetic benchmark. They run in roughly **25 milliseconds total**
(no LLM calls, no DB) so they're cheap enough to gate every commit.

| Suite                          | Metric                | Latest      | Target  | What it actually checks |
|--------------------------------|-----------------------|-------------|---------|--------------------------|
| Alert reduction ratio          | reduction             | **75.3 %**  | ≥ 70 %  | **Real measurement** of the 3-tier fusion logic on a noisy 1 000-alert stream |
| MITRE ATT&CK tactic accuracy   | accuracy              | **97.0 %**  | ≥ 80 %  | **Substrate self-consistency** — keyword extractor vs. dataset that's written for it |
| Investigation completeness     | mean keyword coverage | **94.3 %**  | ≥ 85 %  | **Substrate self-consistency** — report template wraps the description; judge finds keywords from the description |
| Response-plan quality          | mean rubric score     | **1.000**   | ≥ 0.80  | **Substrate self-consistency** — synthesizer embeds the keywords the rubric checks for |

These numbers move with the codebase. The current snapshot lives at
[`eval-results/eval/results/latest.json`](https://github.com/beenuar/AiSOC/blob/eval-results/eval/results/latest.json).

## Reproduce these numbers

You don't have to take our word for it. From a fresh clone:

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
python3 scripts/run_evals.py
```

That's it. No Docker, no API key, no GPU, no LLM. Expected output:

```text
============================================================================
  AiSOC Pillar-1 Eval - 200-incident synthetic benchmark
============================================================================
  [PASS] mitre_accuracy               accuracy               0.970  (target >= 0.80)
  [PASS] alert_reduction              reduction_ratio        0.753  (target >= 0.70)
  [PASS] investigation_completeness   mean_keyword_coverage  0.943  (target >= 0.85)
  [PASS] response_quality             mean_rubric_score      1.000  (target >= 0.80)
============================================================================
  ALL GATES PASSED
```

For machine-readable output (CI/dashboards):

```bash
python3 scripts/run_evals.py --json
# or, fail non-zero on regression:
python3 scripts/run_evals.py --ci --out report.json
```

## What each suite actually measures

We took a hard look at the harness and tightened the language so the
documentation matches the code. Here is the honest breakdown:

### 1. Alert reduction ratio — `Real measurement`

**Source:** [`services/agents/tests/test_alert_reduction.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)

A 1 000-alert noisy stream — pure duplicates, near-duplicates within a
30-minute host window, multi-host rule storms, and benign low-score chatter —
is fed into the **real** fusion pipeline:

- **Tier 1** — same `(rule, host, user)` within 10 minutes → 1 incident
- **Tier 2** — same `(rule, host)` within 30 minutes → merge into a Tier-1 incident
- **Tier 3** — same rule within 5 minutes across ≥ 3 hosts → "storm" incident

Incidents below the noise threshold (`score < 0.35`) are dropped. The output is
whatever the code produces — a fusion regression will move the number. This is
a legitimate measurement of fusion behavior on a controlled dataset.

We deliberately quote ~75 % rather than the 90 % that vendors tend to market,
because we're measuring the same logic on a fixed dataset every time, and we'd
rather an auditor see a real number than a marketing one.

### 2. MITRE ATT&CK tactic accuracy — `Substrate self-consistency`

**Source:** [`services/agents/tests/test_mitre_accuracy.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_mitre_accuracy.py)

Each synthetic incident is generated with a labeled MITRE tactic and a
description that is, by design, written to include keywords the **hand-curated
extractor** in the test recognizes. A case is "correct" if the predicted
tactic set has at least one overlap with the curated expected-tactic set.

The 97 % therefore mostly checks that **dataset and extractor agree** with each
other. It is useful as:

- A **regression sentinel** — if someone breaks the extractor or rewrites the
  dataset without updating the other, this suite catches it.
- A **schema sanity check** — every incident carries at least one tactic the
  extractor can reach.

It is **not**:

- A measure of LLM agent accuracy on real telemetry.
- A score that should be compared to vendor MITRE benchmarks.

Treat it as a regression sentinel for the substrate, not a leaderboard score.

### 3. Investigation completeness — `Substrate self-consistency`

**Source:** [`services/agents/tests/test_investigation_completeness.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_investigation_completeness.py)

Each synthetic incident ships with a list of `evidence_keywords`. A
deterministic report **simulator** wraps the incident's `description` field
into a Markdown report; the **judge** then looks for those evidence keywords in
the report.

Because the description is what produces the evidence keywords in the first
place, and the simulator pastes the description back into the report verbatim,
the score is close to a string-copy tautology. It confirms:

- The report template still includes the description.
- The keyword judge can still tokenize and match.

It does **not** confirm an LLM agent wrote a complete investigation. The
real value of this suite is catching template breakage — not LLM quality.

### 4. Response-plan quality — `Substrate self-consistency`

**Source:** [`services/agents/tests/test_response_quality.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_response_quality.py)

A deterministic response-plan **synthesizer** produces a containment plan for
each incident. By construction, the synthesizer embeds:

- The expected MITRE techniques into the plan summary.
- The first `evidence_keyword` into the plan steps.

An offline judge then scores each plan against a 5-criterion rubric:

1. **Action aligned** — the plan's action class matches the curated `response_class`
2. **Severity aware** — plan tone scales with `severity`
3. **MITRE aligned** — plan references at least one expected tactic
4. **Evidence grounded** — plan references at least one expected evidence keyword
5. **Actionable** — plan contains concrete imperative verbs and step-by-step structure

Because the synthesizer embeds exactly what the rubric checks for, criteria 3
and 4 are essentially guaranteed; 1, 2, and 5 are also driven by the templated
generator. The score is ~1.000 by construction.

This catches a broken templating pipeline (e.g. someone removes the MITRE
references from the synthesizer, or the rubric stops matching) — it is
**not** a grade of LLM-written response plans.

## Honest comparison vs vendors

| Capability                                     | AiSOC | Wazuh | Splunk | Anvilogic | Prophet | Dropzone |
|-----------------------------------------------|:-----:|:-----:|:------:|:---------:|:-------:|:--------:|
| Open-source (MIT)                              |  ✅   |  ✅   |   ❌   |    ❌     |   ❌    |    ❌    |
| Self-hostable (your data never leaves)         |  ✅   |  ✅   |   ✅   |    ❌     |   ❌    |    ❌    |
| Agent decisions are step-by-step auditable     |  ✅   |  N/A  |  N/A   |    ❌     |   ❌    |    ❌    |
| Public, reproducible regression harness        |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| Eval dataset shipped in the repo               |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| Substrate-level regression gate in CI          |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| Plugin SDK (Python + Go)                       |  ✅   |  ✅   |   ✅   |    ⚠️     |   ❌    |    ❌    |
| Free                                           |  ✅   |  ✅   |   ❌   |    ❌     |   ❌    |    ❌    |

> **Why this matters:** A regulated bank cannot deploy a vendor whose agent is a
> black box cloud service. They can deploy AiSOC. Your auditor reviews the same
> dataset, the same harness, and the same CI numbers we publish on this page —
> and we tell them straight which numbers are real measurements and which are
> regression sentinels.

## What this is _not_

We're allergic to overclaiming, so a few honest caveats:

- **No LLM agent runs in this harness.** It exercises deterministic extractors
  and templated report/plan synthesis. The live `services/agents/` LangGraph
  orchestrator that talks to OpenAI/Anthropic is **not** under test here. A
  separate **online eval** (LLM-as-judge, real orchestrator) is on the
  [Phase-1 roadmap](https://github.com/beenuar/AiSOC/blob/main/.cursor/plans/aisoc_leading-ai-soc_90-day_plan_9999bc93.plan.md#1c-eval-harness-from-20--200-cases--public-benchmark)
  and will run nightly. That is where actual agent accuracy gets measured.
- **The dataset is synthetic.** 200 incidents is enough to flag major
  regressions but not enough to claim production parity. Real-customer
  blindness is on the roadmap (federated, opt-in).
- **Three of the four judges are tautological by design.** The dataset, the
  templates, and the judge were written together to keep the gate fast and
  deterministic. They will pass as long as the substrate is internally
  consistent. They will fail if it is not.
- **"Public benchmark" means the harness, not a third-party leaderboard.**
  These numbers are reproducible by anyone with `python3`. They are not
  comparable to numbers from MITRE Engenuity, MLPerf, or any other external
  evaluator.

## Historical results

Every CI run on `main` writes a snapshot into the [`eval-results`](https://github.com/beenuar/AiSOC/tree/eval-results) branch:

```text
eval/results/<commit_sha>.json   # one snapshot per commit
eval/results/latest.json         # always points to most recent passing build
eval/results/badge-*.json        # shields.io endpoints
```

You can `git clone -b eval-results` to graph the trend yourself, or open the
[Actions tab](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml) for
per-run job summaries.

## Help us harden the harness

Pull requests welcome. The fastest ways to make this harness honestly stronger:

- **Land the online LLM-as-judge variant.** Wire `OPENAI_API_KEY` /
  `ANTHROPIC_API_KEY` through the harness so the report and response judges run
  against actual LLM output instead of the templated synthesizer. That is what
  turns this page into a real agent benchmark.
- **Find a tactic the keyword extractor misses.** Add a fixture incident, watch
  the MITRE accuracy ticker move, fix the extractor.
- **Find a fusion miss.** Add a contrived alert pattern that should de-dupe but
  doesn't. The reduction-ratio gate will block the regression.
- **Tighten the report and plan rubrics.** The completeness and quality suites
  are intentionally permissive in v1. PRs that add stricter evidence-grounding
  or that decouple the synthesizer from the judge keywords are highly welcome.

See [`CONTRIBUTING.md`](https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md) for the full path.
