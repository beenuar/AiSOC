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

Vendor claims about AI SOC performance — alert reduction percentages, MITRE
coverage, analyst throughput — are typically not reproducible by buyers. The
dataset, the baseline, and the rubric are not published. AiSOC takes the
opposite approach: ship a small harness, label which metrics are real
measurements and which are substrate self-checks, and let anyone reproduce
the numbers.

1. **The dataset is in the repo** — [`services/agents/tests/eval_data/synthetic_incidents.json`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json), 200 cases, deterministic, regenerable.
2. **The harness is in the repo** — four pytest suites under [`services/agents/tests/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/tests).
3. **The CI gate runs on every commit** — [latest run](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml).
4. **Historical numbers are queryable** — every successful build pushes its `eval_report.json` to the [`eval-results`](https://github.com/beenuar/AiSOC/tree/eval-results) branch as `eval/results/<commit_sha>.json`.

## Latest results

The four numbers below are produced by `scripts/run_evals.py` against the
200-incident synthetic dataset. They run in roughly 25 milliseconds total (no
LLM calls, no DB) so they're cheap enough to gate every commit.

| Suite                          | Metric                | Latest    | Target  | What it checks |
|--------------------------------|-----------------------|-----------|---------|----------------|
| Alert reduction ratio          | reduction             | 75.3 %    | ≥ 70 %  | Real measurement of the 3-tier fusion logic on a noisy 1 000-alert stream |
| MITRE ATT&CK tactic accuracy   | accuracy              | 97.0 %    | ≥ 80 %  | Substrate self-consistency — keyword extractor vs. dataset written for it |
| Investigation completeness     | mean keyword coverage | 94.3 %    | ≥ 85 %  | Substrate self-consistency — report template wraps the description; judge finds keywords from the description |
| Response-plan quality          | mean rubric score     | 1.000     | ≥ 0.80  | Substrate self-consistency — synthesizer embeds the keywords the rubric checks for |

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

The reported ~75 % is the actual output of the fusion pipeline on this fixed
dataset. It is not tuned to match a marketing number.

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

## Comparison to other AI SOC offerings

| Capability                                     | AiSOC | Wazuh | Splunk | Anvilogic | Prophet | Dropzone |
|-----------------------------------------------|:-----:|:-----:|:------:|:---------:|:-------:|:--------:|
| Open-source (MIT)                              |  yes  |  yes  |   no   |    no     |   no    |    no    |
| Self-hostable                                  |  yes  |  yes  |  yes   |    no     |   no    |    no    |
| Agent decisions step-by-step auditable         |  yes  |  n/a  |  n/a   |    no     |   no    |    no    |
| Public, reproducible regression harness        |  yes  |  no   |   no   |    no     |   no    |    no    |
| Eval dataset shipped in the repo               |  yes  |  no   |   no   |    no     |   no    |    no    |
| Substrate-level regression gate in CI          |  yes  |  no   |   no   |    no     |   no    |    no    |
| Plugin SDK (Python + Go)                       |  yes  |  yes  |  yes   |  partial  |   no    |    no    |
| Free                                           |  yes  |  yes  |   no   |    no     |   no    |    no    |

A self-hostable, MIT-licensed agent with a published regression harness is
something an auditor or regulated buyer can review directly. Vendor cloud
agents typically cannot be reviewed at the same level.

## What this is not

A few caveats:

- **No LLM agent runs in this harness.** It exercises deterministic extractors
  and templated report/plan synthesis. The live `services/agents/` LangGraph
  orchestrator that talks to OpenAI or Anthropic is not under test here. A
  separate online eval (LLM-as-judge, real orchestrator) is on the roadmap and
  will run nightly. That is where actual agent accuracy gets measured.
- **The dataset is synthetic.** 200 incidents is enough to flag major
  regressions but not enough to claim production parity. Federated, opt-in
  real-customer evaluation is on the roadmap.
- **Three of the four judges are tautological by design.** The dataset, the
  templates, and the judge were written together to keep the gate fast and
  deterministic. They will pass as long as the substrate is internally
  consistent. They will fail if it is not.
- **"Public eval harness" means this harness, not a third-party leaderboard.**
  These numbers are reproducible by anyone with `python3`. They are not
  comparable to MITRE Engenuity, MLPerf, or any other external evaluator.

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
