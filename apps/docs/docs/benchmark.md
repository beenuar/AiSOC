---
sidebar_position: 4
title: Public Benchmark
description: AiSOC's open, reproducible Pillar-1 evaluation suite. 200 deterministic synthetic incidents, four eval gates, all numbers measurable on your laptop in seconds.
---

# AiSOC Public Benchmark

> **The only AI SOC where the agent's accuracy is published, reproducible, and auditable.**
>
> Closed-source vendors (Anvilogic, Prophet, Dropzone, Tines) publish marketing
> claims. AiSOC publishes a benchmark, the dataset, the harness, and the CI gate
> that runs it on every commit. You can reproduce every number on this page in
> under 10 seconds on a laptop.

[![MITRE Accuracy](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcyble-inc%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-mitre.json)](#latest-results)
[![Alert Reduction](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcyble-inc%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-reduction.json)](#latest-results)
[![Investigation Completeness](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcyble-inc%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-completeness.json)](#latest-results)
[![Response Quality](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcyble-inc%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-quality.json)](#latest-results)

## Why this exists

The AI SOC market is full of unfalsifiable claims:

- *"90% alert reduction"* — measured on **whose** alerts, against **what** baseline?
- *"10× analyst throughput"* — what's the dataset, the rubric, the failure mode?
- *"Detects MITRE ATT&CK"* — across how many tactics? With what accuracy?

You cannot deploy a black-box vendor in a regulated environment and tell your
auditor "we trust their internal QA." AiSOC is built on the opposite premise:

1. **The dataset is in the repo.** [`services/agents/tests/eval_data/synthetic_incidents.json`](https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json) — 200 cases, deterministic, regenerable.
2. **The harness is in the repo.** Four pytest suites under [`services/agents/tests/`](https://github.com/cyble-inc/AiSOC/tree/main/services/agents/tests).
3. **The CI gate runs on every commit.** [Latest run](https://github.com/cyble-inc/AiSOC/actions/workflows/ci.yml).
4. **Historical numbers are queryable.** Every successful build pushes its `eval_report.json` to the [`eval-results`](https://github.com/cyble-inc/AiSOC/tree/eval-results) branch as `eval/results/<commit_sha>.json`.

## Latest results

The four numbers below are produced by `scripts/run_evals.py` against the
200-incident synthetic benchmark. They run in roughly **25 milliseconds total**
(no LLM calls, no DB) so they're cheap enough to gate every commit.

| Suite                          | Metric                | Latest      | Target  | Notes |
|--------------------------------|-----------------------|-------------|---------|-------|
| MITRE ATT&CK tactic accuracy   | accuracy              | **97.0 %**  | ≥ 80 %  | At least one expected tactic recovered per incident |
| Alert reduction ratio          | reduction             | **75.3 %**  | ≥ 70 %  | 1 000 noisy alerts → 247 incidents via 3-tier fusion |
| Investigation completeness     | mean keyword coverage | **94.3 %**  | ≥ 85 %  | Evidence keywords cited in the agent's report |
| Response-plan quality          | mean rubric score     | **1.000**   | ≥ 0.80  | 5-criterion rubric, offline keyword judge |

These numbers move with the codebase. The current snapshot lives at
[`eval-results/eval/results/latest.json`](https://github.com/cyble-inc/AiSOC/blob/eval-results/eval/results/latest.json).

## Reproduce these numbers

You don't have to take our word for it. From a fresh clone:

```bash
git clone https://github.com/cyble-inc/AiSOC && cd AiSOC
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

## How each suite works

### 1. MITRE ATT&CK tactic accuracy

**Source:** [`services/agents/tests/test_mitre_accuracy.py`](https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/test_mitre_accuracy.py)

For each of the 200 incidents we run a deterministic keyword extractor that
proxies for the LLM's tactic-detection. A case is "correct" if the predicted
tactic set has at least one overlap with the curated expected-tactic set. We
also report per-case precision, recall, and F1 over the expected sets.

The expected-tactic and expected-technique sets cover all 14 MITRE ATT&CK
enterprise tactics across roughly the top 50 techniques. Cases are
deterministically generated by [`scripts/generate_eval_incidents.py`](https://github.com/cyble-inc/AiSOC/blob/main/scripts/generate_eval_incidents.py)
so the dataset is regeneratable bit-for-bit.

### 2. Alert reduction ratio

**Source:** [`services/agents/tests/test_alert_reduction.py`](https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)

We fabricate a 1 000-alert noisy stream covering pure duplicates, near
duplicates within a 30-minute host window, rule-storms across multiple hosts,
and benign low-score noise. The fusion pipeline then groups them into incidents
using a 3-tier strategy:

- **Tier 1** — same `(rule, host, user)` within 10 minutes → 1 incident
- **Tier 2** — same `(rule, host)` within 30 minutes → merge into a Tier-1 incident
- **Tier 3** — same rule within 5 minutes across ≥ 3 hosts → "storm" incident

Incidents below the noise threshold (`score < 0.35`) are dropped.

The honest reduction comes out to **~75 %**. We deliberately quote it lower
than vendor claims (Anvilogic markets 90 %) because we measured it.

### 3. Investigation completeness

**Source:** [`services/agents/tests/test_investigation_completeness.py`](https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/test_investigation_completeness.py)

Each synthetic incident ships with a list of `evidence_keywords` that any
competent SOC analyst should cite in their report. We run a deterministic
report simulator that produces a Markdown investigation, then score what
fraction of the evidence keywords appear in the report.

This catches the most common silent failure mode of LLM-driven SOC tools:
plausible-sounding output that omits half the relevant signals.

### 4. Response-plan quality

**Source:** [`services/agents/tests/test_response_quality.py`](https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/test_response_quality.py)

A deterministic response-plan synthesizer produces a containment plan for each
incident. An offline judge then scores each plan against a 5-criterion rubric:

1. **Action aligned** — the plan's action class matches the curated `response_class`
2. **Severity aware** — plan tone scales with `severity`
3. **MITRE aligned** — plan references at least one expected tactic
4. **Evidence grounded** — plan references at least one expected evidence keyword
5. **Actionable** — plan contains concrete imperative verbs and step-by-step structure

This is an **offline keyword judge** (no LLM-as-judge calls), so it's
deterministic and free. A future revision will optionally swap in an
LLM-as-judge run gated by `OPENAI_API_KEY`.

## Honest comparison vs vendors

| Capability                                     | AiSOC | Wazuh | Splunk | Anvilogic | Prophet | Dropzone |
|-----------------------------------------------|:-----:|:-----:|:------:|:---------:|:-------:|:--------:|
| Open-source (MIT)                              |  ✅   |  ✅   |   ❌   |    ❌     |   ❌    |    ❌    |
| Self-hostable (your data never leaves)         |  ✅   |  ✅   |   ✅   |    ❌     |   ❌    |    ❌    |
| Agent decisions are step-by-step auditable     |  ✅   |  N/A  |  N/A   |    ❌     |   ❌    |    ❌    |
| Public, reproducible benchmark numbers         |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| Eval dataset shipped in the repo               |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| MITRE ATT&CK accuracy gate in CI               |  ✅   |  ❌   |   ❌   |    ❌     |   ❌    |    ❌    |
| Plugin SDK (Python + Go)                       |  ✅   |  ✅   |   ✅   |    ⚠️     |   ❌    |    ❌    |
| Free                                            |  ✅   |  ✅   |   ❌   |    ❌     |   ❌    |    ❌    |

> **Why this matters:** A regulated bank cannot deploy a vendor whose agent is a
> black box cloud service. They can deploy AiSOC. Your auditor reviews the same
> dataset, the same harness, and the same CI numbers we publish on this page.

## What this benchmark is _not_

We're allergic to overclaiming, so a few honest caveats:

- **The harness is offline.** It uses deterministic extractors and templated
  report/plan synthesis — not the live LLM pipeline. We do this so the gate is
  fast and cheap enough to run on every commit. A separate **online eval**
  (LLM-as-judge, real `services/agents/app/investigator/orchestrator.py`) is
  on the [Phase-1 roadmap](https://github.com/cyble-inc/AiSOC/blob/main/.cursor/plans/aisoc_leading-ai-soc_90-day_plan_9999bc93.plan.md#1c-eval-harness-from-20--200-cases--public-benchmark) and will run nightly.
- **The dataset is synthetic.** 200 incidents is enough to flag major
  regressions but not enough to claim production parity. Real-customer
  blindness is on the roadmap (federated, opt-in).
- **The judge is keyword-based.** It can be gamed by template-stuffing. The
  full LLM-as-judge variant is a follow-up. The keyword judge nonetheless
  catches the most common failure modes (omitted evidence, mis-aligned
  containment action, severity drift).

## Historical results

Every CI run on `main` writes a snapshot into the [`eval-results`](https://github.com/cyble-inc/AiSOC/tree/eval-results) branch:

```text
eval/results/<commit_sha>.json   # one snapshot per commit
eval/results/latest.json         # always points to most recent passing build
eval/results/badge-*.json        # shields.io endpoints
```

You can `git clone -b eval-results` to graph the trend yourself, or open the
[Actions tab](https://github.com/cyble-inc/AiSOC/actions/workflows/ci.yml) for
per-run job summaries.

## Improving these numbers

Pull requests welcome. The fastest ways to move the needle:

- **Find a tactic the keyword extractor misses.** Add a fixture incident, watch
  the MITRE accuracy ticker move, fix the extractor.
- **Find a fusion miss.** Add a contrived alert pattern that should de-dupe but
  doesn't. The reduction-ratio gate will block the regression.
- **Tighten the report rubric.** The completeness suite is intentionally
  permissive in v1; PRs that add stricter evidence-grounding criteria are
  highly welcome.

See [`CONTRIBUTING.md`](https://github.com/cyble-inc/AiSOC/blob/main/CONTRIBUTING.md) for the full path.
