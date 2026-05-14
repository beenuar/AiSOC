# Eval harness re-grade — v8.0 wave-2 vs upstream/main

Captured during stabilization of branch `v8.0/agentic-soc-foundation` (HEAD =
`9a5e63ed` at capture time). Both runs use the deterministic 200-incident
synthetic dataset (`services/agents/tests/eval_data/synthetic_incidents.json`)
plus the aligned synthetic telemetry corpus, so any delta reflects substrate
behaviour, not LLM stochasticity.

| Run | Commit | Command |
|-----|--------|---------|
| BEFORE | `upstream/main` @ `182afc5b` | `python scripts/run_evals.py --json --out /tmp/eval_before.json` |
| AFTER | `v8.0/agentic-soc-foundation` @ `9a5e63ed` | `python scripts/run_evals.py --json --out /tmp/eval_after.json` |

## Four-axis substrate metrics

| Axis | BEFORE | AFTER | Target | Δ |
|------|--------|-------|--------|---|
| `mitre_accuracy` (accuracy) | **0.97** | **0.97** | ≥ 0.80 | 0 |
| `alert_reduction` (reduction_ratio) | **0.753** | **0.753** | ≥ 0.70 | 0 |
| `investigation_completeness` (mean_keyword_coverage) | **0.9425** | **0.9425** | ≥ 0.85 | 0 |
| `response_quality` (mean_rubric_score) | **1.000** | **1.000** | ≥ 0.80 | 0 |

All four axes remain green on both branches. No regression.

Three of those four are substrate self-consistency gates over the
deterministic synthetic dataset — they are expected to stay flat across PRs
that don't touch detection content or the eval scorer; only `mitre_accuracy`
exercises the live agent. The wave-2 work is intentionally scaffold-level
(connectors, new endpoints, schema edges, UI pages) and does not move any of
the four axes, which is the expected outcome.

## Extended suites (also tracked)

| Suite | BEFORE | AFTER | Target | Passed |
|-------|--------|-------|--------|--------|
| `hunt_corpus` (positive_scenario_catch_rate) | 1.000 | 1.000 | 1.000 | ✅ |
| `adversary_eval` (graceful_degradation_catch_rate) | 0.475 | 0.475 | ≥ 0.40 | ✅ |
| `confidence_calibration` (investigation_brier_score) | 0.0605 | 0.0605 | ≤ 0.18 | ✅ |
| `memory_recall` (memory_recall_accuracy) | 1.000 | 1.000 | 1.000 | ✅ |
| `override_accuracy` (override_accuracy) | 1.000 | 1.000 | 1.000 | ✅ |
| `playbook_completion_rate` (completion_rate) | 0.735 | 0.735 | ≥ 0.50 | ✅ |
| `detection_fp_rate` (worst_per_rule_fp_rate) | 0.0049 | 0.0049 | ≤ 0.05 | ✅ |

`all_passed: true` on both runs.

## Per-investigation telemetry

The wave-2 `T2.3` change wires per-investigation token / USD / latency stats
into `run_evals.py`'s `per_investigation` block. On `upstream/main` the
`per_investigation` section is empty (`[]`); on `v8.0/agentic-soc-foundation`
it carries the rate-card-priced aggregate below. This is a pure additive
diff — the substrate metrics are unchanged.

| Stat | BEFORE | AFTER |
|------|--------|-------|
| `tokens_per_investigation.mean` | _n/a_ | 2186.13 |
| `tokens_per_investigation.median` | _n/a_ | 2114.00 |
| `tokens_per_investigation.p95` | _n/a_ | 2452 |
| `usd_per_investigation.mean` | _n/a_ | $0.014693 |
| `usd_per_investigation.median` | _n/a_ | $0.013685 |
| `usd_per_investigation.p95` | _n/a_ | $0.016930 |
| `latency_per_investigation_ms.mean` | _n/a_ | 0.0078 |
| `latency_per_investigation_ms.p95` | _n/a_ | 0.0119 |

> **Reading note.** The latency figure is the scorer's per-investigation
> compute envelope on the deterministic dataset, not wall-clock LLM latency.
> Token + USD figures come from the rate-card rather than a live LLM run —
> see `--no-telemetry-records` and `apps/docs/docs/benchmark.md` for the
> transparency contract.

## Runtime

Both runs complete in ≈ 1.5 s (deterministic in-process scorer, no live LLM
call). Wall-clock comparison is dominated by Python startup, so we don't
publish a delta.

## Take-aways for PR review

1. No regression on any axis. `all_passed` is `True` for both BEFORE and AFTER.
2. Wave-2 adds per-investigation telemetry to the eval report. Existing
   four-axis gates remain unchanged on the deterministic dataset, as designed.
3. Wet-eval (`scripts/wet_eval_check.py`) is the separate live-LLM track and
   is not part of this BEFORE/AFTER comparison.
