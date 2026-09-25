---
sidebar_position: 1
title: Alert Reduction
description: Two alert-reduction numbers, why both are published, and which one describes AiSOC. Methodology, the retraction of the legacy 75.3% figure, reproduction, and CI artefact location.
---

# Alert Reduction

> **Synthetic, deterministic, reproducible in under a second.** This page
> documents the AiSOC alert-reduction benchmark — what it measures, how a
> noisy alert stream collapses into actionable incidents, and how to
> reproduce the numbers locally.
>
> **Two numbers are published, and only one of them describes this product.**
> **33.3 %** is measured against `RawAlert.correlation_key()`, the grouping
> `Correlator` actually calls. **75.3 %** comes from a four-tier scheme
> implemented inside a test; it is retained for continuity and **does not
> describe this product**. See [Why there are two
> numbers](#why-there-are-two-numbers) before quoting either.

[![Alert Reduction](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-reduction.json)](#latest-results)

:::warning Read this first
Both numbers are **synthetic**. The 1,000-alert stream is generated with a
fixed RNG seed and is not a capture from a real SIEM.

The legacy suite in
[`services/agents/tests/test_alert_reduction.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)
was long described here as a faithful in-harness re-implementation of the
production grouping rules. That description was wrong, and the gap is wider
than "minus the DB-backed deduplicator and the ML scorer": the test does not
merely reimplement fusion's grouping, it implements **different** grouping.
Its four tiers key on `(rule_id, host, user)` with 10/30/5-minute windows,
while `RawAlert.correlation_key()` keys on `{tenant}:{entity}:{tactic}` over a
one-hour window.

[`services/fusion/tests/test_alert_reduction_real.py`](https://github.com/beenuar/AiSOC/blob/main/services/fusion/tests/test_alert_reduction_real.py)
measures the real key. Neither suite is an end-to-end measurement of the
production fusion service against real customer telemetry.
:::

## TL;DR

| Metric | Value | Target | Describes AiSOC? |
|---|---|---|---|
| **Reduction ratio (product logic)** | **33.3 %** (1,000 alerts → 667 incidents) | 20–95 % | **Yes** — groups with `RawAlert.correlation_key()` |
| Reduction ratio (legacy suite) | 75.3 % (1,000 alerts → 247 incidents) | ≥ 70 % | **No** — four-tier scheme implemented inside the test |
| Critical alerts preserved (legacy suite) | 93 / 93 (zero drop) | 100 % | Invariant of the legacy suite |
| Storm incidents collapsed (legacy Tier 3) | 16 (avg ~8.9 alerts each, 3–8 distinct hosts) | ≥ 1 | Legacy suite only |
| Determinism | Same RNG seed → same byte-for-byte output | Required | Both |
| Wall time | ~8 ms on a laptop | &lt; 100 ms | Both |

The real-key gate is bounded on **both** sides rather than floored. A floor
alone is satisfied by a key that collapses everything into one incident —
99.9 % reduction and a useless SOC — so "more reduction is better" is only
true up to a point, and the gate says where.

The legacy snapshot lives at
[`eval-results/eval/results/latest.json`](https://github.com/beenuar/AiSOC/blob/eval-results/eval/results/latest.json)
under `suites.alert_reduction`. Every successful build on `main` / `develop`
appends a new commit-keyed entry alongside it (see
[CI artefact location](#ci-artefact-location)).

## What this measures

A SOC's first-order pain isn't "did we catch the threat" — it's "did we drown
in the catch." Modern detection stacks routinely emit thousands of alerts per
hour, and the same underlying event (a single misconfigured agent, one phish
campaign, one credential-stuffing burst) can light up dozens of rules at once.
The job of fusion is to take that raw rule output and emit a small,
deduplicated, human-reviewable list of **incidents**.

This benchmark answers exactly one question:

> **Given a controlled, realistic distribution of noise, what fraction of
> incoming alerts collapse into incidents — and does the substrate drop any
> of the alerts that an analyst genuinely needed to see?**

Answered twice, because the harness has answered it twice. The other three
substrate suites on the [public eval page](../benchmark.md) are tautological
by design (dataset and judge written together to gate template breakage);
neither alert-reduction suite is. But only one of them groups the way the
product groups.

## Why there are two numbers {#why-there-are-two-numbers}

The original suite was honest about being synthetic and always carried a
`PARTIAL` row saying it gated "an in-test fusion re-impl". Reading it closely,
the gap was wider than that wording admitted: the test did not merely
reimplement fusion's grouping, it implemented **different** grouping.

Its four tiers key on `(rule_id, host, user)` with 10/30/5-minute windows.
`RawAlert.correlation_key()` — what `Correlator` actually calls — keys on
`{tenant}:{entity}:{tactic}` over a one-hour window. Different dimensions,
different windows, different answer. So the 75.3 % described an algorithm the
product does not run, and a reimplementation can drift from the thing it
stands for without any test failing.

[`services/fusion/tests/test_alert_reduction_real.py`](https://github.com/beenuar/AiSOC/blob/main/services/fusion/tests/test_alert_reduction_real.py)
measures the real key. It reports **33.3 %** on a comparable stream. That is
less flattering and it is ours.

`Correlator` itself needs Redis, but Redis is where it *stores* incidents —
the grouping decision is entirely `correlation_key()` plus the configured
window, so the ratio is computed from the real method without the storage
layer.

Both numbers stay published. Deleting the old one would make the history
unreadable; presenting it without this note would be the thing this page
exists to prevent.

The sections below describe the **legacy** suite's dataset and tier
structure, which is where the 75.3 % comes from. Read them as documentation
of a retained regression gate, not of the shipping correlation logic.

## The synthetic dataset

The 1,000-alert stream is generated by
[`generate_noisy_alert_stream`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)
with a fixed seed so every run is byte-for-byte identical. The mix is
deliberately shaped to look like the worst hour of a real SIEM:

| Bucket | Share | What it represents |
|---|---|---|
| Pure duplicates | ~25 % | Same `(rule, host, user)` within the same minute — the agent re-firing on the same telemetry |
| Near-duplicates | ~30 % | Same `(rule, host)`, different user **or** ±5-minute window — same root event, slight metadata drift |
| Storms | ~15 % | One rule firing across many hosts within a 5-minute window — campaign / worm / misconfigured push |
| Benign noise | ~10 % | Low-score rules (`score < 0.35`) — the chatter every SOC silences but the SIEM still emits |
| Unique high-signal events | ~20 % | Distinct `(rule, host, user)` events with no friends — the things you actually want to look at |

The full distribution from the latest run:

| Severity in | Alerts | Incidents out (post-fusion) |
|---|---:|---:|
| `critical` | 93 | 38 |
| `high` | 417 | 130 |
| `medium` | 303 | 79 |
| `low` | 187 | 0 (collapsed below the noise floor) |
| **Total** | **1,000** | **247** |

The `low`-severity bucket disappears entirely: those alerts carry `score < 0.35`
by construction and get dropped by the noise threshold. This is intentional —
the benign-noise bucket exists to verify the noise-floor cut still fires, not
to be shown to a human.

## The legacy suite's 3-tier grouping

The legacy algorithm has three rules, applied in order. The exact code lives
in [`fuse_alerts`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)
inside the test file. It is **not** the production logic in
[`services/fusion`](https://github.com/beenuar/AiSOC/tree/main/services/fusion),
which keys on `{tenant}:{entity}:{tactic}` over a one-hour window — see [Why
there are two numbers](#why-there-are-two-numbers).

### Tier 1 — strict identity collapse

Same `(rule_id, host, user)` within a **10-minute window** → 1 incident.
This is the "the agent re-fired on the same telemetry" case. Most pure
duplicates and same-source loops collapse here.

### Tier 2 — host-scoped merge

Same `(rule_id, host)` within a **30-minute window**, but spanning multiple
users (or the same user with ±5-minute drift) → merged into one Tier-1
incident. This catches "same root event, slightly different metadata"
duplicates, including a single attacker pivoting between local accounts on
the same host.

### Tier 3 — rule-storm collapse

Same `rule_id` firing within a **5-minute window** across **≥ 3 distinct
hosts** → one "storm" incident with `host = <storm:N-hosts>`. This is the
"campaign / worm / misconfigured deployment push" case — the kind of event
that historically generates a hundred near-identical tickets.

### Noise-floor drop

Any incident with aggregate `score < 0.35` is dropped before being emitted.
This is the configurable knob a tenant uses to silence chronically chatty
rules without de-listing them; in the benchmark it means the 187 `low`
alerts vanish.

## Latest results {#latest-results}

The numbers below are produced by `python3 scripts/run_evals.py --json` on the
current `main` and rendered into `eval/results/latest.json` on the
`eval-results` branch by the CI gate. `run_evals.py` emits the **legacy**
suite under the `alert_reduction` key; the real-key figure is produced by
pytest in `services/fusion` and is shown alongside it.

### Headline

| Field | Product logic (real correlation key) | Legacy suite |
|---|---|---|
| `metric` | `reduction_ratio` | `reduction_ratio` |
| `value` | `0.333` | `0.753` |
| `target` | `0.20 – 0.95` (bounded both sides) | `≥ 0.70` (floor only) |
| `passed` | `true` | `true` |
| `duration_ms` | ~30 | `7.9` |
| Describes this product | **yes** | **no** |

### Collapse breakdown

| Bucket | Count | Avg alerts collapsed | Notes |
|---|---:|---:|---|
| Tier 1/2 multi-member incidents (non-storm) | 56 | ~8.8 alerts each | Same root event, deduplicated |
| Tier 3 storm incidents | 16 | ~8.9 alerts each | 3 – 8 distinct hosts per storm |
| Single-member incidents | 175 | 1 each | Genuine unique signal — exactly what an analyst needs to triage |
| **Total emitted incidents** | **247** | — | from 1,000 raw alerts |

The 175 single-member incidents are the floor: those are the alerts that
*should* survive fusion, because they represent distinct events. Anything
beyond that floor is a deduplication win.

### Critical-alert preservation

| Severity tier | Alerts in | Preserved in incidents | Dropped |
|---|---:|---:|---:|
| `critical` | 93 | **93 (100 %)** | **0** |

This is the non-negotiable invariant: **fusion never silently drops a critical
alert.** The substrate may merge a critical alert into a multi-member incident
(it does — 93 critical alerts are represented across the 38 critical incidents
emitted), but it will never delete one. The
[`test_critical_alerts_never_dropped`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)
test asserts this directly and is part of the same CI gate.

### Determinism

Two consecutive runs on the same commit produce byte-for-byte identical
output. The benchmark uses a fixed RNG seed inside `generate_noisy_alert_stream`,
and the fusion algorithm is order-stable on its inputs. This matters for two
reasons:

1. **CI flakiness has a single root cause.** If two CI runs disagree on the
   reduction ratio, it's a code change, not a coincidence.
2. **Diff-friendly regression review.** When a PR moves the number, you can
   inspect *which* incidents changed shape (single-member ↔ multi-member ↔
   storm) instead of being told "the noise moved."

The
[`test_run_is_deterministic`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py)
test enforces this — it runs `fuse_alerts` twice and compares the incident
lists element-for-element.

## Reproduce locally

From a fresh clone:

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
python3 scripts/run_evals.py
```

Expected output (excerpt):

```text
[PASS] alert_reduction               reduction_ratio        0.753  (target >= 0.70)
```

For machine-readable output:

```bash
python3 scripts/run_evals.py --json --out /tmp/eval.json
python3 -c "import json; print(json.dumps(json.load(open('/tmp/eval.json'))['suites']['alert_reduction'], indent=2))"
```

To run the figure that describes this product — the real correlation key:

```bash
cd services/fusion
python3 -m pytest tests/test_alert_reduction_real.py -v -s
# [eval] alert reduction (real correlation_key): 1000 alerts -> 667 incidents = 33.3%
```

To run only the legacy alert-reduction tests under `pytest`:

```bash
cd services/agents
python3 -m pytest tests/test_alert_reduction.py -v
```

That covers four assertions:

- `test_reduction_ratio_meets_target` — the headline `≥ 70 %` gate
- `test_critical_alerts_never_dropped` — the zero-loss invariant
- `test_run_is_deterministic` — same seed → same output
- `test_storms_collapse` — Tier 3 fires when ≥ 3 hosts share a rule in a 5-minute window

## CI artefact location

Every push to `main` or `develop` triggers
[`.github/workflows/ci.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/ci.yml),
which runs `scripts/run_evals.py --ci --out report.json`. On success, the
report is committed to the orphan
[`eval-results`](https://github.com/beenuar/AiSOC/tree/eval-results) branch:

```text
eval/results/<commit_sha>.json   # one snapshot per commit
eval/results/latest.json         # most recent passing build on main
eval/results/badge-reduction.json # shields.io endpoint backing the badge above
```

Reading the latest snapshot from CI:

```bash
curl -s https://raw.githubusercontent.com/beenuar/AiSOC/eval-results/eval/results/latest.json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d['suites']['alert_reduction'], indent=2))"
```

Drop that into a dashboard, a Slack notifier, or a tenant-facing report — it's
the same JSON shape `run_evals.py` writes locally.

## What this benchmark does *not* tell you

In the spirit of being painfully honest about synthetic vs. real:

- **The legacy `fuse_alerts` does not implement the production grouping at
  all.** It keys on `(rule_id, host, user)`; the product keys on
  `{tenant}:{entity}:{tactic}`. This was described here as a faithful
  re-implementation for several releases and it was not one.
- **Neither suite measures the production fusion service end-to-end.** The
  real-key measurement drives `RawAlert.correlation_key()` directly, but the
  production service additionally runs a Postgres-backed deduplicator
  (cross-window persistence) and an ML scorer (lifts and depresses scores
  based on historical FP rate). Those components have their own unit tests;
  they are out of scope here because this gate has to run in milliseconds in
  CI.
- **It does not exercise real telemetry.** The 1,000-alert stream is shaped
  to look like the worst hour of a SIEM, but it isn't a capture from one.
  Real-customer evaluation is on the v1.5 roadmap and will be opt-in /
  federated; see [`apps/docs/docs/benchmark.md`](../benchmark.md#what-this-is-not).
- **It does not compute per-rule false-positive rates.** That is the next
  stage of this benchmark, tracked under
  [issue #5 — per-rule cross-fire FP eval gate](https://github.com/beenuar/AiSOC/issues/5)
  ([PR #89](https://github.com/beenuar/AiSOC/pull/89), in flight). Once that
  ships, this page will gain a "per-rule FP rate" section that surfaces which
  rules contribute most to the noise floor and how their merge rate trends
  over time.
- **It does not score "alerts an analyst would have wanted."** That requires
  labeled human-judgement data, which we don't have synthetically. The
  closest proxy here is the critical-alert preservation invariant — *zero*
  alerts above the noise floor are silently dropped.

## Roadmap

The pieces that turn this from a substrate gate into a buyer-grade benchmark:

- **Per-rule FP rate breakdown** — depends on
  [issue #5](https://github.com/beenuar/AiSOC/issues/5) /
  [PR #89](https://github.com/beenuar/AiSOC/pull/89). Will surface per-rule
  contribution to the noise floor and gate net-new noisy detections in CI.
- **Per-tenant fusion config replay** — let an operator paste their fusion
  knobs (window sizes, noise threshold, severity overrides) and replay the
  stream against them. Lets a buyer answer "what would *my* number look like"
  before deploying.
- **Live-fusion online benchmark** — once the production
  [`services/fusion`](https://github.com/beenuar/AiSOC/tree/main/services/fusion)
  service has a stable replay API, run the same 1,000-alert stream through the
  real DB-backed deduplicator + ML scorer in a nightly job. The delta vs.
  this in-harness number is the "what does the substrate gate miss" signal.
- **Federated, opt-in real-tenant evaluation** — collapsed against tenant
  telemetry under DP-style aggregation so the headline number reflects a
  population, not a single deployment.

PRs against any of those are welcome — the
[`Help us harden the harness`](../benchmark.md#help-us-harden-the-harness)
section on the umbrella benchmark page lists the contribution path.

## See also

- [Public Eval Harness](../benchmark.md) — the umbrella page covering all five
  CI-gated suites (MITRE accuracy, alert reduction, investigation
  completeness, response quality, playbook completion).
- [Synthetic telemetry corpus](../benchmark.md#5-synthetic-telemetry-corpus) —
  the 14-source backing event corpus that connector and Sigma rule PRs wire
  against.
- [`scripts/run_evals.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/run_evals.py) —
  the unified runner that produces the JSON snapshot consumed by this page.
- [`services/fusion/tests/test_alert_reduction_real.py`](https://github.com/beenuar/AiSOC/blob/main/services/fusion/tests/test_alert_reduction_real.py) —
  the measurement against `RawAlert.correlation_key()`. This is the one that
  describes AiSOC.
- [`services/agents/tests/test_alert_reduction.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_alert_reduction.py) —
  the legacy test file containing both the synthetic stream generator and the
  four-tier grouping under test.
