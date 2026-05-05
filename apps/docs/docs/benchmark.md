---
sidebar_position: 4
title: Public Eval Harness
description: AiSOC's open, deterministic regression harness. 200 synthetic incidents drawn from 55 distinct templates with backing telemetry (Sysmon, M365, CloudTrail, Okta, Linux auditd, …). Per-case and per-template CI gates over the substrate. Honest about what it measures — and what it doesn't.
---

# AiSOC Public Eval Harness

> **An open, deterministic regression harness over the AiSOC substrate.**
>
> This page is _not_ a leaderboard for AI SOC agents. It is a CI-gated harness
> that exercises the deterministic substrate underneath AiSOC — the keyword
> extractors, the in-harness fusion grouping (a faithful re-implementation of
> the production Tier 1/2/3 logic in `services/fusion`, minus the DB-backed
> dedup and ML scoring), the report and response templates, and the offline
> judges that grade them. The dataset, the harness, and the CI gate are all in
> the repo. You can reproduce every number on this page in under 10 seconds on
> a laptop.
>
> **What's new (v1.4):**
>
> 1. Every synthetic incident now ships with a backing **synthetic telemetry
>    corpus** — Sysmon / Windows-Security / M365 audit / CloudTrail / Okta /
>    Azure sign-in / Linux auditd / journald / EDR / firewall / DNS / VPN / DB
>    audit events — written to
>    [`synthetic_telemetry.jsonl`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_telemetry.jsonl).
>    Connector and Sigma PRs now have something concrete to wire against. See
>    [Synthetic telemetry corpus](#5-synthetic-telemetry-corpus) below.
> 2. Each of the substrate suites now reports a **per-template macro** alongside
>    the per-case mean. The 200-case dataset draws from 55 distinct templates,
>    so a single broken template moves the per-case headline by ~0.5 % but
>    moves the per-template macro by ~1.8 %. The macro is a stronger
>    regression signal that doesn't dilute when the dataset is enlarged. See
>    [Per-case vs. per-template metrics](#per-case-vs-per-template-metrics).

[![MITRE Accuracy](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-mitre.json)](#latest-results)
[![Alert Reduction](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-reduction.json)](#latest-results)
[![Investigation Completeness](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-completeness.json)](#latest-results)
[![Response Quality](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbeenuar%2FAiSOC%2Feval-results%2Feval%2Fresults%2Fbadge-quality.json)](#latest-results)

:::warning Read this first
This harness does **not** exercise the live LLM agent (`services/agents`
LangGraph orchestrator), and the `alert_reduction` suite does **not** call the
production `services/fusion` engine — it calls a standalone re-implementation
of the same Tier 1/2/3 grouping rules that lives in the test file. It runs
**deterministic substrate code** against **synthetic data** so we can gate
every PR targeting `main` / `develop` in milliseconds. Three of the four
metrics on this page measure the **internal consistency** of that substrate —
not agent accuracy. We explain exactly what each suite measures — and doesn't
— below.
:::

## Why this exists

Vendor claims about AI SOC performance — alert reduction percentages, MITRE
coverage, analyst throughput — are typically not reproducible by buyers. The
dataset, the baseline, and the rubric are not published. AiSOC takes the
opposite approach: ship a small harness, label which metrics are real
measurements and which are substrate self-checks, and let anyone reproduce
the numbers.

1. **The dataset is in the repo** — [`services/agents/tests/eval_data/synthetic_incidents.json`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json) (200 cases, deterministic, drawn from 55 distinct templates) plus its companion [`synthetic_telemetry.jsonl`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_telemetry.jsonl) (361 backing events across 14 log sources). Both are regenerable from `scripts/generate_eval_incidents.py`. Three of the four offline suites use the incident dataset; the alert-reduction suite uses a separately generated 1 000-alert stream produced by `generate_noisy_alert_stream` in the test file.
2. **The harness is in the repo** — five pytest suites under [`services/agents/tests/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/tests) (four scoring suites + a synthetic-telemetry schema/coverage gate).
3. **The CI gate runs on every PR targeting `main` / `develop`** — [latest run](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml). (CI is currently scoped to those two branches; PRs to long-lived feature branches are not gated.)
4. **Historical numbers are queryable** — every successful build pushes its report (written by `scripts/run_evals.py --out`) to the [`eval-results`](https://github.com/beenuar/AiSOC/tree/eval-results) branch as `eval/results/<commit_sha>.json`.

## Latest results

The four numbers below are produced by `scripts/run_evals.py`. The MITRE,
completeness, and response-quality suites run against the 200-incident
synthetic dataset; the alert-reduction suite runs against a separately
generated 1 000-alert noisy stream. The whole run takes roughly 25 ms total
(no LLM calls, no DB) so it's cheap enough to gate every PR targeting `main`
or `develop`.

| Suite                          | Metric                  | Per-case   | Per-template macro     | Target  | What it checks |
|--------------------------------|-------------------------|------------|------------------------|---------|----------------|
| Alert reduction ratio          | reduction               | 75.3 %     | _n/a_                  | ≥ 70 %  | Real measurement of the 3-tier fusion logic on a noisy 1 000-alert stream |
| MITRE ATT&CK tactic accuracy   | accuracy                | 97.0 %     | 96.4 % (n=55)          | ≥ 80 %  | Substrate self-consistency — keyword extractor vs. dataset written for it |
| Investigation completeness     | mean keyword coverage   | 94.2 %     | 94.3 % (n=55)          | ≥ 85 %  | Substrate self-consistency — report template wraps the description; judge finds keywords from the description |
| Response-plan quality          | mean rubric score       | 1.000      | 1.000 (n=55)           | ≥ 0.80  | Substrate self-consistency — synthesizer embeds the keywords the rubric checks for |

> The synthetic telemetry suite is a **schema/coverage gate**, not a scoring
> suite, so it does not appear in the table. It checks that every incident has
> ≥ 1 backing event, that all `{user}/{host}/{ip}/{campaign}` placeholders
> resolve, that every event carries the fields a real connector pivots on,
> and that the source distribution is not concentrated on a single template.
> It currently passes against 361 events spanning 14 distinct log sources
> wired to all 200 incidents.

These numbers move with the codebase. The current snapshot lives at
[`eval-results/eval/results/latest.json`](https://github.com/beenuar/AiSOC/blob/eval-results/eval/results/latest.json).

### Per-case vs. per-template metrics

The 200-case dataset is built by drawing each case from one of **55 distinct
templates** (Sysmon process-injection, M365 admin-impersonation, CloudTrail
GuardDuty findings, Okta MFA-bombing, Linux auditd reverse-shell, …) and
swapping the `{user}/{host}/{ip}/{campaign}` slot in each one. That gives the
substrate a wider blast radius to regress against without inflating the
generator. Two metrics are reported for every scoring suite:

- **Per-case mean** — the headline number, weighted across all 200 incidents.
  Closest to "how often does the substrate get an answer right".
- **Per-template macro** — the unweighted mean across the 55 distinct
  templates. A single broken template (≈ 4 cases) moves the per-case mean by
  only ~0.5 % but moves the per-template macro by ~1.8 %. This is the
  dilution-resistant signal that catches template-class regressions.

Both gates have to pass for CI to be green. The harness output prints the
per-template macro under each suite headline, plus the IDs of any individual
templates that fall below the per-template floor (those are surfaced as
information, not as failures, as long as the macro stays above the gate).
This addresses a fair concern raised on the launch thread that 200 cases
cycled from 55 templates can hide regressions behind the duplicates: the
macro is exactly the metric that surfaces them.

## Reproduce these numbers

You don't have to take our word for it. From a fresh clone:

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
python3 scripts/run_evals.py
```

That's it. No Docker, no API key, no GPU, no LLM. Expected output:

```text
==============================================================================
  AiSOC Pillar-1 Eval - 200-incident synthetic benchmark
==============================================================================
  [PASS] mitre_accuracy                accuracy               0.970  (target >= 0.80)
         per-template macro            0.964  (target >= 0.80, n=55 templates) [PASS]
  [PASS] alert_reduction               reduction_ratio        0.753  (target >= 0.70)
  [PASS] investigation_completeness    mean_keyword_coverage  0.942  (target >= 0.85)
         per-template macro            0.943  (target >= 0.80, n=55 templates) [PASS]
  [PASS] response_quality              mean_rubric_score      1.000  (target >= 0.80)
         per-template macro            1.000  (target >= 0.75, n=55 templates) [PASS]
------------------------------------------------------------------------------
  Synthetic telemetry: 361 events across 14 sources,
                       200 incidents wired up
                       (services/agents/tests/eval_data/synthetic_telemetry.jsonl)
==============================================================================
  ALL GATES PASSED
```

To regenerate the dataset and its backing telemetry from scratch (e.g. after
adding a template):

```bash
python3 scripts/generate_eval_incidents.py
```

That writes `services/agents/tests/eval_data/synthetic_incidents.json` and
the companion `synthetic_telemetry.jsonl` deterministically (seeded RNG).

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
is fed into the in-harness `fuse_alerts` function. That function is a
deterministic, in-memory re-implementation of the same Tier 1/2/3 grouping
rules used by the production `services/fusion` engine — minus the
DB-backed deduplicator and the ML scorer. The grouping logic itself is the
same:

- **Tier 1** — same `(rule, host, user)` within 10 minutes → 1 incident
- **Tier 2** — same `(rule, host)` within 30 minutes → merge into a Tier-1 incident
- **Tier 3** — same rule within 5 minutes across ≥ 3 hosts → "storm" incident

Incidents below the noise threshold (`score < 0.35`) are dropped. The output is
whatever the code produces — a fusion-rule regression will move the number.
This is a legitimate measurement of grouping behavior on a controlled dataset,
but it is **not** end-to-end coverage of the production fusion service.

The reported ~75 % is the actual output of the in-harness grouping function on
this fixed dataset. It is not tuned to match a marketing number.

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

### 5. Synthetic telemetry corpus — `Schema and coverage gate`

**Source:** [`services/agents/tests/test_synthetic_telemetry.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_synthetic_telemetry.py)
· **Output:** [`synthetic_telemetry.jsonl`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_telemetry.jsonl)

Every synthetic incident now ships with at least one backing telemetry event
written to a companion JSONL file. This addresses a real ask from the
community: connector and Sigma rule PRs need concrete events to wire against
without having to make up their own. The corpus currently covers 14 sources:

| Source                | What it represents                                                | Common pivot fields                            |
|-----------------------|-------------------------------------------------------------------|------------------------------------------------|
| `sysmon`              | Windows process / network / image-load events (EID 1, 3, 7, 11)   | `Computer`, `User`, `Image`, `CommandLine`     |
| `windows_security`    | Windows Security log (logon, privilege use, account changes)      | `Computer`, `TargetUserName`, `EventID`        |
| `m365_audit`          | Microsoft 365 unified audit log                                   | `UserId`, `Operation`, `Workload`, `ClientIP`  |
| `azure_signin`        | Azure AD / Entra sign-in log                                      | `userPrincipalName`, `appDisplayName`, `ipAddress` |
| `okta`                | Okta system log                                                   | `actor.alternateId`, `eventType`, `outcome`    |
| `cloudtrail`          | AWS CloudTrail management events                                  | `eventName`, `userIdentity`, `sourceIPAddress` |
| `linux_auditd`        | Linux auditd records (execve, syscall)                            | `host`, `auid`, `exe`, `proctitle`             |
| `linux_journald`      | Linux journald / syslog                                           | `_HOSTNAME`, `MESSAGE`, `SYSLOG_IDENTIFIER`    |
| `edr`                 | Generic EDR detection (CrowdStrike / SentinelOne shape)           | `device.hostname`, `process.command_line`      |
| `firewall`            | Perimeter firewall (deny / allow / threat)                        | `src_ip`, `dst_ip`, `action`, `rule`           |
| `dns`                 | DNS resolver / sinkhole                                           | `query`, `client_ip`, `response_code`          |
| `vpn`                 | VPN concentrator (auth and tunnel events)                         | `username`, `client_ip`, `assigned_ip`         |
| `db_audit`            | Database audit trail (Postgres / Oracle / SQL Server shapes)      | `db_user`, `client_host`, `statement`          |
| `idp`                 | Generic IdP / federated auth                                      | `actor`, `event`, `target`                     |

Each event has its `{user}/{host}/{ip}/{campaign}` placeholders resolved
against the parent incident, so an event for `INC-EVAL-044` carries the same
user and host as the incident itself.

The schema/coverage gate ([`test_synthetic_telemetry.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/test_synthetic_telemetry.py))
checks five things on every CI run:

1. **No unresolved placeholders** — every event survives a recursive walk
   without finding a stray `{...}` slot.
2. **Per-source required fields** — for each declared source, the fields a
   real connector pivots on are present and non-empty.
3. **Coverage** — every incident in `synthetic_incidents.json` has ≥ 1 backing
   event in the JSONL corpus.
4. **Source diversity** — at least 12 distinct sources appear across the
   corpus (we currently ship 14).
5. **No single-template concentration** — no one template accounts for more
   than 5 % of the events, which keeps the corpus useful for connector
   regressions instead of being dominated by one scenario.

This is **not** a scoring suite. It does not gate detection accuracy or
agent quality — it gates "did the synthetic substrate produce something an
external connector or Sigma rule can be run against." A failing
synthetic-telemetry test means a template stopped emitting events of the
shape it promised, not that the agent got worse.

If you are landing a new connector, point it at this file:

```bash
head -n 5 services/agents/tests/eval_data/synthetic_telemetry.jsonl
```

Each line is a self-contained event with `incident_id`, `template_id`,
`source`, and the event payload. Filter by `source` to focus your tests.

## Comparison to other AI SOC offerings

| Capability                                     | AiSOC | Wazuh | Splunk | Closed-source AI SOC |
|-----------------------------------------------|:-----:|:-----:|:------:|:---------------------:|
| Open-source (MIT)                              |  yes  |  yes  |   no   |          no           |
| Self-hostable                                  |  yes  |  yes  |  yes   |          no           |
| Agent decisions step-by-step auditable         |  yes  |  n/a  |  n/a   |          no           |
| Public, reproducible regression harness        |  yes  |  no   |   no   |          no           |
| Eval dataset shipped in the repo               |  yes  |  no   |   no   |          no           |
| Substrate-level regression gate in CI          |  yes  |  no   |   no   |          no           |
| Plugin SDK (Python + Go)                       |  yes  |  yes  |  yes   |        partial        |
| Free                                           |  yes  |  yes  |   no   |          no           |

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
- **The dataset is synthetic.** 200 incidents drawn from 55 templates is
  enough to flag major regressions and to give connector PRs concrete events
  to wire against, but it is not enough to claim production parity.
  Federated, opt-in real-customer evaluation is on the roadmap.
- **The synthetic telemetry corpus is hand-shaped, not captured from a live
  tenant.** It models the structure that real connectors pivot on (process
  tree, principal, source IP, log source) but is not a substitute for
  capturing real M365 / CloudTrail / Sysmon events from a production
  environment. Treat it as a contract for connector development, not as a
  red-team dataset.
- **Three of the four scoring judges are tautological by design.** The dataset,
  the templates, and the judge were written together to keep the gate fast and
  deterministic. They will pass as long as the substrate is internally
  consistent. They will fail if it is not. The per-template macro adds a
  non-tautological dimension on top: a single broken template stops being
  hidden behind 199 working duplicates.
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
- **Add a connector and a Sigma rule against the synthetic telemetry corpus.**
  Pick a source from `synthetic_telemetry.jsonl` (e.g. `m365_audit` or
  `cloudtrail`), wire a connector that ingests events of that shape into the
  fusion service, and land a Sigma rule that fires on the events backing the
  matching `INC-EVAL-*` cases. The corpus is exactly the contract you can
  develop against without provisioning a real tenant.
- **Add a new template with backing telemetry.** Drop a new entry into
  `_TEMPLATES` in [`scripts/generate_eval_incidents.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/generate_eval_incidents.py)
  with a unique `template_id` and a tuple of telemetry events. Re-run the
  generator and the per-template gate will keep us honest about whether the
  substrate handles the new class.
- **Find a template the keyword extractor misses.** Watch the per-template MITRE
  macro under each suite — if it dips, the failing-templates list is printed
  inline. Fixtures for those cases land as a single PR against the extractor.
- **Find a fusion miss.** Add a contrived alert pattern that should de-dupe but
  doesn't. The reduction-ratio gate will block the regression.
- **Tighten the report and plan rubrics.** The completeness and quality suites
  are intentionally permissive in v1. PRs that add stricter evidence-grounding
  or that decouple the synthesizer from the judge keywords are highly welcome.

See [`CONTRIBUTING.md`](https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md) for the full path.
