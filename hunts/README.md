# AiSOC hunts/ — hunt-as-code corpus

This directory holds AiSOC's hunt hypotheses as YAML. Each file describes a
single threat hypothesis the agent layer can run on a schedule, scoring the
target telemetry corpus against a set of expected indicators.

The corpus is part of the same **eval-graded** pipeline as detections and
prompts: every hunt ships with a synthetic positive scenario in
`services/agents/tests/eval_data/synthetic_telemetry.jsonl` and is scored by
`scripts/run_hunt_evals.py` (or as part of `scripts/run_evals.py` when run in
`--all` mode).

## Schema

```yaml
id: hunt-<slug>                # stable identifier, must be unique
name: Human readable name
description: |
  One-paragraph description of the hypothesis the hunt is testing.
version: 1.0.0
severity: low | medium | high | critical
category: identity | endpoint | cloud | network | data-exfil | application
tags:
  - mitre.attack.t1078         # MITRE technique IDs welcome
  - threat.<actor>             # optional threat actor hint
log_sources:                    # what telemetry the hunt expects
  - sysmon
  - m365_audit
  - linux_auditd
schedule:
  enabled: true
  interval_minutes: 60         # how often the scheduler should run this
  jitter_seconds: 60           # randomized jitter to avoid herd
hypothesis:
  question: |
    "Did any service account log into a workstation outside business hours
    and immediately enumerate domain groups?"
  indicators:
    - field: source
      equals: windows_security
    - field: EventID
      in: [4624, 4625]
    - field: TargetUserName
      regex: "^svc-.*"
expected:
  # synthetic positive scenario for eval grading
  positive_incident_id: INC-HUNT-001
  positive_template_id: hunt-svc-account-after-hours
  # at least this fraction of indicators must match for the hunt to fire
  min_match_score: 0.8
  # synthetic negative scenario id (a benign event sequence the hunt must NOT fire on)
  negative_incident_id: INC-HUNT-001-NEG
references:
  - https://attack.mitre.org/techniques/T1078/
author: AiSOC
created: '2026-05-05'
modified: '2026-05-05'
```

## Eval grading

Each hunt is scored on:

1. **True positive rate** — does the hunt fire on `expected.positive_incident_id`?
2. **False positive rate** — does the hunt *not* fire on `expected.negative_incident_id`?
3. **Indicator quality** — fraction of declared indicators that actually match
   the synthetic events (the substrate self-consistency check, like the rest
   of the eval harness).

The aggregate "Hunt Coverage" score is the macro-average of true positive rate
across all enabled hunts. CI gates regression by ≥ 1pp, identical to the
detection-as-code gate.

## How the scheduler runs

`services/agents` runs an APScheduler `AsyncIOScheduler` job per enabled hunt.
On each fire the hunt agent:

1. Loads the hunt YAML from disk.
2. Queries the telemetry warehouse (or the synthetic corpus in dev) for events
   matching `hypothesis.indicators`.
3. If `min_match_score` is reached, persists a **hunt finding** as a first-class
   artifact alongside the Investigation Ledger (table `hunt_findings`).
4. Writes a run record to `hunt_runs` regardless of whether the hunt fired.

## Adding a hunt

1. Drop a new YAML into `hunts/`.
2. Add at least one synthetic positive scenario to
   `services/agents/tests/eval_data/synthetic_telemetry.jsonl` with the matching
   `incident_id` and `template_id`.
3. Add a synthetic negative scenario (benign events that match *some* but not
   all indicators).
4. Run `python scripts/run_hunt_evals.py` locally to confirm the hunt scores
   100% true-positive and 0% false-positive.
5. Open a PR — CI will re-run the hunt evals and gate on regression.
