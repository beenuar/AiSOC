# AiSOC incident runbooks

This directory holds the on-call playbook for every alert defined in
[`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml).
Each runbook follows the same five-section structure so an on-call
engineer can locate the right diagnostic command without reading
prose end-to-end:

1. **What the alert means** — one paragraph; what symptom is
   Prometheus describing.
2. **First five minutes** — copy-pasteable commands that turn the
   alert into a hypothesis. Logs, metrics queries, container
   status. No prose.
3. **Mitigation** — what to do BEFORE root-causing. The point is
   to stop customer pain even if we don't yet know why it started.
4. **Root cause** — the deeper debugging path once the bleeding
   has stopped.
5. **References** — source code, dashboards, Slack channels.

Runbook quality bar: a runbook is "done" when an engineer who has
never seen this alert before can resolve a real incident using
only the runbook and the standard AiSOC dev environment. If you
ever followed the runbook and it didn't work — fix it before you
close the incident, not after.

## Index

| Alert | Severity | Runbook |
|---|---|---|
| `AisocServiceDown` | critical | [service-down.md](./service-down.md) |
| `AisocHttpP95LatencyHigh` | warning | [http-latency-high.md](./http-latency-high.md) |
| `AisocHttpErrorRateHigh` | critical | [http-5xx-high.md](./http-5xx-high.md) |
| `AisocKafkaConsumerLagHigh` | warning | [kafka-consumer-lag.md](./kafka-consumer-lag.md) |
| `AisocDetectionPipelineStalled` | critical | [detection-pipeline-stalled.md](./detection-pipeline-stalled.md) |
| `AisocActionExecutorFailureRateHigh` | critical | [action-executor-failures.md](./action-executor-failures.md) |
| (not alert-bound — manual triage) | — | [database-incident.md](./database-incident.md) |

## Versioning

Updated: **2026-06-28** (Phase 2.5).
