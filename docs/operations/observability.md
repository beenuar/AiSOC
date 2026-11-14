# Observability & SLOs

AiSOC is instrumented so an operator can answer "is it healthy, and if not,
where?" with a single trace and four golden signals per service.

## Service-level objectives

Every service declares its reliability posture in
[`slos.yaml`](./slos.yaml). `scripts/check_slos.py` gates it: a new service
under `services/` cannot ship without either an SLO block (availability + p95
latency + golden signals) or an explicit `exempt` entry with a reason.

The objectives are targets, not measured SLIs — they define the **error
budget** (`1 − availability_target` over a rolling 30 days) that the golden
signals below are measured against.

### Alerts are generated from the objectives

`infra/docker/alerts/slo.rules.yml` is produced by
`scripts/generate_slo_alerts.py` from `slos.yaml`, and a CI gate fails when
the two disagree. Before this, the SLO file declared targets nothing
alerted on while the alert rules used thresholds — a 5% error rate, a
2-second p95 — that corresponded to no objective in the file. Two numbers
meant to agree, maintained separately, will not agree for long.

Alerts are **burn-rate**, not instantaneous. A 99.9% target allows roughly
43 minutes of error a month; alerting the moment the rate exceeds 0.1%
pages on every transient blip. Fast burn (2% of the budget in an hour) is
a page. Slow burn (10% in six hours) is a ticket — not an outage, but the
shape that exhausts a month's budget without any single incident to point
at.

**Coverage is five of nineteen services**, because only five expose
`/metrics`. Generating rules for the other fourteen would produce alerts
that can never fire, and an alert that can never fire reads as coverage
while providing none. The generator names the uncovered services on every
run rather than quietly skipping them, and
`scripts/audit_prometheus_targets.py` prints the current split.

## The four golden signals

For each service we track the standard golden signals:

- **Latency** — request duration (p50/p95/p99). The p95 target per service is in
  `slos.yaml`.
- **Traffic** — request/event rate.
- **Errors** — rate of failed requests / dead-lettered events (the fusion DLQ,
  Phase 5, is a first-class error signal here).
- **Saturation** — how full the service is (queue depth, pool utilisation).

## Single trace across services

`api`, `agents`, `ueba`, `honeytokens`, `ingest` (Go) and `realtime` (TypeScript) are instrumented with **OpenTelemetry** and export via OTLP. The last two were the ends of the Kafka spine, so a trace used to begin at the API and stop at the pipeline boundary — which is where the interesting latency lives: an event that takes four seconds to become an alert is invisible if nothing spans the part that took four seconds.

All six share `OTEL_EXPORTER_OTLP_ENDPOINT` and propagate W3C `traceparent`, so a request continues as one trace rather than becoming several disconnected ones. Tracing is **off unless that variable is set**: emitting spans into a connection error is worse than emitting none, because it fills the logs and makes a missing trace ambiguous between "no span" and "no collector".

Sampling is parent-based at 5% by default (`OTEL_TRACES_SAMPLER_ARG`). Parent-based matters more than the ratio — a trace sampled at one service and re-decided at the next produces gaps that look like a service not participating.

Spans carry the tenant and run/incident ids.

A collector now ships: `docker compose --profile monitoring up` starts an OpenTelemetry Collector on `otel-collector:4317` (the endpoint the services already default to) forwarding into Grafana Tempo, with Tempo wired into Grafana as a datasource alongside Prometheus. Previously no collector existed in any compose file, so out of the box every span went into a connection error — which is worse than no tracing, because the code looks instrumented and nobody can tell a missing span from a missing collector.

Tempo's retention in the dev stack is 24 hours. It is there so a developer can follow a trace, not to retain them.

- Trace context does **not** yet propagate across the Kafka spine. The reason
  changed and is worth stating precisely, because this bullet used to give the
  old one: both ends *are* instrumented now (see above). What is missing is
  that `services/ingest`'s publisher writes no `traceparent` into the Kafka
  message headers, and `services/fusion` — the service that consumes
  `raw_events` — emits no spans at all, so there is nothing on either side of
  the queue to join. HTTP hops between the instrumented services (api ↔ agents)
  do propagate.
- The Investigation Ledger records per-step model and tool attribution, so the
  reasoning path inside the `agents` span is itself replayable. (This bullet
  used to link a model-router and an LLMOps page; neither exists — `docs/concepts/`
  is not a directory in this repository.)

## Metrics endpoints

**Five of nineteen services expose `/metrics`** — `api`, `ingest`, `fusion`,
`threatintel` and `agents`. The other fourteen emit nothing for Prometheus to
scrape; `scripts/audit_prometheus_targets.py` names them on every run rather
than letting the gap read as coverage.

The scrape config lives in `infra/docker/prometheus.yml` and is gated: every
`job_name` must point at a real, instrumented `hostname:port`, so a scrape job
cannot silently break. The gate checks the config against the tree — it does
not make an unscraped service scraped.

## Governance

Reliability + governance are two halves of "run this next to your crown
jewels". See [`GOVERNANCE.md`](../../GOVERNANCE.md) for how the project is run
and [`MAINTAINERS.md`](../../MAINTAINERS.md) for who runs it.
