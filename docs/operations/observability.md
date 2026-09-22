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

## The four golden signals

For each service we track the standard golden signals:

- **Latency** — request duration (p50/p95/p99). The p95 target per service is in
  `slos.yaml`.
- **Traffic** — request/event rate.
- **Errors** — rate of failed requests / dead-lettered events (the fusion DLQ,
  Phase 5, is a first-class error signal here).
- **Saturation** — how full the service is (queue depth, pool utilisation).

## Single trace across services

**Partial today.** `api`, `agents`, `ueba` and `honeytokens` are instrumented with **OpenTelemetry** and export via OTLP. `ingest` (Go) and `realtime` (TypeScript) are **not instrumented**, and they are the two ends of the Kafka spine — so a trace does not yet run unbroken from raw event to response action. Spans that are emitted carry the tenant and run/incident ids.

Note also that the default exporter endpoint is `http://otel-collector:4317` and **no collector ships in any compose file**, so out of the box spans are emitted into a connection error. Bring your own collector, or expect no traces.

- Trace context does **not** yet propagate across the Kafka spine, because the producing
  and consuming ends are the two uninstrumented services. HTTP hops between the
  instrumented services (api ↔ agents) do propagate.
- The Investigation Ledger records per-step model/tool attribution (see the
  [model router](../concepts/model-router.md) and
  [LLMOps](../concepts/llmops.md) docs), so the reasoning path inside the
  `agents` span is itself replayable.

## Metrics endpoints

Each service exposes Prometheus metrics at `/metrics`; the scrape config lives
in `infra/docker/prometheus.yml` and is gated (every `job_name` must point at a
real, instrumented `hostname:port` — a CI check enforces this so a scrape job
can't silently break).

## Governance

Reliability + governance are two halves of "run this next to your crown
jewels". See [`GOVERNANCE.md`](../../GOVERNANCE.md) for how the project is run
and [`MAINTAINERS.md`](../../MAINTAINERS.md) for who runs it.
