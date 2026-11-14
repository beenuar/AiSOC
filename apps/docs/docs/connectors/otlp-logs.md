---
id: otlp-logs
title: OpenTelemetry logs (OTLP)
sidebar_label: OTLP logs receiver
---

If you already run an OpenTelemetry Collector, you already have a logs
pipeline and an exporter. What you have been missing is somewhere to point
the exporter. The ingest service accepts OTLP logs directly.

```
POST /v1/logs
```

Both encodings the specification defines are accepted —
`application/x-protobuf` and `application/json` — because real collectors
emit both and a receiver that reads one of them is a receiver half the
estates cannot use. `Content-Encoding: gzip` is accepted, which is what the
stock exporter sends.

The path is not configurable. An OTLP exporter appends `/v1/logs` to the
endpoint you give it, so the route has to be exactly there.

## Mint a token

OTLP has no notion of a tenant, and every attribute on a record is set by
the emitter, so the tenant comes from a credential and from nothing in the
payload. Mint one with the `otlp-logs` template:

```bash
curl -sS -X POST "$AISOC_URL/api/v1/inbox/tokens" \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"template_id": "otlp-logs", "label": "collector-prod"}'
```

One token is one tenant. A deployment collecting for several tenants mints
one per tenant and runs one collector pipeline per tenant.

## Turn the receiver on

It is off by default.

```bash
AISOC_OTLP_LOGS_ENABLED=true
```

The receiver shares the ingest service's HTTP port; there is no second
address to publish.

## Point the collector at it

```yaml
exporters:
  otlphttp/aisoc:
    logs_endpoint: https://ingest.example.internal/v1/logs
    headers:
      Authorization: "Bearer ${AISOC_INGEST_TOKEN}"
    compression: gzip

service:
  pipelines:
    logs:
      receivers: [filelog, otlp]
      exporters: [otlphttp/aisoc]
```

Or, for an SDK exporting directly:

```bash
export OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="https://ingest.example.internal/v1/logs"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer ${AISOC_INGEST_TOKEN}"
```

If your collector cannot be made to send `Authorization`, the token is also
read from `X-Inbox-Token`, which every other push path on this service
accepts.

## What arrives

Each log record becomes one OCSF event of class 1007 (Process Activity),
in category 1. It is deliberately **not** class 2001 (Security Finding):
the promoter promotes category 2 unconditionally, so filing routine
application logs as findings would turn every line into an alert. A
detection rule is what turns one of these into an alert.

Resource, scope and record attributes are merged into one namespace, with
the narrower scope winning, and dotted keys become nested fields — so
`service.name` and `host.name` reach `actor.process.name` and
`device.hostname`. The trace id reaches `metadata.correlation_uid`, so an
alert can be joined back to the trace it came from.

Severity comes from `severity_number` when the emitter left `severity_text`
unset: the number is the authoritative field in the data model, and
reading only the text would file every such record as Unknown.

## What the receiver tells your collector

The partial-success contract is implemented rather than skipped, because
the alternatives both lose data:

| Outcome | Answer | Why |
|---|---|---|
| Everything projected | `200`, empty body | — |
| Some records unprojectable | `200` with `partial_success.rejected_log_records` | A blanket `200` would tell the collector records it never delivered had landed |
| The event bus is unreachable | `503` with `Retry-After` | The collector's queue is what holds them; a `200` discards them and a `400` marks them permanently invalid |
| No or wrong token | `401` / `403` naming the fix | — |
| Not an OTLP encoding | `415` | — |

The only record the receiver refuses is one carrying no body, no
attributes, no severity, no timestamp and no trace id — which is the shape
a truncated or garbled batch arrives as. Resource attributes do not rescue
it: they are identical for every record in the batch and carry no event
content.

## Readiness

`/readyz` names the receiver under `otlp_logs` and reports how much it has
taken, including when nothing has arrived yet. A receiver nobody is
exporting to and one refusing every request look identical from outside
unless readiness says which.

## Limits

* 16 MiB per request, after decompression.
* No metrics or traces receiver. This is a logs endpoint; AiSOC's own
  traces go the other way, to a collector you run.
