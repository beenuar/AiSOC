---
id: kafka-input
title: Kafka input (your own topics)
sidebar_label: Kafka input
---

Some estates already have every log they care about on a broker. Asking
them to run a forwarder that re-publishes those records over HTTP is
asking them to run a second pipeline to feed the first one. The ingest
service can consume your topics directly.

## Mint a token per tenant

A Kafka record carries no authenticated principal. A tenant read from the
payload or from a record header would be set by whoever produced the
record, so the tenant comes from a minted ingest token and from nothing
else. One source serves one tenant.

```bash
curl -sS -X POST "$AISOC_URL/api/v1/inbox/tokens" \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"template_id": "generic-json", "label": "kafka-customer-a"}'
```

Use whichever template matches the shape on the topic. `generic-json` is
the usual answer; `splunk-hec` and `cef-syslog` are there if the topic
carries those shapes. The source's `template_id` must match the one the
token was minted with — a mismatch is a permanent failure that names the
fix rather than retrying.

## Declare the sources

One JSON array, not numbered environment variables: a deployment reading
three tenants' topics needs three of everything, and numbered variables
are how a fourth source silently gets the third one's token.

```bash
AISOC_KAFKA_INPUT_SOURCES='[
  {
    "name": "customer-a-security",
    "brokers": "broker-1.example.internal:9092,broker-2.example.internal:9092",
    "topic": "security.events",
    "group_id": "aisoc-ingest-customer-a",
    "token": "tok_live_...",
    "template_id": "generic-json"
  }
]'
```

| Field | Required | Notes |
|---|---|---|
| `name` | yes | What readiness, the logs and the metrics call this source |
| `brokers` | yes | Comma-separated bootstrap list |
| `topic` | yes | Your topic |
| `group_id` | no | Defaults to `aisoc-ingest-<name>`, per source. Two sources sharing a group id on different topics is legal in Kafka and almost never what was meant |
| `token` | yes | The minted ingest token; this is where the tenant comes from |
| `template_id` | yes | Must match the token's template |
| `from_beginning` | no | Default `false`. Replaying a week of a production topic into the detection pipeline is not a thing to do by accident |
| `max_bytes` | no | Fetch cap, default 10 MiB |

A malformed array is a hard error at startup that names the problem. It
does not start with the input silently off.

TLS is resolved the same way as every other Kafka client in this service;
see [Secrets](../operations/secrets.md). A reader that cannot be built
securely in a protected environment is not built at all.

## What arrives

Each record becomes one OCSF event through the template you named. A
record that is not JSON is carried as a log line rather than refused — a
plain-text topic is a legitimate source, and refusing it would be a
consumer that looks attached and drops everything.

Kafka's own metadata rides along as `kafka_topic`, `kafka_partition`,
`kafka_offset`, `kafka_key` and `kafka_header_*`, so a detection rule can
clause on where a record came from. Headers are carried for context and
are explicitly not read for a tenant.

## What happens when something breaks

This is a long-lived consumer, and the question that matters is whether
the loop can tell a condition that will never resolve from one that might.
Three classes, not two:

| Class | Example | What happens |
|---|---|---|
| **Transient** | A broker restarting, a rebalance, a leader election | Capped exponential backoff. A rebalance happens on every deploy; stopping on it would be an outage |
| **Permanent** | `TopicAuthorizationFailed`, `SASLAuthenticationFailed`, an invalid group id | The loop stops and logs the operator action at error level. Retrying a misconfiguration is not progress, it is churn you have to filter out of the logs |
| **Poison** | One record that cannot be decoded | Skipped **and** committed. The subscription is demonstrably working; a poison record that is not committed is re-read forever |

A publish failure is the one case that does **not** commit. Kafka is the
only input in this service that can withhold an acknowledgement, so an
undelivered record stays undelivered rather than being lost.

A transient failure that outlives two minutes stops being reported as
transient and is reported as **not resolving** — the point at which the
operator's next move stops being "wait" and becomes "go and look".

## Readiness

`/readyz` names every source as `kafka_input:<name>` with its state, and
says something useful when healthy too: a quiet topic is a legitimate
state, so the detail carries what it is attached to and how much it has
seen. A consumer detached from its topic behind a `200` that never
mentions it is indistinguishable from an idle one.

## Metrics

| Series | Meaning |
|---|---|
| `aisoc_ingest_kafka_input_records_total{source}` | Records accepted |
| `aisoc_ingest_kafka_input_attached{topic}` | 1 while consuming |
| `aisoc_ingest_kafka_input_errors_total{topic,class}` | By failure class |
| `aisoc_ingest_kafka_input_not_resolving{topic}` | 1 when a fault has outlived a transient explanation |

`aisoc_ingest_kafka_input_not_resolving` is the alertable one.
