# Runbook: `AisocKafkaConsumerLagHigh`

> **Severity:** warning (ticket)
> **Alert source:** [`aisoc-kafka` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

`{{ $labels.job }}` has fallen more than **10,000 messages
behind** on `{{ $labels.topic }}` for **10 minutes**. Either the
consumer is slow (per-message processing time too high), the
partition count is too low for the current throughput, or the
consumer is stuck (deadlocked, crashing on the head message and
retrying forever).

Affected services and their canonical topics:

| Service       | Topic(s)                            |
|---------------|-------------------------------------|
| `fusion`      | `aisoc.alerts.raw`                  |
| `actions`     | `aisoc.actions.dispatch`            |
| `threatintel` | `aisoc.indicators.enrich`           |
| `ueba`        | `aisoc.events.normalized`           |

## First five minutes

```bash
# 1. Per-partition lag breakdown.
docker compose exec kafka kafka-consumer-groups \
  --bootstrap-server kafka:29092 \
  --describe --group <consumer-group>

# 2. Per-message processing time (P95 / P99).
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,sum%20by%20(le)(rate(kafka_consumer_record_processing_seconds_bucket{job="<job>"}[5m])))'

# 3. Is the consumer stuck on a poison message?
docker compose logs <service> --tail 200 \
  | grep -E '"event":"kafka.*(error|retry|skip)"' \
  | tail -20

# 4. Producer rate vs consumer rate.
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=rate(kafka_messages_in_total{topic="<topic>"}[5m])'
```

## Mitigation

- **Slow per-message processing:** the consumer needs more
  parallelism. The fusion service uses one `aiokafka` consumer
  per partition; increasing the partition count for the topic
  (without losing ordering guarantees) is the right knob.
  `kafka-topics --alter --topic aisoc.alerts.raw --partitions
  <N>` — but check the downstream consumer first; the fusion
  worker is the consumer here.
- **Poison message:** the consumer is retrying the head message
  forever. Skip with a one-off offset commit:
  `kafka-consumer-groups --reset-offsets --group <g> --topic
  <t>:<partition> --to-offset <offset+1> --execute`. ALWAYS
  capture the message body first so the post-mortem can replay
  it offline.
- **Consumer dead:** `docker compose restart <service>`. If it
  doesn't recover, the consumer config is at fault — check
  `KAFKA_BOOTSTRAP_SERVERS` env var resolves and the broker has
  the consumer's group in `kafka-consumer-groups --list`.

## Root cause

- Producer rate sustained 2x consumer rate means partition count
  is undersized for the current load. Quote the rate from step 4
  in the follow-up ticket so capacity planning has a number.
- Slow processing usually traces to an external call (HTTP API,
  DB query). Find the slow span in the consumer's structlog
  output filtered by `"event":"process_record"`.

## References

- Source rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- Consumer code: `services/<svc>/app/workers/consumer.py`
- Kafka broker config: [`docker-compose.yml`](../../docker-compose.yml) (`kafka` service)

Updated: **2026-06-28** (Phase 2.5).
