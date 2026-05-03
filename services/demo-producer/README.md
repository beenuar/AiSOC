# AiSOC Demo Event Producer

A tiny Go CLI that pumps synthetic but realistic security events
(CrowdStrike, Defender, Suricata, GuardDuty, Okta, Splunk) into the
AiSOC ingest service so the dashboard, alerts, copilots, and the attack
graph have real-looking data while you develop locally.

## Quick start

```bash
# 1. Make sure the dev stack is running
pnpm docker:dev

# 2. Seed the database with the demo tenant + baseline alerts/cases
pnpm seed:demo

# 3. Stream live events into the ingest service
pnpm demo:produce         # ~24 events/sec across 6 connectors
pnpm demo:produce:fast    # 480 events/sec — for stress demos
```

## Flags

| Flag           | Default                                                       | Notes                              |
| -------------- | ------------------------------------------------------------- | ---------------------------------- |
| `--ingest-url` | `http://localhost:8001/v1/ingest`                             | Ingest service endpoint            |
| `--tenant`     | `00000000-0000-0000-0000-000000000001` (matches `seed:demo`)  | Sent as `X-Tenant-ID` header       |
| `--rate`       | `4`                                                           | Batches per second per connector   |
| `--batch`      | `5`                                                           | Events per batch                   |
| `--duration`   | `0`                                                           | How long to run (0 = forever)      |

Environment variables `INGEST_URL` and `TENANT_ID` are honored as defaults.

## Design notes

Each "connector" runs in its own goroutine so output looks naturally
interleaved. Events are randomised with a per-connector RNG, but enough
fields (host, user, ATT&CK tactic) are stable across connectors that
they look correlatable in the UI — which is the whole point of a SOC
demo.

This binary is intentionally **tiny** — no Kafka, no protobuf, just an
HTTP POST to the ingest service. That keeps the dependency graph small
and means the producer works against any AiSOC environment that exposes
`/v1/ingest`.
