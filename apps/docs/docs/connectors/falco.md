---
sidebar_position: 72
title: Falco
description: Receive Falco / falcosidekick runtime security events over HTTP into AiSOC.
---

# Falco

The Falco connector receives **JSON rule hits over HTTP** from one of two sources:

1. **falcosidekick HTTP output** — the de-facto forwarder that sits next to Falco, receives the rule-engine output, and fans it out to AiSOC. Sends batched JSON arrays.
2. **Falco's built-in HTTP output plugin** — Falco itself can POST events directly. Sends one event per request.

The connector accepts either shape. Events are normalised with `source: falco`, `category: siem`.

This connector is **push-based** — there is no polling and no API key. The poll loop drains an in-memory webhook buffer instead.

## Prerequisites

- A running **Falco** install (Linux node-agent or Kubernetes DaemonSet).
- Either **falcosidekick ≥ 2.x** configured to forward to AiSOC, *or* Falco's `http_output` plugin enabled directly.
- (Optional) A shared secret to validate the `X-Falco-Secret` header on each delivery.

## Setup walkthrough

### 1. Add the connector in AiSOC

1. **Connectors → Add connector → Falco**.
2. `webhook_path` = the path the AiSOC ingest service exposes; defaults to `/v1/webhooks/falco`.
3. `shared_secret` *(optional)* = a random 32-byte secret. Save it; you'll configure it on the Falco side next.
4. `minimum_priority` = lowest Falco priority that will be accepted (drop everything below). Use `WARNING` in noisy environments, `DEBUG` for full firehose.
5. **Save**.

### 2. Point falcosidekick at AiSOC

In your `falcosidekick.yaml` (Helm `values.yaml` or stand-alone config):

```yaml
webhook:
  address: "https://aisoc.acme.io/v1/webhooks/falco"
  method: "POST"
  customHeaders: "X-Falco-Secret: <your-shared-secret>"
```

Or, with the Falco built-in `http_output` plugin:

```yaml
http_output:
  enabled: true
  url: "https://aisoc.acme.io/v1/webhooks/falco"
  user_agent: "falco/0.x"
  echo: false
```

(The built-in plugin doesn't support arbitrary headers; leave `shared_secret` blank in the AiSOC connector if you use it directly.)

## Severity mapping

Falco's syslog-style priority ladder collapses to the AiSOC 4-tier ladder:

| Falco priority | AiSOC severity |
|---|---|
| `EMERGENCY` | `high` |
| `ALERT` | `high` |
| `CRITICAL` | `high` |
| `ERROR` | `medium` |
| `WARNING` / `WARN` | `low` |
| `NOTICE` | `info` |
| `INFORMATIONAL` / `INFO` / `DEBUG` | `info` |

The `minimum_priority` field is enforced *server-side* before normalisation, so dropped events never count against ingest quotas.

## Webhook verification

If `shared_secret` is set, every incoming POST must include a matching `X-Falco-Secret` header. The connector uses a constant-time compare to avoid timing oracles. If the secret is blank, the endpoint accepts unauthenticated deliveries (acceptable for in-cluster traffic that's already mTLS-fronted; not recommended for internet-facing ingestion).

## Troubleshooting

**No events arriving** — confirm the Falco / falcosidekick pod can resolve the AiSOC ingest hostname and that no NetworkPolicy is blocking egress. Test with `kubectl exec` + `curl`.

**HTTP 401 on every POST** — the shared secret doesn't match. Compare the value in the AiSOC connector edit screen with `customHeaders` in falcosidekick config; ensure no trailing newline.

**All events drop with priority floor set** — Falco emits a lot of `DEBUG` / `INFORMATIONAL` traffic from default rules. Lowering `minimum_priority` will unblock those; but consider tuning the Falco ruleset instead so the noise doesn't reach AiSOC.

## What this connector does **not** cover

- **Falco rule authoring** — rule content lives in the Falco config; AiSOC ingests whatever Falco fires.
- **Bidirectional remediation** — AiSOC cannot tell Falco to silence a rule; that's a deliberate scope boundary for runtime-security tools.

## Related

- [Kubernetes Audit](/docs/connectors/kubernetes-audit) — complementary control-plane audit trail next to Falco's data-plane runtime view.
