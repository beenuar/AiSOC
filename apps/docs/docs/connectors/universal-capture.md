---
sidebar_position: 2
title: Universal capture (push & email)
description: Webhook URLs, email relay, CEF syslog, and Splunk HEC — accept any alert source with five-minute setup.
---

# Universal capture

The polling connector catalog covers ~26 vendors. **Universal capture** is the escape hatch for everything else.

If a tool can do any of the following, AiSOC can ingest it:

- POST a webhook to a URL.
- Send email to a mailbox.
- Emit CEF over syslog.
- Send to a Splunk HTTP Event Collector (HEC) endpoint.

Each path lands in the same OCSF event stream as native connectors — same detections, same correlation, same lake.

## When to use this vs. a polling connector

| Situation | Use |
|---|---|
| Vendor is in the catalog | Native connector — better fidelity, schema drift detection, freshness SLO |
| Vendor exposes webhooks | `POST /v1/inbox/{tenant_token}` |
| Vendor only emails alerts | `POST /v1/inbox/email/{tenant_token}` (or pair the [Email Inbox connector](#email-inbox-as-last-resort)) |
| Legacy on-prem appliance | `/v1/inbox/cef` over syslog-to-HTTPS |
| Drop-in Splunk HEC replacement | `/v1/inbox/hec` |

If the vendor offers both webhooks and a polled API, prefer the polled API — you get historical backfill on outage and structured pagination. Webhooks are at-most-once on the vendor side.

## How it works

1. Operator picks a **template** in the console (PagerDuty, Cloudflare Logpush, generic JSON, etc.).
2. Console mints an **inbox token** scoped to that template + tenant. The full token is shown once; only the SHA-256 fingerprint is stored.
3. Operator pastes the resulting URL into the vendor's webhook field.
4. Vendor POSTs JSON. The ingest service:
   - resolves the token from `tenant_inbox_tokens` (LRU-cached, 60s TTL),
   - optionally verifies HMAC if a signing secret was set on mint,
   - applies the YAML template to map vendor fields → OCSF,
   - publishes to the same Kafka topic as polled events.
5. The detection pipeline doesn't know — or care — that the event arrived push-side.

The token never grants any privilege beyond "write events scoped to this template into this tenant." Rotation is a one-click operation in the console; the cache invalidates within 60 seconds, sooner if `Invalidate()` is called by the rotation flow.

## Endpoints

### `POST /v1/inbox/{tenant_token}` — generic JSON webhook

The default route. Accepts a single JSON object **or** an NDJSON batch.

```bash
curl -X POST https://ingest.example.com/v1/inbox/aisoc_inbox_xxxxx \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_type": "incident.triggered",
      "occurred_at": "2026-05-08T09:00:00Z",
      "data": {
        "id": "Q1234ABCD",
        "title": "Database CPU > 90%",
        "urgency": "high",
        "service": {"summary": "prod-postgres"}
      }
    }
  }'
```

**Headers**

| Header | Required | Notes |
|---|---|---|
| `Content-Type` | yes | `application/json` or `application/x-ndjson` |
| `X-Signature` / `X-Hub-Signature-256` | if signing secret set | `hex(HMAC-SHA256(secret, body))`, optionally prefixed `sha256=` |
| `X-AiSOC-Idempotency-Key` | optional | If set, repeated POSTs with the same key inside 24h are deduped |

**Response**

```json
{ "accepted": 1, "template": "pagerduty" }
```

A 4xx response means the token, signature, or body shape is wrong — the vendor will retry, but until you fix the cause it'll keep bouncing. Watch `aisoc_ingest_inbox_requests_total{outcome!="ok"}` in Prometheus.

### `POST /v1/inbox/email/{tenant_token}` — email-relay JSON

Designed for SES inbound, SendGrid Inbound Parse, Postmark, or any service that turns email into a JSON POST.

The template `email-forwarded` extracts:

- `from`, `to`, `subject` → `finding.title`, evidence,
- plaintext body → `message`,
- attachments listed → `finding.evidence.file`.

If your relay can't push directly, see [Email Inbox connector](#email-inbox-as-last-resort).

### `POST /v1/inbox/cef` — CEF over HTTPS

Common Event Format from legacy SIEM, firewalls, and on-prem appliances. The path is **token-less** because most syslog forwarders can't set custom URL paths reliably; use a shared secret + IP allowlist on the load balancer.

```text
CEF:0|Vendor|Product|1.0|100|User login failed|3|src=10.0.0.1 suser=alice cs1=mfa
```

`ParseCEFBatch` handles newline-delimited inputs and unescapes `\|`, `\\`, and `\=` per the CEF spec. Malformed lines are dropped and counted in `aisoc_ingest_inbox_requests_total{outcome="malformed"}` rather than rejecting the whole batch.

### `POST /v1/inbox/hec` — Splunk HEC compatible

Drop-in replacement for `services/collector/event` — useful for on-prem fleets already configured to write to Splunk HEC. Authorization is the standard `Authorization: Splunk <token>` header where `<token>` is the inbox token minted in the console.

```bash
curl -X POST https://ingest.example.com/v1/inbox/hec \
  -H "Authorization: Splunk aisoc_inbox_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"event": {"action": "login_failed", "user": "alice"}, "sourcetype": "auth"}'
```

## Templates

The bundled templates ship with the `services/ingest` binary and are loaded at startup from `services/ingest/internal/normalizer/templates/`:

| Template ID | Use for |
|---|---|
| `generic-json` | Anything not in the list below — passes the body through with light timestamp normalization |
| `pagerduty` | PagerDuty Events API v2 webhooks |
| `opsgenie` | Opsgenie alert webhooks |
| `cloudflare-logpush` | Cloudflare Logpush jobs (HTTP destination) |
| `aws-eventbridge` | AWS EventBridge → API destination |
| `aws-sns` | AWS SNS → HTTPS subscription |
| `splunk-hec` | Anything that already speaks Splunk HEC envelope |
| `cef-syslog` | CEF lines posted as text to `/v1/inbox/cef` |
| `email-forwarded` | Inbound-email relays + the Email Inbox connector |
| `microsoft-defender-email` | Defender for Office 365 alert emails forwarded as text |
| `github-security-advisory` | GitHub security advisory webhooks |

Adding a template is a single YAML file plus an entry in `ALLOWED_TEMPLATE_IDS` on the API service — see `services/api/app/api/v1/inbox.py`. Templates are validated at load time; a bad map blocks startup rather than silently dropping events.

### Template structure

```yaml
id: my-vendor
vendor_name: My Vendor
product_name: My Vendor Cloud
class_uid: 2001
class_name: Security Finding
activity_id: 1
field_map:
  alert.id: finding.uid
  alert.message: message
  alert.url: url
severity_field: alert.priority
severity_map:
  P1: 5
  P2: 4
  P3: 3
time_field: alert.created_at
constants:
  source_type: my-vendor
  metadata.product.feature.name: alerts
```

`metadata.*` paths are merged into the OCSF metadata object — they don't clobber the version/uid stamped at ingest time.

## Email Inbox as last resort

When the vendor can't be configured to push at all but **can** email alerts, run the [Email Inbox connector](https://github.com/beenuar/AiSOC/tree/main/plugins/email-inbox). It polls a dedicated mailbox over IMAPS, marks messages `\Seen`, and feeds each one through the `email-forwarded` template — the same pipeline `/v1/inbox/email` uses, just polled from your side instead of pushed from theirs.

Required config:

| Field | Notes |
|---|---|
| `host` | e.g. `imap.gmail.com` |
| `port` | Defaults to `993` (IMAPS) |
| `username` | Mailbox login (e.g. `aisoc-alerts@example.com`) |
| `password` | **App-specific password** — never the primary account password; encrypted at rest in the credential vault |
| `mailbox` | Defaults to `INBOX` |
| `max_messages` | Per-poll cap; defaults to 50 |
| `use_ssl` | Defaults to `true`; set `false` only on isolated networks |

Recommended pairing: forward all vendor alerts to a **single dedicated mailbox** with a vendor-prefixed subject (`[CrowdStrike] ...`, `[Tenable] ...`) and let the detection pipeline route on `vendor_name` extracted from the subject.

## Observability

| Metric | Use for |
|---|---|
| `aisoc_ingest_inbox_requests_total{route, template, outcome}` | Per-vendor throughput, error rate, and template drift |
| `aisoc_ingest_inbox_events_total{template}` | Event volume by template — basis for the freshness SLO |
| `aisoc_ingest_inbox_token_cache_size` | Cache pressure; spikes indicate token churn |

The console connector cards expose a **Push** tab next to **Polling** that surfaces the request count, last-seen timestamp, and 24-hour error rate for each minted token. Rotating a token through the UI also pushes an `Invalidate(token)` to ingest so the cache flushes immediately rather than waiting out the TTL.

## Security model

- **Token strength:** 32 random bytes, base32-encoded with `aisoc_inbox_` prefix; ~160 bits of entropy.
- **Storage:** Only the SHA-256 fingerprint is persisted. The full token is shown once at mint time. Rotation is a one-click operation; the old token stops resolving after the next cache TTL (60s) at the latest.
- **Scope:** A token is bound to a single template + tenant. It cannot pivot to other templates, other tenants, or any non-write API. There is no read surface on `/v1/inbox/*`.
- **Signing:** Optional HMAC-SHA256 secret on mint. When set, requests without a valid `X-Signature` are rejected with 401 even if the token resolves.
- **RLS:** `tenant_inbox_tokens` is row-level-secured by `tenant_id`. The API service only ever queries with the caller's tenant context.
- **Network:** The token URL is unguessable, but treat it like a credential. Use the per-tenant rate limit (`AISOC_INBOX_RATE_LIMIT_PER_MIN`, default 600/min) to cap blast radius if it leaks.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401 invalid token` | Token rotated or revoked; mint a new one |
| `401 invalid signature` | Wrong signing secret, or vendor canonicalized the body before signing — check vendor docs |
| `400 unknown template` | Token's template was removed from `ALLOWED_TEMPLATE_IDS`; revoke and re-mint |
| `413 body too large` | Body exceeded `AISOC_INBOX_MAX_BODY_BYTES` (default 10MiB); check for vendor-side pagination misconfig |
| `429 too many requests` | Tenant rate limit hit; increase `AISOC_INBOX_RATE_LIMIT_PER_MIN` or have the vendor batch |
| Events accepted but never appear | Almost always a template mismatch — check `aisoc_ingest_inbox_events_total{template="..."}` to confirm and inspect the OCSF event in the lake |
