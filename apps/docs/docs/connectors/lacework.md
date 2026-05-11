---
sidebar_position: 18
title: Lacework
description: Lacework cloud security platform alerts and compliance findings into AiSOC via the Lacework v2 API.
---

# Lacework

The Lacework connector pulls **alerts** (formerly "events") from a
Lacework tenant into AiSOC. One connector instance covers every Lacework
surface — workload, container, cloud configuration, and identity — because
the Lacework v2 `/Alerts` API is unified across all of them.

## What you get

| Source | Lacework v2 endpoint | Notes |
|---|---|---|
| Alerts | `GET /api/v2/Alerts` | All severities, last poll window |

Events are normalized with `source: lacework` and the original Lacework
alert envelope is preserved on `raw_event` so playbooks can target
specific alert categories (e.g. `Compliance`, `CloudActivity`).

## Prerequisites

- A **Lacework tenant** with an account subdomain (e.g. `yourcorp` for
  `https://yourcorp.lacework.net`).
- A Lacework **API access key**:
  - `keyId` — the access-key ID
  - `secret` — the access-key secret
- (Optional) A **subaccount** name if your tenant runs the multi-account
  model and you want to scope ingestion to a single subaccount.

API keys are created in the Lacework console under **Settings → API Keys
→ Create New**. Copy the key and secret immediately — Lacework only shows
the secret once.

## Setup walkthrough

### 1. Create the API key

1. In the Lacework console, **Settings → API Keys → Create New**.
2. Name the key `aisoc-prod` (or similar) and submit.
3. Save the **Key ID** and **Secret** to a password manager.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Lacework**.
2. **Account subdomain** — first label of your console URL (e.g.
   `yourcorp` for `https://yourcorp.lacework.net`).
3. **Subaccount (optional)** — leave blank unless you want to scope the
   poll to a Lacework subaccount.
4. **Access Key ID** and **Secret Key** — paste from step 1.
5. **Test connection** — AiSOC exchanges the key/secret for a 1-hour
   bearer token via `POST /api/v2/access/tokens` and confirms a 200 on a
   1-row `/Alerts` query.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll re-authenticates against `POST /api/v2/access/tokens` if the
  cached bearer is expired (Lacework tokens are valid for ~1 hour).
- The poll requests **the last `interval × 2` seconds of alerts** (default
  10 minutes) using `startTime` / `endTime` query parameters in the
  `/Alerts` endpoint.

## Severity mapping

Lacework alerts use a numeric severity (1 = critical, 5 = info). AiSOC
maps these into the canonical 4-tier ladder:

| Lacework severity | AiSOC severity |
|---|---|
| `1` — Critical | `high` |
| `2` — High | `high` |
| `3` — Medium | `medium` |
| `4` — Low | `low` |
| `5` — Info | `info` |

The original numeric severity is preserved under `raw_event.severity`.

## Subaccount scoping

If you operate multiple Lacework subaccounts (typical for MSSPs and
multi-business-unit deployments), create **one AiSOC connector instance
per subaccount** rather than rotating the same instance. This keeps
per-tenant audit logs clean and lets you set different polling cadences
per subaccount.

When the **Subaccount** field is set, the connector adds the
`Account-Name` header to every API call and the bearer token is scoped
to that subaccount.

## Live actions

The Lacework connector is **read-only** in v7.1.0. Containment for cloud
findings flows through the [AWS Security Hub](/docs/connectors/aws-security-hub),
[Cloudflare](/docs/connectors/cloudflare), or
[GCP Cloud Audit](/docs/connectors/gcp-cloud-audit) connectors.

## Troubleshooting

**`could not authenticate to lacework`** — the keyId / secret pair is
wrong, or the account subdomain has a typo. Test the credentials directly:

```bash
curl -X POST "https://YOUR_ACCOUNT.lacework.net/api/v2/access/tokens" \
  -H "X-LW-UAKS: YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"YOUR_KEY_ID","expiryTime":3600}'
```

A 200 response with `{ "token": "..." }` confirms the credentials are
good — the issue is then in the AiSOC field values.

**`HTTP 403` on `/Alerts`** — the API key was created on the parent
account but you set a **Subaccount** value the key cannot reach. Either
clear the Subaccount field or generate a key from the subaccount itself.

**`events_added: 0` between polls** — the tenant generated no alerts in
the last 10 minutes. Lower-severity alerts can take up to 5 minutes to
appear in `/Alerts`; that is expected steady state for a quiet tenant.

## Related

- [Wiz](/docs/connectors/wiz) — alternative CNAPP path.
- [AWS Security Hub](/docs/connectors/aws-security-hub) — alternative
  cloud finding source if you want native AWS aggregation.
