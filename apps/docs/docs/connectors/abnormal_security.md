---
sidebar_position: 76
title: Abnormal Security
description: Abnormal Security behavioural-AI email threat events into AiSOC via the public REST API.
---

# Abnormal Security

The Abnormal Security connector polls the **/v1/threats** and **/v1/cases**
endpoints of the Abnormal API and emits one AiSOC alert per detected
threat (and one per case, since a case rolls up multiple threats and
carries its own severity).

## What you get

| Source | Abnormal endpoint | Notes |
|---|---|---|
| Threats | `GET /v1/threats` | One row per detected message threat |
| Cases   | `GET /v1/cases`   | Case-ified aggregations across multiple threats |

Events are normalised with `source: abnormal_security` and the original
Abnormal envelope is preserved on `raw_event` so playbooks can target
specific `threatType` values (`businessEmailCompromise`,
`credentialPhishing`, `accountTakeover`, …).

## Prerequisites

- An **Abnormal Security tenant** with API access enabled.
- An **API token** generated in the Abnormal Console under
  *Settings → Integrations → API → Generate token*. The token must
  have read scope on threats and cases.
- (Optional) A regional override for `base_url` if your Abnormal tenant
  is provisioned outside the default
  `https://api.abnormalplatform.com`.

## Setup walkthrough

1. Sign in to the Abnormal Console as an administrator.
2. Navigate to **Settings → Integrations → API**.
3. Click **Generate token** and copy the value to a password manager.
4. In AiSOC: **Connectors → Add connector → Abnormal Security**.
5. Paste the API token (and override `base_url` only if your tenant
   requires a regional endpoint).
6. Click **Test connection**. AiSOC issues a `GET /v1/threats?pageSize=1`
   request and confirms a `200`.
7. Save.

## Severity mapping

The connector collapses Abnormal `threatType` into the AiSOC ladder:

| AiSOC severity | Abnormal threat type |
|---|---|
| `high`   | `businessEmailCompromise`, `credentialPhishing`, `accountTakeover`, `phishing`, `malware`, `invoiceFraud`, `vendorEmailCompromise`, `extortion` |
| `medium` | every other threat — Abnormal only reports things it considers abnormal, so there is no `info` floor |
| `low`    | `spam`, `graymail`, `promotional`, `marketing` |

Cases (`/v1/cases`) carry their own `severity` and the connector takes
the **max** of the constituent threats' severity and the case's
declared severity.

## Capabilities

- `pull_alerts` — passive polling of threats + cases.
- `pivot_user` — given a mailbox, return Abnormal context for that user.
- `read_audit_trail` — surface the API call lineage during investigation.

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: 100 items / page, up to 25 pages (`pageNumber` /
  `nextPageNumber`).
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`401 Unauthorized`** — the API token has expired or has been
  rotated. Regenerate under *Settings → Integrations → API* and update
  the connector.
- **No events** — confirm there is recent email traffic. Abnormal only
  emits threat rows when its model flags a message; benign mail is
  silently dropped.
- **`429 Too Many Requests`** — the connector backs off automatically;
  if it persists, lower the poll frequency in the scheduler.
