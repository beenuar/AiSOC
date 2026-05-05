---
sidebar_position: 2
title: Microsoft Entra ID
description: Pull directory audit logs and risky sign-ins from Microsoft Entra ID (formerly Azure AD) into AiSOC.
---

# Microsoft Entra ID

The Entra connector streams **directory audit events** (group changes, role assignments, conditional-access edits) and **risky users / risky sign-ins** from Microsoft Graph into the AiSOC pipeline. It is the foundation of identity-plane coverage in any Microsoft-heavy environment.

## What you get

| Source | Microsoft Graph endpoint | Retention |
|---|---|---|
| Directory audit events | `/auditLogs/directoryAudits` | 90 days (Microsoft default) |
| Risky users | `/identityProtection/riskyUsers` | While risk state is non-`none` |

Events are normalized into AiSOC's event schema with `category: identity` so existing identity-plane Sigma rules apply without glue code.

## Prerequisites

You will need:

- An **Azure AD app registration** with admin consent in your tenant.
- The following **application permissions** (admin-consent required):
  - `AuditLog.Read.All`
  - `Directory.Read.All`
  - `IdentityRiskyUser.Read.All`
- A **client secret** (Certificates & secrets → New client secret).
- The tenant ID, application (client) ID, and client secret value to paste into the AiSOC wizard.

## Setup walkthrough

### 1. Register the app

1. Sign in to the [Azure portal](https://portal.azure.com) as a Global Admin or Application Administrator.
2. Navigate to **Microsoft Entra ID → App registrations → New registration**.
3. Name it something obvious like `AiSOC Entra Connector`. Leave the redirect URI blank — this connector uses client credentials, not user OAuth.
4. Click **Register**. Copy the **Application (client) ID** and the **Directory (tenant) ID** from the Overview tab.

### 2. Grant API permissions

1. In the new app, open **API permissions → Add a permission → Microsoft Graph → Application permissions**.
2. Add `AuditLog.Read.All`, `Directory.Read.All`, and `IdentityRiskyUser.Read.All`.
3. Click **Grant admin consent for &lt;tenant&gt;**. Confirm the status changes to a green check.

### 3. Mint a client secret

1. Open **Certificates & secrets → Client secrets → New client secret**.
2. Pick a description and an expiry that matches your rotation policy (24 months max, 6-12 months recommended). The connector will start failing on `health_status` once the secret expires.
3. Copy the **Value** (not the Secret ID). Microsoft only shows it once.

### 4. Add the connector in AiSOC

1. AiSOC console → **Connectors → Add connector → Microsoft Entra ID**.
2. Fill in `tenant_id`, `client_id`, `client_secret`. All three are the values you copied above.
3. Click **Test connection**. A successful test means Microsoft Graph accepted the client credentials and returned at least one page of audit logs.
4. Click **Save**. The connector starts polling within ~30 seconds.

## Polling details

- Default interval: **300 seconds**. Override via `connector_config.poll_interval_seconds`.
- The connector requests `directoryAudits?$filter=activityDateTime ge {since}` so the first poll only pulls the last interval, not 90 days of history.
- Risky users are fetched separately on each poll because Microsoft Graph does not support `since`-style filtering on that resource; only currently-risky users are returned.
- Token caching: the OAuth `access_token` from `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` is cached until 60 seconds before expiry.

## Severity heuristics

`normalize()` maps Entra audit `result` values into AiSOC severity:

| Microsoft signal | AiSOC severity |
|---|---|
| `failure` on a high-blast-radius operation (role assignment, app credential add, conditional-access disable) | `high` |
| Generic `failure` on directory writes | `medium` |
| Risky user with `riskLevel = high` | `high` |
| Risky user with `riskLevel = medium` | `medium` |
| `success` on a routine read | `info` |

Detection rules in `detections/identity/` consume the normalized event; tune severity there rather than monkey-patching the connector.

## Troubleshooting

**`AADSTS7000215: Invalid client secret provided`** — the secret expired or was copied incorrectly. Mint a new one and update the connector via the wizard's edit path.

**`AADSTS65001: The user or administrator has not consented`** — admin consent was not granted on at least one permission. Re-open API permissions and click _Grant admin consent_ again.

**`Authorization_RequestDenied`** — the app is missing one of the three required permissions. The most commonly missed one is `IdentityRiskyUser.Read.All`.

**`health_status: error` with `503` from Graph** — Microsoft Graph is throttling or partially down. The scheduler will retry on the next interval; no action required.

## Related

- [Microsoft 365 Audit](/docs/connectors/m365-audit) — same Azure AD app can supply both connectors; just add `ActivityFeed.Read` to the permission set.
- [Credential vault](/docs/operations/credentials) — how secrets are encrypted and rotated.
