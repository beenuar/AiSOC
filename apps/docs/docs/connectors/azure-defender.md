---
sidebar_position: 4
title: Microsoft Defender (XDR)
description: Cross-product Defender alerts from Microsoft 365 Defender into AiSOC via the Microsoft Graph Security API.
---

# Microsoft Defender (XDR)

The Defender connector pulls **alerts from the unified Microsoft 365 Defender XDR fabric** — Defender for Endpoint, Defender for Identity, Defender for Cloud Apps, and Defender for Office — into AiSOC via the Microsoft Graph Security API (`/security/alerts_v2`).

## What you get

| Source | Microsoft Graph endpoint | Notes |
|---|---|---|
| Unified alerts | `/security/alerts_v2` | All XDR products, deduplicated and incident-correlated |

Events are normalized with `category: xdr` and the original `productName` preserved on the event for downstream routing.

## Prerequisites

- An **Azure AD app registration** (the [Entra app](/docs/connectors/azure-entra) is fine to reuse).
- The following **application permission** (admin-consent required):
  - `SecurityAlert.Read.All`
- The tenant ID, client ID, and client secret.

A Defender for Endpoint license is required for endpoint-class alerts to flow; other Defender skus are independent.

## Setup walkthrough

### 1. Add the Graph permission

1. Open the app registration → **API permissions → Add a permission → Microsoft Graph → Application permissions**.
2. Add **`SecurityAlert.Read.All`**.
3. **Grant admin consent** for the tenant.

That is the only step beyond the standard Entra app setup.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Microsoft Defender (XDR)**.
2. `tenant_id`, `client_id`, `client_secret`.
3. **Test connection** → calls `/security/alerts_v2?$top=1` to validate.
4. **Save**.

## Polling details

- Default interval: **300 seconds**.
- The connector requests `?$filter=createdDateTime ge {since}&$orderby=createdDateTime asc`.
- OAuth scope: `https://graph.microsoft.com/.default`.

## Severity mapping

Defender ships its own severity. AiSOC honours it 1:1:

| Defender severity | AiSOC severity |
|---|---|
| `high` | `high` |
| `medium` | `medium` |
| `low` | `low` |
| `informational` | `info` |

The `serviceSource` field (e.g. `microsoftDefenderForEndpoint`, `microsoftDefenderForIdentity`) is preserved on the event so playbooks can branch on the originating product.

## Troubleshooting

**`Authorization_RequestDenied`** — admin consent is missing on `SecurityAlert.Read.All`. The app permission shows green only *after* consent, not just after Add.

**`Resource not found` on `/security/alerts_v2`** — your tenant has not been migrated to the unified Defender XDR. Microsoft has been slow-rolling this; check the Microsoft 365 Defender portal first to confirm the unified experience is live.

**`events_added: 0` indefinitely** — Defender does not generate alerts in clean tenants. Test by triggering a benign EICAR test against an enrolled endpoint; the alert should land within a few minutes.

## Related

- [Microsoft Entra ID](/docs/connectors/azure-entra) — identity context for Defender for Identity alerts.
- [Microsoft 365 Audit](/docs/connectors/m365-audit) — full M365 audit telemetry to cross-reference Defender alerts against user activity.
