---
sidebar_position: 16
title: Wiz
description: Wiz cloud security findings (CSPM, CWPP, CIEM, container, code) into AiSOC via the Wiz GraphQL API.
---

# Wiz

The Wiz connector pulls **cloud security issues from the Wiz GraphQL API**
into AiSOC. One connector instance covers every Wiz product surface — CSPM,
CWPP, CIEM, container, and code findings — because Wiz exposes them all as
`Issue` objects on the same GraphQL graph.

## What you get

| Source | Wiz GraphQL field | Notes |
|---|---|---|
| Cloud security issues | `issues(first: 200, filterBy: { status: OPEN })` | All OPEN issues across CSPM/CWPP/CIEM/container/code |

Events are normalized with `source: wiz` and the original Wiz issue payload
is preserved on `raw_event` for downstream playbooks and the Investigation
Ledger.

## Prerequisites

- A **Wiz tenant** with a GraphQL API endpoint (e.g. `https://api.us20.app.wiz.io/graphql`).
- A **Wiz service account** with at least `read:issues` scope.
- The service-account **client ID** and **client secret**.

The Wiz auth endpoint defaults to `https://auth.app.wiz.io/oauth/token` and
only needs to be overridden for **gov-cloud tenants** (e.g.
`https://auth.gov.wiz.io/oauth/token`).

## Setup walkthrough

### 1. Create a Wiz service account

1. In the Wiz console, open **Settings → Service Accounts → Create Service
   Account**.
2. Grant **`read:issues`** as the minimum scope (add `read:vulnerabilities`
   and `read:cloud_resources` if you want richer enrichment downstream).
3. Save the **Client ID** and **Client Secret** — Wiz only shows the secret
   once.
4. Note the **API Endpoint URL** from **Settings → Tenant → API Endpoint**
   (region-specific, e.g. `https://api.us20.app.wiz.io/graphql`).

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Wiz**.
2. Enter **Client ID**, **Client Secret**, and **API Endpoint URL**.
3. Leave **Auth URL** blank unless you are on a gov-cloud tenant.
4. **Test connection** → AiSOC exchanges the credentials for an OAuth bearer
   token and runs a 1-row `issues` query against the GraphQL endpoint.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll authenticates fresh against the OAuth `/token` endpoint.
- The GraphQL query requests up to **200 OPEN issues per poll** and
  unwraps `issues.nodes`.

## Severity mapping

Wiz ships a 5-tier severity ladder. AiSOC collapses it into the canonical
4-tier ladder used across the platform:

| Wiz severity | AiSOC severity |
|---|---|
| `CRITICAL` | `high` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFORMATIONAL` | `info` |

The original Wiz severity is preserved verbatim under
`raw_event.severity` for playbooks that need the full 5-tier signal.

## Live actions

The Wiz connector is **read-only** as of v7.3.1 — it pulls findings but
does not push back into Wiz. Containment for cloud findings flows through
the [AWS Security Hub](/docs/connectors/aws-security-hub) and
[Cloudflare](/docs/connectors/cloudflare) connectors which expose
`BLOCK_IP` / `ALLOW_IP` capabilities. A future `RESOLVE_ISSUE` capability
that calls back into the Wiz GraphQL `updateIssue` mutation is on the
roadmap.

## Troubleshooting

**`could not authenticate to wiz`** — the service account credentials are
wrong, or the Auth URL is overridden but pointing at the wrong cloud
(commercial vs gov-cloud). Reset the Auth URL to blank to fall back to the
default commercial endpoint.

**`HTTP 401` on `issues` query** — the OAuth bearer was issued but lacks
`read:issues` scope. Re-grant the scope on the service account in the Wiz
console; tokens cache scopes at issue time, so wait one poll cycle for the
new token to take effect.

**`events_added: 0` indefinitely** — your Wiz tenant has no OPEN issues.
That is the expected steady state for a clean tenant. Trigger a benign
finding (e.g. open a public S3 bucket in a sandbox account) to confirm the
connector path is healthy.

## Related

- [AWS Security Hub](/docs/connectors/aws-security-hub) — alternative cloud
  finding source if you have not adopted Wiz.
- [Lacework](/docs/connectors/lacework) — alternative CNAPP path.
