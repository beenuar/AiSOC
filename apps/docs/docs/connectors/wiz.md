---
sidebar_position: 16
title: Wiz
description: Wiz cloud security findings (CSPM, CWPP, CIEM, container, code) into AiSOC via the Wiz GraphQL API.
---

# Wiz

The Wiz connector pulls **cloud security issues from the Wiz GraphQL API**
into AiSOC as alerts, and optionally three further finding classes as
**triage context rather than as alerts**.

The distinction is the point. An issue is a finding Wiz has already
correlated and decided is worth raising, so it belongs in an analyst queue.
A CNAPP's standing backlog of misconfigurations does not — pushing tens of
thousands of them into a queue is the noise a CNAPP exists to triage. What
that backlog is good for is answering a different question, the one a verdict
has: *is the resource in front of me already known to be wrong?*

## What you get

| Source | Wiz GraphQL query | Becomes | Default |
|---|---|---|---|
| Cloud security issues | `issues` | **Alerts** in the queue | on |
| Vulnerability findings | `vulnerabilityFindings` | Rows in the per-asset CVE inventory, with a patch window | off |
| Configuration findings | `configurationFindings` (result `FAIL`) | Cloud-posture context a verdict can read | off |
| Runtime detections | `detections` | Cloud-posture context a verdict can read | off |

Each of the three context reads is an additional standing poll against your
Wiz tenant and needs a scope your API client may not hold, so each is off
until you enable it. Nothing changes when they stay off: the connector keeps
pulling issues exactly as before.

**Secrets are not collected.** Wiz detects exposed secrets, but no public
reference documents a top-level secrets query the way it documents the three
above, and writing one from the product's marketing surface would be
inventing an endpoint. Secrets reach AiSOC as `issues` where Wiz raises them
as such.

Events are normalized with `source: wiz` and the original Wiz issue payload
is preserved on `raw_event` for downstream playbooks and the Investigation
Ledger.

## How posture context reaches a verdict

When auto-triage handles an alert, it asks what is already open against the
resources the alert names, matching on every identifier the resource answers
to — the cloud provider's id, Wiz's own graph id and the display name — so a
finding Wiz recorded against an ARN still matches an alert that names the
same bucket by its short name.

What the model is told is bounded and caveated: a standing misconfiguration
makes the activity easier, so it is a reason to weigh the activity
differently, and it is never evidence that the activity happened or that it
was authorised.

**An absent CNAPP is never rendered as a clean estate.** A tenant with no
cloud-security connector gets no block in the prompt at all, rather than a
line saying the resource has no findings — which a model would reasonably
read as exculpatory. The same distinction reaches `GET /posture/summary`,
which reports `collected: false` with null counts instead of a confident
zero.

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

Wiz ships a 5-tier severity ladder and AiSOC's ladder is also five tiers, so
`CRITICAL` is preserved end to end rather than collapsed into `high`:

| Wiz severity | AiSOC severity |
|---|---|
| `CRITICAL` | `critical` |
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

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `client_id` | Client ID | string | yes | — | — |
| `client_secret` | Client Secret | secret | yes | — | **encrypted at rest** |
| `api_endpoint_url` | API Endpoint URL | string | yes | — | Your tenant's GraphQL API endpoint. |
| `auth_url` | Auth URL | string | no | `https://auth.app.wiz.io/oauth/token` | OAuth2 token endpoint. Override only for gov-cloud tenants. |
| `collect_vulnerabilities` | Collect vulnerability findings | boolean | no | `False` | Pull per-asset CVE findings into the vulnerability inventory (not the alert queue). Needs the read:vulnerabilities scope. |
| `collect_configuration_findings` | Collect configuration findings | boolean | no | `False` | Pull failed cloud-configuration checks as posture context for triage (not the alert queue). Needs the read:cloud_configuration scope. |
| `collect_runtime_detections` | Collect runtime detections | boolean | no | `False` | Pull runtime threat detections as posture context for triage (not the alert queue). Needs the read:detections scope. |

:::note Credential handling
`client_secret` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
