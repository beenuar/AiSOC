---
sidebar_position: 82
title: Sysdig Secure
description: Pull Sysdig Secure runtime / cloud detection events (Falco-style policy hits) into AiSOC.
---

# Sysdig Secure

The Sysdig connector pulls **runtime / cloud-detection events** from the Sysdig Secure Events API — every Falco-style policy hit raised by the same engine that powers the open-source `falco` connector, plus the higher-level posture detections Sysdig layers on top.

If you already run the open-source `falco` connector for self-hosted clusters, the Sysdig connector is what you add for cross-account / multi-cluster Sysdig SaaS visibility without standing up a per-cluster Falco sidecar.

## What you get

| Event family | Examples |
|---|---|
| **Workload policy hits** | `Read sensitive file untrusted`, `Disallowed binary in container`, `Network connection to unfamiliar destination` |
| **Cloud policy hits** | AWS / GCP / Azure posture rules (e.g. public S3 bucket created) |
| **Container drift** | Image substitution, runtime image hash diverges from registry |
| **Identity policy** | Service-account token mounted outside expected namespace |
| **CNAPP correlations** | Sysdig's own multi-signal CDR (cloud detection-and-response) entries |

Events are normalized with `source: sysdig`, `category: siem` (runtime detection plane).

## Prerequisites

- A **Sysdig Secure** subscription (Sysdig Secure Plus or Enterprise — the free Sysdig Monitor tier does not expose Secure Events).
- A **Sysdig API token** scoped to **read** access on Secure Events. Tokens are minted under **Settings → API → Tokens**.
- Know your **Sysdig region prefix** (visible in the URL of any Sysdig page):

| Region prefix | Hostname |
|---|---|
| `us1` | `secure.sysdig.com` |
| `us2` | `us2.app.sysdig.com` |
| `us3` | `app.us3.sysdig.com` |
| `us4` | `app.us4.sysdig.com` |
| `eu1` | `eu1.app.sysdig.com` |
| `au1` | `app.au1.sysdig.com` |
| `me2` | `app.me2.sysdig.com` |

## Setup walkthrough

### 1. Mint the API token

1. **Sysdig Secure → Settings → API → Tokens → New Token**.
2. Name it `aisoc-readonly` so it's auditable.
3. Scope: **Secure Events: Read** only. Do not grant Posture: Write or Compliance: Write — they are unnecessary for ingestion.
4. Copy the token immediately. Sysdig will not show it again.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Sysdig Secure**.
2. `region` = the prefix from the table above.
3. `api_token` = the token from step 1 (stored encrypted in the credential vault).
4. **Test connection** → calls `GET /api/v1/secureEvents?limit=1`.
5. **Save**.

## Polling details

- Default interval: **300 seconds** (configurable down to 60s and up to 3600s).
- The connector queries `GET /api/v1/secureEvents` with a `from`/`to` window in nanoseconds covering the last `since_seconds` window plus a 30-second overlap to absorb out-of-order event delivery.
- Pagination walks both `offset`/`limit` and `cursor` styles depending on which the tenant's API version honours.
- An upper bound of **25 pages × 100 events = 2,500 events per poll** prevents the connector from monopolising an API quota during a burst — additional events are picked up on the next poll cycle.

## Severity mapping

Sysdig event severities use the Falco syslog ladder (0..7, lower = more severe). The connector folds this onto the AiSOC scale:

| Sysdig severity | AiSOC severity |
|---|---|
| 0 (Emergency) / 1 (Alert) | `critical` |
| 2 (Critical) / 3 (Error) | `high` |
| 4 (Warning) | `medium` |
| 5 (Notice) | `low` |
| 6 (Informational) / 7 (Debug) | `info` (suppressed by default — flip the env var `AISOC_SYSDIG_KEEP_INFO=1` to keep them) |

## Troubleshooting

**`HTTP 401: invalid token`** — token was revoked / rotated, or you copied the **Monitor** API token rather than the **Secure** API token (they share the UI but the scopes differ).

**`HTTP 403: insufficient permissions`** — token lacks the `Secure Events: Read` scope. Re-mint with the right scope; do not escalate the existing token.

**`Connection timeout`** — region prefix wrong. The connector resolves the prefix to a fixed hostname (see table above); a US1 token will not authenticate against the EU1 endpoint.

**No events returned despite Sysdig dashboard showing detections** — the API only surfaces events from policies tagged for **Secure Events** output. Posture findings on un-tagged policies stay inside the Sysdig UI.

## Related

- [Falco](./falco.md) — self-hosted runtime detection. Use this if you run open-source Falco and want the raw policy hits without the Sysdig SaaS subscription.
- [Kubernetes Audit](./kubernetes-audit.md) — control-plane audit log. Pairs well with Sysdig for cluster-level forensics (control + data plane in one investigation).
