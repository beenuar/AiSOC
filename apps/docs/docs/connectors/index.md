---
sidebar_position: 1
title: Connectors overview
description: Click-and-connect data sources for AiSOC — Azure, GCP, Microsoft 365, Google Workspace, Cloudflare, GitHub, and the rest of the catalog.
---

# Connectors

A **connector** is the bridge between an external data source (an identity provider, a cloud audit log, an EDR, a SaaS platform) and the AiSOC pipeline. Once a connector instance is enabled, the connector microservice polls it on a schedule, pulls new events, normalizes them into AiSOC's event schema, and posts them to the ingest service for detection and triage.

Everything ships with three guarantees:

- **Credentials are encrypted at rest.** Tokens, client secrets, and service-account JSON keys are sealed with `Fernet` (AES-128-CBC + HMAC-SHA256) before they touch the database. See [Credential vault](/docs/operations/credentials).
- **Schemas are self-describing.** The connector tells the UI what fields it needs; the wizard renders them. There is no hardcoded form that drifts from the backend.
- **Polling is observable.** Every poll records `last_poll_at`, `events_added`, and `health_status`. Failures show up in the connector card with the underlying error message.

## Catalog

| Connector | Category | Auth | Notes |
|---|---|---|---|
| [Microsoft Entra ID](/docs/connectors/azure-entra) | Identity | Azure AD app (client credentials) | Directory audits + risky sign-ins via Microsoft Graph |
| [Azure Activity Logs](/docs/connectors/azure-activity) | Cloud (control plane) | Azure AD app + subscription | Subscription-scope ARM activity, IAM grants, policy changes |
| [Microsoft Defender (XDR)](/docs/connectors/azure-defender) | EDR / XDR | Azure AD app | Cross-product alerts via Microsoft Graph Security |
| [GCP Cloud Audit Logs](/docs/connectors/gcp-cloud-audit) | Cloud (control plane) | Service account JSON | Admin Activity + Data Access + System Event |
| [GCP Security Command Center](/docs/connectors/gcp-scc) | Cloud (posture) | Service account JSON | Org-scope active findings |
| [Microsoft 365 Audit](/docs/connectors/m365-audit) | SaaS | Azure AD app (shares Entra creds) | Unified audit log: AAD, Exchange, SharePoint, Teams |
| [Google Workspace](/docs/connectors/google-workspace) | SaaS / Identity | Service account + DWD | Admin SDK Reports: login, admin, drive, token, mobile |
| [Cloudflare](/docs/connectors/cloudflare) | SaaS | API token | Account audit logs (operator activity, not edge traffic) |
| [GitHub](/docs/connectors/github) | VCS | PAT or App installation token | Org audit log + Code Scanning alerts |
| Okta | Identity | API token | System log (already shipped) |
| AWS Security Hub | Cloud (posture) | AWS keys / role | Findings (already shipped) |
| CrowdStrike Falcon | EDR | OAuth2 client credentials | Detections (already shipped) |
| Splunk | SIEM | HEC token / API | Saved-search results (already shipped) |
| Microsoft Sentinel | SIEM | Azure AD app | Incidents (already shipped) |

## Adding a connector

1. Open the AiSOC console → **Connectors** → **Add connector**.
2. Pick a connector from the catalog grid. The wizard advances to a schema-driven configuration form.
3. Fill in the required fields. Secret fields (tokens, client secrets, service-account JSON) are obscured.
4. Click **Test connection**. The pre-save test is stateless — credentials are sent once over TLS, the target API is called, and **nothing is persisted** unless the test passes and you click **Save**.
5. On save, the credentials are encrypted in the vault, the instance is stored with `is_enabled=true`, and the scheduler picks it up on the next reload (within 30 seconds).

## How polling works

Each enabled connector instance becomes one job in an in-process [`APScheduler`](https://apscheduler.readthedocs.io/) running inside `services/connectors`:

- Default poll interval: **300 seconds** (5 minutes). Override per-instance via `connector_config.poll_interval_seconds`. Minimum is 30s.
- Every 30s the scheduler queries the database for `is_enabled = true` instances and rebuilds the job set. Add, remove, or change the polling interval and the next reload picks it up.
- On poll: the vault decrypts `auth_config` in memory, the connector class is instantiated, `fetch_alerts(since_seconds=poll_interval)` runs, results pass through `normalize()`, and the resulting events are POSTed to the ingest service with the tenant ID header.
- On failure: the error message is recorded on `health_status` and surfaced in the UI. The job stays scheduled; the next interval will retry.

## Categories

Connector categories drive the catalog grouping and downstream routing hints. The current set is:

`identity` · `cloud` · `vcs` · `siem` · `edr` · `xdr` · `network` · `posture` · `saas`

These map to the same taxonomy used by detection rules, so a Microsoft Entra alert flowing in here can be matched against `category: identity` Sigma rules without any glue code.

## What "hosted OAuth" means

Several connectors today require you to bring your own credentials (an Azure AD app registration, a GitHub PAT, a service-account JSON). The connector schema includes an `oauth` block that advertises whether a hosted OAuth flow is available — for now, every connector that supports OAuth marks it `supported_in_hosted: false`. Hosted OAuth (where AiSOC owns the app registration and you click "Connect") is on the roadmap; see [Credential vault](/docs/operations/credentials#hosted-oauth-roadmap).

## Writing a new connector

See [Plugin SDK overview](/docs/plugins/overview) and [Contributing](/docs/contributing/guidelines). The short version: subclass `BaseConnector`, implement `schema()`, `test_connection()`, `fetch_alerts()`, and `normalize()`, register it in `services/connectors/app/connectors/__init__.py`, drop a `plugin.yaml` under `plugins/<id>/`, and run `pnpm marketplace:sync`.
