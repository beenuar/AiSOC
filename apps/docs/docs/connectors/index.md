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

If your tool isn't in the catalog, see [Universal capture](/docs/connectors/universal-capture) — webhook URLs, email relay, CEF syslog, and Splunk HEC let any vendor that can POST or send mail land events in the same OCSF stream.

## Catalog

The catalog ships with **50 connectors** out of the box, registered in [`services/connectors/app/connectors/__init__.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/app/connectors/__init__.py). The list below is grouped by category; only a subset has dedicated walkthrough pages today (linked entries) — the rest follow the same schema-driven wizard described under [Adding a connector](#adding-a-connector).

### Identity

| Connector | Category | Auth | Notes |
|---|---|---|---|
| [Microsoft Entra ID](/docs/connectors/azure-entra) | Identity | Azure AD app (client credentials) | Directory audits + risky sign-ins via Microsoft Graph |
| Okta | Identity | API token | System log |
| Auth0 | Identity | Mgmt API token | Tenant log events (logins, MFA, anomaly) |
| Duo Security | Identity / MFA | Integration key + secret | Authentication logs and policy events |
| 1Password | IAM / Secrets | Service account token | Vault access events and shared-item changes |

### EDR / XDR

| Connector | Category | Auth | Notes |
|---|---|---|---|
| CrowdStrike Falcon | EDR | OAuth2 client credentials | Detections |
| SentinelOne | EDR / XDR | API token | Threats with severity mapped from `confidenceLevel` |
| [Microsoft Defender (XDR)](/docs/connectors/azure-defender) | EDR / XDR | Azure AD app | Cross-product alerts via Microsoft Graph Security |
| Palo Alto Cortex XDR | EDR / XDR | API key + ID | Incidents and alerts |
| Palo Alto Cortex XSIAM | XDR / SIEM | API key + ID | XSIAM incidents and prioritised alerts |
| VMware Carbon Black | EDR | API ID + secret | Endpoint detections and alerts |
| Trellix Helix | XDR | API key | Cross-vendor correlated alerts |
| Trend Vision One | XDR | API token | Workbench alerts and observed attack techniques |

### SIEM

| Connector | Category | Auth | Notes |
|---|---|---|---|
| Splunk | SIEM | HEC token / API | Saved-search results |
| Microsoft Sentinel | SIEM | Azure AD app | Incidents |
| Elastic | SIEM | API key | Detection alerts |
| Sumo Logic | SIEM | Access ID + key | Search and alert events |
| Datadog Cloud SIEM | SIEM | API + app key | Security signals and detection rule hits |
| Google Chronicle | SIEM | Service account JSON | UDM events and detection rule hits |
| Rapid7 InsightIDR | SIEM | API key | Investigations and detection alerts |

### Cloud (control plane / posture / CNAPP)

| Connector | Category | Auth | Notes |
|---|---|---|---|
| AWS Security Hub | Cloud (posture) | AWS keys / role | Findings |
| AWS GuardDuty | Cloud (threat) | AWS keys / role | Threat findings across regions |
| AWS CloudTrail | Cloud (control plane) | AWS keys / role | Account-wide API activity |
| AWS VPC Flow Logs | Cloud (network) | AWS keys / role + S3 / CWL | Layer-3/4 flow telemetry |
| [Azure Activity Logs](/docs/connectors/azure-activity) | Cloud (control plane) | Azure AD app + subscription | Subscription-scope ARM activity, IAM grants, policy changes |
| [GCP Cloud Audit Logs](/docs/connectors/gcp-cloud-audit) | Cloud (control plane) | Service account JSON | Admin Activity + Data Access + System Event |
| [GCP Security Command Center](/docs/connectors/gcp-scc) | Cloud (posture) | Service account JSON | Org-scope active findings |
| Wiz | CSPM / CNAPP | OAuth2 client credentials | Cloud security findings via GraphQL |
| Lacework | CSPM / CNAPP | API key + secret | Composite alerts and compliance violations |
| Tenable | Vuln mgmt | API access + secret | Vulns + plugin findings (Tenable.io / Nessus) |
| Prisma Cloud | CSPM / CNAPP | Access key + secret | Cloud findings and policy violations |
| Orca | CSPM / CNAPP | API token | Side-scanned cloud findings |

### SaaS / Communication / ITSM

| Connector | Category | Auth | Notes |
|---|---|---|---|
| [Microsoft 365 Audit](/docs/connectors/m365-audit) | SaaS | Azure AD app (shares Entra creds) | Unified audit log: AAD, Exchange, SharePoint, Teams |
| [Google Workspace](/docs/connectors/google-workspace) | SaaS / Identity | Service account + DWD | Admin SDK Reports: login, admin, drive, token, mobile |
| Slack Audit | SaaS / Comms | Audit API token | Workspace audit logs (org-grid required) |
| Salesforce | SaaS / CRM | OAuth2 / connected app | Login history, setup audit trail, security events |
| [Cloudflare](/docs/connectors/cloudflare) | SaaS / Edge | API token | Account audit logs (operator activity, not edge traffic) |
| Proofpoint | Email Security | Service principal | Threat events and click telemetry |
| Mimecast | Email Security | API key + secret | Email threat events and policy actions |
| Email Inbox | Email Security / Phishing | IMAP / Graph | Reported-phishing inbox triage |
| ServiceNow | ITSM | OAuth2 / basic auth | Security incident table updates |
| Jira | Ticketing | API token | Security ticket and project events |

### VCS / AppSec

| Connector | Category | Auth | Notes |
|---|---|---|---|
| [GitHub](/docs/connectors/github) | VCS | PAT or App installation token | Org audit log + Code Scanning alerts |
| Snyk | SCA / AppSec | API token | Dependency, container, and IaC issues |

### Endpoint fleet / Container

| Connector | Category | Auth | Notes |
|---|---|---|---|
| osctrl | Endpoint fleet | API token | Fleet-wide osquery results from osctrl |
| FleetDM | Endpoint fleet | API token | Fleet-wide osquery results from FleetDM |
| Kubernetes Audit | Container / Orchestration | apiserver webhook or `audit.log` tail | Cluster API server audit events |

### Network

| Connector | Category | Auth | Notes |
|---|---|---|---|
| Tailscale | Network | API key | ACL audit + device changes |
| Zscaler | Network / Cloud Proxy | API key | ZIA and ZPA security events |
| Cisco Umbrella | Network / DNS | API key + secret | Security events and DNS verdicts |

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
