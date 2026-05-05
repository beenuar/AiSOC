---
sidebar_position: 5
title: GCP Cloud Audit Logs
description: Project-scope Admin Activity, Data Access, and System Event audit logs from Google Cloud into AiSOC.
---

# GCP Cloud Audit Logs

The GCP Cloud Audit connector streams **Cloud Logging audit log entries** from a single GCP project into AiSOC. This covers the three Google audit log types: **Admin Activity** (always on), **Data Access** (off by default for most services), and **System Event**.

## What you get

| Audit type | Logged by default | What's in it |
|---|---|---|
| Admin Activity | Yes, always | IAM grants, project metadata changes, resource create/delete |
| Data Access | No (opt-in per service) | Reads against user data — high volume, high signal for exfiltration |
| System Event | Yes, always | GCP-initiated changes (auto-resize, automatic migration, etc.) |

Events are normalized with `category: cloud` and `cloud_provider: gcp`.

## Prerequisites

- A **GCP project** to monitor.
- A **service account** in that project (or an org-level account with project access).
- The service account must have at minimum the **Logs Viewer** role (`roles/logging.viewer`) on the project. For private logs (Data Access for some services), grant **Private Logs Viewer** (`roles/logging.privateLogViewer`).
- A **JSON key** for that service account.
- The **Project ID** (the human-readable one, not the numeric Project Number).

## Setup walkthrough

### 1. Create the service account

1. Open the [GCP Console → IAM & Admin → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) for your project.
2. **Create service account** → name it `aisoc-cloud-audit-reader`. Skip the optional grant step inside the wizard.
3. Once created, on the project's IAM page, **Grant access** to the new service account email with role **Logs Viewer** (and **Private Logs Viewer** if you want Data Access).

### 2. Mint a JSON key

1. Open the service account → **Keys → Add key → Create new key → JSON**.
2. Download the JSON file. Treat it like a password — anyone with this file can read your audit logs.

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → GCP Cloud Audit Logs**.
2. `project_id` = your Project ID (not the number).
3. `service_account_json` = paste the **entire** JSON file contents into the textarea. The connector validates that it parses as JSON and contains a `private_key` field; it never logs the contents.
4. **Test connection** → makes a test `entries.list` call against `cloudaudit.googleapis.com/activity` for your project.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- The connector calls `entries.list` with `filter='timestamp >= "{since}" AND logName:"cloudaudit.googleapis.com"'` to pull all three audit types in one query.
- Auth: standard GCP service-account JWT bearer flow against `https://oauth2.googleapis.com/token`.

## Severity heuristics

GCP audit logs do not carry a built-in severity; AiSOC infers from `methodName`:

| Pattern | Severity |
|---|---|
| `SetIamPolicy` with role grants like `roles/owner`, `roles/iam.securityAdmin` | `high` |
| `SetIamPolicy` (other) | `medium` |
| `Delete*` on networks, firewalls, KMS keys, sinks | `high` |
| `services.disable` on `cloudaudit.googleapis.com` (audit-log tampering) | `high` |
| Any `severity: ERROR` returned by GCP | bumped one level |
| Routine `Get*` / `List*` | dropped |

## Troubleshooting

**`PERMISSION_DENIED: Cloud Logging API has not been used in project ... before or it is disabled`** — enable the Cloud Logging API in the GCP project (`gcloud services enable logging.googleapis.com`).

**`PERMISSION_DENIED: ... does not have logging.logEntries.list`** — the service account is missing `roles/logging.viewer`. Re-grant on the project IAM page.

**`Service account JSON key file is invalid`** — the file has been re-formatted (e.g. `\n` in private key got escaped twice). Re-download a fresh key from the GCP console and paste without modification.

**`events_added: 0` on a busy project** — make sure you used the Project **ID**, not the Project **Number**. The numeric form does not work with the audit log filter.

## Related

- [GCP Security Command Center](/docs/connectors/gcp-scc) — pairs perfectly: SCC findings give you posture and threat detection; Cloud Audit gives you the raw control-plane events behind them.
- [Credential vault](/docs/operations/credentials) — the service-account JSON is encrypted at rest in the connector record.
