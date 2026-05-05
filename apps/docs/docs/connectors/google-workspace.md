---
sidebar_position: 8
title: Google Workspace
description: Admin, login, drive, and token activity from Google Workspace (formerly G Suite) into AiSOC via the Reports API.
---

# Google Workspace

The Google Workspace connector pulls **activity reports** from the Reports API — admin actions, user logins, Drive file events, OAuth token grants, and more — into AiSOC. It is the identity-and-collaboration counterpart to the Microsoft 365 connector.

## What you get

| Application name | Examples |
|---|---|
| `admin` | User created, group changed, 2SV settings modified |
| `login` | Successful and failed logins, suspicious-login challenges |
| `drive` | File create, share, download (requires Drive audit log) |
| `token` | OAuth grant to third-party app, token revoke |
| `mobile` | Device enrollment, suspicious activity |

Events are normalized with `source: google_workspace` and `category` derived from the application name.

## Prerequisites

- A **Google Cloud project** in the same organization as your Workspace tenant.
- A **service account** with **domain-wide delegation enabled**.
- A **JSON key** for that service account.
- A **Workspace super-admin email** to impersonate (the Reports API requires admin context).
- The OAuth scope `https://www.googleapis.com/auth/admin.reports.audit.readonly` granted to the service account's client ID in **Workspace Admin → Security → API controls → Domain-wide delegation**.

## Setup walkthrough

### 1. Create the service account

1. **GCP Console → IAM & Admin → Service Accounts → Create**.
2. Name: `aisoc-workspace-reports`.
3. Skip the "grant access to project" step — domain-wide delegation is what matters here.
4. Open the service account → **Keys → Add key → JSON**. Download.

### 2. Enable domain-wide delegation

1. On the service account detail page, click **Show advanced settings → Enable Google Workspace Domain-wide Delegation**.
2. Note the **OAuth client ID** that appears (a long numeric string).

### 3. Authorize the scope in Workspace

1. **admin.google.com → Security → API controls → Manage domain-wide delegation → Add new**.
2. Client ID: paste from step 2.
3. OAuth scopes: `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
4. **Authorize**.

### 4. Pick an admin email to impersonate

The Reports API will not return events unless the credential is acting as a super-admin. Pick a dedicated `aisoc@yourdomain.com` super-admin if possible — easier to audit than impersonating a human admin.

### 5. Add the connector in AiSOC

1. **Connectors → Add connector → Google Workspace**.
2. `admin_email` = the super-admin to impersonate.
3. `service_account_json` = paste the entire downloaded JSON file as one blob.
4. **Test connection** → calls `activities.list(applicationName=admin, maxResults=1)`.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- The connector iterates over the configured application names (default: `admin`, `login`, `drive`, `token`) and pulls activities since the last poll, paginating with `nextPageToken`.
- Reports API has up to 30 minutes of ingestion latency on `drive` events; other applications are typically 1-2 min.

## Severity heuristics

| Event | Severity |
|---|---|
| `CHANGE_USER_2_STEP_VERIFICATION` from `enabled` → `disabled` | `high` |
| `GRANT_ADMIN_PRIVILEGE`, `ASSIGN_ROLE` on a privileged role | `high` |
| `login_failure` clusters from a single user (3+ in a window) | `medium` |
| `suspicious_login` challenge result `passed` | `medium` |
| `authorize` (OAuth) on a non-internal third-party app with broad scopes | `medium` |
| Routine file open/edit | dropped |

## Troubleshooting

**`unauthorized_client: Client is unauthorized to retrieve access tokens using this method`** — domain-wide delegation is not authorized for the scope. Re-check step 3 and confirm the **client ID** (not the email) matches the service account's OAuth client ID.

**`Forbidden: Access denied`** despite a working test — the impersonated user is not a super-admin. The Reports API requires super-admin scope; "User Management Admin" is not enough.

**`Daily Limit Exceeded`** — the Reports API has a daily quota per project. Either request a quota bump in GCP, or lengthen the poll interval to reduce call volume.

## Related

- [Microsoft 365 Audit](/docs/connectors/m365-audit) — Microsoft equivalent. If you have both, run both — they are non-overlapping.
- [GitHub Audit + Code Scanning](/docs/connectors/github) — for the dev side of identity if your engineering team lives in GitHub.
