---
sidebar_position: 77
title: Box
description: Box enterprise admin audit log events into AiSOC via the Box Events API.
---

# Box

The Box connector polls the **/2.0/events?stream_type=admin_logs**
endpoint of the Box API and emits one AiSOC alert per admin event
(login, shared-link creation, MFA / device-trust changes, folder
permission changes, file lifecycle).

## What you get

| Source | Box endpoint | Notes |
|---|---|---|
| Admin events | `GET /2.0/events?stream_type=admin_logs` | All security-relevant admin actions |

Events are normalised with `source: box` and the original Box envelope
is preserved on `raw_event` so detection rules can match on the
`event_type` (e.g. `SHARE`, `LOGIN`, `ITEM_RENAME`,
`ENTERPRISE_APP_AUTHORIZATION`).

## Prerequisites

- A **Box Business / Enterprise** tenant with admin access.
- An **access token** with the `manage_enterprise_properties` scope.
  Two ways to get one:
  - Production: **Custom App → JWT / OAuth 2.0** with the *Manage
    enterprise properties* permission, then mint a server-side token.
  - Proof-of-concept: a **Developer Token** generated from the Box
    Developer Console (expires every 60 minutes — fine for a one-off
    smoke test, not for production).

## Setup walkthrough

1. Sign in to the **Box Developer Console**
   (`https://app.box.com/developers/console`).
2. Create a new **Custom App → Server Authentication (with JWT)**.
3. Enable **Manage enterprise properties** under *Application Scopes*.
4. **Authorize the app** for your enterprise (Admin Console → Apps →
   Custom Apps Manager → Authorize). This step is required and is
   the single most common setup failure.
5. Generate a server-side access token via the Box SDK or the
   `/oauth2/token` endpoint and copy it.
6. In AiSOC: **Connectors → Add connector → Box**.
7. Paste the access token.
8. Click **Test connection**. AiSOC issues a `GET /2.0/users/me` and
   confirms a `200`.
9. Save.

## Severity mapping

The connector escalates Box `event_type` against a small high/medium
ladder; everything else falls through to `info`. The canonical lists
live in `services/connectors/app/connectors/box.py`.

| AiSOC severity | Box `event_type` |
|---|---|
| `high`   | `SHIELD_ALERT`, `SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED`, `SHIELD_EXTERNAL_COLLAB_INVITE_ABNORMAL_LOCATION`, `GROUP_ADMIN_CREATED`, `ROLE_CHANGE_TO_ADMIN`, `MASTER_INVITE_ACCEPT`, `MASTER_INVITE_REJECT`, `APPLICATION_PUBLIC_KEY_DELETED`, `APPLICATION_PUBLIC_KEY_ADDED`, `ITEM_SHARED_LINK`, `DELETE_USER` |
| `medium` | `COLLABORATION_INVITE`, `COLLABORATION_ACCEPT`, `COLLABORATION_REMOVE`, `COLLABORATION_ROLE_CHANGE`, `COLLABORATION_EXPIRATION`, `FAILED_LOGIN`, `ADD_LOGIN_ACTIVITY_DEVICE`, `REMOVE_LOGIN_ACTIVITY_DEVICE`, `ITEM_SHARED_UPDATE` |
| `info`   | everything else |
| `high` (override) | `ITEM_DOWNLOAD` whose actor login ends with `@gmail.com`, `@yahoo.com`, or `@outlook.com` (treated as external collaborator exfiltration) |

## Capabilities

- `pull_audit` — passive polling of admin audit events.
- `pivot_user` — given a Box email, surface that user's recent activity.
- `read_audit_trail` — surface the API call lineage during investigation.

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: cursor-based using `next_stream_position`. The connector
  follows up to 25 pages per poll cycle.
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`401 Unauthorized`** — the access token has expired (Developer
  Tokens last 60 minutes). Mint a new token via JWT/OAuth and update
  the connector.
- **`403 Forbidden`** — the custom app was not authorized for the
  enterprise (Admin Console → Custom Apps Manager). Authorize it and
  retry the connection test.
- **No events** — confirm there is recent admin activity. Box only
  populates `admin_logs` when an enterprise-admin event occurs;
  individual user activity lives on a different stream.
