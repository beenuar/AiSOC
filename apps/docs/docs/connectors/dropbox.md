---
sidebar_position: 79
title: Dropbox
description: Dropbox Business team audit log events into AiSOC via /2/team_log/get_events.
---

# Dropbox

The Dropbox connector polls the **/2/team_log/get_events** endpoint of
the Dropbox Business API and emits one AiSOC alert per team event
(login, sharing, file lifecycle, device approvals, password resets,
admin role changes).

## What you get

| Source | Dropbox endpoint | Notes |
|---|---|---|
| Team events | `POST /2/team_log/get_events` | Full team audit log |

Events are normalised with `source: dropbox` and the original Dropbox
envelope is preserved on `raw_event` so detection rules can match on
`event_category` (`sharing`, `logins`, `file_operations`, …) and
`event_type.tag` (`login_fail`, `member_change_admin_role`, etc).

## Prerequisites

- A **Dropbox Business** team with team-admin access.
- An **OAuth 2.0 access token** with the `team_data.member` and
  `events.read` scopes, minted from a Dropbox app of type
  *Scoped Dropbox API + Team scope*.

## Setup walkthrough

1. Sign in to **App Console → My Apps** (`https://www.dropbox.com/developers/apps`).
2. **Create app → Scoped access → Choose API: Dropbox API + Type of access:
   Full Dropbox**. Set the *App folder name* and create.
3. **Permissions tab → Team scopes**: enable `events.read` and
   `team_data.member`.
4. **Settings tab → OAuth 2** : add a redirect URI (only required if you
   intend to perform user-driven OAuth; otherwise skip), then click
   **Generate** under *Generated access token* to get a long-lived
   team-admin token.
5. Copy the token.
6. In AiSOC: **Connectors → Add connector → Dropbox Business**.
7. Paste the team-admin token.
8. Click **Test connection**. AiSOC issues a single 1-row
   `/2/team_log/get_events` and confirms a `200`.
9. Save.

## Severity mapping

The connector inspects `event_type.tag` and matches against a
prefix-driven ladder (see `services/connectors/app/connectors/dropbox.py`
for the canonical lists):

| AiSOC severity | Dropbox `event_type.tag` prefixes |
|---|---|
| `high`   | `account_external_password_unmask`, `team_member_create_team_invite_link`, `shared_content_change_link_audience_to_public`, `shared_content_remove_member`, `app_link_team`, `member_change_admin_role`, `team_folder_change_status`, `sso_change_policy` |
| `medium` | `shared_`, `shared_content_`, `shared_link_`, `shmodel_`, `login_fail`, `login_success_with_two_factor`, `device_link`, `group_create`, `group_delete`, `member_change_status`, `member_change_email` |
| `info`   | anything not matching either list (the floor) |

Additional refinements applied last (in order):

- `event_type == "login_fail"` is forced to `medium`.
- `event_type == "login_success"` carrying a device tag is lowered to
  `low` if no stronger rule already applied.

## Capabilities

- `pull_audit` — passive polling of team audit events.
- `pivot_user` — given a member email, surface their recent activity.
- `read_audit_trail` — surface the API call lineage during investigation.

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: cursor-based using `has_more` / `cursor`. The connector
  follows up to 25 pages per poll cycle.
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`401 Unauthorized`** — token has been revoked. Regenerate in the
  App Console and update the connector.
- **`400 Bad Request` with `path/invalid_cursor`** — the cursor expired
  (Dropbox cursors live ~30 days). The connector resets the cursor on
  the next poll cycle automatically.
- **No events** — confirm there is recent team activity. Personal-account
  Dropbox instances do not have a team audit log.
