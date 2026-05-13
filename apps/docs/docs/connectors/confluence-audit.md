---
sidebar_position: 75
title: Atlassian Confluence Audit
description: Pull Confluence Cloud audit-trail events (page, space, permission, user/group) into AiSOC.
---

# Atlassian Confluence Audit

The Confluence Audit connector pulls the **audit trail** from Confluence Cloud via the REST API. Events include:

- Page and space lifecycle (create / update / delete / restore).
- Permission and restriction changes — page restrictions, space permissions, global permissions, external-share link creation.
- User and group changes — additions, removals, role assignments at site scope.
- Site export and bulk-delete operations.

Events are normalised with `source: confluence_audit`, `category: saas`.

## Prerequisites

- An **Atlassian Cloud** site that includes Confluence (`*.atlassian.net`).
- An **Atlassian Cloud API token** issued at [id.atlassian.com → Security → API tokens](https://id.atlassian.com/manage-profile/security/api-tokens).
- The user who owns the token **must have site-admin access**. The audit endpoint returns `403` for non-admin users; the test-connection probe distinguishes this case explicitly.

## Setup walkthrough

### 1. Create the API token

1. Sign in to [id.atlassian.com](https://id.atlassian.com) as a **site admin**.
2. **Security → API tokens → Create API token**.
3. **Label**: `aisoc-confluence-audit`.
4. Copy the token (Atlassian shows it once).

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Atlassian Confluence Audit**.
2. `site_url` = your Confluence URL (e.g. `https://acme.atlassian.net`).
3. `email` = the Atlassian Cloud account email of the token owner.
4. `api_token` = the token (encrypted in the credential vault).
5. **Test connection** — probes `GET /wiki/rest/api/user/current` to validate credentials, then `GET /wiki/rest/api/audit?limit=1` to confirm audit access. The response includes `audit_available: true/false` so the operator knows immediately whether the user has site-admin rights.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `GET /wiki/rest/api/audit?startDate=<ms>&limit=100&start=<offset>` — paginated by `start` offset.
- Pagination terminates when the response's `size` field is smaller than `limit`, signalling the end of the window.

## Severity mapping

Most events are routine and stay at `info`. Permission and security-category events bump to at least `medium`. A short allowlist of summary fragments maps to `high`:

| Trigger | AiSOC severity |
|---|---|
| Summary contains `Removed user from site` | `high` |
| Summary contains `Granted site admin` | `high` |
| Summary contains `Site-wide deletion` / `Bulk delete` | `high` |
| Summary contains `External share link created` / `Public link enabled` | `high` |
| Summary contains `Permissions granted to anyone` / `Anonymous access enabled` | `high` |
| Summary contains `Site export started` | `high` |
| Summary contains `Space permissions updated` / `Page restricted` / `Restrictions updated` | `medium` |
| Summary contains `User added to group` / `User removed from group` / `Group created` / `Group deleted` | `medium` |
| Summary contains `Space created` / `Space deleted` / `Global permissions updated` | `medium` |
| Category in `permissions` / `security` / `users and groups`, no other match | `medium` |
| Everything else | `info` |

Summary matching is case-insensitive (Atlassian sometimes prefixes the summary with locale-specific qualifiers).

## Troubleshooting

**`HTTP 401`** — bad email/token pair. Recreate the token; tokens are pinned to the account that issued them, so a token from a deleted user will fail this way.

**`audit_available: false`** in the test connection response — auth works but the user is not a site admin. Switch to a site-admin account or grant the existing user site-admin rights.

**Events with `creationDate` far in the past** — Confluence audit retention is 6 months on Standard / 12 months on Premium. The `since_seconds` window is enforced server-side via `startDate`, so this should never overshoot the retention window; if it does, the API returns an empty page and the connector terminates cleanly.

## What this connector does **not** cover

- **Page content diffs** — only audit metadata (who, what, when) is pulled, not the per-revision content.
- **Jira audit log** — separate connector planned for a future wave. Jira has its own audit endpoint at `/rest/api/3/auditing/record`.

## Related

- [GitHub Audit + Code Scanning](/docs/connectors/github) — sibling audit surface for source-control supply-chain events.
