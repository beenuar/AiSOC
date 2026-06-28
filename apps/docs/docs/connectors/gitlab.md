---
sidebar_position: 11
title: GitLab Audit + Vulnerability Findings
description: Group audit events and security vulnerability findings from GitLab SaaS or self-managed into AiSOC.
---

# GitLab Audit + Vulnerability Findings

The GitLab connector pulls two streams from a single GitLab group:

1. **Group audit events** — every group-level admin action: member adds, role changes, project create/delete, PAT issuance, protected-branch removal, two-factor toggles, Runner registration, security-dashboard toggles.
2. **Security vulnerability findings** — Container Scanning, SAST, DAST, Secret Detection, Dependency Scanning, and Coverage Fuzzing results across every project in the group (Ultimate-tier feature).

Events are normalized with `source: gitlab`, `category: vcs`.

## Prerequisites

- A **GitLab group** on either gitlab.com or a self-managed instance. Personal-account projects don't expose the group audit endpoint.
- A **Personal Access Token** with the `api` scope. The authenticating user must be an **Owner** of the group to read audit events.
- **Audit events availability**: on gitlab.com, available from Premium up. On self-managed installs, available from Premium up.
- **Vulnerability findings availability**: Ultimate-tier only. Without it the connector still pulls audit events and treats the security endpoint as a non-fatal 403.

## Setup walkthrough

### 1. Create the PAT

1. **GitLab → User Settings → Access Tokens**.
2. Token name: `aisoc-connector` (or similar — choose something that makes the audit trail obvious).
3. Expiration: 90 days max recommended; rotate via the AiSOC connector edit screen.
4. Scopes: `api` (covers audit + security endpoints in one).
5. Click **Create personal access token** and copy the value (`glpat-…`).

If you'd rather not bind the token to a human user, use a **group access token** instead — same scopes, same flow, scoped to the group itself.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → GitLab**.
2. `gitlab_url` — leave default (`https://gitlab.com`) for SaaS, or paste the URL operators use for your self-managed instance (no trailing slash, e.g. `https://gitlab.corp.test`).
3. `group` — the group slug or numeric ID. For nested groups (`parent/child`) use the full path; the connector URL-encodes it automatically.
4. `token` — the PAT from step 1.
5. **Test connection**. A success response confirms the group is reachable and tells you whether audit events are available on your tier.
6. **Save & enable**. The in-process scheduler polls every 5 minutes by default.

## What you'll see in the case workspace

- **High-severity audit events**: any of `User_add`, `User_remove`, `Personal_access_token_create`, `Group_access_token_create`, `Project_access_token_create`, `Ssh_key_add`, `Two_factor_authentication_disabled`, `Remove_protected_branch`, `Remove_protected_tag`, `Project_destroyed`, `Group_destroyed`, `Project_transfer`, `Security_dashboard_disabled`, `Container_scanning_disabled`, `Sast_disabled`, `Secret_detection_disabled`, `Ci_cd_settings_changed`, `Runner_registered`.
- **Medium severity**: catch-all for actions whose name contains `destroy`, `delete`, or `remove` but isn't on the high-risk list.
- **Vulnerability findings**: severity maps 1:1 from GitLab's native ladder (`critical/high/medium/low/info/unknown`). The `critical` tier is preserved end-to-end so P1 SAST/DAST findings keep their priority.

## Limitations

- **Project-scoped audit events** (`/projects/{id}/audit_events`) are not yet polled — only the group-level stream. Open an issue if you need this.
- **GraphQL endpoints** are not used. The REST `/security/vulnerability_findings` endpoint is reliable on Ultimate and is what the connector pulls.
- **OAuth flow** is advertised in the connector schema but is deferred to Workstream 2; today you paste a PAT.
- **Self-managed instances** behind a corporate proxy or a non-standard CA bundle need the proxy + CA injected via the platform-level `httpx` configuration; the connector does not yet expose per-instance proxy settings.

## Troubleshooting

| Symptom                                                                                            | Likely cause                                          |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `HTTP 401: 401 Unauthorized` on Test connection                                                    | Token expired, revoked, or missing the `api` scope.   |
| `HTTP 404: 404 Group Not Found`                                                                    | Group path is wrong, or the user can't see the group. |
| Test connection success but `audit_events_available: false`                                        | Free-tier group, or the user isn't an Owner.          |
| No findings in case workspace, but Ultimate confirmed                                              | Findings exist outside the lookback window.           |

## Code

- Connector class: [`services/connectors/app/connectors/gitlab.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/app/connectors/gitlab.py)
- Tests: [`services/connectors/tests/connectors/test_gitlab.py`](https://github.com/beenuar/AiSOC/blob/main/services/connectors/tests/connectors/test_gitlab.py)
