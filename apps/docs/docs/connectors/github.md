---
sidebar_position: 10
title: GitHub Audit + Code Scanning
description: Organization audit log and Code Scanning alerts from GitHub Enterprise / Cloud into AiSOC.
---

# GitHub Audit + Code Scanning

The GitHub connector pulls two streams from a single GitHub organization:

1. **Organization audit log** — every administrative action: member adds, repo creates, secret-scanning toggles, Actions secret changes, branch-protection edits, OAuth app installs.
2. **Code Scanning alerts** — open, dismissed, and fixed findings from CodeQL or any third-party SARIF uploader (e.g. Semgrep).

Events are normalized with `source: github`, `category: vcs`.

## Prerequisites

- A **GitHub organization** (Cloud or Enterprise Server). Personal-account repos have no audit log API.
- An **organization-scoped token**. Two options:
  - **Fine-grained personal access token (recommended)** with org access and the following permissions:
    - **Organization permissions → Members → Read-only**
    - **Organization permissions → Audit log → Read-only**
    - **Repository permissions → Code scanning alerts → Read-only**
  - **GitHub App** installed on the org with the same permissions, then use an installation token. This is the right path for production deployments.
- (Cloud) **Audit log streaming must be enabled** on the org, or use the standard `GET /orgs/{org}/audit-log` endpoint (available on Enterprise Cloud + GHE Server).

## Setup walkthrough

### 1. Create the token

**Fine-grained PAT path:**

1. **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. **Resource owner**: select the organization.
3. **Repository access**: All repositories (or a curated subset).
4. **Permissions**: as listed above.
5. **Expiration**: 90 days max recommended; rotate via the AiSOC connector edit screen.
6. Generate and copy the token (`github_pat_…`).

**GitHub App path** (preferred for prod):

1. **Org Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Permissions match the PAT path above.
3. Install the app on your org.
4. Generate an installation access token via the App's private key.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → GitHub**.
2. `organization` = your GitHub org login slug (e.g. `acme-corp`, not the full URL).
3. `token` = the fine-grained PAT or installation token (encrypted in the credential vault).
4. **Test connection** → calls `GET /orgs/{org}` to verify token + org access.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `GET /orgs/{org}/audit-log?phrase=created:>=<lastpoll>&per_page=100` — paginates audit events.
  - `GET /orgs/{org}/code-scanning/alerts?state=open&per_page=100` — pulls open Code Scanning findings (newly opened or reopened).
- **Rate limit awareness**: the connector reads `X-RateLimit-Remaining` and backs off if &lt;100 calls are left in the hour.
- Audit log events appear in the API typically within **&lt;5 minutes** of the action. Code Scanning alerts depend on the scanning schedule of the upstream workflow.

## Severity heuristics

| Event | Severity |
|---|---|
| `org.add_member` granting `admin` role | `high` |
| `org.disable_two_factor_requirement` | `high` |
| `repo.public_repository_disabled_visibility` (private → public) | `high` |
| `org.update_actions_secret` | `medium` |
| `repo.delete_protected_branch_rule` on `main` | `medium` |
| `oauth_application.create` on an unknown app | `medium` |
| Code Scanning alert with `severity: critical` and `tool: CodeQL` | `high` |
| Code Scanning alert with `severity: error` | `medium` |
| Routine `repo.access` reads | dropped |

## Troubleshooting

**`Bad credentials`** — token is invalid, revoked, or scoped to a different org. Tokens are organization-scoped on fine-grained PATs; pasting a token created for a different org silently fails with this error.

**`Resource not accessible by personal access token`** — token lacks the `Audit log: Read` permission. Recreate the token; you cannot patch permissions on an existing fine-grained PAT.

**Empty Code Scanning results** — the org may not have any repos with CodeQL or other SARIF uploaders enabled. Confirm via `GET /orgs/{org}/code-scanning/alerts?state=all` outside AiSOC.

**Rate-limit exhaustion** — fine-grained PATs share a 5,000-req/hour budget across all GitHub usage by that token. If you also use the same token in CI, expect contention. GitHub Apps get a higher per-installation limit and are recommended for production.

## What this connector does **not** cover

- **Push events / commit content**: this connector reads metadata only, not commit diffs. For commit-content scanning, use a separate ingestion path or rely on Code Scanning's own SARIF outputs.
- **Dependabot alerts**: separate API. Not currently included; will land as a follow-on connector.
- **Secret scanning alerts**: separate API requiring `secret_scanning_alerts: read`. Not currently included; same follow-on.

## Related

- [Microsoft 365 Audit](/docs/connectors/m365-audit) — for the OAuth-grant side of the same identity surface (third-party app installs that target Microsoft Graph).
- [Cloudflare Audit Logs](/docs/connectors/cloudflare) — for the edge-deploy side of changes that originated as a GitHub commit.
