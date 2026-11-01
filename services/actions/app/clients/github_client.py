"""GitHub client for code-platform containment and secret-scanning reads.

Depth 5.5 names GitHub member, deploy-key and workflow containment, and
wave-2 Phase 6.1 adds two more: revoking a leaked token through the
platform's credential-revocation API, and a read verb for the
secret-scanning alerts on the repositories a compromised token could reach.
Nothing in the tree could reach GitHub to act; the GitHub connector reads
audit events and stops there.

API references, each fetched before this module was written:

* remove an organization member — https://docs.github.com/en/rest/orgs/members#remove-an-organization-member
* set organization membership — https://docs.github.com/en/rest/orgs/members#set-organization-membership-for-a-user
* delete a deploy key — https://docs.github.com/en/rest/deploy-keys/deploy-keys#delete-a-deploy-key
* disable a workflow — https://docs.github.com/en/rest/actions/workflows#disable-a-workflow
* enable a workflow — https://docs.github.com/en/rest/actions/workflows#enable-a-workflow
* get a workflow — https://docs.github.com/en/rest/actions/workflows#get-a-workflow
* revoke a list of credentials — https://docs.github.com/en/rest/credentials/revoke
* secret scanning — https://docs.github.com/en/rest/secret-scanning/secret-scanning

The credential-revocation endpoint is the odd one, in two ways that both
change how it has to be called
------------------------------------------------------------------------
It is **unauthenticated by design** — the documentation states that any
authenticated request returns 403, because the endpoint exists for
reporting a credential you *found* rather than one you own. So this client
must strip its own Authorization header for that one call, and a wrapper
that adds auth uniformly would break it in a way that reads as a
permissions problem.

And it is **irreversible**: "GitHub cannot reactivate any credentials that
have been revoked". The contract for that verb therefore declares
``Reversal.NONE`` and a human approval floor, rather than claiming a
rollback that does not exist.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_API = "https://api.github.com"
_ACCEPT = "application/vnd.github+json"
#: Pinned so a future default-version bump on GitHub's side cannot change
#: a response shape under a containment action without a commit here.
_API_VERSION = "2022-11-28"

#: The endpoint's own documented ceiling. Exceeding it is a 422, so the
#: client refuses locally with a message that names the limit rather than
#: forwarding a batch it knows will be rejected.
MAX_CREDENTIALS_PER_REVOKE = 1000


class GitHubAPIError(RuntimeError):
    """GitHub answered and declined."""


class GitHubClient:
    """Async client over the GitHub REST API."""

    def __init__(self, token: str, *, base_url: str | None = None, timeout: float = 30.0) -> None:
        self._token = token
        self._base = (base_url or _API).rstrip("/")
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": _ACCEPT,
            "X-GitHub-Api-Version": _API_VERSION,
        }

    async def _request(self, method: str, path: str, *, json_body: dict | None = None, params: dict | None = None) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(method, f"{self._base}{path}", headers=self._headers(), json=json_body, params=params)
        if response.status_code >= 400:
            raise GitHubAPIError(f"GitHub {method} {path} failed with HTTP {response.status_code}: {_message(response)}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    # ------------------------------------------------------------------
    # Organisation membership
    # ------------------------------------------------------------------

    async def remove_org_member(self, org: str, username: str) -> dict[str, Any]:
        """Remove a user from the organisation and all its teams.

        Reversible through ``set_org_membership``, which re-invites them.
        The re-invite is not silent — the user has to accept it — so the
        rollback restores access rather than restoring the session, and the
        contract says so.
        """
        await self._request("DELETE", f"/orgs/{org}/members/{username}")
        logger.info("github.remove_org_member.success", org=org, username=username)
        return {"org": org, "username": username, "removed": True}

    async def set_org_membership(self, org: str, username: str, *, role: str = "member") -> dict[str, Any]:
        """Re-invite a user to the organisation. The rollback for removal."""
        if role not in ("member", "admin"):
            raise ValueError(f"role must be member or admin, got {role!r}")
        body = await self._request("PUT", f"/orgs/{org}/memberships/{username}", json_body={"role": role})
        return {"org": org, "username": username, "role": role, "state": body.get("state")}

    async def get_org_membership(self, org: str, username: str) -> dict[str, Any] | None:
        """The read the membership probe uses. ``None`` when not a member."""
        try:
            body = await self._request("GET", f"/orgs/{org}/memberships/{username}")
        except GitHubAPIError as exc:
            if "404" in str(exc):
                return None
            raise
        return {"org": org, "username": username, "state": body.get("state"), "role": body.get("role")}

    # ------------------------------------------------------------------
    # Deploy keys
    # ------------------------------------------------------------------

    async def delete_deploy_key(self, owner: str, repo: str, key_id: int | str) -> dict[str, Any]:
        """Delete a repository deploy key.

        Not reversible by the platform: GitHub stores only the public key
        and re-adding it needs the key material, which AiSOC never holds.
        An operator re-adds it from their own copy, which is a decision
        they should be making anyway.
        """
        await self._request("DELETE", f"/repos/{owner}/{repo}/keys/{key_id}")
        logger.info("github.delete_deploy_key.success", owner=owner, repo=repo, key_id=key_id)
        return {"owner": owner, "repo": repo, "key_id": str(key_id), "deleted": True}

    async def get_deploy_key(self, owner: str, repo: str, key_id: int | str) -> dict[str, Any] | None:
        """The read the deploy-key probe uses. ``None`` once deleted."""
        try:
            body = await self._request("GET", f"/repos/{owner}/{repo}/keys/{key_id}")
        except GitHubAPIError as exc:
            if "404" in str(exc):
                return None
            raise
        return {"id": body.get("id"), "title": body.get("title"), "read_only": body.get("read_only")}

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    async def set_workflow_enabled(self, owner: str, repo: str, workflow: str, *, enabled: bool) -> dict[str, Any]:
        """``PUT .../enable`` or ``.../disable`` on one workflow.

        ``workflow`` is the numeric id or the file name (``ci.yml``), which
        is what GitHub accepts and what an analyst reading an alert has.
        """
        verb = "enable" if enabled else "disable"
        await self._request("PUT", f"/repos/{owner}/{repo}/actions/workflows/{workflow}/{verb}")
        logger.info("github.workflow.updated", owner=owner, repo=repo, workflow=workflow, enabled=enabled)
        return {"owner": owner, "repo": repo, "workflow": workflow, "enabled": enabled}

    async def get_workflow(self, owner: str, repo: str, workflow: str) -> dict[str, Any]:
        """The read the workflow probe uses. ``state`` is the field that moves."""
        body = await self._request("GET", f"/repos/{owner}/{repo}/actions/workflows/{workflow}")
        return {"id": body.get("id"), "name": body.get("name"), "path": body.get("path"), "state": body.get("state")}

    # ------------------------------------------------------------------
    # Credential revocation
    # ------------------------------------------------------------------

    async def revoke_credentials(self, credentials: list[str]) -> dict[str, Any]:
        """``POST /credentials/revoke`` for tokens found exposed.

        Sends **no** Authorization header: the documentation states that an
        authenticated request to this endpoint returns 403. That is the
        single most load-bearing line in this module — adding auth here the
        way every other call does it produces a 403 that reads as a missing
        scope, and the leaked token stays live while an operator goes
        looking for a permissions problem that is not there.

        The response is 202 with no useful body; GitHub notifies the
        credential's owner. There is no read-back, so this verb records a
        verification gap rather than claiming a probe.
        """
        if not credentials:
            raise ValueError("no credentials supplied; refusing to call the revocation endpoint with an empty list")
        if len(credentials) > MAX_CREDENTIALS_PER_REVOKE:
            raise ValueError(f"{len(credentials)} credentials exceeds GitHub's documented ceiling of {MAX_CREDENTIALS_PER_REVOKE} per request")
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base}/credentials/revoke",
                headers={"Accept": _ACCEPT, "X-GitHub-Api-Version": _API_VERSION},
                json={"credentials": credentials},
            )
        if response.status_code >= 400:
            raise GitHubAPIError(f"GitHub credential revocation failed with HTTP {response.status_code}: {_message(response)}")
        logger.info("github.revoke_credentials.accepted", count=len(credentials), status=response.status_code)
        return {
            "submitted": len(credentials),
            "http_status": response.status_code,
            "accepted": response.status_code == 202,
        }

    # ------------------------------------------------------------------
    # Secret scanning (read)
    # ------------------------------------------------------------------

    async def list_secret_scanning_alerts(
        self,
        *,
        org: str | None = None,
        owner: str | None = None,
        repo: str | None = None,
        state: str = "open",
        per_page: int = 50,
    ) -> list[dict[str, Any]]:
        """Open secret-scanning alerts for an organisation or one repository.

        The read wave-2 Phase 6.1 asks for alongside token revocation: once
        a token is known compromised, the question is what *else* is
        exposed on the repositories it could reach, and that answer is one
        call away and was previously unreachable from an investigation.

        Secret values are never returned by this API and are not stored by
        this client. ``secret_type`` and the location are what an analyst
        needs; the secret itself is the thing you are trying not to spread.
        """
        if state not in ("open", "resolved"):
            raise ValueError(f"state must be open or resolved, got {state!r}")
        if org:
            path = f"/orgs/{org}/secret-scanning/alerts"
        elif owner and repo:
            path = f"/repos/{owner}/{repo}/secret-scanning/alerts"
        else:
            raise ValueError("supply either org= or both owner= and repo=")
        rows = await self._request("GET", path, params={"state": state, "per_page": min(per_page, 100)})
        if not isinstance(rows, list):
            return []
        return [
            {
                "number": row.get("number"),
                "state": row.get("state"),
                "secret_type": row.get("secret_type"),
                "secret_type_display_name": row.get("secret_type_display_name"),
                "created_at": row.get("created_at"),
                "html_url": row.get("html_url"),
                "repository": (row.get("repository") or {}).get("full_name"),
                "push_protection_bypassed": row.get("push_protection_bypassed"),
            }
            for row in rows
        ]


def _message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        return str(body.get("message") or body)[:300]
    return str(body)[:300]
