"""Containment for the AI estate: provider keys, memberships and gateways.

Wave-2 Phase 7.5 (depth 6.6). The AI inventory knows which coding agents,
MCP servers, IDE extensions and provider keys exist and scores each one's
exposure. Nothing could act on any of it, so a provider key found in a
public repository was a finding with a recommendation and no verb.

API references, each fetched before this module was written:

* OpenAI API reference — https://platform.openai.com/docs/api-reference
* OpenAI OpenAPI specification — https://github.com/openai/openai-openapi
* Anthropic update API key — https://docs.claude.com/en/api/admin-api/apikeys/update-api-key
* Anthropic update user — https://docs.claude.com/en/api/admin-api/users/update-user
* Anthropic remove user — https://docs.claude.com/en/api/admin-api/users/remove-user
* Anthropic remove workspace member — https://docs.claude.com/en/api/admin-api/workspace_members/delete-workspace-member
* LiteLLM virtual keys — https://docs.litellm.ai/docs/proxy/virtual_keys

(OpenAI's deep documentation anchors answer 403 to any non-browser request,
so the two URLs above are the pages that do resolve. The endpoint shapes
were read from the published OpenAPI specification.)

The three providers differ in exactly the way the contract cares about
---------------------------------------------------------------------
**OpenAI deletes a project API key.** There is no undelete, so that arm
carries no rollback and says so.

**Anthropic deactivates one.** ``status: "inactive"`` is a field, and
setting it back to ``active`` restores the same key — so that arm has a
real platform rollback, and it is the reason ``restore_token`` exists as a
verb at all.

**A gateway blocks one.** Blocking and unblocking are a pair, and a spend
cap is a number that can be put back, so both are reversible.

Three different answers to "can this be undone" for what looks like one
verb is exactly why the contract belongs to the capability and the
reversibility to the arm's own declaration.

Spend caps, stated rather than implied
--------------------------------------
Only the gateway has one. Neither OpenAI's nor Anthropic's public admin
API exposes a per-key or per-project budget this platform could set, so
there is no ``set_spend_cap`` arm for either, and the absence is recorded
here rather than left as a verb that quietly does nothing.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_OPENAI_BASE = "https://api.openai.com/v1/organization"
_ANTHROPIC_BASE = "https://api.anthropic.com/v1/organizations"
#: Pinned, because Anthropic's admin API requires the version header and a
#: default that moves could change a response shape under a containment.
_ANTHROPIC_VERSION = "2023-06-01"


class AIProviderError(RuntimeError):
    """The provider answered and declined."""


async def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 30.0,
    label: str,
) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(method, url, headers=headers, json=json_body, params=params)
    if response.status_code >= 400:
        raise AIProviderError(f"{label} failed with HTTP {response.status_code}: {_message(response)}")
    if not response.content:
        return {}
    try:
        body = response.json()
    except ValueError:
        return {"raw": response.text}
    return body if isinstance(body, dict) else {"result": body}


class OpenAIAdminClient:
    """Organisation administration: project keys and project membership."""

    def __init__(self, admin_key: str, *, base_url: str | None = None, timeout: float = 30.0) -> None:
        self._key = admin_key
        self._base = (base_url or _OPENAI_BASE).rstrip("/")
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}

    async def delete_project_api_key(self, *, project_id: str, key_id: str) -> dict[str, Any]:
        """Delete one project API key.

        Irreversible: OpenAI returns no undelete and a replacement key is a
        different credential. The contract declares no rollback rather than
        naming one that would hand back something else and call it a
        restore.
        """
        body = await _request(
            "DELETE",
            f"{self._base}/projects/{project_id}/api_keys/{key_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="OpenAI delete project api key",
        )
        logger.info("openai.api_key.deleted", project_id=project_id, key_id=key_id)
        return {"project_id": project_id, "key_id": key_id, "deleted": bool(body.get("deleted", True))}

    async def set_project_user_role(self, *, project_id: str, user_id: str, role: str) -> dict[str, Any]:
        """Move a project member between ``owner`` and ``member``.

        The containment for a compromised account that holds project
        ownership: demotion stops them minting keys and leaves their work
        intact, which is a far narrower action than removal.
        """
        if role not in ("owner", "member"):
            raise ValueError(f"role must be owner or member, got {role!r}")
        body = await _request(
            "POST",
            f"{self._base}/projects/{project_id}/users/{user_id}",
            headers=self._headers(),
            json_body={"role": role},
            timeout=self._timeout,
            label="OpenAI set project user role",
        )
        return {"project_id": project_id, "user_id": user_id, "role": body.get("role", role)}

    async def remove_project_user(self, *, project_id: str, user_id: str) -> dict[str, Any]:
        body = await _request(
            "DELETE",
            f"{self._base}/projects/{project_id}/users/{user_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="OpenAI remove project user",
        )
        logger.info("openai.project_user.removed", project_id=project_id, user_id=user_id)
        return {"project_id": project_id, "user_id": user_id, "removed": bool(body.get("deleted", True))}

    async def get_project_user(self, *, project_id: str, user_id: str) -> dict[str, Any]:
        """The read behind the demotion and removal probes."""
        body = await _request(
            "GET",
            f"{self._base}/projects/{project_id}/users/{user_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="OpenAI get project user",
        )
        return {"id": body.get("id"), "email": body.get("email"), "role": body.get("role"), "added_at": body.get("added_at")}


class AnthropicAdminClient:
    """Organisation administration: API keys, users and workspace members."""

    def __init__(self, admin_key: str, *, base_url: str | None = None, timeout: float = 30.0) -> None:
        self._key = admin_key
        self._base = (base_url or _ANTHROPIC_BASE).rstrip("/")
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }

    async def set_api_key_status(self, *, api_key_id: str, status: str) -> dict[str, Any]:
        """``active`` or ``inactive``.

        One method for both directions so the containment and its rollback
        cannot drift into different request shapes — the defect that makes
        a rollback target a field the containment never set.
        """
        if status not in ("active", "inactive"):
            raise ValueError(f"status must be active or inactive, got {status!r}")
        body = await _request(
            "POST",
            f"{self._base}/api_keys/{api_key_id}",
            headers=self._headers(),
            json_body={"status": status},
            timeout=self._timeout,
            label="Anthropic update api key",
        )
        logger.info("anthropic.api_key.status", api_key_id=api_key_id, status=status)
        return {"api_key_id": api_key_id, "status": body.get("status", status), "name": body.get("name")}

    async def get_api_key(self, *, api_key_id: str) -> dict[str, Any]:
        body = await _request(
            "GET",
            f"{self._base}/api_keys/{api_key_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="Anthropic get api key",
        )
        return {"id": body.get("id"), "name": body.get("name"), "status": body.get("status"), "workspace_id": body.get("workspace_id")}

    async def set_user_role(self, *, user_id: str, role: str) -> dict[str, Any]:
        """Demote or promote an organisation member."""
        if role not in ("user", "developer", "billing", "admin"):
            raise ValueError(f"role must be one of user, developer, billing, admin; got {role!r}")
        body = await _request(
            "POST",
            f"{self._base}/users/{user_id}",
            headers=self._headers(),
            json_body={"role": role},
            timeout=self._timeout,
            label="Anthropic update user",
        )
        return {"user_id": user_id, "role": body.get("role", role), "email": body.get("email")}

    async def remove_workspace_member(self, *, workspace_id: str, user_id: str) -> dict[str, Any]:
        body = await _request(
            "DELETE",
            f"{self._base}/workspaces/{workspace_id}/members/{user_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="Anthropic remove workspace member",
        )
        logger.info("anthropic.workspace_member.removed", workspace_id=workspace_id, user_id=user_id)
        return {"workspace_id": workspace_id, "user_id": user_id, "removed": True, "type": body.get("type")}

    async def get_user(self, *, user_id: str) -> dict[str, Any]:
        body = await _request(
            "GET",
            f"{self._base}/users/{user_id}",
            headers=self._headers(),
            timeout=self._timeout,
            label="Anthropic get user",
        )
        return {"id": body.get("id"), "email": body.get("email"), "role": body.get("role"), "name": body.get("name")}


class AIGatewayClient:
    """A LiteLLM-compatible proxy: block a virtual key, or cap its spend.

    The gateway is where a self-hosted estate's AI traffic is actually
    governable, and it is the only one of the three surfaces here that
    offers a budget this platform can set. Blocking and unblocking are a
    documented pair, so both arms are reversible.
    """

    def __init__(self, base_url: str, master_key: str, *, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._key = master_key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}

    async def block_key(self, key: str) -> dict[str, Any]:
        body = await _request(
            "POST",
            f"{self._base}/key/block",
            headers=self._headers(),
            json_body={"key": key},
            timeout=self._timeout,
            label="AI gateway block key",
        )
        logger.info("ai_gateway.key.blocked")
        return {"blocked": True, "result": body}

    async def unblock_key(self, key: str) -> dict[str, Any]:
        body = await _request(
            "POST",
            f"{self._base}/key/unblock",
            headers=self._headers(),
            json_body={"key": key},
            timeout=self._timeout,
            label="AI gateway unblock key",
        )
        return {"blocked": False, "result": body}

    async def set_max_budget(self, key: str, *, max_budget: float) -> dict[str, Any]:
        """Cap a key's spend.

        A cap of ``0`` stops the key without deleting it, which is a
        softer containment than a block for a key that is merely spending
        anomalously rather than known compromised. Negative budgets are
        refused here rather than sent: the gateway's behaviour on one is
        undocumented, and an undocumented behaviour is not a control.
        """
        if max_budget < 0:
            raise ValueError("max_budget cannot be negative")
        body = await _request(
            "POST",
            f"{self._base}/key/update",
            headers=self._headers(),
            json_body={"key": key, "max_budget": max_budget},
            timeout=self._timeout,
            label="AI gateway set budget",
        )
        return {"max_budget": max_budget, "result": body}

    async def key_info(self, key: str) -> dict[str, Any]:
        """The read behind the block and budget probes."""
        body = await _request(
            "GET",
            f"{self._base}/key/info",
            headers=self._headers(),
            params={"key": key},
            timeout=self._timeout,
            label="AI gateway key info",
        )
        info = body.get("info") if isinstance(body.get("info"), dict) else body
        return {
            "blocked": bool(info.get("blocked", False)),
            "max_budget": info.get("max_budget"),
            "spend": info.get("spend"),
            "key_alias": info.get("key_alias"),
        }


def _message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error)[:300]
        return str(body.get("message") or body.get("detail") or body)[:300]
    return str(body)[:300]
