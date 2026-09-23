"""
HTTP clients for the AiSOC backend services.

The Slack bot is a thin adapter — it never touches Postgres or Redis directly.
Every Slack interaction is translated into one or more HTTP calls against
``services/api`` (cases, investigations) and ``services/actions`` (response
actions, approval flows).

We expose two narrow clients:

* :class:`AisocApiClient` — proxies ``/api/v1/cases/*`` endpoints used by the
  ``/aisoc list``, ``/aisoc investigate`` and ``/aisoc explain`` commands.
* :class:`AisocActionsClient` — submits and approves response actions used by
  ``/aisoc isolate`` and ``/aisoc block``.

Both clients:

* Authenticate as a service principal using an ``aisoc_*`` API key (see
  ``services/api/app/api/v1/deps.py``).
* Set ``X-Tenant-Id`` so the API can scope queries even when the token's own
  tenant is wildcarded.
* Surface failures as :class:`AisocClientError` so command handlers can render
  a friendly Slack message instead of leaking a traceback.

The HTTP transport (``httpx.AsyncClient``) is injectable so unit tests can swap
in ``respx`` mocks without monkey-patching the module-level client.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.core.config import SlackBotSettings, get_settings

log = structlog.get_logger(__name__)


class AisocClientError(RuntimeError):
    """
    Raised when an AiSOC backend call fails for any reason — non-2xx, network
    error, or malformed JSON. ``status_code`` is ``None`` for transport errors.

    Command handlers should catch this and render a short Block Kit error
    message; never re-raise it inside a Bolt handler because Slack times out
    interactive responses at 3 seconds.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _service_headers(token: str, tenant_id: str) -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": "application/json",
        "X-Tenant-Id": tenant_id,
    }
    if token:
        # The API resolves ``aisoc_*`` keys via the api_keys table and assigns
        # the service principal's permissions. An empty token is allowed only
        # in tests where the dependency override bypasses auth entirely.
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _raise_for_response(response: httpx.Response, *, context: str) -> None:
    """
    Convert an HTTP error response into :class:`AisocClientError` with a
    human-readable message. Truncates the upstream body so we never leak a
    stack trace into Slack.
    """
    if response.is_success:
        return
    body = response.text or ""
    snippet = body.strip().splitlines()[0] if body.strip() else response.reason_phrase
    log.warning(
        "aisoc_client.upstream_error",
        context=context,
        status_code=response.status_code,
        body=body[:500],
    )
    raise AisocClientError(
        f"{context} failed ({response.status_code}): {snippet[:160]}",
        status_code=response.status_code,
    )


class _BaseClient:
    """Shared transport plumbing — base URL, headers, ``httpx.AsyncClient``."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        tenant_id: str,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._tenant_id = tenant_id
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=_service_headers(token, tenant_id),
            timeout=timeout_seconds,
            transport=transport,
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> _BaseClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        context: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        try:
            response = await self._client.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            log.warning(
                "aisoc_client.transport_error",
                context=context,
                error=str(exc),
                base_url=self._base_url,
            )
            raise AisocClientError(f"{context} failed: {exc.__class__.__name__}", status_code=None) from exc
        await _raise_for_response(response, context=context)
        return response


# ────────────────────────────────────────────────────────────────────────────
# services/api client
# ────────────────────────────────────────────────────────────────────────────


class AisocApiClient(_BaseClient):
    """
    Narrow client for the ``services/api`` endpoints the Slack bot needs.

    Only exposes the verbs we actually use; every other endpoint stays out of
    the Slack surface for blast-radius reasons. Adding a new command means
    explicitly adding a new method here.
    """

    @classmethod
    def from_settings(
        cls,
        settings: SlackBotSettings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> AisocApiClient:
        s = settings or get_settings()
        return cls(
            base_url=s.AISOC_API_BASE_URL,
            token=s.AISOC_API_SERVICE_TOKEN,
            tenant_id=s.AISOC_DEFAULT_TENANT_ID,
            timeout_seconds=s.AISOC_HTTP_TIMEOUT_SECONDS,
            transport=transport,
        )

    async def list_open_cases(
        self,
        *,
        limit: int = 10,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return the most recently created cases that are not yet ``closed``.

        services/api supports filtering by ``status``/``severity`` separately.
        Slack callers want "active work" by default so we fetch the latest
        ``limit`` rows and filter terminal states client-side; this keeps a
        single round-trip and stays correct if new transitional statuses are
        added to the API later.
        """
        params: dict[str, Any] = {"limit": max(1, min(limit * 3, 200))}
        if severity:
            params["severity"] = severity

        response = await self._request("GET", "/api/v1/cases", context="list cases", params=params)
        try:
            rows = response.json()
        except ValueError as exc:
            raise AisocClientError("list cases failed: invalid JSON") from exc
        if not isinstance(rows, list):
            raise AisocClientError("list cases failed: unexpected response shape")
        active = [r for r in rows if isinstance(r, dict) and r.get("status") != "closed"]
        return active[:limit]

    async def get_case(self, case_id: str) -> dict[str, Any]:
        """
        Fetch a single case by id or case-number.

        services/api accepts both forms on this route — we URL-encode the
        identifier so a stray ``/`` in user input cannot escape the path.
        """
        safe_id = quote(case_id, safe="")
        response = await self._request("GET", f"/api/v1/cases/{safe_id}", context="get case")
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("get case failed: invalid JSON") from exc

    async def launch_investigation(
        self,
        case_id: str,
        *,
        alert_summary: str = "",
    ) -> dict[str, Any]:
        """
        Kick off a new investigation run for a case.

        services/api proxies to the agents service; the response carries the
        ``run_id`` we link back into Slack so the analyst can follow it in the
        web console.
        """
        safe_id = quote(case_id, safe="")
        response = await self._request(
            "POST",
            f"/api/v1/cases/{safe_id}/investigate",
            context="launch investigation",
            json={"alert_summary": alert_summary},
        )
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("launch investigation failed: invalid JSON") from exc

    async def get_case_summary(self, case_id: str) -> dict[str, Any]:
        """
        Fetch the structured per-case auto-summary used by ``/aisoc explain``.
        """
        safe_id = quote(case_id, safe="")
        response = await self._request(
            "GET",
            f"/api/v1/cases/{safe_id}/summary",
            context="case summary",
            params={"format": "json"},
        )
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("case summary failed: invalid JSON") from exc


# ────────────────────────────────────────────────────────────────────────────
# services/actions client
# ────────────────────────────────────────────────────────────────────────────


class AisocActionsClient(_BaseClient):
    """
    Narrow client for the ``services/actions`` endpoints.

    Only the ``isolate`` and ``block`` commands hit this client today. Both
    actions are in :data:`APPROVAL_REQUIRED_ACTIONS`, so ``submit_action``
    will return ``status="awaiting_approval"`` and the bot must then post a
    Block Kit approval card. The action_id from the response feeds the
    approve/reject buttons.
    """

    @classmethod
    def from_settings(
        cls,
        settings: SlackBotSettings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> AisocActionsClient:
        s = settings or get_settings()
        # The actions service is happy to fall back to the API service token
        # when a dedicated actions key isn't provisioned (single-secret rollout).
        token = s.AISOC_ACTIONS_SERVICE_TOKEN or s.AISOC_API_SERVICE_TOKEN
        return cls(
            base_url=s.AISOC_ACTIONS_BASE_URL,
            token=token,
            tenant_id=s.AISOC_DEFAULT_TENANT_ID,
            timeout_seconds=s.AISOC_HTTP_TIMEOUT_SECONDS,
            transport=transport,
        )

    async def submit_action(
        self,
        *,
        action_type: str,
        target: str,
        case_id: str,
        rationale: str,
        requested_by: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Submit a response action. For approval-required actions the response
        contains ``status="awaiting_approval"`` and ``id`` (action_id); the bot
        is then responsible for surfacing an approval card to a human.
        """
        payload: dict[str, Any] = {
            "incident_id": case_id,
            "tenant_id": self._tenant_id,
            "action_type": action_type,
            "target": target,
            "rationale": rationale,
            "requested_by": requested_by,
            "parameters": parameters or {},
        }
        response = await self._request("POST", "/api/v1/actions", context="submit action", json=payload)
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("submit action failed: invalid JSON") from exc

    @staticmethod
    def chatops_approver(platform: str, platform_user_id: str | None) -> dict[str, Any] | None:
        """Build the body carrying an identity the platform itself verified.

        Slack signs every interaction payload and Teams payloads are
        HMAC-signed, so the user id on a button click is attested rather than
        claimed. It is sent as identity only — the actions service maps it to
        permissions — because this bot has no idea what a given Slack user may
        do in AiSOC, and a bot permitted to assert its own permissions could
        grant itself anything.

        The platform is a parameter rather than a constant because the Teams
        bot imports this client when it is on the image, and stamping "slack"
        onto a Teams user would resolve against the wrong half of the approver
        map.

        Until this was wired, approve/reject sent no body at all, so the
        actions service authorized nobody: the permission tier and separation
        of duties were both skipped, and the human survived only in a log line.
        """
        if not platform_user_id:
            return None
        return {
            "chatops_approver": {
                "platform": platform,
                "platform_user_id": platform_user_id,
            }
        }

    async def approve_action(
        self,
        action_id: str,
        *,
        approver: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Approve a pending action (called from the approve button).

        ``approver`` is the payload from :meth:`chatops_approver`. Omitting it
        makes the actions service refuse by default — which is why the
        approval-timeout scheduler only ever rejects.
        """
        safe_id = quote(action_id, safe="")
        response = await self._request(
            "POST",
            f"/api/v1/actions/{safe_id}/approve",
            context="approve action",
            json=approver,
        )
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("approve action failed: invalid JSON") from exc

    async def reject_action(
        self,
        action_id: str,
        *,
        approver: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Reject a pending action (called from the deny button).

        Identity is recorded when supplied but not required: a rejection
        causes no vendor effect, and a timeout-driven rejection has no human.
        """
        safe_id = quote(action_id, safe="")
        response = await self._request(
            "POST",
            f"/api/v1/actions/{safe_id}/reject",
            context="reject action",
            json=approver,
        )
        try:
            return response.json()
        except ValueError as exc:
            raise AisocClientError("reject action failed: invalid JSON") from exc
