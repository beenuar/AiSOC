"""The API service's client for ``services/actions``.

``services/actions`` owns execution: the executor registry, the vendor
clients and the blast-radius gate all live there, and it is the only service
that can actually isolate a host. Everything else — the console, the
responder app, the email link, the agents worker — has to reach it over HTTP.

Until now exactly one endpoint did, with the base URL read inline from
``os.environ``, and the default it fell back to was wrong: ``aisoc-actions``
is the compose ``container_name``, while the DNS name on the network is the
service name, ``actions``. Nothing caught it because the only code path that
used the default was itself a fallback nobody exercised.

One client, one contract, one place to fix the next thing.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

#: Generous relative to an internal hop, because an approved action runs the
#: real vendor call inline: the actions service executes on approve rather
#: than queueing, so this timeout covers a CrowdStrike or Okta round trip.
_TIMEOUT_SECONDS = 30.0


class ActionsServiceError(RuntimeError):
    """The actions service refused or could not be reached.

    Carries the upstream status when there was one, so a caller can map a
    refusal (403, 409) differently from an outage (None, 502).

    ``upstream_detail`` is the only field safe to show a user. The exception
    message can include a transport error, which carries internal hostnames
    and occasionally a stack frame; the detail is the actions service's own
    operator-facing string, which it deliberately builds as an error *type*
    rather than a raw exception. Rendering the wrong one into an HTML page is
    how an unauthenticated email-approval link starts leaking topology.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        upstream_detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.upstream_detail = upstream_detail or "The action service refused the decision."


def base_url() -> str:
    return settings.AISOC_ACTIONS_BASE_URL.rstrip("/")


def service_headers() -> dict[str, str]:
    """Headers for a service-to-service call to the actions service.

    The bearer token is added here and only here, so it cannot leak into a
    browser-facing response: routes that proxy on a user's behalf call this
    rather than forwarding whatever the client sent.
    """
    headers = {"Accept": "application/json"}
    token = settings.AISOC_ACTIONS_SERVICE_TOKEN.strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _post(path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    url = f"{base_url()}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(url, headers=service_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise ActionsServiceError(f"actions service unreachable: {exc}") from exc

    if response.status_code >= 400:
        detail = _detail(response)
        raise ActionsServiceError(detail, status_code=response.status_code, upstream_detail=detail)

    try:
        body = response.json()
    except ValueError as exc:
        raise ActionsServiceError("actions service returned a non-JSON body") from exc
    if not isinstance(body, dict):
        raise ActionsServiceError("actions service returned an unexpected body shape")
    return body


async def _get(path: str) -> Any:
    url = f"{base_url()}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=service_headers())
    except httpx.HTTPError as exc:
        raise ActionsServiceError(f"actions service unreachable: {exc}") from exc
    if response.status_code >= 400:
        detail = _detail(response)
        raise ActionsServiceError(detail, status_code=response.status_code, upstream_detail=detail)
    try:
        return response.json()
    except ValueError as exc:
        raise ActionsServiceError("actions service returned a non-JSON body") from exc


#: Capability verbs are short identifiers from a closed vocabulary. This one
#: is interpolated into an upstream path that carries the service token, so
#: it is checked here rather than trusted — the same guard the browser-facing
#: proxy applies, for the same reason.
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")


async def vendors_for_capability(capability: str) -> list[str]:
    """Vendor ids with a registered executor for ``capability``.

    Asked of the actions service rather than mirrored here. A second copy of
    the registry in this process would be a list that goes stale the first
    time somebody ships a vendor, and the failure would look like "this
    tenant has no integration" rather than "the list is old".
    """
    if not _IDENTIFIER.match(capability):
        raise ActionsServiceError(f"{capability!r} is not a capability identifier")
    body = await _get(f"/api/v1/live-actions/by-capability/{capability}")
    if not isinstance(body, list):
        raise ActionsServiceError("actions service returned an unexpected body shape")
    return [str(v) for v in body]


def _detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"actions service returned {response.status_code}"
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str) and detail.strip():
            return detail
    return f"actions service returned {response.status_code}"


async def submit_action(
    *,
    action_id: str,
    action_type: str,
    target: str,
    tenant_id: str,
    incident_id: str,
    rationale: str,
    parameters: dict[str, Any] | None = None,
    principal: dict[str, Any] | None = None,
    requested_by: str = "aisoc-api",
) -> dict[str, Any]:
    """Submit an action. The gate decides whether it executes or waits."""
    payload: dict[str, Any] = {
        "id": action_id,
        "action_type": action_type,
        "target": target,
        "tenant_id": tenant_id,
        "incident_id": incident_id,
        "rationale": rationale,
        "requested_by": requested_by,
        "parameters": parameters or {},
    }
    if principal is not None:
        payload["principal"] = principal
    return await _post("/api/v1/actions", payload)


async def decide_action(
    *,
    action_id: str,
    approve: bool,
    approver: dict[str, Any] | None = None,
    chatops_approver: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Approve or reject a pending action, carrying the deciding identity.

    An approval with no resolvable identity is refused upstream by default,
    because separation of duties cannot be evaluated against nobody.
    """
    verb = "approve" if approve else "reject"
    body: dict[str, Any] = {}
    if approver is not None:
        body["approver"] = approver
    if chatops_approver is not None:
        body["chatops_approver"] = chatops_approver
    return await _post(f"/api/v1/actions/{action_id}/{verb}", body or None)


async def dispatch_live_action(
    *,
    capability: str,
    vendor_id: str,
    target: str,
    tenant_id: str,
    params: dict[str, Any] | None = None,
    auth_config: dict[str, Any] | None = None,
    dry_run: bool = True,
    requested_by: str = "aisoc-api",
    case_id: str | None = None,
    confidence: float | None = None,
    playbook_run_id: str | None = None,
    playbook_step_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch a ``(vendor_id, capability)`` pair to the live-action registry.

    ``dry_run`` defaults to True. Every caller that wants a vendor touched has
    to say so, which is the opposite of the usual default and deliberate: the
    live-action layer is the one place in the platform that changes somebody
    else's estate, and a forgotten keyword argument should cost a preview
    rather than an unintended containment.

    ``auth_config`` carries decrypted connector credentials in *connector
    schema* field names; the actions service translates them into the
    executor's vendor-prefixed parameters at the dispatch boundary. They are
    passed per call and never persisted here.

    ``confidence`` is how good the reason for acting is, and it is a real
    input: the approval matrix grades impact against it, and omitting it is
    the lowest band rather than no opinion.
    """
    payload: dict[str, Any] = {
        "capability": capability,
        "vendor_id": vendor_id,
        "target": target,
        "tenant_id": tenant_id,
        "params": params or {},
        "dry_run": dry_run,
        "requested_by": requested_by,
    }
    if auth_config:
        payload["auth_config"] = auth_config
    if case_id:
        payload["case_id"] = case_id
    if confidence is not None:
        payload["confidence"] = confidence
    if playbook_run_id:
        payload["playbook_run_id"] = playbook_run_id
    if playbook_step_id:
        payload["playbook_step_id"] = playbook_step_id
    # `/dry-run` forces dry_run server-side regardless of the body, so a
    # preview cannot become a live call through a serialisation mistake.
    path = "/api/v1/live-actions/dispatch" if not dry_run else "/api/v1/live-actions/dry-run"
    return await _post(path, payload)
