"""Browser-facing proxy for the live-action registry in ``services/actions``.

The action registry — which vendor can isolate which host, what each verb
costs in blast radius, what a dry run would do — is the answer to "what can
AiSOC actually do to my estate right now". It lived behind
``Depends(require_service_auth)`` on the actions service, reachable only by
another service holding the shared token. A repository-wide search for
``live-actions`` outside that service returned nothing: no console page, no
API route, no agent tool. The registry was complete and unreachable.

This proxy is the browser's way in, and it differs from the upstream in three
deliberate ways:

**It authenticates a person, not a service.** Every route requires a session
and a permission. The service token is added by this process on the way out,
so it never reaches a browser.

**It is read-mostly.** Discovery and dry-run are proxied; live dispatch is
not. A live containment must go through the approval path, which records who
authorised it — exposing ``/dispatch`` here would be a way to execute the
most disruptive actions in the product with no approver bound, which is the
exact hole the ChatOps work closed.

**Tenant comes from the session.** A dry-run request carries a tenant, and
accepting the client's copy of it would let any authenticated user preview
actions against another tenant's assets.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.v1.deps import AuthUser, require_permission
from app.services.actions_client import base_url, service_headers

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/live-actions", tags=["actions"])

_TIMEOUT_SECONDS = 20.0

#: Capability verbs and vendor ids are short identifiers from a closed
#: vocabulary. Interpolating one into the upstream path unchecked lets the
#: caller steer the request somewhere else entirely — `../../admin` is a
#: perfectly good "capability" as far as string formatting is concerned, and
#: the service token this proxy attaches would go with it.
#:
#: Refused at the edge rather than percent-encoded. Encoding would turn a
#: hostile value into a harmless upstream 404 while still forwarding it;
#: rejecting says what happened and keeps the request inside this process.
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _safe_segment(value: str, *, field: str) -> str:
    if not _IDENTIFIER.match(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be a short identifier of letters, digits, dot, dash or underscore.",
        )
    return value


async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    url = f"{base_url()}/api/v1/live-actions{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=service_headers(), params=params)
    except httpx.HTTPError as exc:
        logger.warning("live_actions.unreachable", path=path, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The action service is unreachable. It runs in the `full` and `chatops` compose profiles.",
        ) from exc
    return _unwrap(response, path)


def _unwrap(response: httpx.Response, path: str) -> Any:
    if response.status_code >= 400:
        logger.warning("live_actions.upstream_error", path=path, status=response.status_code)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"The action service returned {response.status_code}.",
        )
    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The action service returned a non-JSON body.",
        ) from exc


@router.get("", summary="List every registered live action")
async def discover(
    user: Annotated[AuthUser, Depends(require_permission("actions:read"))],
    vendor_id: str | None = Query(default=None),
    capability: str | None = Query(default=None),
) -> Any:
    params: dict[str, Any] = {}
    if vendor_id:
        params["vendor_id"] = _safe_segment(vendor_id, field="vendor_id")
    if capability:
        params["capability"] = _safe_segment(capability, field="capability")
    return await _get("", params or None)


@router.get("/by-capability/{capability}", summary="Vendors implementing a capability")
async def vendors_for_capability(
    capability: str,
    user: Annotated[AuthUser, Depends(require_permission("actions:read"))],
) -> Any:
    safe = _safe_segment(capability, field="capability")
    return await _get(f"/by-capability/{safe}")


@router.get("/by-vendor/{vendor_id}", summary="Capabilities a vendor supports")
async def capabilities_for_vendor(
    vendor_id: str,
    user: Annotated[AuthUser, Depends(require_permission("actions:read"))],
) -> Any:
    safe = _safe_segment(vendor_id, field="vendor_id")
    return await _get(f"/by-vendor/{safe}")


@router.post("/dry-run", summary="Preview a live action without touching a vendor")
async def dry_run(
    body: dict[str, Any],
    user: Annotated[AuthUser, Depends(require_permission("actions:execute"))],
) -> Any:
    """Proxy a dry run, with the tenant taken from the session.

    Only ``/dry-run`` is proxied, never ``/dispatch``. Upstream, ``/dry-run``
    forces ``dry_run=true`` server-side regardless of the body, so a client
    cannot talk its way into a live vendor call through this route.
    """
    payload = {**body, "tenant_id": str(user.tenant_id), "dry_run": True}
    url = f"{base_url()}/api/v1/live-actions/dry-run"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(url, headers=service_headers(), json=payload)
    except httpx.HTTPError as exc:
        logger.warning("live_actions.unreachable", path="/dry-run", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The action service is unreachable. It runs in the `full` and `chatops` compose profiles.",
        ) from exc
    return _unwrap(response, "/dry-run")
