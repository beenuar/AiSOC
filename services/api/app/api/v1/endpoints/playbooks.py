"""
Pillar-2 Playbook proxy endpoints.

The api service acts as a gateway that forwards playbook CRUD and run
requests to the agents service.  This keeps the public API contract in
one place while the engine lives in services/agents.

Authorization
-------------

Every route below is gated. The module previously declared no dependency of
any kind — no ``Depends``, no ``require_permission`` — and there is no global
auth middleware in ``app/main.py``, so all eight routes were reachable
unauthenticated, including ``POST /playbooks/{id}/run``, which executes a
playbook against the estate.

The three permissions used here (``playbooks:read``, ``playbooks:write``,
``playbooks:execute``) already existed in ``ROLE_PERMISSIONS`` and had no
reader. ``playbooks:execute`` is deliberately distinct from ``:write`` so an
analyst can run a governed playbook without being able to edit one.
"""

from __future__ import annotations

import os
import re
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.v1.deps import SERVICE_TENANT_HEADER, AuthUser, require_permission

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL", "http://agents:8084")
# See cases.py: the agents router fails closed without a bearer credential.
_AGENTS_SERVICE_TOKEN = (os.getenv("AISOC_AGENTS_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

ReadUser = Annotated[AuthUser, Depends(require_permission("playbooks:read"))]
WriteUser = Annotated[AuthUser, Depends(require_permission("playbooks:write"))]
ExecuteUser = Annotated[AuthUser, Depends(require_permission("playbooks:execute"))]

# Allowlist for playbook/run IDs: UUIDs or short slug-style alphanumeric IDs.
# Prevents partial-SSRF via path traversal in proxied requests.
_SAFE_ID_RE = re.compile(r"^[0-9a-zA-Z_\-]{1,128}$")


def _validate_path_id(value: str, name: str = "id") -> str:
    """Validate that *value* is a safe ID and return it to break the taint flow.

    Raising HTTPException here prevents any tainted data from reaching _proxy.
    Returning the validated string (rather than void) lets callers use the
    return value in path construction, which CodeQL recognises as untainted.
    """
    if not _SAFE_ID_RE.match(value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid {name} format",
        )
    # Return a new string built from the match to break the taint chain.
    return _SAFE_ID_RE.match(value).group(0)  # type: ignore[union-attr]


async def _proxy(method: str, path: str, *, tenant_id: Any, **kwargs) -> Any:
    """Forward a request to the agents service and return the JSON body.

    The agents service accepts a service token only together with the tenant
    it acts for (``require_console_or_service_auth``), and fails closed with
    403 otherwise. This proxy sent the token alone, so every /api/v1/playbooks
    route answered "403 Upstream service error" for every caller, admins
    included; the console only worked because it calls the agents service
    directly. ``tenant_id`` is keyword-only and required so a new route cannot
    forget it. Same header the cases proxy already sends.
    """
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    headers = dict(kwargs.pop("headers", None) or {})
    if _AGENTS_SERVICE_TOKEN:
        headers.setdefault("Authorization", f"Bearer {_AGENTS_SERVICE_TOKEN}")
    headers[SERVICE_TENANT_HEADER] = str(tenant_id)
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.request(method, url, headers=headers, **kwargs)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail="Upstream service error")
        if r.status_code == 204:
            return None
        return r.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Agents service unavailable") from exc


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.get("", summary="List playbooks")
async def list_playbooks(user: ReadUser, enabled_only: bool = False):
    return await _proxy("GET", "", params={"enabled_only": enabled_only}, tenant_id=user.tenant_id)


@router.post("", summary="Create playbook", status_code=201)
async def create_playbook(request: Request, user: WriteUser):
    body = await request.json()
    return await _proxy("POST", "", json=body, tenant_id=user.tenant_id)


@router.get("/runs", summary="List playbook runs")
async def list_runs(user: ReadUser, limit: int = 50):
    return await _proxy("GET", "/runs", params={"limit": limit}, tenant_id=user.tenant_id)


@router.get("/runs/{run_id}", summary="Get a playbook run")
async def get_run(run_id: str, user: ReadUser):
    safe_run_id = _validate_path_id(run_id, "run_id")
    return await _proxy("GET", f"/runs/{safe_run_id}", tenant_id=user.tenant_id)


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str, user: ReadUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    return await _proxy("GET", f"/{safe_id}", tenant_id=user.tenant_id)


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, request: Request, user: WriteUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await request.json()
    return await _proxy("PUT", f"/{safe_id}", json=body, tenant_id=user.tenant_id)


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str, user: WriteUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    await _proxy("DELETE", f"/{safe_id}", tenant_id=user.tenant_id)


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(playbook_id: str, request: Request, user: ExecuteUser):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await request.json()
    return await _proxy("POST", f"/{safe_id}/run", json=body, tenant_id=user.tenant_id)
