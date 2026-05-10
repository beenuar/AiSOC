"""
Pillar-2 Playbook proxy endpoints.

The api service acts as a gateway that forwards playbook CRUD and run
requests to the agents service.  This keeps the public API contract in
one place while the engine lives in services/agents.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL", "http://agents:8084")

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

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


async def _proxy(method: str, path: str, **kwargs) -> Any:
    """Forward a request to the agents service and return the JSON body."""
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.request(method, url, **kwargs)
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
async def list_playbooks(enabled_only: bool = False):
    return await _proxy("GET", "", params={"enabled_only": enabled_only})


@router.post("", summary="Create playbook", status_code=201)
async def create_playbook(request: Request):
    body = await request.json()
    return await _proxy("POST", "", json=body)


@router.get("/runs", summary="List playbook runs")
async def list_runs(limit: int = 50):
    return await _proxy("GET", "/runs", params={"limit": limit})


@router.get("/runs/{run_id}", summary="Get a playbook run")
async def get_run(run_id: str):
    safe_run_id = _validate_path_id(run_id, "run_id")
    return await _proxy("GET", f"/runs/{safe_run_id}")


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    return await _proxy("GET", f"/{safe_id}")


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, request: Request):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await request.json()
    return await _proxy("PUT", f"/{safe_id}", json=body)


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    await _proxy("DELETE", f"/{safe_id}")


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(playbook_id: str, request: Request):
    safe_id = _validate_path_id(playbook_id, "playbook_id")
    body = await request.json()
    return await _proxy("POST", f"/{safe_id}/run", json=body)
