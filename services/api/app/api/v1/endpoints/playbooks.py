"""
Pillar-2 Playbook proxy endpoints.

The api service acts as a gateway that forwards playbook CRUD and run
requests to the agents service.  This keeps the public API contract in
one place while the engine lives in services/agents.
"""
from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL", "http://agents:8000")

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


async def _proxy(method: str, path: str, **kwargs) -> Any:
    """Forward a request to the agents service and return the JSON body."""
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.request(method, url, **kwargs)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        if r.status_code == 204:
            return None
        return r.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"Agents service unavailable: {exc}") from exc


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
    return await _proxy("GET", f"/runs/{run_id}")


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str):
    return await _proxy("GET", f"/{playbook_id}")


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, request: Request):
    body = await request.json()
    return await _proxy("PUT", f"/{playbook_id}", json=body)


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204)
async def delete_playbook(playbook_id: str):
    await _proxy("DELETE", f"/{playbook_id}")


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(playbook_id: str, request: Request):
    body = await request.json()
    return await _proxy("POST", f"/{playbook_id}/run", json=body)
