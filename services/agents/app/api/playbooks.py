"""
Pillar-2 Playbook REST API
===========================
Endpoints:
  GET    /api/v1/playbooks              → list all playbooks
  POST   /api/v1/playbooks              → create a playbook
  GET    /api/v1/playbooks/{id}         → get a playbook
  PUT    /api/v1/playbooks/{id}         → update a playbook
  DELETE /api/v1/playbooks/{id}         → delete a playbook
  POST   /api/v1/playbooks/{id}/run     → execute a playbook against a context
  GET    /api/v1/playbooks/runs/{run_id} → get a run result
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookRun,
    PlaybookStore,
    draft_from_nl,
)

logger = logging.getLogger("aisoc.api.playbooks")
router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"])

# In-memory run store for Pillar-2 (swap for Redis/DB in production)
_runs: dict[str, PlaybookRun] = {}


# ---------------------------------------------------------------------------
# Request / Response helpers
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    context: dict[str, Any] = {}
    dry_run: bool = False


class DraftFromNLRequest(BaseModel):
    """T3.7 — analyst prompt to draft a playbook from."""

    prompt: str
    # When ``False`` the substrate (no-LLM) drafter is used. CI sets this
    # to ``False`` so tests are hermetic; the production default is
    # ``True`` so the LLM is consulted when configured.
    allow_llm: bool = True


# ---------------------------------------------------------------------------
# NL drafter (T3.7) — declared BEFORE /{playbook_id} so "draft-from-nl" isn't
# parsed as an id.
# ---------------------------------------------------------------------------


@router.post("/draft-from-nl", summary="Draft a playbook from natural language")
async def draft_playbook_from_nl(req: DraftFromNLRequest) -> dict:
    """Turn an analyst-authored sentence into a draft playbook.

    The returned playbook ships with ``enabled=false`` so the editor
    is the gate — a human reviews each step before the playbook is
    eligible to run.
    """

    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    if len(prompt) > 4000:
        raise HTTPException(status_code=400, detail="prompt is too long (max 4000 chars)")

    result = await draft_from_nl(prompt, allow_llm=bool(req.allow_llm))
    return result.to_dict()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.get("", summary="List all playbooks")
async def list_playbooks(enabled_only: bool = False) -> list[dict]:
    store = PlaybookStore.default()
    return [pb.model_dump() for pb in store.list(enabled_only=enabled_only)]


@router.post("", summary="Create a playbook", status_code=201)
async def create_playbook(playbook: Playbook) -> dict:
    store = PlaybookStore.default()
    created = store.create(playbook)
    return created.model_dump()


# ---------------------------------------------------------------------------
# Run queries (declared BEFORE /{playbook_id} so FastAPI matches the literal
# "/runs" prefix instead of treating "runs" as a playbook_id path param).
# ---------------------------------------------------------------------------


@router.get("/runs", summary="List recent playbook runs")
async def list_runs(limit: int = 50) -> list[dict]:
    recent = sorted(
        _runs.values(),
        key=lambda r: r.started_at or "",
        reverse=True,
    )[:limit]
    return [r.to_dict() for r in recent]


@router.get("/runs/{run_id}", summary="Get a playbook run result")
async def get_run(run_id: str) -> dict:
    pr = _runs.get(run_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return pr.to_dict()


# ---------------------------------------------------------------------------
# CRUD by id
# ---------------------------------------------------------------------------


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str) -> dict:
    store = PlaybookStore.default()
    pb = store.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb.model_dump()


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, data: dict[str, Any]) -> dict:
    store = PlaybookStore.default()
    updated = store.update(playbook_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return updated.model_dump()


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str) -> None:
    store = PlaybookStore.default()
    if not store.delete(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


async def _execute(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_holder: list) -> None:
    """Background task: run the playbook and store the result."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    _runs[pr.run_id] = pr
    run_holder.append(pr.run_id)


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(
    playbook_id: str,
    body: RunRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    store = PlaybookStore.default()
    pb = store.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Create a placeholder run immediately so the caller can poll it
    from app.playbook.engine import PlaybookRun as _PR
    from app.playbook.engine import RunStatus as _RS

    placeholder = _PR(pb, body.context)
    placeholder.status = _RS.PENDING
    _runs[placeholder.run_id] = placeholder

    background_tasks.add_task(_execute_and_update, pb, body.context, body.dry_run, placeholder.run_id)

    return {
        "run_id": placeholder.run_id,
        "playbook_id": playbook_id,
        "status": "pending",
        "message": f"Playbook execution started. Poll GET /api/v1/playbooks/runs/{placeholder.run_id}",
    }


async def _execute_and_update(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_id: str) -> None:
    """Background task: overwrite placeholder with real run."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    # Preserve the pre-allocated run_id
    pr.run_id = run_id
    _runs[run_id] = pr
