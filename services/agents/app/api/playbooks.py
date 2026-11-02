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

import html
import logging
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookRun,
    PlaybookStore,
    draft_from_nl,
    verification,
)
from app.playbook import engine as engine_module
from app.playbook import pause as playbook_pause
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)

logger = logging.getLogger("aisoc.api.playbooks")
#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"], dependencies=[Depends(require_console_or_service_auth)])

#: A second router with no auth dependency, for the one route that cannot
#: have one. See `resume_wait` at the bottom of this file for why, and note
#: that it is a separate router rather than an exemption on the one above:
#: an `Annotated[..., Depends(...)]`-less route inside an authenticated
#: router reads as authenticated to everyone who skims it, and this repo has
#: already shipped eleven routes whose authorization looked present and
#: never ran.
waits_router = APIRouter(prefix="/api/v1/playbook-waits", tags=["playbooks"])

#: And a third, for the verification answer. Same reasoning as
#: ``waits_router`` and one addition: the person clicking is the *subject* of
#: an alert, not an operator, so they hold no session by construction and
#: never will. The credential is the token plus a signature over the answer
#: and the stage — see ``app.playbook.verification`` for why the token alone
#: is not enough.
verifications_router = APIRouter(prefix="/api/v1/playbook-verifications", tags=["playbooks"])

#: The resolved caller, bound as a handler parameter.
#:
#: The router-level ``dependencies=[...]`` above authenticates every request
#: and hands the result nowhere. That is how GHSA-27wx-pcv5-pr7q happened: a
#: ``TenantPrincipal`` was resolved on every call and discarded, so the
#: service knew who was asking and never asked. Declaring it here is what
#: makes the tenant reachable from the handler — the dependency alone never
#: was.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]


@dataclass(frozen=True)
class _OwnedRun:
    """A run and the tenant it belongs to.

    ``_runs`` was a bare ``dict[str, PlaybookRun]`` — deployment-global, with
    no tenant anywhere — so ``GET /runs/{id}`` returned any run to anyone
    holding its id and ``GET /runs`` returned every tenant's runs to everyone
    without needing one. A run record carries the *resolved* value of each
    ``${NAME}`` integration reference, which is how the victim tenant's
    vault-decrypted webhook URLs and bearer headers reached the attacker.
    """

    tenant_id: str
    run: PlaybookRun


# In-memory run store for Pillar-2 (swap for Redis/DB in production)
_runs: dict[str, _OwnedRun] = {}


def _remember(tenant_id: str, run: PlaybookRun) -> None:
    _runs[run.run_id] = _OwnedRun(tenant_id=tenant_id, run=run)


def _run_or_404(run_id: str, tenant_id: str) -> PlaybookRun:
    """A run this tenant owns, or the same refusal an absent one gets.

    404 rather than 403 deliberately: a 403 on a real id and a 404 on an
    invented one would let a caller enumerate which run ids exist across every
    tenant. The two answers are required to be byte-identical.
    """
    owned = _runs.get(run_id)
    if owned is None or owned.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return owned.run


def _remember_resumed(run: PlaybookRun) -> None:
    """Record a run that resumed from a durable pause.

    The two callback routes have no session — a vendor webhook and the subject
    of an alert hold no credential by construction — so the tenant comes from
    the run's own context, which the engine wrote from the *authenticated*
    tenant when the run started. A run that somehow carries none is left
    unrecorded rather than stored under an empty key that every tenant would
    match: an absent scope must narrow to nothing, never widen to everything.
    """
    tenant_id = str(run.context.get("tenant_id") or run.trigger_context.get("tenant_id") or "")
    if not tenant_id:
        logger.warning("playbook run %s resumed with no tenant; not recording it", run.run_id)
        return
    _remember(tenant_id, run)


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
async def list_playbooks(principal: ScopedPrincipal, enabled_only: bool = False) -> list[dict]:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    return [pb.model_dump() for pb in store.list(tenant_id=tenant_id, enabled_only=enabled_only)]


@router.post("", summary="Create a playbook", status_code=201)
async def create_playbook(playbook: Playbook, principal: ScopedPrincipal) -> dict:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    created = store.create(playbook, tenant_id=tenant_id)
    return created.model_dump()


# ---------------------------------------------------------------------------
# Run queries (declared BEFORE /{playbook_id} so FastAPI matches the literal
# "/runs" prefix instead of treating "runs" as a playbook_id path param).
# ---------------------------------------------------------------------------


@router.get("/runs", summary="List recent playbook runs")
async def list_runs(principal: ScopedPrincipal, limit: int = 50) -> list[dict]:
    tenant_id = str(scoped_tenant_or_403(principal))
    recent = sorted(
        (owned.run for owned in _runs.values() if owned.tenant_id == tenant_id),
        key=lambda r: r.started_at or "",
        reverse=True,
    )[:limit]
    return [r.to_dict() for r in recent]


@router.get("/runs/{run_id}", summary="Get a playbook run result")
async def get_run(run_id: str, principal: ScopedPrincipal) -> dict:
    tenant_id = str(scoped_tenant_or_403(principal))
    return _run_or_404(run_id, tenant_id).to_dict()


# ---------------------------------------------------------------------------
# CRUD by id
# ---------------------------------------------------------------------------


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str, principal: ScopedPrincipal) -> dict:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    pb = store.get(playbook_id, tenant_id=tenant_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb.model_dump()


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, data: dict[str, Any], principal: ScopedPrincipal) -> dict:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    updated = store.update(playbook_id, data, tenant_id=tenant_id)
    if not updated:
        # Also the answer for a shipped pack playbook, which no tenant owns
        # and none may edit.
        raise HTTPException(status_code=404, detail="Playbook not found")
    return updated.model_dump()


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str, principal: ScopedPrincipal) -> None:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    if not store.delete(playbook_id, tenant_id=tenant_id):
        raise HTTPException(status_code=404, detail="Playbook not found")


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _execution_context(body_context: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """The context a run executes under, with the tenant taken from the credential.

    ``tenant_id`` is **removed** from whatever the caller sent and then set
    from the authenticated principal. Deleting rather than validating is the
    point: the engine reads ``context["tenant_id"]`` when it resolves
    ``${NAME}`` integration references, creates approvals and dispatches
    actions, and a value the caller can supply is a value that can be wrong.
    After this there is nothing left to compare.

    That read is the whole of GHSA-27wx-pcv5-pr7q: naming another tenant here
    made the platform resolve *their* vault-decrypted integration values and
    write them into a run record the caller read straight back.
    """
    context = {k: v for k, v in body_context.items() if k != "tenant_id"}
    context["tenant_id"] = tenant_id
    return context


async def _execute(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_holder: list, tenant_id: str) -> None:
    """Background task: run the playbook and store the result."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    _remember(tenant_id, pr)
    run_holder.append(pr.run_id)


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(
    playbook_id: str,
    body: RunRequest,
    background_tasks: BackgroundTasks,
    principal: ScopedPrincipal,
) -> dict:
    store = PlaybookStore.default()
    tenant_id = str(scoped_tenant_or_403(principal))
    pb = store.get(playbook_id, tenant_id=tenant_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    context = _execution_context(body.context, tenant_id)

    # Create a placeholder run immediately so the caller can poll it
    from app.playbook.engine import PlaybookRun as _PR
    from app.playbook.engine import RunStatus as _RS

    placeholder = _PR(pb, context)
    placeholder.status = _RS.PENDING
    _remember(tenant_id, placeholder)

    background_tasks.add_task(_execute_and_update, pb, context, body.dry_run, placeholder.run_id, tenant_id)

    return {
        "run_id": placeholder.run_id,
        "playbook_id": playbook_id,
        "status": "pending",
        "message": f"Playbook execution started. Poll GET /api/v1/playbooks/runs/{placeholder.run_id}",
    }


async def _execute_and_update(
    playbook: Playbook,
    context: dict[str, Any],
    dry_run: bool,
    run_id: str,
    tenant_id: str,
) -> None:
    """Background task: overwrite placeholder with real run."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    # Preserve the pre-allocated run_id
    pr.run_id = run_id
    _remember(tenant_id, pr)


# ---------------------------------------------------------------------------
# Wait callbacks
# ---------------------------------------------------------------------------


@waits_router.post("/{resume_token}/resume", summary="Resume a playbook run waiting on a callback", status_code=202)
async def resume_wait(resume_token: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Wake a run suspended at a ``wait`` step with ``until: "callback"``.

    Deliberately on its own router with **no** auth dependency, and the
    reason is the shape of the thing: a callback comes from whatever the
    playbook was waiting for — a vendor webhook, a scanner finishing, a
    ticket closing — none of which holds an AiSOC session or a service
    token. The token in the path is the credential. It is 32 random bytes,
    it is unique-indexed so a guess has one target, it is minted separately
    from the pause id (which appears in run records an analyst can read),
    and it is single-use: resuming resolves the pause, so a second delivery
    of the same callback matches no waiting row.

    Returns 202 and resumes in the background. A vendor's webhook sender
    wants a fast 2xx, and holding the connection open for the remainder of
    a playbook is how a sender decides the delivery failed and retries it.
    """
    if not await playbook_pause.find_wait_by_token(resume_token=resume_token):
        # One answer for "no such token" and "already resumed", on purpose.
        # Distinguishing them would turn this route into an oracle for
        # whether a token was ever valid.
        raise HTTPException(status_code=404, detail="no run is waiting on this token")

    background_tasks.add_task(_resume_wait_in_background, resume_token)
    return {"status": "resuming"}


async def _resume_wait_in_background(resume_token: str) -> None:
    run = await engine_module.resume_wait(resume_token=resume_token)
    if run is None:
        # Not an error: another delivery of the same callback, or the
        # sweeper's timer, got there first.
        logger.info("playbook wait callback matched no waiting run (already resumed)")
        return
    _remember_resumed(run)


# ---------------------------------------------------------------------------
# Verification answers
# ---------------------------------------------------------------------------


@verifications_router.get(
    "/{resume_token}/{answer}",
    summary="Record a verification answer and resume the run",
    response_class=HTMLResponse,
)
async def answer_verification(resume_token: str, answer: str, sig: str = Query("", max_length=128)) -> HTMLResponse:
    """The link in the chat message. A GET, because it is clicked.

    Answers HTML rather than JSON: it lands in whatever browser the chat
    client opens, in front of a person who is not an operator and should
    see a sentence rather than a payload.

    One refusal for every way this can fail — unknown token, wrong
    signature, stale stage, already answered. Distinguishing them would
    turn the route into an oracle for whether a token was ever valid, and
    the person clicking cannot act on the difference anyway.

    The run resumes **inline** rather than in a background task, unlike the
    wait callback next door. A vendor's webhook sender wants a fast 2xx and
    retries on a slow one; a person wants to be told their answer was
    recorded, and the containment that follows is the thing they are
    waiting to hear about.
    """
    if answer not in verification.ANSWERS:
        return HTMLResponse(_verification_html(_VERIFY_REFUSED_TITLE, _VERIFY_REFUSED_BODY, ok=False), status_code=400)

    run = await engine_module.resume_verification(resume_token=resume_token, answer=answer, signature=sig)
    if run is None:
        return HTMLResponse(_verification_html(_VERIFY_REFUSED_TITLE, _VERIFY_REFUSED_BODY, ok=False), status_code=400)

    _remember_resumed(run)
    return HTMLResponse(
        _verification_html(
            "Thanks — that's recorded",
            "Your security team has your answer and the alert has been updated. You do not need to do anything else.",
            ok=True,
        ),
        status_code=200,
    )


_VERIFY_REFUSED_TITLE = "We couldn't record that"
_VERIFY_REFUSED_BODY = (
    "This link is no longer valid — it may have expired, already been used, or been replaced by a newer request. "
    "Contact your security team if you still need to respond."
)


def _verification_html(title: str, body: str, *, ok: bool) -> str:
    """A plain acknowledgement page.

    No framework and no external asset: this is served to a person's
    browser from a service that is not the console, and a page that fetches
    anything would fail differently on every corporate network.
    """
    colour = "#0f766e" if ok else "#b91c1c"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title></head>"
        '<body style="font-family:Arial,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.6">'
        f"<h1 style='color:{colour};font-size:1.3rem'>{html.escape(title)}</h1>"
        f"<p>{html.escape(body)}</p></body></html>"
    )
