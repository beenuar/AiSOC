"""Realtime co-investigation REST + WS endpoints (Theme 2l).

Three surfaces, one router:

* ``GET  /cases/{case_id}/workspace`` — snapshot fetch: returns the
  workspace head plus an ordered slice of ops (``since_seq``-paginated).
  This is what a freshly-loaded client calls to backfill before it
  attaches the websocket.
* ``POST /cases/{case_id}/workspace/ops`` — apply a new op. Humans
  appending a note, replacing a block, or typing ``@investigator`` all
  funnel through here. If the op is a ``mention`` and the parsed text
  resolves to dispatchable agents, we hand off to the dispatcher *after*
  the op has been committed.
* ``WS   /cases/{case_id}/workspace/ws`` — live op stream filtered to
  this case. We share the global :data:`app.api.events.bus` so the same
  envelope shape (``kind="workspace.op"``) flows out of every channel.

Auth model
----------

REST endpoints use :func:`app.security.require_tenant`. The WebSocket
endpoint accepts a JWT via the ``token`` query parameter (browsers can't
set ``Authorization`` headers on the WS handshake) — same pattern as
``/ws/events`` in :mod:`app.api.routes`. In both paths we ensure the
caller can view the case's tenant_id via
:func:`app.security.ensure_row_visible`. The WS additionally filters
each delivered envelope to ``case_id`` and ``tenant_id`` so a connection
opened against case A never receives ops from case B even if the
caller's viewable set covers both.

Why a separate router
---------------------

We *could* fold these into :mod:`app.api.routes`, but the workspace
contract is hot-path and version-sensitive: changing the op envelope
breaks every connected console. Pulling it into its own module makes
the wire format easy to audit in isolation.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.api.events import bus
from app.config import settings
from app.db import get_session
from app.models.case import Case
from app.models.workspace import WorkspaceAuthorKind, WorkspaceOpKind
from app.security import (
    TenantContext,
    ensure_row_visible,
    require_tenant,
)
from app.workspace import (
    SUPPORTED_OP_KINDS,
    WorkspaceError,
    apply_op,
    dispatch_mentions,
    ensure_workspace,
    fetch_ops,
    parse_mentions,
    serialize_op,
    unique_agents,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["workspace"])


# ── Request models ─────────────────────────────────────────────────────


class _ApplyOpRequest(BaseModel):
    """Payload for ``POST /cases/{id}/workspace/ops``.

    ``kind`` is validated against :data:`SUPPORTED_OP_KINDS` at the
    service layer; we still type it as ``str`` here so unknown kinds
    surface a 400 instead of a Pydantic 422 (the API contract says
    "unknown op kind" is a caller mistake, not a schema violation).
    """

    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    author_kind: str = WorkspaceAuthorKind.HUMAN.value
    author_id: str | None = None
    client_op_id: str | None = None


# ── Helpers ────────────────────────────────────────────────────────────


def _load_case_or_404(
    db: Session, *, case_id: int, ctx: TenantContext
) -> Case:
    """Fetch a case and verify the caller can see its tenant.

    A missing case and a cross-tenant case both surface as ``404`` —
    we don't want guessing case ids to leak existence across tenants.
    The dedicated workspace error path then maps ``WorkspaceError``
    raised by the service layer to ``400`` for shape problems.
    """
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    # ensure_row_visible raises 403 if the caller can't view the tenant.
    # We catch nothing — the route shouldn't try to mask 403 as 404 here
    # because the caller already proved they have valid credentials; a
    # 403 is a clearer signal than pretending the case doesn't exist.
    ensure_row_visible(ctx, case.tenant_id)
    return case


# ── GET snapshot ───────────────────────────────────────────────────────


@router.get("/cases/{case_id}/workspace")
def get_workspace(
    case_id: int,
    since_seq: int = Query(
        default=0,
        ge=0,
        description="Return ops with seq strictly greater than this.",
    ),
    limit: int = Query(
        default=500,
        ge=1,
        le=2000,
        description="Max ops to return in one snapshot.",
    ),
    session: Session = Depends(get_session),
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Return the workspace head plus ops with ``seq > since_seq``.

    On first connect a client calls this with ``since_seq=0`` to
    backfill the whole log. On reconnect after a transient WS drop,
    it passes the last ``seq`` it received so the response is the
    delta only. We don't include the case row in the response because
    the analyst console already has it cached from ``GET /cases/{id}``.
    """
    case = _load_case_or_404(session, case_id=case_id, ctx=ctx)

    # ``ensure_workspace`` will create the parent row on first access.
    # We do it here (rather than inside ``fetch_ops``) so the response
    # ``head_seq`` is correct even before any op has been written.
    try:
        ws = ensure_workspace(
            session, case_id=case_id, tenant_id=case.tenant_id
        )
    except WorkspaceError as exc:
        # Should be impossible after _load_case_or_404, but surface as 404
        # rather than 500 so the contract stays stable.
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    ops = fetch_ops(
        session,
        case_id=case_id,
        tenant_id=case.tenant_id,
        since_seq=since_seq,
        limit=limit,
    )
    return {
        "case_id": case_id,
        "tenant_id": case.tenant_id,
        "head_seq": ws.head_seq,
        "since_seq": since_seq,
        "ops": [serialize_op(op) for op in ops],
    }


# ── POST apply op ──────────────────────────────────────────────────────


@router.post(
    "/cases/{case_id}/workspace/ops",
    status_code=status.HTTP_201_CREATED,
)
async def post_workspace_op(
    case_id: int,
    body: _ApplyOpRequest,
    session: Session = Depends(get_session),
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Append one op to the workspace log.

    For ``note.append`` / ``note.replace`` we just persist and let
    :func:`apply_op` broadcast. For ``mention`` ops we additionally
    parse the payload's ``text`` for ``@agent`` handles and queue the
    dispatcher; the dispatcher itself writes ``agent.started`` /
    ``agent.finished`` ops so the analyst sees live progress without
    this endpoint blocking on the agent run.

    A caller that posts a ``mention`` op without any parseable handles
    still succeeds — the op is durable and useful as a UI marker — we
    just don't queue any agents.
    """
    case = _load_case_or_404(session, case_id=case_id, ctx=ctx)

    if body.kind not in SUPPORTED_OP_KINDS:
        raise HTTPException(
            status_code=400, detail=f"unsupported op kind: {body.kind!r}"
        )

    # Author identity. Humans get their JWT subject, but we let the
    # caller override it (an MSSP analyst might be impersonating a
    # tenant user) as long as ``author_kind`` is consistent. System /
    # agent ops should not come in via this endpoint in normal use —
    # the dispatcher and agents write them directly — but we don't
    # forbid them so dev tools can replay traffic.
    author_id = body.author_id or ctx.subject

    try:
        op = apply_op(
            session,
            case_id=case_id,
            tenant_id=case.tenant_id,
            kind=body.kind,
            payload=body.payload,
            author_kind=body.author_kind,
            author_id=author_id,
            client_op_id=body.client_op_id,
            broadcast=True,
        )
    except WorkspaceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Mention fan-out. We do this *after* commit so the dispatcher's
    # background task can reference a real, durable op id. The
    # dispatcher needs a running event loop to actually schedule agent
    # runs — FastAPI's sync route handlers run inside a threadpool but
    # the asyncio loop is still reachable via ``get_running_loop`` from
    # the main thread; ``dispatch_mentions`` handles the "no loop" case
    # by returning an empty task list (ops are durable, agents can be
    # re-dispatched later if needed).
    if op.kind == WorkspaceOpKind.MENTION.value:
        text = (op.payload or {}).get("text", "")
        if isinstance(text, str) and text:
            mentions = parse_mentions(text)
            agents = unique_agents(mentions)
            if agents:
                try:
                    dispatch_mentions(
                        tenant_id=case.tenant_id,
                        case_id=case_id,
                        mention_op_id=op.id or 0,
                        agents=agents,
                        requested_by=author_id,
                    )
                except Exception:
                    # Dispatcher failure must not 500 the request — the
                    # op is committed and the analyst will see their note
                    # even if no agent ran. Log and move on.
                    log.exception(
                        "workspace: dispatch_mentions failed "
                        "tenant=%s case=%s op_id=%s",
                        case.tenant_id, case_id, op.id,
                    )

    return serialize_op(op)


# ── WebSocket: live ops for one case ───────────────────────────────────


def _resolve_ws_tenants(token: str | None) -> list[str] | None:
    """Resolve a WS query-string token to a viewable tenant filter.

    Mirrors the auth logic in :func:`app.api.routes.ws_events` so the
    two websocket endpoints can't drift apart. Returns either:

    * ``None`` — caller is platform admin, no tenant filter.
    * A list of tenant_ids — the caller can subscribe to events for
      any of these tenants.

    Raises ``PermissionError`` for an invalid token. Anonymous dev
    mode is allowed only when ``settings.dev_allow_anon_tenant`` is on.
    """
    if token:
        # Local import: keeps the JWT module out of the cold-start
        # path for tests that don't touch auth.
        from app.security.jwt import claims_from_payload, decode_token

        try:
            claims = claims_from_payload(decode_token(token))
        except Exception as exc:  # noqa: BLE001
            raise PermissionError("invalid token") from exc
        if claims.is_admin:
            return None
        if claims.is_mssp:
            return list(claims.allowed_tenants) + [claims.tenant_id]
        return [claims.tenant_id]

    if settings.dev_allow_anon_tenant:
        return [settings.default_tenant]

    raise PermissionError("missing token")


@router.websocket("/cases/{case_id}/workspace/ws")
async def workspace_ws(websocket: WebSocket, case_id: int) -> None:
    """Stream workspace ops for ``case_id`` to the client in real time.

    Wire envelope is whatever :func:`app.realtime.workspace_events.publish_workspace_op`
    publishes: ``{"kind": "workspace.op", "tenant_id": ..., "case_id":
    ..., "ts": ..., "op": {...}}``. We filter the subscriber queue to
    envelopes whose ``case_id`` matches the URL so a single analyst
    console can keep multiple workspace tabs open without crossing
    streams.

    We deliberately do **not** replay the snapshot here — the client is
    expected to call ``GET /cases/{id}/workspace`` first to backfill,
    then attach this socket to pick up ops with ``seq`` greater than
    what it just received. Doing both in one channel would mean
    inventing a "this is the snapshot, the rest are live ops" framing
    that the existing event bus doesn't provide.
    """
    token = websocket.query_params.get("token")
    try:
        tenant_ids = _resolve_ws_tenants(token)
    except PermissionError:
        await websocket.close(code=4401)
        return

    # Verify the case exists and the caller can view it. We open a
    # short-lived session here rather than using ``Depends(get_session)``
    # because FastAPI doesn't run Depends() on websocket routes the
    # same way it does for HTTP routes — and we don't want to keep the
    # session open for the entire socket lifetime.
    from app.db import session_scope as _session_scope  # local import

    case_tenant_id: str | None = None
    try:
        with _session_scope() as s:
            case = s.get(Case, case_id)
            if case is None:
                await websocket.close(code=4404)
                return
            # If we have a tenant filter, enforce row visibility against
            # it. Admin tokens (filter=None) skip this check.
            if tenant_ids is not None and case.tenant_id not in tenant_ids:
                # Closing with 4403 (custom auth-failure code) rather
                # than 4404 because the caller is authenticated but
                # not authorized — matching the REST behavior of
                # ``ensure_row_visible``.
                await websocket.close(code=4403)
                return
            case_tenant_id = case.tenant_id
    except Exception:
        log.exception(
            "workspace ws: case visibility check failed case_id=%s", case_id
        )
        await websocket.close(code=1011)
        return

    await websocket.accept()
    q = bus.subscribe(tenant_ids=tenant_ids)
    try:
        while True:
            ev = await q.get()
            # Filter: only workspace.op envelopes for *this* case.
            # The bus already enforces tenant scope, but we still
            # double-check tenant_id here in case the caller's filter
            # was None (admin) — we don't want to leak ops from other
            # tenants onto an admin's per-case socket.
            if ev.get("kind") != "workspace.op":
                continue
            if ev.get("case_id") != case_id:
                continue
            if case_tenant_id is not None and ev.get("tenant_id") not in (
                case_tenant_id,
                None,
            ):
                continue
            await websocket.send_json(ev)
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        # Server shutdown — close cleanly.
        raise
    finally:
        bus.unsubscribe(q)
