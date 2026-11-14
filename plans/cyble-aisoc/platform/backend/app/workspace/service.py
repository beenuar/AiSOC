"""Workspace operations service (Theme 2l).

The single place that mutates the workspace op log. Centralizing it
matters because the ordering contract (server-assigned monotonic
``seq``) is fragile if multiple call sites can insert ops independently.

Hot-path responsibilities:

1. **Ensure a workspace exists.** First write to a case lazily creates
   the parent ``CaseWorkspace`` row. We do *not* eagerly create one when
   a case is opened — most cases close without anyone touching the
   workspace, and the parent row is small but non-zero overhead.

2. **Allocate ``seq`` monotonically per-workspace.** We use an explicit
   ``SELECT MAX(seq) + 1`` inside the same transaction as the INSERT.
   SQLite serializes write transactions per-database, so two concurrent
   ``apply_op`` calls for the same workspace can't allocate the same
   ``seq``. If we move to Postgres later, we'll need an advisory lock
   or a per-workspace sequence; the call site stays the same.

3. **Persist + broadcast.** After commit, fan the op out to subscribers
   via :mod:`app.realtime.workspace_events`. Broadcast happens *after*
   commit so a failed insert never leaks a phantom op to clients.

What this module deliberately does **not** do:

* No mention dispatch. The ``mention`` op is persisted here, but the
  agent dispatcher reads ``mention`` ops out-of-band (see
  ``app.workspace.dispatcher``). Keeping the two concerns separate
  means the API layer can apply a mention op and respond synchronously
  while the dispatcher runs the agent on its own task.

* No payload validation beyond shape. We trust the API layer to have
  shaped the payload correctly because the API is the only public
  entry point. Internal callers (the dispatcher, agents emitting
  ``agent.started`` ops) also go through this service, but they are
  trusted code.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from app.models.case import Case
from app.models.trace import AgentName
from app.models.workspace import (
    CaseWorkspace,
    WorkspaceAuthorKind,
    WorkspaceOp,
    WorkspaceOpKind,
)

log = logging.getLogger(__name__)


SUPPORTED_OP_KINDS: frozenset[str] = frozenset(k.value for k in WorkspaceOpKind)
"""Closed set of allowed op kinds. The API uses this for input validation."""


AGENT_NAMES: frozenset[str] = frozenset(a.value for a in AgentName)
"""Closed set of dispatchable agent names. Used by the mention parser."""


class WorkspaceError(Exception):
    """Raised for caller-fixable workspace errors (unknown case, bad op).

    The API layer maps these to 4xx. Programming errors (broken invariants,
    DB failures) raise the original exception untouched so they bubble
    into 5xx logging.
    """


# ── Read path ─────────────────────────────────────────────────────────

def get_workspace(
    db: Session, *, case_id: int, tenant_id: str
) -> CaseWorkspace | None:
    """Return the workspace for ``case_id`` within ``tenant_id`` or None.

    Tenant scoping is checked here even though ``case_id`` is the
    primary key — we never want one tenant to read another tenant's
    workspace by guessing the case id.
    """
    q = select(CaseWorkspace).where(
        CaseWorkspace.case_id == case_id,
        CaseWorkspace.tenant_id == tenant_id,
    )
    return db.exec(q).first()


def ensure_workspace(
    db: Session, *, case_id: int, tenant_id: str
) -> CaseWorkspace:
    """Get-or-create the workspace for ``case_id``.

    The case row is checked for tenant ownership; mismatch raises
    :class:`WorkspaceError` to surface as 403/404 at the API layer.
    We commit the new workspace row before returning so subsequent
    ops can reference its ``id``.
    """
    case = db.get(Case, case_id)
    if case is None:
        raise WorkspaceError(f"case {case_id} not found")
    if case.tenant_id != tenant_id:
        # Treat cross-tenant peeks as not-found rather than 403 so we
        # don't leak existence. The route layer can decide otherwise.
        raise WorkspaceError(f"case {case_id} not found")

    existing = get_workspace(db, case_id=case_id, tenant_id=tenant_id)
    if existing is not None:
        return existing

    ws = CaseWorkspace(tenant_id=tenant_id, case_id=case_id, head_seq=0)
    db.add(ws)
    db.commit()
    db.refresh(ws)
    return ws


def fetch_ops(
    db: Session,
    *,
    case_id: int,
    tenant_id: str,
    since_seq: int = 0,
    limit: int = 500,
) -> list[WorkspaceOp]:
    """Return ops for ``case_id`` with ``seq > since_seq`` in order.

    ``since_seq=0`` returns the whole log (the common "first connect"
    case). The cap on ``limit`` is defensive — a client that joins
    after a long offline period should paginate rather than dump the
    entire log into one frame.
    """
    if limit <= 0:
        return []
    q = (
        select(WorkspaceOp)
        .where(
            WorkspaceOp.case_id == case_id,
            WorkspaceOp.tenant_id == tenant_id,
            WorkspaceOp.seq > since_seq,
        )
        .order_by(WorkspaceOp.seq.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    return list(db.exec(q))


# ── Write path ────────────────────────────────────────────────────────

def _allocate_seq(db: Session, *, workspace_id: int) -> int:
    """Return the next ``seq`` value for ``workspace_id``.

    Implementation note: we use ``SELECT MAX(seq)`` rather than a
    sequence / autoincrement because ``seq`` is per-workspace, not
    global. Two workspaces share the same ``WorkspaceOp`` table but
    each has its own counter that starts at 1.
    """
    q = select(func.max(WorkspaceOp.seq)).where(
        WorkspaceOp.workspace_id == workspace_id
    )
    current = db.exec(q).one_or_none()
    # ``one_or_none()`` returns either ``None`` (empty workspace) or
    # the max-seq scalar. Defend against both.
    if current is None:
        return 1
    # SQLModel scalar selects return the raw value; SQLAlchemy ones
    # return a Row. Handle both shapes.
    if hasattr(current, "_mapping"):
        value = list(current)[0]
    else:
        value = current
    if value is None:
        return 1
    return int(value) + 1


def apply_op(
    db: Session,
    *,
    case_id: int,
    tenant_id: str,
    kind: str,
    payload: dict[str, Any] | None = None,
    author_kind: str = WorkspaceAuthorKind.HUMAN.value,
    author_id: str = "unknown",
    client_op_id: str | None = None,
    broadcast: bool = True,
) -> WorkspaceOp:
    """Append a new op to the workspace log.

    ``author_kind`` must be one of :class:`WorkspaceAuthorKind`. ``kind``
    must be one of :class:`WorkspaceOpKind`. The function:

    1. Ensures the parent workspace exists (creating it on first write).
    2. Allocates the next ``seq`` for that workspace.
    3. Inserts the op and updates ``workspace.head_seq`` in one txn.
    4. Schedules a best-effort broadcast on the running event loop, if
       ``broadcast=True`` and an event loop is available. Callers that
       are themselves async (the API route handler) can pass
       ``broadcast=False`` and call :func:`broadcast_op` directly with
       ``await`` for stricter delivery semantics.
    """
    if kind not in SUPPORTED_OP_KINDS:
        raise WorkspaceError(f"unsupported op kind: {kind!r}")
    if author_kind not in {k.value for k in WorkspaceAuthorKind}:
        raise WorkspaceError(f"unsupported author_kind: {author_kind!r}")

    ws = ensure_workspace(db, case_id=case_id, tenant_id=tenant_id)
    assert ws.id is not None, "ensure_workspace must commit & refresh id"

    seq = _allocate_seq(db, workspace_id=ws.id)
    op = WorkspaceOp(
        tenant_id=tenant_id,
        workspace_id=ws.id,
        case_id=case_id,
        seq=seq,
        kind=kind,
        payload=payload or {},
        author_kind=author_kind,
        author_id=author_id,
        client_op_id=client_op_id,
    )
    db.add(op)
    # Roll the workspace head forward so future GET ``/workspace`` calls
    # see a consistent ``head_seq`` without a SUM query.
    ws.head_seq = seq
    ws.updated_at = datetime.now(timezone.utc)
    db.add(ws)
    db.commit()
    db.refresh(op)

    if broadcast:
        _schedule_broadcast(tenant_id=tenant_id, case_id=case_id, op=op)
    return op


def serialize_op(op: WorkspaceOp) -> dict[str, Any]:
    """Convert a :class:`WorkspaceOp` to its on-the-wire dict shape.

    Kept here so the websocket broadcast, the GET endpoint, and the
    test harness all produce identical envelopes. Renaming a field
    here is a wire-format breaking change.
    """
    return {
        "id": op.id,
        "seq": op.seq,
        "kind": op.kind,
        "payload": op.payload,
        "author_kind": op.author_kind,
        "author_id": op.author_id,
        "client_op_id": op.client_op_id,
        "created_at": op.created_at.isoformat() if op.created_at else None,
    }


def _schedule_broadcast(
    *, tenant_id: str, case_id: int, op: WorkspaceOp
) -> None:
    """Best-effort fire-and-forget broadcast.

    The broadcast layer is async, but most callers (DB writes from
    sync routes, agent threads) are sync. We hop onto the running loop
    if there is one; if there isn't, we silently drop the broadcast —
    the op is durably stored, so a reconnecting client will catch up
    via ``fetch_ops`` anyway.
    """
    # Import locally to keep the realtime layer from being loaded when
    # workspace service is used in pure-sync contexts (e.g. tests that
    # never touch the bus).
    from app.realtime.workspace_events import publish_workspace_op

    payload = serialize_op(op)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop. Best effort: spin up a one-shot loop in a
        # thread? Too heavy. Just log and rely on op replay.
        log.debug(
            "workspace broadcast skipped (no running loop) "
            "tenant=%s case=%s seq=%s",
            tenant_id, case_id, op.seq,
        )
        return
    loop.create_task(
        publish_workspace_op(tenant_id=tenant_id, case_id=case_id, op=payload)
    )
