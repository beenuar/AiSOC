"""Public-facing WebSocket proxy for graph-update streaming (T1.4 — v8.0).

The browser opens ``wss://api.../v1/graph_ws/stream`` with the user's
session bearer token. This endpoint authenticates the token, derives
the tenant_id from the resolved user, then dials the *internal*
ingest broadcaster at ``$AISOC_INGEST_GRAPH_WS_URL`` with the
tenant_id bound in the URL. Every envelope the upstream sends is
relayed verbatim to the browser; the browser cannot subscribe to
another tenant because the proxy controls the upstream URL.

Why a proxy and not direct?
---------------------------
Two reasons:

  1. **Auth boundary.** The ingest WebSocket runs on the internal
     service network and has no notion of users. The API service
     already owns the auth path (``app.api.v1.deps.get_current_user``)
     and the RBAC model. Re-implementing JWT/API-key validation
     inside the Go broadcaster would duplicate state and risk drift.
  2. **Tenant binding.** A browser-facing endpoint that respects an
     attacker-supplied ``?tenant_id=...`` query param is a
     cross-tenant leak waiting to happen. We rebind the tenant
     server-side from ``current_user.tenant_id``.

Registration
------------
The matching router-include lives in
``services/api/app/api/v1/router.py``.

Permission gate
---------------
``graph:read`` — same scope used by the relational /graph endpoints.
We do not introduce a new permission; the live tail surfaces the
same data the user can already query.

Failure modes
-------------
* Upstream unreachable → 1011 close, structured log.
* Auth fails → 401 close before upgrade.
* Tenant_id missing from CurrentUser → 403.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Annotated, Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, _resolve_api_key
from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
    is_dev_mode,
)
from app.core.security import decode_token
from app.db.database import get_db
from app.models.tenant import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph_ws", tags=["graph", "realtime"])

# Default upstream — matches the ingest binary's default port (8080)
# and the route registered by services/ingest/internal/server/server.go.
# Operators override per-deployment with AISOC_INGEST_GRAPH_WS_URL,
# e.g. ws://ingest.aisoc.svc.cluster.local:8080/v1/graph_ws/stream.
_DEFAULT_UPSTREAM = "ws://ingest:8080/v1/graph_ws/stream"


def _upstream_url(tenant_id: uuid.UUID) -> str:
    """Build the upstream URL with the resolved tenant bound."""

    base = os.environ.get("AISOC_INGEST_GRAPH_WS_URL", _DEFAULT_UPSTREAM)
    parts = urlsplit(base)
    qs = parts.query
    binding = f"tenant_id={quote(str(tenant_id), safe='')}"
    qs = f"{qs}&{binding}" if qs else binding
    return urlunsplit((parts.scheme, parts.netloc, parts.path, qs, parts.fragment))


async def _authenticate_ws(
    websocket: WebSocket,
    token: str | None,
    db: AsyncSession,
) -> CurrentUser | None:
    """Resolve a CurrentUser from a websocket token query param.

    FastAPI's ``Depends(get_current_user)`` only works for HTTP — for
    WebSocket connections we have to do the resolution by hand because
    the upgrade response cannot carry a ``WWW-Authenticate`` header
    and the bearer-scheme middleware sees no Authorization header on
    the upgrade. We reuse the same helpers ``get_current_user`` uses
    so the auth contract is identical.

    Returns ``None`` after closing the websocket on failure.
    """

    if not token:
        if is_dev_mode():
            return CurrentUser(
                user_id=DEMO_USER_ID,
                tenant_id=DEMO_TENANT_ID,
                role=DEMO_USER_ROLE,
                email=DEMO_USER_EMAIL,
            )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="not authenticated")
        return None

    # API key path
    if token.startswith("aisoc_"):
        try:
            return await _resolve_api_key(token, db)
        except HTTPException as exc:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason=str(exc.detail)[:120],
            )
            return None

    # JWT path
    try:
        payload = decode_token(token)
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        return None
    sub = payload.get("sub")
    token_type = payload.get("type", "access")
    if not sub or token_type != "access":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        return None
    try:
        user_uuid = uuid.UUID(sub)
    except ValueError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid subject")
        return None
    result = await db.execute(select(User).where(User.id == user_uuid, User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="user not found")
        return None
    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )


@router.websocket("/stream")
async def graph_updates_stream(
    websocket: WebSocket,
    token: Annotated[str | None, Query()] = None,
    db: AsyncSession = Depends(get_db),
) -> None:
    """WebSocket: live graph-update stream scoped to the caller's tenant.

    The browser opens this with a ``?token=<jwt|api_key>`` query
    parameter (browsers can't set ``Authorization`` headers on a
    WebSocket open). After authentication, the connection is proxied
    to the internal ingest broadcaster with ``tenant_id`` bound from
    the resolved user — the client cannot influence which tenant they
    subscribe to.

    Closes with policy-violation if auth fails. Closes with
    internal-error if the upstream is unreachable.
    """

    await websocket.accept()
    user = await _authenticate_ws(websocket, token, db)
    if user is None:
        return

    # Enforce the ``graph:read`` permission — same scope as the
    # relational graph endpoints.
    try:
        user.require_permission("graph:read")
    except HTTPException as exc:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason=str(exc.detail)[:120],
        )
        return

    upstream_url = _upstream_url(user.tenant_id)
    logger.info(
        "graph_ws: proxying for tenant=%s upstream=%s user=%s",
        user.tenant_id,
        _redact_url(upstream_url),
        user.email,
    )

    try:
        await _relay(websocket, upstream_url)
    except WebSocketDisconnect:
        logger.debug("graph_ws: client disconnected tenant=%s", user.tenant_id)
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning(
            "graph_ws: relay error tenant=%s err=%s",
            user.tenant_id,
            exc,
        )
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream error")
        except RuntimeError:
            # The socket was already closed by the client or the ASGI
            # server (Starlette raises ``RuntimeError`` on double close).
            # Nothing useful we can do at this point, and re-raising
            # would mask the original ``exc`` above.
            pass


async def _relay(websocket: WebSocket, upstream_url: str) -> None:
    """Pipe envelopes from the internal broadcaster to the browser.

    We use ``httpx`` for the upstream WebSocket because the existing
    API service already depends on httpx. The implementation is
    deliberately stripped-down: we only need server→client streaming,
    not bidirectional message passing.
    """

    # httpx's WebSocket API is exposed via ``httpx.AsyncClient`` +
    # ``ws_connect``; the import sits inside the function so a
    # production environment that lacks the optional ws extras still
    # imports the module successfully (the WS endpoint just becomes
    # 503 at connect time).
    try:
        from httpx_ws import aconnect_ws  # type: ignore[import-not-found]
    except ImportError:
        await websocket.close(
            code=status.WS_1011_INTERNAL_ERROR,
            reason="server missing httpx-ws extra",
        )
        return

    try:
        async with aconnect_ws(upstream_url) as upstream:
            done: asyncio.Event = asyncio.Event()

            async def client_to_upstream() -> None:
                try:
                    while not done.is_set():
                        # The browser is read-only for this stream;
                        # we still drain frames so a polite client
                        # close propagates cleanly.
                        msg = await websocket.receive()
                        if msg.get("type") == "websocket.disconnect":
                            return
                except WebSocketDisconnect:
                    return
                except Exception:  # pragma: no cover
                    return

            async def upstream_to_client() -> None:
                try:
                    while not done.is_set():
                        envelope = await upstream.receive_text()
                        await websocket.send_text(envelope)
                except Exception:
                    return

            tasks = [
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            ]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                done.set()
                for t in tasks:
                    if not t.done():
                        t.cancel()
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            # We're tearing down the relay; either the
                            # task acknowledged cancellation
                            # (``CancelledError``) or it died with its
                            # own exception that was already handled
                            # inside the task body. Either way we
                            # intentionally swallow here so cleanup
                            # always finishes for every task.
                            pass
    except httpx.HTTPError as exc:
        logger.warning("graph_ws: upstream dial failed url=%s err=%s", _redact_url(upstream_url), exc)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream unreachable")
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("graph_ws: upstream error url=%s err=%s", _redact_url(upstream_url), exc)
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream error")
        except RuntimeError:
            # Socket already closed (Starlette raises ``RuntimeError`` on
            # double close). Best-effort teardown only; the original
            # ``exc`` is the meaningful failure signal here.
            pass


def _redact_url(url: str) -> str:
    """Drop the query string from a URL before logging."""

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


__all__: list[Any] = ["router"]
