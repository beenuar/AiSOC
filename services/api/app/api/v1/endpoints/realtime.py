"""Short-lived ticket minting for the realtime WS/SSE edge — Issue #239.

The Node realtime service (``services/realtime``) fans out case/graph events
over WebSocket and SSE. Browsers cannot attach an ``Authorization`` header to a
WS upgrade, so instead of letting the realtime edge accept *any* connection
(the broken-access-control bug this endpoint closes), the flow is:

  1. The authenticated SPA calls ``POST /api/v1/realtime/ticket`` with its
     normal session bearer token.
  2. This endpoint mints a short-TTL (≤60s), audience-scoped HS256 ticket
     signed with the **shared realtime secret** (``AISOC_REALTIME_JWT_SECRET``
     or the dev fallback) — deliberately *not* ``SECRET_KEY``.
  3. The SPA appends the ticket as ``?token=`` on the WS/SSE URL.
  4. The realtime service verifies signature + ``aud`` + ``exp`` and derives the
     subscription ``tenant_id`` from the verified claim, so a browser can never
     subscribe to another tenant.

Fail-closed: outside a development-class environment, if the shared secret is
unset or set to a known insecure placeholder, ``realtime_ticket_secret`` returns
``None`` and we 503 rather than minting a ticket nobody can verify.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser, get_current_user
from app.core.config import realtime_ticket_secret, settings
from app.core.security import create_realtime_ticket

router = APIRouter(prefix="/realtime", tags=["realtime"])

# Hard ceiling on ticket lifetime regardless of configuration, so a
# misconfigured ``AISOC_REALTIME_TICKET_TTL_SECONDS`` can never mint a
# long-lived bearer that survives session revocation for minutes.
_MAX_TICKET_TTL_SECONDS = 60


class RealtimeTicket(BaseModel):
    """Response body for ``POST /realtime/ticket``."""

    token: str = Field(..., description="Signed HS256 ticket for the WS/SSE edge.")
    expires_in: int = Field(..., description="Ticket lifetime in seconds.")
    tenant_id: str = Field(..., description="Tenant the ticket is scoped to.")


@router.post("/ticket", response_model=RealtimeTicket)
async def mint_realtime_ticket(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> RealtimeTicket:
    """Mint a short-lived ticket for the realtime WS/SSE edge.

    Requires a valid session (``get_current_user`` 401s otherwise). The ticket's
    tenant is bound server-side from the authenticated user — the client cannot
    request a tenant.
    """
    secret = realtime_ticket_secret(settings)
    if secret is None:
        # Production with the shared secret unset/insecure: fail closed rather
        # than mint a ticket the realtime verifier will reject anyway.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=("Realtime ticket signing is not configured. Set AISOC_REALTIME_JWT_SECRET " "to enable WS/SSE connections."),
        )

    ttl = max(1, min(settings.AISOC_REALTIME_TICKET_TTL_SECONDS, _MAX_TICKET_TTL_SECONDS))
    tenant_id = str(current_user.tenant_id)
    token = create_realtime_ticket(
        secret=secret,
        tenant_id=tenant_id,
        user_id=str(current_user.user_id),
        ttl_seconds=ttl,
    )
    return RealtimeTicket(token=token, expires_in=ttl, tenant_id=tenant_id)
