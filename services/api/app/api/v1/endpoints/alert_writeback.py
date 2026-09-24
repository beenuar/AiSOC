"""Write an AiSOC verdict back to the finding that produced the alert.

Two callers, two identities, one governed path.

A person in the console reaches ``POST /alerts/{id}/source-writeback`` with a
session and ``alerts:write``. The agents worker reaches the same route with a
shared service token, because it has no session to present and no human to
attribute the call to.

The service token is **fail-closed**: when ``AISOC_AGENTS_SERVICE_TOKEN`` is
unset there is no service path at all, and an unauthenticated caller is
refused rather than admitted. An empty secret that means "allow everybody" is
how an internal route becomes a public one, and this route can change state in
a customer's SIEM.

Nothing here executes by default. ``AISOC_SIEM_WRITEBACK_EXECUTE`` is off, so
the response says ``mode: "dry_run"`` and ``executed: false`` until an operator
turns it on.
"""

from __future__ import annotations

import hmac
import os
import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, CurrentUser, DBSession, bearer_scheme, get_current_user
from app.db.database import get_db
from app.models.alert import Alert
from app.services import siem_writeback
from app.services.alert_source_link import links_for_alert

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

_SERVICE_TOKEN_ENV = "AISOC_AGENTS_SERVICE_TOKEN"


class SourceWritebackRequest(BaseModel):
    """What the caller believes about the alert."""

    disposition: str = Field(description="Canonical AiSOC disposition. Anything unrecognised is refused, not guessed.")
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    rationale: str = Field(default="", max_length=4000)
    #: Required from a service caller, which has no session to read it from.
    #: Ignored for a session caller, whose tenant comes from the session.
    tenant_id: uuid.UUID | None = None


class SourceLinkResponse(BaseModel):
    vendor: str
    external_id: str
    external_url: str | None = None
    last_disposition: str | None = None
    last_writeback_action: str | None = None
    last_writeback_status: str | None = None
    #: TRUE only when a vendor call actually ran. A dry run is FALSE.
    executed: bool = False


def service_token_valid(presented: str | None) -> bool:
    """Constant-time check against the configured service token.

    Returns False when no token is configured: an unset secret disables the
    service path rather than opening it to everybody.
    """
    configured = os.getenv(_SERVICE_TOKEN_ENV, "").strip()
    if not configured or not presented:
        return False
    return hmac.compare_digest(configured, presented.strip())


async def optional_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: AsyncSession = Depends(get_db),
) -> CurrentUser | None:
    """A session if there is one, ``None`` if there is not.

    The normal dependency raises on a missing or invalid session, which would
    make the service path unreachable. Swallowing the 401 here is safe because
    the caller still has to satisfy one of the two branches in
    :func:`_resolve_caller`; it never admits anybody on its own.
    """
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


def _resolve_caller(
    body_tenant_id: uuid.UUID | None,
    user: CurrentUser | None,
    service_token: str | None,
) -> tuple[uuid.UUID, str]:
    """Return ``(tenant_id, requested_by)`` for an authorised caller.

    A session always wins, and its tenant comes from the session rather than
    the body — accepting the client's copy would let any authenticated user
    write a disposition into another tenant's SIEM.
    """
    if user is not None:
        user.require_permission("alerts:write")
        return user.tenant_id, f"user:{user.email}"

    if service_token_valid(service_token):
        if body_tenant_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="a service caller must name the tenant it is acting for",
            )
        return body_tenant_id, "aisoc-agents"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/{alert_id}/source-writeback", summary="Write an AiSOC verdict back to the source finding")
async def write_back(
    alert_id: uuid.UUID,
    body: SourceWritebackRequest,
    db: DBSession,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
    user: Annotated[CurrentUser | None, Depends(optional_user)] = None,
) -> dict[str, Any]:
    """Project ``disposition`` onto every source finding behind this alert.

    The response distinguishes four things a caller could otherwise confuse:
    ``mode`` (live / dry_run / disabled), ``executed`` (whether a vendor call
    actually ran), each outcome's ``status``, and the per-vendor ``detail``
    explaining a refusal. A dry run reports ``executed: false`` and a detail
    that begins ``DRY RUN``.
    """
    tenant_id, requested_by = _resolve_caller(body.tenant_id, user, x_aisoc_service_token)

    result = await db.execute(select(Alert.id).where(Alert.id == alert_id, Alert.tenant_id == tenant_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    report = await siem_writeback.write_back_disposition(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        disposition=body.disposition,
        confidence=body.confidence,
        rationale=body.rationale,
        requested_by=requested_by,
    )
    logger.info(
        "alert_writeback.completed",
        alert_id=str(alert_id),
        mode=report.mode,
        executed=report.executed_count,
        requested_by=str(requested_by).replace("\r", "").replace("\n", " ")[:128],
    )
    return report.as_dict()


@router.get(
    "/{alert_id}/source-links",
    response_model=list[SourceLinkResponse],
    summary="Which vendor findings produced this alert",
)
async def source_links(
    alert_id: uuid.UUID,
    db: DBSession,
    user: AuthUser,
) -> list[SourceLinkResponse]:
    """The reconciliation view: source findings and their last writeback."""
    user.require_permission("alerts:read")
    links = await links_for_alert(db, tenant_id=user.tenant_id, alert_id=alert_id)
    return [
        SourceLinkResponse(
            vendor=link.vendor,
            external_id=link.external_id,
            external_url=link.external_url,
            last_disposition=link.last_disposition,
            last_writeback_action=link.last_writeback_action,
            last_writeback_status=link.last_writeback_status,
            executed=link.executed,
        )
        for link in links
    ]
