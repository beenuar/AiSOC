"""The route a playbook step reaches governed dispatch through.

The playbook engine runs in ``services/agents``, which holds no credential
vault and no tenant database session. It therefore cannot dispatch a response
action, and until now it did not try: ``block_ip`` and ``isolate_host``
returned ``{"simulated": true}`` from inside the engine and twelve further
step types had no handler at all.

This route is the hop between them. It authenticates the same two ways
``alerts/{id}/source-writeback`` does — a session for a person, a shared
service token for the agents worker — and delegates every question about
whether the action may run to ``services/actions``, which owns the contract.

One step, one request, one grading. A playbook is not approved as a unit:
each step arrives here on its own and is graded on its own capability, so
authorising a playbook cannot authorise whatever its steps happen to contain.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.alert_writeback import optional_user, service_token_valid
from app.db.database import get_db
from app.services.playbook_step_dispatch import dispatch_step

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/playbook-steps", tags=["playbooks"])


class StepDispatchRequest(BaseModel):
    """One playbook step, expressed as the verb it names."""

    capability: str = Field(description="Response verb, e.g. 'isolate_host'. Must be a registered capability.")
    target: str = Field(default="", max_length=512, description="Host, user, address or id the verb acts on.")
    params: dict[str, Any] = Field(default_factory=dict)
    vendor_id: str = Field(default="", max_length=64, description="Pin a vendor. Honoured only if the tenant has it configured.")
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    #: Defaults to a preview. Every caller that wants a vendor touched has to
    #: say so — a forgotten field should cost a preview, not a containment.
    dry_run: bool = True
    playbook_run_id: str = Field(default="", max_length=64)
    playbook_step_id: str = Field(default="", max_length=64)
    #: Required from a service caller, which has no session to read it from.
    #: Ignored for a session caller, whose tenant comes from the session.
    tenant_id: uuid.UUID | None = None


def _resolve_caller(
    body_tenant_id: uuid.UUID | None,
    user: CurrentUser | None,
    service_token: str | None,
) -> tuple[uuid.UUID, str]:
    """``(tenant_id, requested_by)`` for an authorised caller, or 401/403.

    A session's tenant comes from the session. Taking the client's copy would
    let any authenticated user drive a containment against another tenant's
    estate through a playbook step.
    """
    if user is not None:
        user.require_permission("actions:execute")
        return user.tenant_id, f"user:{user.email}"

    if service_token_valid(service_token):
        if body_tenant_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="a service caller must name the tenant it is acting for",
            )
        return body_tenant_id, "aisoc-playbook"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/dispatch", summary="Run one playbook step through governed action dispatch")
async def dispatch_playbook_step(
    body: StepDispatchRequest,
    user: Annotated[CurrentUser | None, Depends(optional_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Dispatch one step and report what actually happened.

    Never raises for an action-level outcome. A blocked action, an approval
    queue, a missing integration and a vendor failure are all 200 with
    ``executed: false`` and a status naming which one it was, so the engine
    has a single shape to read. ``HTTPException`` is reserved for callers
    this route will not serve at all.
    """
    tenant_id, requested_by = _resolve_caller(body.tenant_id, user, x_aisoc_service_token)

    report = await dispatch_step(
        db,
        tenant_id=tenant_id,
        capability=body.capability,
        target=body.target,
        params=body.params,
        vendor_id=body.vendor_id,
        confidence=body.confidence,
        dry_run=body.dry_run,
        requested_by=requested_by,
        playbook_run_id=body.playbook_run_id,
        playbook_step_id=body.playbook_step_id,
    )
    return report.as_dict()
