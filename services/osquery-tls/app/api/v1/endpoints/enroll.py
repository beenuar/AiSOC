"""POST /api/v1/osquery/enroll — osquery TLS plugin enroll endpoint.

osqueryd calls this once on startup. If the enroll_secret matches, we
register the node (or rotate its node_key) and return a fresh node_key.

Reference:
  https://osquery.readthedocs.io/en/stable/deployment/remote/#enroll
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_enroll_secret
from app.db.session import get_db
from app.services.node_registry import enroll_node
from app.services.tenant_resolver import resolve_tenant_key

router = APIRouter()


class EnrollRequest(BaseModel):
    enroll_secret: str
    host_identifier: str
    host_details: dict | None = None


class EnrollResponse(BaseModel):
    node_key: str
    node_invalid: bool = False


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(
    body: EnrollRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_tenant: Annotated[str | None, Header()] = None,
) -> EnrollResponse:
    """Register an osquery node, or rotate its node_key.

    The credential here is the enroll secret, not a bearer token: osqueryd
    has no session and this is the call that establishes its identity. That
    is why this route is not behind ``require_console_or_service_auth`` — the
    enroll secret *is* the authentication, and it is verified per-tenant
    before anything is written.

    What changed is the tenant the node is filed under. The header ref used
    to be stored verbatim, defaulting to the literal ``"default"``, which
    matches no row in ``tenants`` on any seeded deployment — so every node
    enrolled into a tenancy the rest of the platform could not name, and the
    FIM console queried a UUID that nothing had ever been written under. The
    ref is now resolved to the canonical tenant UUID, and an unresolvable ref
    is refused rather than silently filed under a string nobody can read
    back.
    """
    tenant_ref = x_aisoc_tenant or "default"

    # Verified against the ref the operator configured on the agent, which is
    # what the secret was issued for. Resolution is a separate question from
    # authentication and must not change which secret is accepted.
    if not verify_enroll_secret(body.enroll_secret, tenant_ref):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"node_invalid": True},
        )

    tenant_id = await resolve_tenant_key(db, tenant_ref)
    if tenant_id is None:
        # Logged inside the resolver at warning with the ref. Refusing beats
        # enrolling into an unreadable tenancy: a node that never enrols is a
        # visible failure, a node filed under an unmatched string is not.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "node_invalid": True,
                "reason": (f"tenant {tenant_ref!r} does not resolve to a known tenant; set X-AiSOC-Tenant to the tenant UUID or slug"),
            },
        )

    node = await enroll_node(
        db,
        host_identifier=body.host_identifier,
        tenant_id=tenant_id,
        host_details=body.host_details,
    )
    return EnrollResponse(node_key=node.node_key)
