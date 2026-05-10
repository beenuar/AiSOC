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
    tenant_id = x_aisoc_tenant or "default"

    if not verify_enroll_secret(body.enroll_secret, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"node_invalid": True},
        )

    node = await enroll_node(
        db,
        host_identifier=body.host_identifier,
        tenant_id=tenant_id,
        host_details=body.host_details,
    )
    return EnrollResponse(node_key=node.node_key)
