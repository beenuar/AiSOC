"""POST /api/v1/osquery/distributed/enqueue — internal API for playbook engine.

This endpoint is NOT part of the standard osquery TLS plugin spec.
It is called by the AiSOC action client (``aisoc_direct_client``) to enqueue
a distributed query targeted at a specific host by its host_identifier.

Authentication uses the same bearer-token mechanism as the rest of the
internal service APIs (Authorization: Bearer <AISOC_OSQUERY_TLS_API_TOKEN>).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.distributed_queue import enqueue_query
from app.services.node_registry import get_node_by_host

router = APIRouter()


class EnqueueRequest(BaseModel):
    host_identifier: str
    query_text: str
    tenant_id: str = "default"


class EnqueueResponse(BaseModel):
    query_id: str


@router.post("/distributed/enqueue", response_model=EnqueueResponse)
async def distributed_enqueue(
    body: EnqueueRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EnqueueResponse:
    node = await get_node_by_host(db, body.host_identifier, body.tenant_id)
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {body.host_identifier!r} not enrolled for tenant {body.tenant_id!r}",
        )
    dq = await enqueue_query(db, node, body.query_text)
    return EnqueueResponse(query_id=dq.query_id)
