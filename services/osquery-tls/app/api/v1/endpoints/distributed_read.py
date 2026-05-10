"""POST /api/v1/osquery/distributed/read — dequeue pending queries for a node.

Reference:
  https://osquery.readthedocs.io/en/stable/deployment/remote/#distributed-queries
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_valid_node_key
from app.db.session import get_db
from app.models.node import OsqueryNode
from app.services.distributed_queue import get_pending_queries
from app.services.node_registry import mark_seen

router = APIRouter()


@router.post("/distributed/read")
async def distributed_read(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    node: Annotated[OsqueryNode, Depends(require_valid_node_key)],
) -> dict:
    await mark_seen(db, node)
    pending = await get_pending_queries(db, node)
    queries = {dq.query_id: dq.query_text for dq in pending}
    return {"queries": queries, "node_invalid": False}
