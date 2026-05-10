"""POST /api/v1/osquery/distributed/write — receive completed distributed query results.

Reference:
  https://osquery.readthedocs.io/en/stable/deployment/remote/#distributed-queries
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_valid_node_key
from app.db.session import get_db
from app.models.node import OsqueryNode
from app.services.distributed_queue import complete_query
from app.services.log_forwarder import forward_events
from app.services.node_registry import mark_seen
from app.services.normalizer import normalize_row

router = APIRouter()


class DistributedWriteRequest(BaseModel):
    node_key: str
    queries: dict[str, list[dict]]  # query_id -> list of result rows
    statuses: dict[str, int] = {}  # query_id -> exit code


@router.post("/distributed/write")
async def distributed_write(
    body: DistributedWriteRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    node: Annotated[OsqueryNode, Depends(require_valid_node_key)],
) -> dict:
    await mark_seen(db, node)

    events: list[dict] = []
    for query_id, rows in body.queries.items():
        await complete_query(db, query_id, rows)
        for row in rows:
            events.append(
                normalize_row(
                    row,
                    host_identifier=node.host_identifier,
                    tenant_id=node.tenant_id,
                    query_name=query_id,
                    log_type="distributed",
                )
            )

    await forward_events(events, node.tenant_id)
    return {"node_invalid": False}
