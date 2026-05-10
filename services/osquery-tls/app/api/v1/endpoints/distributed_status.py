"""GET /api/v1/osquery/distributed/{query_id} — check query status (internal API).

Used by ``aisoc_direct_client`` to poll for distributed query results.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.distributed_queue import get_query_by_id

router = APIRouter()


class QueryStatusResponse(BaseModel):
    query_id: str
    status: str
    rows: list[dict] | None = None
    error: str | None = None


@router.get("/distributed/{query_id}", response_model=QueryStatusResponse)
async def distributed_status(
    query_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> QueryStatusResponse:
    dq = await get_query_by_id(db, query_id)
    if dq is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Query {query_id!r} not found",
        )
    return QueryStatusResponse(
        query_id=dq.query_id,
        status=dq.status,
        rows=dq.results_json if dq.status == "completed" else None,
    )
