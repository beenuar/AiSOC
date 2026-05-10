"""Distributed query queue: enqueue and dequeue per-node ad-hoc queries."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.distributed_query import OsqueryDistributedQuery
from app.models.node import OsqueryNode


async def enqueue_query(db: AsyncSession, node: OsqueryNode, query_text: str) -> OsqueryDistributedQuery:
    """Add a new distributed query for the given node and return it."""
    dq = OsqueryDistributedQuery(
        node_id=node.id,
        query_id=str(uuid.uuid4()),
        query_text=query_text,
        status="pending",
    )
    db.add(dq)
    await db.commit()
    await db.refresh(dq)
    return dq


async def get_pending_queries(db: AsyncSession, node: OsqueryNode) -> list[OsqueryDistributedQuery]:
    """Return all pending distributed queries for this node."""
    result = await db.execute(
        select(OsqueryDistributedQuery).where(
            OsqueryDistributedQuery.node_id == node.id,
            OsqueryDistributedQuery.status == "pending",
        )
    )
    return list(result.scalars().all())


async def complete_query(
    db: AsyncSession,
    query_id: str,
    results: list[dict],
) -> None:
    """Mark a distributed query as completed and store its results."""
    await db.execute(
        update(OsqueryDistributedQuery)
        .where(OsqueryDistributedQuery.query_id == query_id)
        .values(
            status="completed",
            completed_at=datetime.now(UTC),
            results_json=results,
        )
    )
    await db.commit()


async def get_query_by_id(db: AsyncSession, query_id: str) -> OsqueryDistributedQuery | None:
    """Look up a distributed query by its query_id."""
    result = await db.execute(select(OsqueryDistributedQuery).where(OsqueryDistributedQuery.query_id == query_id))
    return result.scalar_one_or_none()
