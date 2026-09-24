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


async def get_query_by_id(db: AsyncSession, query_id: str, tenant_id: str | uuid.UUID | None = None) -> OsqueryDistributedQuery | None:
    """Look up a distributed query by its query_id.

    ``osquery_distributed_query`` carries no ``tenant_id`` of its own — it is
    scoped through the node it was sent to — so when a request supplies a
    tenant the lookup joins onto ``osquery_node`` rather than trusting the
    id. Without that join a query_id is a bearer capability for another
    tenant's host telemetry.
    """
    stmt = select(OsqueryDistributedQuery).where(OsqueryDistributedQuery.query_id == query_id)
    if tenant_id is not None:
        # osquery_node.tenant_id is VARCHAR: the rest of this service stores
        # the tenant as a string, so coerce rather than binding a UUID object
        # against a text column and relying on the driver to guess.
        stmt = stmt.join(OsqueryNode, OsqueryNode.id == OsqueryDistributedQuery.node_id).where(OsqueryNode.tenant_id == str(tenant_id))
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
