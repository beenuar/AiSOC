"""Node registry: enroll, look up, and refresh osquery nodes."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import generate_node_key
from app.models.node import OsqueryNode


async def get_node_by_key(db: AsyncSession, node_key: str) -> OsqueryNode | None:
    """Return the node with the given node_key, or None if not found."""
    result = await db.execute(select(OsqueryNode).where(OsqueryNode.node_key == node_key))
    return result.scalar_one_or_none()


async def get_node_by_host(db: AsyncSession, host_identifier: str, tenant_id: str) -> OsqueryNode | None:
    """Return a node by host_identifier + tenant, or None."""
    result = await db.execute(
        select(OsqueryNode).where(
            OsqueryNode.host_identifier == host_identifier,
            OsqueryNode.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()


async def enroll_node(
    db: AsyncSession,
    host_identifier: str,
    tenant_id: str,
    host_details: dict | None = None,
) -> OsqueryNode:
    """Enroll a new node or re-enroll an existing one (rotate node_key)."""
    existing = await get_node_by_host(db, host_identifier, tenant_id)
    if existing is not None:
        existing.node_key = generate_node_key()
        existing.host_details = host_details
        existing.last_seen = datetime.now(UTC)
        await db.commit()
        await db.refresh(existing)
        return existing

    node = OsqueryNode(
        host_identifier=host_identifier,
        node_key=generate_node_key(),
        tenant_id=tenant_id,
        host_details=host_details,
        last_seen=datetime.now(UTC),
    )
    db.add(node)
    await db.commit()
    await db.refresh(node)
    return node


async def mark_seen(db: AsyncSession, node: OsqueryNode) -> None:
    """Update last_seen timestamp for the given node."""
    await db.execute(update(OsqueryNode).where(OsqueryNode.id == node.id).values(last_seen=datetime.now(UTC)))
    await db.commit()
