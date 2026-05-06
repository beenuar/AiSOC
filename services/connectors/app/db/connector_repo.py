"""Read/write access to the canonical ``connectors`` table.

The schema for that table lives in ``services/api/app/models/connector.py``;
the API service owns the migrations. We deliberately do **not** import that
ORM model here — it would drag the API's full app.* package into our import
graph. Instead we pin the column shape via SQLAlchemy Core ``Table``/
``MetaData`` against the same ``connectors`` table and limit ourselves to the
columns the scheduler needs.

If the API service ever changes the column shape in a backwards-incompatible
way, the scheduler will fail loudly at first poll (column not found), which is
what we want — silent drift between two services that share a table is the
worst possible failure mode.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()

# Mirror of services/api/app/models/connector.py:Connector. Only includes the
# columns the scheduler reads or writes; we don't claim ownership of the full
# table shape.
connectors_table = Table(
    "connectors",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("name", String(255), nullable=False),
    Column("connector_type", String(100), nullable=False),
    Column("category", String(50), nullable=False),
    Column("is_enabled", Boolean, nullable=False),
    Column("auth_config", JSONB, nullable=False),
    Column("connector_config", JSONB, nullable=False),
    Column("health_status", String(20), nullable=False),
    Column("last_health_check", DateTime(timezone=True)),
    Column("last_sync", DateTime(timezone=True)),
    Column("events_ingested", Integer, nullable=False),
    Column("error_count", Integer, nullable=False),
    Column("tags", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


@dataclass
class ConnectorInstance:
    """Light dataclass over a row in ``connectors``.

    We use a plain dataclass instead of an ORM mapping so the scheduler stays
    decoupled from the API service's ``Base`` declarative class and avoids
    lazy-loading attributes from a closed session by mistake.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    connector_type: str
    is_enabled: bool
    auth_config: dict[str, Any]
    connector_config: dict[str, Any]
    health_status: str
    last_sync: datetime | None
    events_ingested: int
    error_count: int


async def fetch_enabled_connectors(connection: Any) -> list[ConnectorInstance]:
    """Return every connector instance with ``is_enabled = True``.

    ``connection`` must be a SQLAlchemy ``AsyncConnection``. We accept ``Any``
    in the type hint to avoid forcing every caller to import the async
    connection type.
    """
    stmt = select(
        connectors_table.c.id,
        connectors_table.c.tenant_id,
        connectors_table.c.name,
        connectors_table.c.connector_type,
        connectors_table.c.is_enabled,
        connectors_table.c.auth_config,
        connectors_table.c.connector_config,
        connectors_table.c.health_status,
        connectors_table.c.last_sync,
        connectors_table.c.events_ingested,
        connectors_table.c.error_count,
    ).where(connectors_table.c.is_enabled.is_(True))

    result = await connection.execute(stmt)
    rows = result.fetchall()
    return [
        ConnectorInstance(
            id=row.id,
            tenant_id=row.tenant_id,
            name=row.name,
            connector_type=row.connector_type,
            is_enabled=row.is_enabled,
            auth_config=row.auth_config or {},
            connector_config=row.connector_config or {},
            health_status=row.health_status,
            last_sync=row.last_sync,
            events_ingested=row.events_ingested,
            error_count=row.error_count,
        )
        for row in rows
    ]


async def record_poll_success(
    connection: Any,
    connector_id: uuid.UUID,
    *,
    events_added: int,
) -> None:
    """Update last_sync, increment events_ingested, mark healthy."""
    now = datetime.now(UTC)
    stmt = (
        update(connectors_table)
        .where(connectors_table.c.id == connector_id)
        .values(
            last_sync=now,
            last_health_check=now,
            health_status="healthy",
            events_ingested=connectors_table.c.events_ingested + events_added,
            updated_at=now,
        )
    )
    await connection.execute(stmt)


async def record_poll_failure(
    connection: Any,
    connector_id: uuid.UUID,
) -> None:
    """Mark a poll attempt as failed without touching last_sync."""
    now = datetime.now(UTC)
    stmt = (
        update(connectors_table)
        .where(connectors_table.c.id == connector_id)
        .values(
            last_health_check=now,
            health_status="unhealthy",
            error_count=connectors_table.c.error_count + 1,
            updated_at=now,
        )
    )
    await connection.execute(stmt)


__all__ = [
    "ConnectorInstance",
    "connectors_table",
    "fetch_enabled_connectors",
    "metadata",
    "record_poll_failure",
    "record_poll_success",
]
