"""
Neo4j driver singleton for AiSOC graph layer.
Cyble Open-Source AI Security Operations Center - MIT License
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import ServiceUnavailable

from app.core.config import settings

logger = logging.getLogger(__name__)

_driver: Optional[AsyncDriver] = None


async def init_neo4j() -> None:
    """Initialize the Neo4j async driver and verify connectivity."""
    global _driver
    if _driver is not None:
        return

    _driver = AsyncGraphDatabase.driver(
        settings.NEO4J_URI,
        auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        max_connection_pool_size=50,
        connection_acquisition_timeout=30,
    )

    # Verify connectivity with retries
    for attempt in range(5):
        try:
            await _driver.verify_connectivity()
            logger.info("Neo4j connection established", uri=settings.NEO4J_URI)

            # Create schema constraints and indexes
            await _create_schema()
            return
        except ServiceUnavailable:
            if attempt < 4:
                wait = 2 ** attempt
                logger.warning("Neo4j not ready, retrying", attempt=attempt + 1, wait=wait)
                await asyncio.sleep(wait)
            else:
                logger.error("Neo4j connection failed after retries")
                raise


async def close_neo4j() -> None:
    """Close the Neo4j driver."""
    global _driver
    if _driver:
        await _driver.close()
        _driver = None
        logger.info("Neo4j connection closed")


def get_driver() -> AsyncDriver:
    """Return the singleton Neo4j driver. Raises if not initialized."""
    if _driver is None:
        raise RuntimeError("Neo4j driver not initialized. Call init_neo4j() first.")
    return _driver


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager yielding a Neo4j session."""
    driver = get_driver()
    async with driver.session(database="neo4j") as session:
        yield session


async def _create_schema() -> None:
    """Create constraints and indexes for the graph schema."""
    constraints = [
        # Uniqueness constraints
        "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Case) REQUIRE c.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.id IS UNIQUE",
        # Indexes for common lookups
        "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
        "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.tenant_id)",
        "CREATE INDEX IF NOT EXISTS FOR (u:User) ON (u.username)",
        "CREATE INDEX IF NOT EXISTS FOR (u:User) ON (u.tenant_id)",
        "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.tenant_id)",
        "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
        "CREATE INDEX IF NOT EXISTS FOR (i:IOC) ON (i.ioc_type)",
        "CREATE INDEX IF NOT EXISTS FOR (i:IOC) ON (i.tenant_id)",
        "CREATE INDEX IF NOT EXISTS FOR (t:Technique) ON (t.tactic)",
    ]

    async with get_session() as session:
        for cypher in constraints:
            try:
                await session.run(cypher)
            except Exception as exc:
                logger.debug("Schema statement skipped", cypher=cypher[:60], error=str(exc))

    logger.info("Neo4j schema constraints and indexes ensured")
