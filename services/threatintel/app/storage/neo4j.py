"""
Neo4j storage layer for threat intelligence relationships.

Writes IOC nodes, actor nodes, and their relationships into the
knowledge graph for attack path and blast-radius queries.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import logging
from typing import Any

from neo4j import AsyncDriver

logger = logging.getLogger(__name__)


class Neo4jStore:
    """
    Async Neo4j writer for threat intelligence graph data.
    """

    def __init__(self, driver: AsyncDriver) -> None:
        self._driver = driver

    async def upsert_iocs(self, iocs: list[dict[str, Any]]) -> None:
        """Merge IOC nodes into the graph."""
        if not iocs:
            return

        async with self._driver.session() as session:
            for ioc in iocs:
                await session.run(
                    """
                    MERGE (i:IOC {value: $value, type: $type})
                    ON CREATE SET
                        i.source      = $source,
                        i.tlp         = $tlp,
                        i.confidence  = $confidence,
                        i.first_seen  = $first_seen,
                        i.last_seen   = $last_seen,
                        i.tags        = $tags
                    ON MATCH SET
                        i.last_seen   = $last_seen,
                        i.confidence  = $confidence
                    """,
                    value=ioc.get("value", ""),
                    type=ioc.get("type", ""),
                    source=ioc.get("source", ""),
                    tlp=ioc.get("tlp", "white"),
                    confidence=ioc.get("confidence", 50),
                    first_seen=ioc.get("first_seen", ""),
                    last_seen=ioc.get("last_seen", ""),
                    tags=ioc.get("tags", []),
                )
        logger.debug("Neo4j IOCs upserted", count=len(iocs))

    async def upsert_actors(self, actors: list[dict[str, Any]]) -> None:
        """Merge threat actor nodes."""
        if not actors:
            return

        async with self._driver.session() as session:
            for actor in actors:
                await session.run(
                    """
                    MERGE (a:ThreatActor {name: $name})
                    ON CREATE SET
                        a.stix_id       = $stix_id,
                        a.aliases       = $aliases,
                        a.description   = $description,
                        a.sophistication= $sophistication,
                        a.source        = $source
                    ON MATCH SET
                        a.description   = $description
                    """,
                    name=actor.get("name", ""),
                    stix_id=actor.get("stix_id", ""),
                    aliases=actor.get("aliases", []),
                    description=actor.get("description", ""),
                    sophistication=actor.get("sophistication", ""),
                    source=actor.get("source", ""),
                )
        logger.debug("Neo4j actors upserted", count=len(actors))

    async def upsert_relationships(self, relationships: list[dict[str, Any]]) -> None:
        """Create USES/TARGETS/ATTRIBUTED_TO relationships between nodes."""
        if not relationships:
            return

        async with self._driver.session() as session:
            for rel in relationships:
                src = rel.get("source_name") or rel.get("source_id", "")
                tgt = rel.get("target_value") or rel.get("target_id", "")
                rel_type = rel.get("relationship_type", "RELATED_TO").upper().replace("-", "_")

                if not src or not tgt:
                    continue

                # Generic relationship query — works for actor→technique, actor→ioc, etc.
                try:
                    await session.run(
                        f"""
                        MATCH (a {{name: $src}})
                        MATCH (b {{value: $tgt}})
                        MERGE (a)-[r:{rel_type}]->(b)
                        ON CREATE SET r.source = $source
                        """,
                        src=src,
                        tgt=tgt,
                        source=rel.get("source", "stix"),
                    )
                except Exception:
                    # Fall through if nodes don't exist
                    pass

    async def link_ioc_to_technique(self, ioc_value: str, technique_id: str) -> None:
        """Link an IOC to a MITRE ATT&CK technique node."""
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (i:IOC {value: $ioc_value})
                MERGE (t:Technique {technique_id: $technique_id})
                MERGE (i)-[:INDICATES]->(t)
                """,
                ioc_value=ioc_value,
                technique_id=technique_id,
            )
