"""
OpenSearch storage layer for threat intelligence IOCs and actors.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog
from opensearchpy import AsyncOpenSearch, helpers

logger = structlog.get_logger(__name__)

_IOC_INDEX = "threatintel-iocs"
_ACTOR_INDEX = "threatintel-actors"

_IOC_MAPPING = {
    "mappings": {
        "properties": {
            "type": {"type": "keyword"},
            "value": {"type": "keyword"},
            "description": {"type": "text"},
            "tags": {"type": "keyword"},
            "source": {"type": "keyword"},
            "source_ref": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "confidence": {"type": "integer"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "ingested_at": {"type": "date"},
        }
    }
}

_ACTOR_MAPPING = {
    "mappings": {
        "properties": {
            "stix_id": {"type": "keyword"},
            "name": {"type": "keyword"},
            "aliases": {"type": "keyword"},
            "description": {"type": "text"},
            "sophistication": {"type": "keyword"},
            "primary_motivation": {"type": "keyword"},
            "source": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "ingested_at": {"type": "date"},
        }
    }
}


class OpenSearchStore:
    """
    Async OpenSearch writer for threat intel data.

    Manages index creation and provides bulk upsert methods.
    """

    def __init__(self, client: AsyncOpenSearch) -> None:
        self._os = client

    async def initialize(self) -> None:
        """Create indices if they don't exist."""
        for index, mapping in [(_IOC_INDEX, _IOC_MAPPING), (_ACTOR_INDEX, _ACTOR_MAPPING)]:
            if not await self._os.indices.exists(index=index):
                await self._os.indices.create(index=index, body=mapping)
                logger.info("Created OpenSearch index", index=index)

    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> int:
        """Bulk upsert IOCs into OpenSearch. Returns count of indexed docs."""
        if not iocs:
            return 0

        now = datetime.now(UTC).isoformat()
        actions = []
        for ioc in iocs:
            doc_id = _stable_id(ioc.get("type", ""), ioc.get("value", ""), ioc.get("source", ""))
            doc = {
                **ioc,
                "ingested_at": now,
                "last_seen": now,
            }
            actions.append(
                {
                    "_op_type": "index",
                    "_index": _IOC_INDEX,
                    "_id": doc_id,
                    "_source": doc,
                }
            )

        success, errors = await helpers.async_bulk(self._os, actions, raise_on_error=False)
        if errors:
            logger.warning("OpenSearch bulk errors", count=len(errors))
        return success

    async def bulk_index_actors(self, actors: list[dict[str, Any]]) -> int:
        """Bulk upsert threat actors."""
        if not actors:
            return 0

        now = datetime.now(UTC).isoformat()
        actions = []
        for actor in actors:
            doc_id = _stable_id("actor", actor.get("name", ""), actor.get("source", "stix"))
            actions.append(
                {
                    "_op_type": "index",
                    "_index": _ACTOR_INDEX,
                    "_id": doc_id,
                    "_source": {**actor, "ingested_at": now},
                }
            )

        success, _ = await helpers.async_bulk(self._os, actions, raise_on_error=False)
        return success

    async def search_iocs(
        self,
        value: str | None = None,
        ioc_type: str | None = None,
        source: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search IOCs by value, type, or source."""
        must: list[dict] = []
        if value:
            must.append({"term": {"value": value}})
        if ioc_type:
            must.append({"term": {"type": ioc_type}})
        if source:
            must.append({"term": {"source": source}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        resp = await self._os.search(
            index=_IOC_INDEX,
            body={"query": query, "size": limit, "sort": [{"last_seen": "desc"}]},
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    async def match_ioc_values(self, values: list[str]) -> list[str]:
        """Return the subset of ``values`` that exist in the IOC index.

        Public read-path consumed by callers that need to verify an arbitrary
        bag of indicator values (e.g. the threat actor attribution engine)
        against collected threat intel. Returns a deterministically sorted
        list of matched values; non-string and empty inputs are filtered.
        """
        cleaned = sorted({str(v) for v in values if v})
        if not cleaned:
            return []
        resp = await self._os.search(
            index=_IOC_INDEX,
            body={
                "query": {"terms": {"value": cleaned}},
                "size": min(len(cleaned), 100),
                "_source": ["value"],
            },
        )
        return sorted({hit["_source"]["value"] for hit in resp["hits"]["hits"]})


def _stable_id(type_: str, value: str, source: str) -> str:
    key = f"{type_}:{value}:{source}"
    return hashlib.sha256(key.encode()).hexdigest()
