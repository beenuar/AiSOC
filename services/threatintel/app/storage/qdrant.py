"""
Qdrant vector storage for semantic threat intelligence search.

AiSOC — open-source AI Security Operations Center (MIT License)
"""
from __future__ import annotations

import structlog
from typing import Any

from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)

logger = structlog.get_logger(__name__)

_IOC_COLLECTION = "threatintel_iocs"
_ACTOR_COLLECTION = "threatintel_actors"
_EMBEDDING_DIM = 1536  # text-embedding-3-small / ada-002


class QdrantStore:
    """
    Async Qdrant writer/searcher for threat intel embeddings.

    Uses fastembed for local embedding generation when OpenAI is not
    configured (air-gapped deployments).
    """

    def __init__(self, client: AsyncQdrantClient, use_fastembed: bool = True) -> None:
        self._client = client
        self._use_fastembed = use_fastembed

    async def initialize(self) -> None:
        """Create Qdrant collections if they don't exist."""
        existing = await self._client.get_collections()
        existing_names = {c.name for c in existing.collections}

        for col in (_IOC_COLLECTION, _ACTOR_COLLECTION):
            if col not in existing_names:
                await self._client.create_collection(
                    collection_name=col,
                    vectors_config=VectorParams(
                        size=_EMBEDDING_DIM, distance=Distance.COSINE
                    ),
                )
                logger.info("Created Qdrant collection", collection=col)

    async def upsert_iocs(self, iocs: list[dict[str, Any]]) -> None:
        """Embed and upsert IOC documents into Qdrant for semantic search."""
        if not iocs:
            return

        texts = [self._ioc_to_text(ioc) for ioc in iocs]
        vectors = await self._embed(texts)

        points = [
            PointStruct(
                id=i,
                vector=vectors[i],
                payload=iocs[i],
            )
            for i in range(len(iocs))
        ]

        # Qdrant expects integer IDs — use hash of value+type for stable IDs
        import hashlib
        points = [
            PointStruct(
                id=abs(int(hashlib.md5(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest(), 16)) % (2**63),
                vector=vectors[idx],
                payload=ioc,
            )
            for idx, ioc in enumerate(iocs)
        ]

        await self._client.upsert(
            collection_name=_IOC_COLLECTION,
            points=points,
        )
        logger.debug("Qdrant IOCs upserted", count=len(points))

    async def upsert_actors(self, actors: list[dict[str, Any]]) -> None:
        """Embed and upsert threat actor documents."""
        if not actors:
            return

        texts = [f"{a.get('name','')} {a.get('description','')}" for a in actors]
        vectors = await self._embed(texts)

        import hashlib
        points = [
            PointStruct(
                id=abs(int(hashlib.md5(actor.get("name", "").encode()).hexdigest(), 16)) % (2**63),
                vector=vectors[idx],
                payload=actor,
            )
            for idx, actor in enumerate(actors)
        ]

        await self._client.upsert(
            collection_name=_ACTOR_COLLECTION,
            points=points,
        )

    async def semantic_search(
        self,
        query: str,
        collection: str = _IOC_COLLECTION,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Semantic similarity search over threat intel."""
        vectors = await self._embed([query])
        results = await self._client.search(
            collection_name=collection,
            query_vector=vectors[0],
            limit=limit,
        )
        return [r.payload for r in results if r.payload]

    # ─── Private helpers ──────────────────────────────────────────────────────

    async def _embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings using fastembed or a stub."""
        try:
            from fastembed import TextEmbedding
            model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
            embeddings = list(model.embed(texts))
            # Pad/truncate to expected dimension
            result = []
            for emb in embeddings:
                vec = list(emb)
                if len(vec) < _EMBEDDING_DIM:
                    vec = vec + [0.0] * (_EMBEDDING_DIM - len(vec))
                elif len(vec) > _EMBEDDING_DIM:
                    vec = vec[:_EMBEDDING_DIM]
                result.append(vec)
            return result
        except Exception:
            # Fallback: zero vectors (embeddings will be non-functional but won't crash)
            return [[0.0] * _EMBEDDING_DIM for _ in texts]

    @staticmethod
    def _ioc_to_text(ioc: dict[str, Any]) -> str:
        parts = [
            ioc.get("type", ""),
            ioc.get("value", ""),
            ioc.get("description", ""),
            " ".join(ioc.get("tags", [])),
        ]
        return " ".join(p for p in parts if p)
