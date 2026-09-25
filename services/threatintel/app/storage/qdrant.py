"""
Qdrant vector storage for semantic threat intelligence search.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import hashlib
from typing import Any

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchAny,
    PointStruct,
    VectorParams,
)

logger = structlog.get_logger(__name__)

_IOC_COLLECTION = "threatintel_iocs"
_ACTOR_COLLECTION = "threatintel_actors"

#: Public aliases. The read route in ``app.api.indicators`` needs to name the
#: collection it scrolls, and importing a private name across modules is how
#: two spellings of the same string end up in the tree.
IOC_COLLECTION = _IOC_COLLECTION
ACTOR_COLLECTION = _ACTOR_COLLECTION
_EMBEDDING_DIM = 1536  # text-embedding-3-small / ada-002

# Sentinel tenant for globally-shared feed intel (STIX/TAXII/MISP), which is
# public and intentionally visible to every tenant. Tenant-submitted or private
# intel is stored under the owning tenant id and is never returned to others.
SHARED_TENANT = "shared"


def tenant_scope_filter(tenant_id: str | None, *, include_shared: bool = True) -> Filter | None:
    """Build the Qdrant payload filter that scopes a search to a tenant.

    - ``tenant_id=None`` -> no filter (privileged/global read; callers must gate).
    - ``tenant_id=X`` -> matches points owned by X, plus the shared feed intel
      when ``include_shared`` (the common analyst case).

    Every tenant-facing search path MUST pass a concrete ``tenant_id`` so a
    query as tenant A can never surface tenant B's private vectors.
    """
    if tenant_id is None:
        return None
    allowed = [tenant_id]
    if include_shared and tenant_id != SHARED_TENANT:
        allowed.append(SHARED_TENANT)
    return Filter(must=[FieldCondition(key="tenant_id", match=MatchAny(any=allowed))])


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
        """Create the collections, then converge the schema.

        Creation is `if not exists`, which is correct for a first run and a
        no-op afterwards — so on its own it can never change the shape of a
        collection that already exists. Anything beyond creation (a payload
        index, a quantization setting, and eventually a re-embed when the
        embedding model changes) has to come from the migration runner.
        """
        existing = await self._client.get_collections()
        existing_names = {c.name for c in existing.collections}

        for col in (_IOC_COLLECTION, _ACTOR_COLLECTION):
            if col not in existing_names:
                await self._client.create_collection(
                    collection_name=col,
                    vectors_config=VectorParams(size=_EMBEDDING_DIM, distance=Distance.COSINE),
                )
                logger.info("Created Qdrant collection", collection=col)

        await self._run_migrations()

    async def _run_migrations(self) -> None:
        """Apply pending vector-store migrations.

        Non-strict, matching the graph and lake runners: threat-intel
        enrichment degrades rather than taking the service down, and a
        pending migration is logged at ``error`` so a degraded start is
        visible rather than assumed.
        """
        try:
            from app.db.vector_migrations import (  # noqa: PLC0415
                pending_ids,
                pending_rebuilds,
                run_migrations,
            )
        except ImportError:
            # The runner lives in services/api and is vendored into
            # deployments that need it. Its absence means no migrations to
            # apply, not a broken store.
            return

        rebuilds = await pending_rebuilds(self._client)
        if rebuilds:
            logger.warning(
                "vector migrations include a re-embed; this is measured in "
                "hours for a large tenant and the alias keeps the existing "
                "collection serving until it completes",
                migrations=rebuilds,
            )

        applied = await run_migrations(self._client, strict=False)
        pending = await pending_ids(self._client)

        if applied:
            logger.info("Qdrant migrations applied", migrations=applied)
        if pending:
            logger.error("Qdrant migrations still pending", migrations=pending)

    async def upsert_iocs(self, iocs: list[dict[str, Any]], *, tenant_id: str = SHARED_TENANT) -> None:
        """Embed and upsert IOC documents into Qdrant for semantic search.

        ``tenant_id`` defaults to :data:`SHARED_TENANT` (global feed intel). It
        is stamped into every payload and folded into the point id so the same
        IOC submitted by two tenants does not collide or overwrite.
        """
        if not iocs:
            return

        texts = [self._ioc_to_text(ioc) for ioc in iocs]
        vectors = await self._embed(texts)

        points = [
            PointStruct(
                id=self._point_id(tenant_id, f"{ioc['type']}:{ioc['value']}"),
                vector=vectors[idx],
                payload={**ioc, "tenant_id": tenant_id},
            )
            for idx, ioc in enumerate(iocs)
        ]

        await self._client.upsert(
            collection_name=_IOC_COLLECTION,
            points=points,
        )
        logger.debug("Qdrant IOCs upserted", count=len(points), tenant_id=tenant_id)

    async def upsert_actors(self, actors: list[dict[str, Any]], *, tenant_id: str = SHARED_TENANT) -> None:
        """Embed and upsert threat actor documents (tenant-scoped payload + id)."""
        if not actors:
            return

        texts = [f"{a.get('name', '')} {a.get('description', '')}" for a in actors]
        vectors = await self._embed(texts)

        points = [
            PointStruct(
                id=self._point_id(tenant_id, actor.get("name", "")),
                vector=vectors[idx],
                payload={**actor, "tenant_id": tenant_id},
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
        *,
        tenant_id: str | None = None,
        include_shared: bool = True,
    ) -> list[dict[str, Any]]:
        """Semantic similarity search over threat intel, scoped to a tenant.

        Tenant-facing callers MUST pass ``tenant_id`` so a search as tenant A
        can never surface tenant B's private vectors. ``tenant_id=None`` is a
        privileged/global read and callers are responsible for gating it.
        """
        vectors = await self._embed([query])
        results = await self._client.search(
            collection_name=collection,
            query_vector=vectors[0],
            limit=limit,
            query_filter=tenant_scope_filter(tenant_id, include_shared=include_shared),
        )
        return [r.payload for r in results if r.payload]

    @staticmethod
    def _point_id(tenant_id: str, natural_key: str) -> int:
        """Stable, tenant-scoped 63-bit point id (no cross-tenant collisions)."""
        raw = f"{tenant_id}:{natural_key}".encode()
        return abs(int(hashlib.md5(raw, usedforsecurity=False).hexdigest(), 16)) % (2**63)

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
