"""Episodic case memory — past cases the Investigator can recall.

Two-tier design:

* **SQLite (SQLModel) mirror** — always-on durable store. Every write lands
  here, even when Qdrant is the primary read path. We never want to lose
  closed-case history because a vector DB blipped.
* **Qdrant** — optional vector-search accelerator. When configured and
  reachable it answers ``episodic_recall`` directly; otherwise we scan
  the SQLite mirror in-process (same cosine math as before).

Tenancy is enforced at the query layer in both backends: a single-tenant
caller is restricted to its own ``tenant_id``; an MSSP parent can pass
``allowed_tenants`` to span its child tenants. Cross-tenant pattern
sharing is a separate, opt-in federated-signal flow (Theme 3b) that
goes through k-anonymity + DP first.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.memory.embedding import cosine, embed, embedding_dim
from app.models.memory import EpisodicMemory

logger = logging.getLogger(__name__)


# ── Backend protocol ──────────────────────────────────────────────────
class _Backend(Protocol):
    """Recall side of the interface. Writes always go to SQLite first."""

    def upsert(
        self,
        *,
        case_id: int,
        tenant_id: str,
        title: str,
        narrative: str,
        verdict: str,
        tags: list[str],
        vector: list[float],
    ) -> None: ...

    def recall(
        self,
        *,
        vector: list[float],
        k: int,
        tenant_id: str | None,
        allowed_tenants: list[str] | None,
    ) -> list[dict]: ...


# ── SQLite backend (durable mirror, always present) ───────────────────
class _SQLiteBackend:
    """In-process cosine scan over the SQLModel store.

    This is the original implementation, kept as the source of truth.
    """

    def upsert(
        self,
        *,
        case_id: int,
        tenant_id: str,
        title: str,
        narrative: str,
        verdict: str,
        tags: list[str],
        vector: list[float],
    ) -> None:
        with session_scope() as s:
            existing = s.exec(
                select(EpisodicMemory).where(EpisodicMemory.case_id == case_id)
            ).first()
            if existing:
                existing.tenant_id = tenant_id
                existing.title = title
                existing.narrative = narrative
                existing.verdict = verdict
                existing.tags = tags
                existing.embedding = vector
                s.add(existing)
            else:
                s.add(
                    EpisodicMemory(
                        case_id=case_id,
                        tenant_id=tenant_id,
                        title=title,
                        narrative=narrative,
                        verdict=verdict,
                        tags=tags,
                        embedding=vector,
                    )
                )

    def recall(
        self,
        *,
        vector: list[float],
        k: int,
        tenant_id: str | None,
        allowed_tenants: list[str] | None,
    ) -> list[dict]:
        with session_scope() as s:
            stmt = select(EpisodicMemory)
            if allowed_tenants:
                stmt = stmt.where(EpisodicMemory.tenant_id.in_(allowed_tenants))
            elif tenant_id is not None:
                stmt = stmt.where(EpisodicMemory.tenant_id == tenant_id)
            memories = s.exec(stmt).all()
            snapshots = [
                {
                    "case_id": m.case_id,
                    "tenant_id": m.tenant_id,
                    "title": m.title,
                    "verdict": m.verdict,
                    "tags": list(m.tags or []),
                    "narrative": (m.narrative or "")[:200],
                    "embedding": list(m.embedding or []),
                }
                for m in memories
            ]
        scored = [
            (cosine(vector, snap["embedding"]), snap)
            for snap in snapshots
            if snap["embedding"]
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "case_id": snap["case_id"],
                "tenant_id": snap["tenant_id"],
                "title": snap["title"],
                "verdict": snap["verdict"],
                "similarity": round(score, 3),
                "tags": snap["tags"],
                "narrative": snap["narrative"],
            }
            for score, snap in scored[:k]
            if score > 0.05
        ]


# ── Qdrant backend ────────────────────────────────────────────────────
class _QdrantBackend:
    """Qdrant-backed recall with payload-filter tenancy.

    Layout:
        Collection:  ``{qdrant_collection_prefix}``  (single collection)
        Point id:    case_id (int)
        Vector:      embedding(title + narrative + tags)
        Payload:     {tenant_id, case_id, title, narrative, verdict, tags}

    Writes also flow through ``fallback`` so the SQLite mirror stays
    current. Reads prefer Qdrant; on any error we silently degrade to
    the mirror so the case keeps moving.
    """

    def __init__(
        self,
        *,
        client: Any,
        collection: str,
        fallback: _Backend,
        models: Any,
    ) -> None:
        self._client = client
        self._collection = collection
        self._fallback = fallback
        # qdrant_client.http.models — passed in so we don't re-import per call.
        self._models = models
        self._collection_ready = False
        self._ready_lock = threading.Lock()

    # -- collection bootstrap ---------------------------------------------
    def _ensure_collection(self, dim: int) -> bool:
        """Create the collection on first use; return False on failure."""
        if self._collection_ready:
            return True
        with self._ready_lock:
            if self._collection_ready:
                return True
            try:
                exists = self._client.collection_exists(self._collection)
            except Exception as exc:  # pragma: no cover - depends on env
                logger.warning(
                    "qdrant collection_exists failed (%s); using SQLite mirror",
                    exc,
                )
                return False
            if not exists:
                try:
                    self._client.create_collection(
                        collection_name=self._collection,
                        vectors_config=self._models.VectorParams(
                            size=dim,
                            distance=self._models.Distance.COSINE,
                        ),
                    )
                    # Index tenant_id so payload-filter recall is fast.
                    try:
                        self._client.create_payload_index(
                            collection_name=self._collection,
                            field_name="tenant_id",
                            field_schema=self._models.PayloadSchemaType.KEYWORD,
                        )
                    except Exception as exc:  # pragma: no cover - depends on env
                        logger.debug(
                            "qdrant payload index create failed (non-fatal): %s",
                            exc,
                        )
                except Exception as exc:  # pragma: no cover - depends on env
                    logger.warning(
                        "qdrant create_collection failed (%s); using SQLite mirror",
                        exc,
                    )
                    return False
            self._collection_ready = True
            return True

    # -- writes -----------------------------------------------------------
    def upsert(
        self,
        *,
        case_id: int,
        tenant_id: str,
        title: str,
        narrative: str,
        verdict: str,
        tags: list[str],
        vector: list[float],
    ) -> None:
        # Always mirror to SQLite first — durable source of truth.
        self._fallback.upsert(
            case_id=case_id,
            tenant_id=tenant_id,
            title=title,
            narrative=narrative,
            verdict=verdict,
            tags=tags,
            vector=vector,
        )
        if not vector:
            return
        if not self._ensure_collection(len(vector)):
            return
        try:
            self._client.upsert(
                collection_name=self._collection,
                points=[
                    self._models.PointStruct(
                        id=int(case_id),
                        vector=list(vector),
                        payload={
                            "case_id": int(case_id),
                            "tenant_id": tenant_id,
                            "title": title,
                            "narrative": (narrative or "")[:1000],
                            "verdict": verdict,
                            "tags": list(tags or []),
                        },
                    )
                ],
            )
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning(
                "qdrant upsert failed for case=%s (%s); SQLite mirror still has it",
                case_id,
                exc,
            )

    # -- reads ------------------------------------------------------------
    def recall(
        self,
        *,
        vector: list[float],
        k: int,
        tenant_id: str | None,
        allowed_tenants: list[str] | None,
    ) -> list[dict]:
        if not vector:
            return self._fallback.recall(
                vector=vector,
                k=k,
                tenant_id=tenant_id,
                allowed_tenants=allowed_tenants,
            )
        if not self._ensure_collection(len(vector)):
            return self._fallback.recall(
                vector=vector,
                k=k,
                tenant_id=tenant_id,
                allowed_tenants=allowed_tenants,
            )
        flt = self._build_filter(tenant_id, allowed_tenants)
        try:
            # Prefer the modern query_points API; fall back to legacy search
            # for older qdrant-client versions still in the wild.
            hits = self._query(vector=vector, k=k, flt=flt)
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning(
                "qdrant recall failed (%s); using SQLite mirror",
                exc,
            )
            return self._fallback.recall(
                vector=vector,
                k=k,
                tenant_id=tenant_id,
                allowed_tenants=allowed_tenants,
            )
        out: list[dict] = []
        for h in hits:
            payload = getattr(h, "payload", None) or {}
            score = float(getattr(h, "score", 0.0) or 0.0)
            if score <= 0.05:
                continue
            out.append(
                {
                    "case_id": int(payload.get("case_id") or getattr(h, "id", 0) or 0),
                    "tenant_id": payload.get("tenant_id", ""),
                    "title": payload.get("title", ""),
                    "verdict": payload.get("verdict", ""),
                    "similarity": round(score, 3),
                    "tags": list(payload.get("tags") or []),
                    "narrative": (payload.get("narrative") or "")[:200],
                }
            )
        return out

    def _build_filter(
        self,
        tenant_id: str | None,
        allowed_tenants: list[str] | None,
    ) -> Any | None:
        models = self._models
        if allowed_tenants:
            return models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchAny(any=list(allowed_tenants)),
                    )
                ]
            )
        if tenant_id is not None:
            return models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchValue(value=tenant_id),
                    )
                ]
            )
        return None

    def _query(
        self,
        *,
        vector: list[float],
        k: int,
        flt: Any | None,
    ) -> list[Any]:
        query_points = getattr(self._client, "query_points", None)
        if callable(query_points):
            resp = query_points(
                collection_name=self._collection,
                query=list(vector),
                query_filter=flt,
                limit=max(1, k),
                with_payload=True,
            )
            return list(getattr(resp, "points", resp) or [])
        # Legacy fallback for older qdrant-client (<=1.7-ish).
        return list(
            self._client.search(  # type: ignore[attr-defined]
                collection_name=self._collection,
                query_vector=list(vector),
                query_filter=flt,
                limit=max(1, k),
                with_payload=True,
            )
        )


# ── pgvector backend ──────────────────────────────────────────────────
class _PgVectorBackend:
    """PostgreSQL + pgvector recall, with SQLite mirror as durable fallback.

    Layout (one row per case):
        Table:   ``{pgvector_table}``
        Columns: case_id BIGINT PRIMARY KEY,
                 tenant_id TEXT NOT NULL,
                 title TEXT, narrative TEXT, verdict TEXT,
                 tags TEXT[] (JSON-encoded if jsonb unavailable),
                 embedding vector({dim})
        Index:   (tenant_id), ivfflat on embedding (cosine).

    Writes mirror to SQLite first. Reads prefer pgvector; on any error
    we silently degrade to the mirror so the case keeps moving — same
    posture as the Qdrant backend.
    """

    def __init__(
        self,
        *,
        dsn: str,
        table: str,
        fallback: _Backend,
        pool: Any | None = None,
    ) -> None:
        self._dsn = dsn
        # Quote identifier defensively (admins set this; still belt-and-braces).
        safe = "".join(ch for ch in table if ch.isalnum() or ch == "_")
        self._table = safe or "aisoc_episodic_memory"
        self._fallback = fallback
        self._pool = pool  # psycopg_pool.ConnectionPool or None
        self._table_ready = False
        self._ready_lock = threading.Lock()

    # -- connection helpers ----------------------------------------------
    def _connect(self) -> Any:
        if self._pool is not None:
            return self._pool.connection()
        import psycopg  # type: ignore

        return psycopg.connect(self._dsn, connect_timeout=5)

    def _ensure_table(self, dim: int) -> bool:
        if self._table_ready:
            return True
        with self._ready_lock:
            if self._table_ready:
                return True
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                        cur.execute(
                            f"""
                            CREATE TABLE IF NOT EXISTS {self._table} (
                                case_id BIGINT PRIMARY KEY,
                                tenant_id TEXT NOT NULL,
                                title TEXT NOT NULL,
                                narrative TEXT NOT NULL DEFAULT '',
                                verdict TEXT NOT NULL DEFAULT '',
                                tags JSONB NOT NULL DEFAULT '[]'::jsonb,
                                embedding vector({int(dim)})
                            )
                            """
                        )
                        cur.execute(
                            f"CREATE INDEX IF NOT EXISTS "
                            f"{self._table}_tenant_idx ON {self._table}(tenant_id)"
                        )
                        # ivfflat needs ANALYZE-able data; create it lazily.
                        # Catch failures because some managed Postgres flavors
                        # ship pgvector without ivfflat (rare); cosine is the
                        # right op-class for our embeddings.
                        try:
                            cur.execute(
                                f"CREATE INDEX IF NOT EXISTS "
                                f"{self._table}_embedding_idx ON {self._table} "
                                f"USING ivfflat (embedding vector_cosine_ops) "
                                f"WITH (lists = 100)"
                            )
                        except Exception as exc:  # pragma: no cover - env dependent
                            logger.debug(
                                "pgvector ivfflat index skipped (non-fatal): %s",
                                exc,
                            )
                    conn.commit()
            except Exception as exc:  # pragma: no cover - depends on env
                logger.warning(
                    "pgvector ensure_table failed (%s); using SQLite mirror",
                    exc,
                )
                return False
            self._table_ready = True
            return True

    @staticmethod
    def _vector_literal(vec: list[float]) -> str:
        # pgvector accepts a textual literal like '[0.1,0.2,...]'. This
        # avoids needing the `pgvector` python adapter — psycopg alone is
        # enough, which keeps our optional-deps surface small.
        return "[" + ",".join(f"{float(x):.6f}" for x in vec) + "]"

    # -- writes -----------------------------------------------------------
    def upsert(
        self,
        *,
        case_id: int,
        tenant_id: str,
        title: str,
        narrative: str,
        verdict: str,
        tags: list[str],
        vector: list[float],
    ) -> None:
        self._fallback.upsert(
            case_id=case_id,
            tenant_id=tenant_id,
            title=title,
            narrative=narrative,
            verdict=verdict,
            tags=tags,
            vector=vector,
        )
        if not vector:
            return
        if not self._ensure_table(len(vector)):
            return
        try:
            import json as _json

            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO {self._table}
                            (case_id, tenant_id, title, narrative, verdict, tags, embedding)
                        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::vector)
                        ON CONFLICT (case_id) DO UPDATE SET
                            tenant_id = EXCLUDED.tenant_id,
                            title = EXCLUDED.title,
                            narrative = EXCLUDED.narrative,
                            verdict = EXCLUDED.verdict,
                            tags = EXCLUDED.tags,
                            embedding = EXCLUDED.embedding
                        """,
                        (
                            int(case_id),
                            tenant_id,
                            title,
                            narrative or "",
                            verdict or "",
                            _json.dumps(list(tags or [])),
                            self._vector_literal(vector),
                        ),
                    )
                conn.commit()
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning(
                "pgvector upsert failed for case=%s (%s); SQLite mirror still has it",
                case_id,
                exc,
            )

    # -- reads ------------------------------------------------------------
    def recall(
        self,
        *,
        vector: list[float],
        k: int,
        tenant_id: str | None,
        allowed_tenants: list[str] | None,
    ) -> list[dict]:
        if not vector or not self._ensure_table(len(vector)):
            return self._fallback.recall(
                vector=vector,
                k=k,
                tenant_id=tenant_id,
                allowed_tenants=allowed_tenants,
            )
        # Tenancy is enforced in SQL — same rule book as the SQLite path.
        where = ""
        params: list[Any] = []
        if allowed_tenants:
            where = "WHERE tenant_id = ANY(%s)"
            params.append(list(allowed_tenants))
        elif tenant_id is not None:
            where = "WHERE tenant_id = %s"
            params.append(tenant_id)
        vec_lit = self._vector_literal(vector)
        # pgvector cosine distance: lower is closer. similarity = 1 - distance.
        sql = (
            f"SELECT case_id, tenant_id, title, narrative, verdict, tags, "
            f"       1 - (embedding <=> %s::vector) AS similarity "
            f"FROM {self._table} {where} "
            f"ORDER BY embedding <=> %s::vector ASC LIMIT %s"
        )
        # Two placeholders for the same vector (one for SELECT, one for ORDER BY)
        # plus the optional tenant params plus the LIMIT.
        full_params = [vec_lit, *params, vec_lit, max(1, k)]
        try:
            import json as _json

            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, full_params)
                    rows = cur.fetchall()
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning(
                "pgvector recall failed (%s); using SQLite mirror",
                exc,
            )
            return self._fallback.recall(
                vector=vector,
                k=k,
                tenant_id=tenant_id,
                allowed_tenants=allowed_tenants,
            )
        out: list[dict] = []
        for row in rows:
            case_id_v, tenant, title, narrative, verdict, tags_raw, sim = row
            score = float(sim or 0.0)
            if score <= 0.05:
                continue
            if isinstance(tags_raw, str):
                try:
                    tags_v = _json.loads(tags_raw)
                except Exception:
                    tags_v = []
            else:
                tags_v = list(tags_raw or [])
            out.append(
                {
                    "case_id": int(case_id_v),
                    "tenant_id": tenant or "",
                    "title": title or "",
                    "verdict": verdict or "",
                    "similarity": round(score, 3),
                    "tags": tags_v,
                    "narrative": (narrative or "")[:200],
                }
            )
        return out


# ── Backend selection (lazy, one-shot) ────────────────────────────────
_backend: _Backend | None = None
_backend_name: str | None = None
_backend_lock = threading.Lock()


def _build_pgvector_backend(fallback: _Backend) -> _Backend | None:
    """Try to construct a pgvector backend; return None on failure."""
    dsn = settings.pgvector_dsn
    if not dsn:
        logger.warning(
            "episodic_backend=pgvector but AISOC_PGVECTOR_DSN is unset; using SQLite",
        )
        return None
    try:
        import psycopg  # type: ignore  # noqa: F401
    except ImportError:
        logger.warning(
            "episodic_backend=pgvector but `psycopg` (v3) is not installed; using SQLite",
        )
        return None
    pool: Any | None = None
    try:
        # Prefer a small connection pool when psycopg_pool is available.
        try:
            from psycopg_pool import ConnectionPool  # type: ignore

            pool = ConnectionPool(dsn, min_size=1, max_size=4, timeout=5.0, open=True)
            # Probe so we fail loud at boot, not on the first write.
            with pool.connection() as conn:  # type: ignore[union-attr]
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
        except ImportError:
            # No pool — fall back to a one-shot probe via psycopg.connect.
            import psycopg as _psycopg  # type: ignore

            with _psycopg.connect(dsn, connect_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
    except Exception as exc:  # pragma: no cover - depends on env
        logger.warning(
            "Failed to connect to pgvector DSN (%s); using SQLite",
            exc,
        )
        if pool is not None:
            try:
                pool.close()
            except Exception:  # pragma: no cover - defensive
                pass
        return None
    table = settings.pgvector_table or "aisoc_episodic_memory"
    logger.info("Episodic memory: using pgvector backend (table=%s)", table)
    return _PgVectorBackend(
        dsn=dsn,
        table=table,
        fallback=fallback,
        pool=pool,
    )


def _build_qdrant_backend(fallback: _Backend) -> _Backend | None:
    """Try to construct a Qdrant backend; return None on any failure.

    Accepts three URL shapes (so tests + local dev don't need a server):

    * ``:memory:``       — in-process Qdrant (no persistence). Good for tests.
    * ``file:///abs/path`` or ``path:///abs/path`` — local on-disk store.
    * anything else      — treated as a remote HTTP(S) URL.
    """
    url = settings.qdrant_url
    if not url:
        logger.warning(
            "episodic_backend=qdrant but AISOC_QDRANT_URL is unset; using SQLite",
        )
        return None
    try:
        from qdrant_client import QdrantClient  # type: ignore
        from qdrant_client.http import models as qmodels  # type: ignore
    except ImportError:
        logger.warning(
            "episodic_backend=qdrant but `qdrant-client` SDK is not installed; "
            "using SQLite",
        )
        return None
    try:
        if url == ":memory:":
            client = QdrantClient(location=":memory:")
        elif url.startswith(("file://", "path://")):
            local_path = url.split("://", 1)[1]
            client = QdrantClient(path=local_path)
        else:
            client = QdrantClient(
                url=url,
                api_key=settings.qdrant_api_key,
                timeout=5.0,
            )
        # Probe so we fail loud at boot, not on the first write.
        client.get_collections()
    except Exception as exc:  # pragma: no cover - depends on env
        logger.warning(
            "Failed to connect to Qdrant at %s (%s); using SQLite",
            url,
            exc,
        )
        return None
    # Single collection (per-tenant filtering is fast with an indexed
    # payload field). Prefix lets the same Qdrant host serve multiple
    # environments without clashing.
    prefix = settings.qdrant_collection_prefix or "aisoc_episodic"
    collection = prefix if "_" in prefix else f"{prefix}_v1"
    logger.info("Episodic memory: using Qdrant backend (%s, %s)", url, collection)
    return _QdrantBackend(
        client=client,
        collection=collection,
        fallback=fallback,
        models=qmodels,
    )


def _resolve_backend() -> _Backend:
    global _backend, _backend_name
    if _backend is not None:
        return _backend
    with _backend_lock:
        if _backend is not None:
            return _backend
        configured = (settings.episodic_backend or "sqlite").lower()
        sqlite = _SQLiteBackend()
        if configured == "qdrant":
            qdrant = _build_qdrant_backend(sqlite)
            if qdrant is not None:
                _backend = qdrant
                _backend_name = "qdrant"
                return _backend
        elif configured == "pgvector":
            pg = _build_pgvector_backend(sqlite)
            if pg is not None:
                _backend = pg
                _backend_name = "pgvector"
                return _backend
        _backend = sqlite
        _backend_name = "sqlite"
        return _backend


def episodic_backend_name() -> str:
    """Return the resolved episodic backend (``sqlite``, ``qdrant``, or ``pgvector``)."""
    _resolve_backend()
    return _backend_name or "sqlite"


# ── Public API (unchanged signatures) ─────────────────────────────────
def episodic_record(
    case_id: int,
    title: str,
    narrative: str,
    verdict: str,
    tags: list[str],
    tenant_id: str = "demo-tenant",
) -> None:
    """Insert or update the episodic record for a case, stamped with tenant."""
    vector = embed(f"{title}\n{narrative}\n{' '.join(tags or [])}")
    _resolve_backend().upsert(
        case_id=case_id,
        tenant_id=tenant_id,
        title=title,
        narrative=narrative,
        verdict=verdict,
        tags=list(tags or []),
        vector=vector,
    )


def episodic_recall(
    query: str,
    k: int = 3,
    tenant_id: str | None = None,
    allowed_tenants: list[str] | None = None,
) -> list[dict]:
    """Return top-k most similar past cases.

    Tenancy rules:
    - If ``allowed_tenants`` is provided (e.g. MSSP parent with child IDs),
      we restrict to that list.
    - Otherwise if ``tenant_id`` is provided, we restrict to that single tenant.
    - If neither is provided we fall back to the legacy "all rows" behavior
      (used by very early bootstrap paths only — agents always pass tenant_id).
    """
    vector = embed(query)
    # Touch embedding_dim() so the cached vector dim is consistent with
    # whatever the backend will create the collection at.
    _ = embedding_dim()
    return _resolve_backend().recall(
        vector=vector,
        k=k,
        tenant_id=tenant_id,
        allowed_tenants=allowed_tenants,
    )
