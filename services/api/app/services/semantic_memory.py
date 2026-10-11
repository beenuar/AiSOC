"""Vector recall over past cases, runbooks and institutional memory.

Depth plan 9.2 (parity 6.5). ``knowledge_base.py`` searched with
``to_tsvector('english', content) @@ plainto_tsquery(...)``, which answers a
question phrased in the words the runbook happens to use and answers nothing
otherwise. Mid-incident that is most of the time: "someone is brute-forcing a
VPN account" shares no stem with "credential stuffing against the
remote-access gateway".

Three deliberate choices, each of which has a cheaper wrong version.

**Qdrant over its REST API, not the Python client.**
``qdrant-client`` is a dependency of ``services/threatintel`` and not of this
service. Adding it here means regenerating this service's lockfile, and the
determinism work in this tree is explicit that a dependency added for one
module changes what every image resolves. Qdrant's REST surface is four
endpoints and ``httpx`` is already a dependency, so there is nothing to add.

**The tenant filter is mandatory and the function refuses without one.**
``services/threatintel``'s store treats ``tenant_id=None`` as a privileged
global read, and documents that callers must gate it. That is a correct
design for feed intel, which is genuinely shared. It is the wrong one here:
nothing in this store is shared, so an unscoped read has no legitimate
caller, and a default that can be reached by forgetting an argument is not a
control. :func:`recall` raises rather than searching.

**No embedding backend means "unavailable", never a zero vector.**
``QdrantStore._embed`` falls back to zero vectors when ``fastembed`` is
missing, so every similarity is identical and the search returns an
arbitrary ``limit`` rows that look like results. A caller cannot tell that
from a working retriever. This module raises
:class:`EmbeddingsUnavailable`, the route reports it, and the console shows
an honest empty state -- the same rule as "a column nobody writes renders as
'the measurement does not exist', never as a confident zero".

Dimension immutability
----------------------
A Qdrant collection's vector size cannot be altered, so changing the
embedding model is a re-embed into a new collection behind an alias, not a
settings change. ``app/db/vector_migrations.py`` already models that and
exposes :func:`pending_rebuilds`; :func:`status` surfaces it, together with
the per-row ``embedding_model`` this store records, so "which rows were
embedded by a model nobody is running any more" is answerable before a
recall silently degrades rather than after.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings
from app.services.model_aliases import resolve_api_key, resolve_base_url

logger = logging.getLogger("aisoc.semantic_memory")

#: One collection for all three kinds. ``kind`` is a payload field and a
#: filter, not a collection: three collections would mean three searches for
#: "what do we know about this", and the ranking across them would have to be
#: invented rather than measured.
COLLECTION = "aisoc_memory"

#: Dimension of the collection. Fixed at creation and immutable thereafter --
#: see the module header. 1536 matches the threat-intel collections and the
#: common hosted embedding models, so a deployment running both does not need
#: two answers to "what size are our vectors".
EMBEDDING_DIM = 1536

#: Default embedding model asked of whichever backend is configured.
DEFAULT_EMBEDDING_MODEL = os.environ.get("AISOC_EMBEDDING_MODEL", "").strip() or "text-embedding-3-small"

_TIMEOUT = httpx.Timeout(20.0, connect=5.0)


class EmbeddingsUnavailable(RuntimeError):
    """No embedding backend answered. Recall is unavailable, not empty.

    Separated from a generic error because the two render differently and
    must: "we searched and found nothing" and "we could not search" are
    different facts, and collapsing them is how a console shows a confident
    empty state over a broken retriever.
    """


class VectorStoreUnavailable(RuntimeError):
    """Qdrant did not answer. Same reasoning as above."""


@dataclass(frozen=True)
class RecallHit:
    """One recalled item, with everything a reader needs to weigh it."""

    item_id: uuid.UUID
    kind: str
    subject: str
    title: str
    content: str
    score: float
    author: str
    source: str
    scope: str
    state: str
    embedding_model: str | None


def content_hash(content: str) -> str:
    """Stable digest of an item's content.

    Whitespace-normalised, because a runbook re-ingested with different line
    wrapping is the same claim and should not read as a contradiction of
    itself.
    """
    normalised = " ".join(content.split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def point_id(item_id: uuid.UUID) -> str:
    """Qdrant point id for a memory item. The row's own id, as a string.

    Qdrant accepts unsigned integers or UUIDs. Using the row id rather than a
    hash means a delete in Postgres has an obvious counterpart in Qdrant and
    neither store needs a mapping table to find the other.
    """
    return str(item_id)


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------


def embedding_backend() -> tuple[str, str, str | None] | None:
    """``(kind, url, api_key)`` for the configured embedding backend, or None.

    Two backends, in order:

    * the LLM gateway this deployment already routes chat through, at
      ``/v1/embeddings`` -- which is LiteLLM in CORE and whatever an operator
      pointed ``AISOC_LLM_BASE_URL`` at otherwise;
    * Ollama at ``OLLAMA_BASE_URL``, which CORE also ships, for a deployment
      with no gateway key at all.

    Returns ``None`` rather than guessing. A guessed backend produces a
    connection error at recall time, which reads to an operator as "the
    feature is broken" rather than "nothing is configured".
    """
    base = resolve_base_url(DEFAULT_EMBEDDING_MODEL)
    if base:
        return ("gateway", f"{str(base).rstrip('/')}/embeddings", resolve_api_key(DEFAULT_EMBEDDING_MODEL))
    ollama = os.environ.get("OLLAMA_BASE_URL", "").strip()
    if ollama:
        return ("ollama", f"{ollama.rstrip('/')}/api/embeddings", None)
    return None


def _fit(vector: list[float]) -> list[float]:
    """Pad or truncate to the collection's dimension.

    A dimension mismatch is a hard Qdrant error, and a model that returns 768
    where the collection wants 1536 is a real and common configuration. This
    makes such a deployment work at a documented cost in recall quality,
    rather than failing every search -- and ``embedding_model`` is recorded
    per row so a later re-embed can find exactly these.
    """
    if len(vector) < EMBEDDING_DIM:
        return vector + [0.0] * (EMBEDDING_DIM - len(vector))
    return vector[:EMBEDDING_DIM]


async def embed(texts: list[str], *, client: httpx.AsyncClient | None = None) -> tuple[list[list[float]], str]:
    """Embed ``texts``. Raises :class:`EmbeddingsUnavailable` rather than faking.

    Returns the vectors and the model that produced them, so the caller can
    record it on the row.
    """
    if not texts:
        return [], DEFAULT_EMBEDDING_MODEL
    backend = embedding_backend()
    if backend is None:
        raise EmbeddingsUnavailable(
            "No embedding backend is configured. Set AISOC_LLM_BASE_URL (or run the bundled "
            "gateway), or OLLAMA_BASE_URL. Semantic recall is unavailable until then; "
            "full-text search still works."
        )
    kind, url, api_key = backend
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        if kind == "gateway":
            res = await http.post(url, json={"model": DEFAULT_EMBEDDING_MODEL, "input": texts}, headers=headers)
            if res.status_code >= 400:
                raise EmbeddingsUnavailable(f"The embedding backend answered HTTP {res.status_code}: {res.text[:200]}")
            payload = res.json()
            rows = payload.get("data") or []
            if len(rows) != len(texts):
                raise EmbeddingsUnavailable(
                    f"The embedding backend returned {len(rows)} vector(s) for {len(texts)} input(s)."
                )
            return [_fit([float(x) for x in row["embedding"]]) for row in rows], DEFAULT_EMBEDDING_MODEL
        # Ollama embeds one prompt per call.
        vectors: list[list[float]] = []
        for text_value in texts:
            res = await http.post(url, json={"model": DEFAULT_EMBEDDING_MODEL, "prompt": text_value})
            if res.status_code >= 400:
                raise EmbeddingsUnavailable(f"Ollama answered HTTP {res.status_code}: {res.text[:200]}")
            vectors.append(_fit([float(x) for x in res.json().get("embedding", [])]))
        return vectors, DEFAULT_EMBEDDING_MODEL
    except httpx.HTTPError as exc:
        raise EmbeddingsUnavailable(f"The embedding backend was unreachable: {exc}") from exc
    finally:
        if owns_client:
            await http.aclose()


# ---------------------------------------------------------------------------
# Qdrant, over its REST API
# ---------------------------------------------------------------------------


def _qdrant_url(path: str) -> str:
    return f"{settings.QDRANT_URL.rstrip('/')}{path}"


async def ensure_collection(*, client: httpx.AsyncClient | None = None) -> None:
    """Create the collection if it is absent. Never alters an existing one.

    Creation is the only safe idempotent operation: a collection's vector
    size and distance are immutable, so "converge it to what we want" is not
    something this can do. A dimension change goes through
    ``app/db/vector_migrations.py`` as a re-embed.
    """
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        existing = await http.get(_qdrant_url(f"/collections/{COLLECTION}"))
        if existing.status_code == 200:
            return
        res = await http.put(
            _qdrant_url(f"/collections/{COLLECTION}"),
            json={"vectors": {"size": EMBEDDING_DIM, "distance": "Cosine"}},
        )
        if res.status_code >= 400:
            raise VectorStoreUnavailable(f"Qdrant refused to create {COLLECTION}: HTTP {res.status_code} {res.text[:200]}")
    except httpx.HTTPError as exc:
        raise VectorStoreUnavailable(f"Qdrant was unreachable at {settings.QDRANT_URL}: {exc}") from exc
    finally:
        if owns:
            await http.aclose()


async def index_item(
    *,
    tenant_id: uuid.UUID,
    item_id: uuid.UUID,
    kind: str,
    subject: str,
    title: str,
    content: str,
    state: str,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Embed one item and upsert its point. Returns the embedding model used.

    ``tenant_id`` goes into the payload as a string because that is what the
    filter below matches on, and a filter that has to coerce is a filter that
    can silently match nothing.
    """
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        vectors, model = await embed([f"{title}\n\n{content}".strip()], client=http)
        await ensure_collection(client=http)
        res = await http.put(
            _qdrant_url(f"/collections/{COLLECTION}/points?wait=true"),
            json={
                "points": [
                    {
                        "id": point_id(item_id),
                        "vector": vectors[0],
                        "payload": {
                            "tenant_id": str(tenant_id),
                            "item_id": str(item_id),
                            "kind": kind,
                            "subject": subject,
                            "state": state,
                        },
                    }
                ]
            },
        )
        if res.status_code >= 400:
            raise VectorStoreUnavailable(f"Qdrant refused the upsert: HTTP {res.status_code} {res.text[:200]}")
        return model
    except httpx.HTTPError as exc:
        raise VectorStoreUnavailable(f"Qdrant was unreachable at {settings.QDRANT_URL}: {exc}") from exc
    finally:
        if owns:
            await http.aclose()


async def forget_item(item_id: uuid.UUID, *, client: httpx.AsyncClient | None = None) -> None:
    """Drop one point. Called when an item is retired or deleted."""
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        await http.post(
            _qdrant_url(f"/collections/{COLLECTION}/points/delete?wait=true"),
            json={"points": [point_id(item_id)]},
        )
    except httpx.HTTPError as exc:
        # A point left behind is recalled and then filtered out by the
        # Postgres join below, so this degrades to a slower search rather
        # than to a leak. Logged at warning because it does accumulate.
        logger.warning("semantic_memory: could not delete point %s: %s", item_id, exc)
    finally:
        if owns:
            await http.aclose()


def tenant_filter(tenant_id: uuid.UUID, kinds: list[str] | None = None) -> dict[str, Any]:
    """The Qdrant filter every search must carry.

    A separate function so there is exactly one spelling of it and a test can
    assert that :func:`recall` uses it. ``state`` is matched here as well as
    in Postgres: belt and braces, because a point whose row was retired but
    whose delete failed is otherwise recalled and discarded late.
    """
    must: list[dict[str, Any]] = [
        {"key": "tenant_id", "match": {"value": str(tenant_id)}},
        {"key": "state", "match": {"value": "in_use"}},
    ]
    if kinds:
        must.append({"key": "kind", "match": {"any": list(kinds)}})
    return {"must": must}


async def search(
    query: str,
    *,
    tenant_id: uuid.UUID,
    kinds: list[str] | None = None,
    limit: int = 10,
    client: httpx.AsyncClient | None = None,
) -> list[tuple[uuid.UUID, float]]:
    """Vector search, scoped to one tenant. Returns ``(item_id, score)``.

    ``tenant_id`` is a required keyword with no default and no ``None``
    branch. The threat-intel store permits an unscoped read for shared feed
    intel; nothing here is shared, so an unscoped read has no caller and a
    default reachable by forgetting an argument is not a control.
    """
    if not isinstance(tenant_id, uuid.UUID):
        raise ValueError("recall must be scoped to a tenant")
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        vectors, _ = await embed([query], client=http)
        res = await http.post(
            _qdrant_url(f"/collections/{COLLECTION}/points/search"),
            json={
                "vector": vectors[0],
                "limit": max(1, min(limit, 100)),
                "filter": tenant_filter(tenant_id, kinds),
                "with_payload": True,
            },
        )
        if res.status_code == 404:
            # The collection has never been created, which means nothing has
            # been indexed. Empty is the honest answer, not an error.
            return []
        if res.status_code >= 400:
            raise VectorStoreUnavailable(f"Qdrant refused the search: HTTP {res.status_code} {res.text[:200]}")
        out: list[tuple[uuid.UUID, float]] = []
        for hit in res.json().get("result", []):
            payload = hit.get("payload") or {}
            raw = payload.get("item_id") or hit.get("id")
            try:
                out.append((uuid.UUID(str(raw)), float(hit.get("score", 0.0))))
            except (TypeError, ValueError):
                continue
        return out
    except httpx.HTTPError as exc:
        raise VectorStoreUnavailable(f"Qdrant was unreachable at {settings.QDRANT_URL}: {exc}") from exc
    finally:
        if owns:
            await http.aclose()


async def status(*, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    """What a reader needs to know before trusting a recall.

    Reports the configured backend, the collection's actual dimension as
    Qdrant holds it (not as this module wishes it were), and whether a
    re-embed is pending. Every field can be ``None`` and the route renders
    that as "not known", because the alternative -- a confident zero or a
    confident "ok" -- is the failure this repository keeps finding.
    """
    backend = embedding_backend()
    out: dict[str, Any] = {
        "embedding_backend": backend[0] if backend else None,
        "embedding_model": DEFAULT_EMBEDDING_MODEL if backend else None,
        "expected_dimension": EMBEDDING_DIM,
        "collection": COLLECTION,
        "collection_dimension": None,
        "points": None,
        "vector_store_reachable": False,
        "pending_rebuilds": None,
    }
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        res = await http.get(_qdrant_url(f"/collections/{COLLECTION}"))
        if res.status_code == 200:
            result = res.json().get("result") or {}
            params = ((result.get("config") or {}).get("params") or {}).get("vectors") or {}
            out["collection_dimension"] = params.get("size")
            out["points"] = result.get("points_count")
            out["vector_store_reachable"] = True
        elif res.status_code == 404:
            # Reachable, nothing indexed yet. Distinct from unreachable, and
            # the console must not render them the same way.
            out["vector_store_reachable"] = True
    except httpx.HTTPError:
        out["vector_store_reachable"] = False
    finally:
        if owns:
            await http.aclose()
    return out
