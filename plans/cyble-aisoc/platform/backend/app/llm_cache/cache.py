"""LLM cache implementation: exact + semantic, per-tenant (t6-llm-cache).

Design points
-------------

* **Tenant-scoped by construction.** Every key carries
  ``tenant_id``. The :class:`CacheStore` API never returns an entry
  whose tenant doesn't match the key. We do not rely on the caller
  remembering to filter — the store does it.
* **Exact-match is the cheap fast path.** SHA-256 of the canonical
  request → lookup. O(1) and deterministic.
* **Semantic match is a fallback.** Hashbag (the same offline
  embedding mode used for episodic memory) plus cosine similarity
  against the per-tenant ring buffer of recent prompts. Threshold
  is tunable; default 0.92 keeps false-positive matches rare.
* **TTL is per-entry** so an operator can set a short-lived cache
  for "live" prompts and a long-lived one for ground-truth lookups
  (e.g. CTI summaries that don't change hour-to-hour).
* **Stats are live.** Every lookup increments either ``hits`` or
  ``misses``; semantic hits are counted separately so the FinOps
  rollup can attribute exact vs. semantic savings.

The module is *not* a circuit breaker. It will gladly serve a
stale cache entry until its TTL expires; cache invalidation on
prompt-template changes is the operator's responsibility (the
``model`` field changing is enough to bust everything keyed on
that model, which is usually all you need).
"""
from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol


@dataclass(frozen=True)
class CacheKey:
    """The canonical key for an LLM cache lookup."""

    tenant_id: str
    model: str
    prompt: str
    temperature: float = 0.0

    def fingerprint(self) -> str:
        """Stable SHA-256 of the canonical key."""

        canonical = (
            f"{self.tenant_id}|{self.model}|"
            f"{self.temperature:.4f}|{self.prompt}"
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass
class CacheEntry:
    tenant_id: str
    model: str
    prompt: str
    response_text: str
    tokens_in: int = 0
    tokens_out: int = 0
    created_at: float = field(default_factory=lambda: time.time())
    ttl_seconds: float = 24 * 60 * 60.0
    semantic_vector: tuple[tuple[str, float], ...] = ()

    def is_fresh(self, *, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return now - self.created_at < self.ttl_seconds


@dataclass
class SemanticCacheConfig:
    """Knobs for the semantic match layer."""

    enabled: bool = True
    similarity_threshold: float = 0.92
    max_recent_per_tenant: int = 200


@dataclass
class CacheStats:
    exact_hits: int = 0
    semantic_hits: int = 0
    misses: int = 0
    tokens_saved_in: int = 0
    tokens_saved_out: int = 0


# ---------------------------------------------------------------------------
# Pluggable store
# ---------------------------------------------------------------------------


class CacheStore(Protocol):
    """The pluggable persistence interface."""

    def get(self, fingerprint: str) -> Optional[CacheEntry]: ...

    def put(self, fingerprint: str, entry: CacheEntry) -> None: ...

    def recent_for_tenant(self, tenant_id: str) -> Iterable[tuple[str, CacheEntry]]: ...

    def clear_tenant(self, tenant_id: str) -> int: ...


class InMemoryCacheStore:
    """Default store backed by two dicts.

    Production deployments swap this for a Redis-backed
    implementation; the contract is identical.
    """

    def __init__(self, *, max_recent_per_tenant: int = 200) -> None:
        self._exact: dict[str, CacheEntry] = {}
        self._recent: dict[str, deque[tuple[str, CacheEntry]]] = defaultdict(
            lambda: deque(maxlen=max_recent_per_tenant)
        )

    def get(self, fingerprint: str) -> Optional[CacheEntry]:
        entry = self._exact.get(fingerprint)
        if entry is None:
            return None
        if not entry.is_fresh():
            self._exact.pop(fingerprint, None)
            return None
        return entry

    def put(self, fingerprint: str, entry: CacheEntry) -> None:
        self._exact[fingerprint] = entry
        self._recent[entry.tenant_id].append((fingerprint, entry))

    def recent_for_tenant(self, tenant_id: str) -> Iterable[tuple[str, CacheEntry]]:
        return list(self._recent.get(tenant_id, deque()))

    def clear_tenant(self, tenant_id: str) -> int:
        recent = self._recent.pop(tenant_id, deque())
        n = 0
        for fp, _ in recent:
            if self._exact.pop(fp, None):
                n += 1
        # Sweep any orphaned exact entries that share the tenant id.
        for fp, entry in list(self._exact.items()):
            if entry.tenant_id == tenant_id:
                self._exact.pop(fp, None)
                n += 1
        return n


# ---------------------------------------------------------------------------
# Hashbag embedding (matches the offline embedding the platform
# already uses for episodic memory; deterministic, no network).
# ---------------------------------------------------------------------------


def _tokenise(text: str) -> list[str]:
    out: list[str] = []
    word = []
    for ch in text.lower():
        if ch.isalnum():
            word.append(ch)
        else:
            if word:
                out.append("".join(word))
                word = []
    if word:
        out.append("".join(word))
    return out


def _hashbag(text: str, *, dim: int = 32) -> tuple[tuple[str, float], ...]:
    """Return a sparse, normalised bag-of-tokens vector.

    Each token contributes ``1.0`` to a bucket determined by a
    stable hash of the token modulo ``dim``. The vector is then
    L2-normalised so cosine similarity reduces to a dot product.

    We stash the buckets as ``(bucket_label, weight)`` tuples
    rather than a numpy array to keep the dependency surface
    minimal — the platform's cold-start path doesn't import
    numpy, and this is hot-path code.
    """

    tokens = _tokenise(text)
    if not tokens:
        return ()
    weights: dict[str, float] = defaultdict(float)
    for token in tokens:
        bucket = str(int(hashlib.sha1(token.encode("utf-8")).hexdigest(), 16) % dim)
        weights[bucket] += 1.0
    # L2 normalise.
    norm = math.sqrt(sum(w * w for w in weights.values()))
    if norm == 0:
        return ()
    return tuple(sorted((b, w / norm) for b, w in weights.items()))


def _cosine(a: tuple[tuple[str, float], ...], b: tuple[tuple[str, float], ...]) -> float:
    if not a or not b:
        return 0.0
    bd = dict(b)
    return sum(weight * bd.get(bucket, 0.0) for bucket, weight in a)


# ---------------------------------------------------------------------------
# LLM cache facade
# ---------------------------------------------------------------------------


class LLMCache:
    """Process-level cache facade.

    Producers call :meth:`get` on the cache before issuing an LLM
    call. On a hit they short-circuit and return the cached
    response. On a miss they run the LLM call and pass the result
    to :meth:`put`.
    """

    def __init__(
        self,
        *,
        store: Optional[CacheStore] = None,
        semantic: Optional[SemanticCacheConfig] = None,
        default_ttl_seconds: float = 24 * 60 * 60.0,
    ) -> None:
        self._store: CacheStore = store or InMemoryCacheStore()
        self._semantic = semantic or SemanticCacheConfig()
        self._default_ttl = default_ttl_seconds
        self.stats = CacheStats()

    @property
    def store(self) -> CacheStore:
        return self._store

    def replace_store(self, store: CacheStore) -> None:
        """Swap the underlying store (used by tests)."""
        self._store = store

    # ─── Reads ────────────────────────────────────────────────────────

    def get(self, key: CacheKey) -> Optional[CacheEntry]:
        """Look up a cached entry, exact match first then semantic."""

        exact = self._store.get(key.fingerprint())
        if exact is not None and exact.tenant_id == key.tenant_id:
            self.stats.exact_hits += 1
            self.stats.tokens_saved_in += exact.tokens_in
            self.stats.tokens_saved_out += exact.tokens_out
            return exact

        if not self._semantic.enabled:
            self.stats.misses += 1
            return None

        candidate_vector = _hashbag(key.prompt)
        if not candidate_vector:
            self.stats.misses += 1
            return None

        best: Optional[CacheEntry] = None
        best_score = 0.0
        for fp, entry in self._store.recent_for_tenant(key.tenant_id):
            if not entry.is_fresh():
                continue
            if entry.model != key.model:
                continue
            score = _cosine(entry.semantic_vector, candidate_vector)
            if score > best_score:
                best_score = score
                best = entry

        if best is None or best_score < self._semantic.similarity_threshold:
            self.stats.misses += 1
            return None

        self.stats.semantic_hits += 1
        self.stats.tokens_saved_in += best.tokens_in
        self.stats.tokens_saved_out += best.tokens_out
        return best

    # ─── Writes ───────────────────────────────────────────────────────

    def put(
        self,
        key: CacheKey,
        *,
        response_text: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        ttl_seconds: Optional[float] = None,
    ) -> CacheEntry:
        entry = CacheEntry(
            tenant_id=key.tenant_id,
            model=key.model,
            prompt=key.prompt,
            response_text=response_text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            ttl_seconds=ttl_seconds or self._default_ttl,
            semantic_vector=_hashbag(key.prompt) if self._semantic.enabled else (),
        )
        self._store.put(key.fingerprint(), entry)
        return entry

    # ─── Maintenance ──────────────────────────────────────────────────

    def clear_tenant(self, tenant_id: str) -> int:
        return self._store.clear_tenant(tenant_id)

    def reset_stats(self) -> None:
        self.stats = CacheStats()


_cache_instance: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = LLMCache()
    return _cache_instance


def set_cache_store(store: CacheStore) -> LLMCache:
    cache = get_llm_cache()
    cache.replace_store(store)
    cache.reset_stats()
    return cache
