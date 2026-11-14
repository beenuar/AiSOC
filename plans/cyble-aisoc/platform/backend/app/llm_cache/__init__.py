"""LLM response caching (t6-llm-cache).

Two layers:

1. **Exact-match** — a hash of (tenant, model, prompt, temperature)
   keyed lookup against an in-memory dict (or Redis in production).
   Hits return the cached response instantly with zero token cost.

2. **Semantic** — a hashbag-based vector similarity lookup against
   the most recent N prompts per tenant. Hits return the cached
   response when the new prompt's bag-of-tokens is similar enough
   (cosine ≥ threshold) to a previous one.

Both layers are *per-tenant by default*. Cache hits never cross
tenants, even if two prompts happen to be byte-for-byte identical.
That keeps the cache compatible with multi-tenant residency
guarantees: tenant A's prompts and answers never reach tenant B's
LLM call sites.

The module is intentionally pluggable: the default in-memory store
is fine for dev; production deployments substitute a Redis-backed
implementation by registering an alternate :class:`CacheStore` via
:func:`set_cache_store`. Either way, the cache accounting (hit rate,
token savings) lands in the FinOps rollup.
"""
from app.llm_cache.cache import (
    CacheEntry,
    CacheKey,
    CacheStats,
    CacheStore,
    InMemoryCacheStore,
    LLMCache,
    SemanticCacheConfig,
    get_llm_cache,
    set_cache_store,
)

__all__ = [
    "CacheEntry",
    "CacheKey",
    "CacheStats",
    "CacheStore",
    "InMemoryCacheStore",
    "LLMCache",
    "SemanticCacheConfig",
    "get_llm_cache",
    "set_cache_store",
]
