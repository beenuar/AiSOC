"""LLM cache REST surface (t6-llm-cache).

  GET    /llm-cache/stats             Hit / miss counters.
  POST   /llm-cache/lookup            Lookup-only probe (no put). For
                                      diagnostics; never actually stores
                                      a request.
  DELETE /llm-cache/{tenant_id}       Clear a tenant's cache. Admin-only.

The lookup probe is intentional: an operator who suspects a stale
or stuck cache entry can replay a prompt against the cache through
the API without going near the orchestrator. Read-only paths return
the response text *and* the cache provenance (exact vs. semantic).
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.llm_cache import (
    CacheKey,
    get_llm_cache,
)
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/llm-cache", tags=["llm-cache"])


@router.get("/stats")
def stats_route(_: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    cache = get_llm_cache()
    s = cache.stats
    total = s.exact_hits + s.semantic_hits + s.misses
    hit_rate = (s.exact_hits + s.semantic_hits) / total if total else 0.0
    return {
        "exact_hits": s.exact_hits,
        "semantic_hits": s.semantic_hits,
        "misses": s.misses,
        "total": total,
        "hit_rate": round(hit_rate, 4),
        "tokens_saved_in": s.tokens_saved_in,
        "tokens_saved_out": s.tokens_saved_out,
    }


class LookupRequest(BaseModel):
    model: str = Field(min_length=1, max_length=200)
    prompt: str = Field(min_length=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)


@router.post("/lookup")
def lookup_route(
    body: LookupRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Probe-only lookup. Does NOT write to the cache."""
    cache = get_llm_cache()
    key = CacheKey(
        tenant_id=ctx.active_tenant_id,
        model=body.model,
        prompt=body.prompt,
        temperature=body.temperature,
    )
    # We can't directly tell exact vs. semantic from the public API
    # so we read the stats counters before/after.
    pre_exact = cache.stats.exact_hits
    pre_semantic = cache.stats.semantic_hits
    entry = cache.get(key)
    post_exact = cache.stats.exact_hits
    post_semantic = cache.stats.semantic_hits

    if entry is None:
        return {"hit": False, "kind": None}
    kind = "exact" if post_exact > pre_exact else (
        "semantic" if post_semantic > pre_semantic else "unknown"
    )
    return {
        "hit": True,
        "kind": kind,
        "model": entry.model,
        "response_text": entry.response_text,
        "tokens_in": entry.tokens_in,
        "tokens_out": entry.tokens_out,
        "created_at": entry.created_at,
        "ttl_seconds": entry.ttl_seconds,
    }


@router.delete("/{tenant_id}")
def clear_tenant_cache(
    tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Clear ``tenant_id``'s LLM cache. Admin-only.

    A tenant clearing their own cache is fine, but the operation
    is admin-gated by default because clearing the wrong tenant
    is one of the easier ways to spike LLM spend mid-incident.
    """
    if not ctx.is_admin and ctx.active_tenant_id != tenant_id:
        raise HTTPException(
            status_code=403,
            detail="cross-tenant cache clear requires admin",
        )
    cleared = get_llm_cache().clear_tenant(tenant_id)
    return {"tenant_id": tenant_id, "entries_cleared": cleared}
