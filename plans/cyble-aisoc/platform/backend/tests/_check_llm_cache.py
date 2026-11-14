"""Smoke test: LLM response cache (t6-llm-cache).

Covers:

* Exact-match hit path returns the previously stored entry and
  bumps ``exact_hits``.
* Semantic-match hit path returns a previously stored entry whose
  prompt is similar (cosine ≥ threshold) but not identical, and
  bumps ``semantic_hits`` instead.
* Tenant scoping — tenant A's entries are never visible to tenant B,
  even on a byte-for-byte identical prompt.
* TTL expiry — a stale entry is never returned and is evicted on
  the way out of :meth:`LLMCache.get`.
* The HTTP surface (stats, lookup probe, tenant-scoped clear) wires
  through to the same in-process cache singleton.
"""
from __future__ import annotations

import os
import tempfile
import time

os.environ["AISOC_AUTH_DISABLED"] = "1"
os.environ["AISOC_LLM_PROVIDER"] = "mock"
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-llm-cache-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.llm_cache import (  # noqa: E402
    CacheKey,
    InMemoryCacheStore,
    SemanticCacheConfig,
    LLMCache,
    get_llm_cache,
    set_cache_store,
)
from app.main import app  # noqa: E402
from app.security.jwt import issue_tenant_token  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _exact_smoke() -> None:
    cache = LLMCache()
    key = CacheKey(
        tenant_id="t-1",
        model="gpt-4o-mini",
        prompt="explain T1190",
        temperature=0.0,
    )
    cache.put(key, response_text="exploitation of public-facing applications.", tokens_in=12, tokens_out=20)
    hit = cache.get(key)
    _expect(hit is not None, "exact match should hit")
    _expect(hit.response_text.startswith("exploitation"), f"wrong payload: {hit}")
    _expect(cache.stats.exact_hits == 1, f"exact_hits: {cache.stats}")
    _expect(cache.stats.misses == 0, "should not have missed")
    _expect(cache.stats.tokens_saved_out == 20, "tokens_saved_out should reflect the hit")


def _semantic_smoke() -> None:
    cache = LLMCache(
        semantic=SemanticCacheConfig(
            enabled=True,
            similarity_threshold=0.5,  # loose for the test
        )
    )
    write_key = CacheKey(
        tenant_id="t-1",
        model="gpt-4o-mini",
        prompt="describe MITRE ATT&CK technique T1059 command line interpreter",
    )
    cache.put(write_key, response_text="abuse of native CLIs", tokens_in=20, tokens_out=12)

    # New prompt — same intent, different surface form.
    read_key = CacheKey(
        tenant_id="t-1",
        model="gpt-4o-mini",
        prompt="MITRE ATT&CK T1059 command line interpreter description",
    )
    hit = cache.get(read_key)
    _expect(hit is not None, "semantic match should hit")
    _expect(cache.stats.semantic_hits == 1, f"semantic_hits: {cache.stats}")


def _tenant_isolation_smoke() -> None:
    cache = LLMCache()
    cache.put(
        CacheKey(tenant_id="tenant-A", model="m", prompt="who am i?"),
        response_text="alice",
    )
    miss = cache.get(CacheKey(tenant_id="tenant-B", model="m", prompt="who am i?"))
    _expect(miss is None, "tenant B should not see tenant A's entry")
    _expect(cache.stats.misses >= 1, "miss counter should bump")


def _ttl_smoke() -> None:
    cache = LLMCache(default_ttl_seconds=0.05)
    key = CacheKey(tenant_id="t-1", model="m", prompt="quick prompt")
    cache.put(key, response_text="hi")
    _expect(cache.get(key) is not None, "fresh entry should hit")
    time.sleep(0.1)
    _expect(cache.get(key) is None, "expired entry should miss")


def _api_smoke() -> None:
    set_cache_store(InMemoryCacheStore())
    cache = get_llm_cache()
    cache.reset_stats()

    cache.put(
        CacheKey(
            tenant_id=settings.default_tenant,
            model="gpt-4o",
            prompt="explain T1190",
        ),
        response_text="public-facing app exploitation",
        tokens_in=10,
        tokens_out=20,
    )

    admin_token = issue_tenant_token(
        tenant_id=settings.default_tenant,
        subject="cache-admin",
        roles=["admin"],
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app) as client:
        r = client.get("/llm-cache/stats", headers=headers)
        _expect(r.status_code == 200, f"stats GET 200 expected, got {r.status_code}")
        body = r.json()
        _expect(body["exact_hits"] == 0, "stats should start fresh")

        r = client.post(
            "/llm-cache/lookup",
            json={"model": "gpt-4o", "prompt": "explain T1190"},
            headers=headers,
        )
        _expect(r.status_code == 200, f"lookup 200 expected, got {r.status_code} {r.text}")
        body = r.json()
        _expect(body["hit"], f"expected hit, got {body}")
        _expect(body["kind"] == "exact", f"expected exact kind, got {body}")
        _expect(body["response_text"].startswith("public-facing"), "response text mismatch")

        r = client.post(
            "/llm-cache/lookup",
            json={"model": "gpt-4o", "prompt": "totally unrelated prompt about kittens"},
            headers=headers,
        )
        _expect(r.status_code == 200, "second lookup 200 expected")
        body = r.json()
        _expect(not body["hit"], f"miss expected, got {body}")

        # Clear tenant cache. Admin OK.
        r = client.delete(
            f"/llm-cache/{settings.default_tenant}",
            headers=headers,
        )
        _expect(r.status_code == 200, "DELETE 200 expected")
        body = r.json()
        _expect(body["entries_cleared"] >= 1, f"clear count: {body}")

        # Cross-tenant clear by an analyst should be 403.
        analyst_token = issue_tenant_token(
            tenant_id=settings.default_tenant,
            subject="analyst-1",
            roles=["analyst"],
        )
        r = client.delete(
            "/llm-cache/some-other-tenant",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        _expect(
            r.status_code == 403,
            f"cross-tenant clear should 403, got {r.status_code}",
        )


def main() -> None:
    _exact_smoke()
    _semantic_smoke()
    _tenant_isolation_smoke()
    _ttl_smoke()
    _api_smoke()
    print("ok: llm cache smoke")


if __name__ == "__main__":
    main()
