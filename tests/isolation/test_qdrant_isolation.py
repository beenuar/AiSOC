"""Offline Qdrant tenant-isolation assertions (Phase 1.3).

Loads the QdrantStore module by path (self-contained; only needs qdrant-client)
and mocks the async client, so the isolation contract is asserted with no live
Qdrant. The live-container replay lands with Phase 3's integration tier.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_QDRANT_PATH = Path(__file__).resolve().parents[2] / "services" / "threatintel" / "app" / "storage" / "qdrant.py"
_spec = importlib.util.spec_from_file_location("aisoc_qdrant_store_under_test", _QDRANT_PATH)
assert _spec and _spec.loader
_qdrant = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_qdrant)

QdrantStore = _qdrant.QdrantStore
tenant_scope_filter = _qdrant.tenant_scope_filter
SHARED_TENANT = _qdrant.SHARED_TENANT


def _match_any_values(f) -> set[str]:
    """Pull the allowed tenant_id values out of a tenant scope Filter."""
    assert f is not None
    cond = f.must[0]
    assert cond.key == "tenant_id"
    return set(cond.match.any)


# ── Filter construction ──────────────────────────────────────────────────────


def test_none_tenant_is_unfiltered_privileged_read():
    assert tenant_scope_filter(None) is None


def test_tenant_filter_includes_self_and_shared_only():
    values = _match_any_values(tenant_scope_filter("tenant-A"))
    assert values == {"tenant-A", SHARED_TENANT}
    assert "tenant-B" not in values  # the core isolation property


def test_tenant_filter_can_exclude_shared():
    values = _match_any_values(tenant_scope_filter("tenant-A", include_shared=False))
    assert values == {"tenant-A"}


# ── Search is always tenant-scoped ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_as_A_cannot_include_B_in_its_filter():
    client = MagicMock()
    client.search = AsyncMock(return_value=[])
    store = QdrantStore(client)

    await store.semantic_search(" transfer to attacker", tenant_id="tenant-A")

    client.search.assert_awaited_once()
    query_filter = client.search.await_args.kwargs["query_filter"]
    allowed = _match_any_values(query_filter)
    assert "tenant-A" in allowed
    assert "tenant-B" not in allowed  # A can never read B


@pytest.mark.asyncio
async def test_search_without_tenant_is_flagged_as_privileged():
    client = MagicMock()
    client.search = AsyncMock(return_value=[])
    store = QdrantStore(client)
    await store.semantic_search("q", tenant_id=None)
    assert client.search.await_args.kwargs["query_filter"] is None


# ── Writes stamp tenant + avoid cross-tenant collisions ──────────────────────


@pytest.mark.asyncio
async def test_upsert_stamps_tenant_and_scopes_point_ids():
    client = MagicMock()
    client.upsert = AsyncMock()
    store = QdrantStore(client)

    ioc = {"type": "ip", "value": "203.0.113.5", "description": "c2"}
    await store.upsert_iocs([dict(ioc)], tenant_id="tenant-A")
    await store.upsert_iocs([dict(ioc)], tenant_id="tenant-B")

    points_a = client.upsert.await_args_list[0].kwargs["points"]
    points_b = client.upsert.await_args_list[1].kwargs["points"]

    assert points_a[0].payload["tenant_id"] == "tenant-A"
    assert points_b[0].payload["tenant_id"] == "tenant-B"
    # Same IOC under two tenants must NOT collide (else B overwrites A).
    assert points_a[0].id != points_b[0].id


@pytest.mark.asyncio
async def test_default_upsert_is_shared_feed_intel():
    client = MagicMock()
    client.upsert = AsyncMock()
    store = QdrantStore(client)
    await store.upsert_iocs([{"type": "domain", "value": "evil.example"}])
    points = client.upsert.await_args.kwargs["points"]
    assert points[0].payload["tenant_id"] == SHARED_TENANT
