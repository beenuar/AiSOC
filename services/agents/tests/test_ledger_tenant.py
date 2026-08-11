"""Ledger tenant resolution (issue #601).

`_resolve_tenant_id` must map the "default" placeholder — the agents service's
fallback when a caller doesn't pass a tenant — to the canonical seed tenant (or
the sole tenant in a single-tenant install), so investigations are actually
persisted instead of silently skipped as `reason=unknown_tenant`.
"""

from __future__ import annotations

import uuid

import pytest
from app.investigator.ledger import _CANONICAL_TENANT_ID, _resolve_tenant_id


class _FakeConn:
    """Minimal asyncpg-connection stub for the resolver's three queries."""

    def __init__(self, *, by_slug=None, canonical_exists=False, all_ids=None):
        self._by_slug = by_slug or {}
        self._canonical_exists = canonical_exists
        self._all_ids = all_ids or []

    async def fetchrow(self, sql: str, *args):
        if "slug = $1 OR name = $1" in sql:
            tid = self._by_slug.get(args[0])
            return {"id": tid} if tid is not None else None
        if "WHERE id = $1" in sql:
            return {"id": _CANONICAL_TENANT_ID} if self._canonical_exists else None
        return None

    async def fetch(self, sql: str, *args):
        if "LIMIT 2" in sql:
            return [{"id": i} for i in self._all_ids[:2]]
        return []


@pytest.mark.asyncio
async def test_explicit_uuid_is_trusted():
    tid = uuid.uuid4()
    assert await _resolve_tenant_id(_FakeConn(), str(tid)) == tid


@pytest.mark.asyncio
async def test_slug_match_resolves():
    demo = uuid.uuid4()
    conn = _FakeConn(by_slug={"demo": demo})
    assert await _resolve_tenant_id(conn, "demo") == demo


@pytest.mark.asyncio
async def test_default_resolves_to_canonical_seed_tenant():
    # The demo seed renamed slug default -> demo, so slug lookup misses; the
    # canonical UUID still exists and 'default' must resolve to it.
    conn = _FakeConn(by_slug={"demo": _CANONICAL_TENANT_ID}, canonical_exists=True)
    assert await _resolve_tenant_id(conn, "default") == _CANONICAL_TENANT_ID


@pytest.mark.asyncio
async def test_default_falls_back_to_sole_tenant():
    only = uuid.uuid4()
    conn = _FakeConn(canonical_exists=False, all_ids=[only])
    assert await _resolve_tenant_id(conn, "default") == only


@pytest.mark.asyncio
async def test_empty_ref_is_treated_as_default():
    conn = _FakeConn(canonical_exists=True)
    assert await _resolve_tenant_id(conn, "") == _CANONICAL_TENANT_ID


@pytest.mark.asyncio
async def test_default_is_ambiguous_with_multiple_tenants_and_no_canonical():
    conn = _FakeConn(canonical_exists=False, all_ids=[uuid.uuid4(), uuid.uuid4()])
    assert await _resolve_tenant_id(conn, "default") is None


@pytest.mark.asyncio
async def test_unknown_ref_returns_none():
    conn = _FakeConn(by_slug={"demo": uuid.uuid4()}, canonical_exists=True, all_ids=[uuid.uuid4()])
    # A genuinely unknown, non-placeholder ref must NOT borrow the canonical
    # tenant — that would cross tenants.
    assert await _resolve_tenant_id(conn, "acme-corp") is None
