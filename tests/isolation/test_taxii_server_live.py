"""The TAXII 2.1 server against real Postgres (depth 4.2).

Why this suite exists rather than a mocked session
--------------------------------------------------
Every defect worth catching here is one a test double cannot see.

* ``added_after`` and the ``next`` cursor are a boundary condition over
  real rows. A fake session returns whatever the test handed it, so the
  off-by-one that loses a client's indicators — two rows written by one
  feed poll sharing ``updated_at`` to the microsecond — is invisible
  unless real rows with a real ordering are paged.
* A collection id is the one value a third party is expected to hold, so
  the tenant predicate is the whole security property. A mocked session
  answers a cross-tenant lookup happily.
* The server's own index (``idx_ioc_taxii_paging``) and the migration's
  RLS policy only exist in a real database.

The suite skips when ``ISOLATION_TAXII_DSN`` is unset, and the workflow
that owns it sets the variable unconditionally — a skip in a job that is
supposed to be live is a pass for the wrong reason.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_TAXII_DSN", "").strip(),
        reason="ISOLATION_TAXII_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_TAXII_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_TAXII_DSN is not set")
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


def _admin_dsn() -> str:
    """The owner connection, used only to seed and tear down fixtures.

    The suite itself runs as the DML-only runtime role, because a suite
    proving tenant scoping while connected as a superuser would pass
    with every RLS policy removed. The runtime role cannot insert a
    tenant — its WITH CHECK requires a tenant it has not been given —
    so the fixture needs the owner, and nothing else does.
    """
    value = os.environ.get("ISOLATION_TAXII_ADMIN_DSN", "").strip() or _dsn()
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def admin_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_admin_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def world(admin_engine):
    """Two tenants, each with a collection and indicators.

    Tenant B exists so every read in this suite is a cross-tenant read
    that must come back empty. A single-tenant fixture cannot tell a
    working tenant predicate from a missing one.
    """
    from sqlalchemy import text

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    base = datetime(2026, 10, 11, 9, 0, 0, tzinfo=UTC)

    async with admin_engine.begin() as conn:
        for tid, slug in ((tenant_a, "taxii-a"), (tenant_b, "taxii-b")):
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": str(tid), "n": slug, "s": f"{slug}-{uuid.uuid4().hex[:8]}"},
            )

        collections: dict[str, uuid.UUID] = {}
        for tid, title, key, ioc_filter in (
            (tenant_a, "Everything", "all", "{}"),
            (tenant_a, "IPs only", "ips", '{"ioc_type": ["ip"]}'),
            (tenant_b, "Tenant B", "b", "{}"),
        ):
            cid = uuid.uuid4()
            collections[key] = cid
            await conn.execute(
                text(
                    "INSERT INTO taxii_collections (id, tenant_id, alias, title, ioc_filter) VALUES (:id, :t, :a, :ti, CAST(:f AS JSONB))"
                ),
                {"id": str(cid), "t": str(tid), "a": key, "ti": title, "f": ioc_filter},
            )

        # Two of these share updated_at to the microsecond, which is what
        # one feed poll produces and what a timestamp-only cursor loses.
        rows = [
            (tenant_a, "ip", "198.51.100.1", base),
            (tenant_a, "ip", "198.51.100.2", base),
            (tenant_a, "domain", "a.example.com", base + timedelta(seconds=1)),
            (tenant_a, "domain", "b.example.com", base + timedelta(seconds=2)),
            # Not publishable: no STIX pattern exists for a CVE.
            (tenant_a, "cve", "CVE-2026-9999", base + timedelta(seconds=3)),
            (tenant_b, "ip", "203.0.113.9", base),
        ]
        ioc_ids: list[uuid.UUID] = []
        for tid, ioc_type, value, stamp in rows:
            iid = uuid.uuid4()
            ioc_ids.append(iid)
            await conn.execute(
                text(
                    "INSERT INTO threat_intel_iocs "
                    "(id, tenant_id, ioc_type, value, confidence, severity, tlp, source, "
                    " first_seen, last_seen, is_active, false_positive, created_at, updated_at) "
                    "VALUES (:id, :t, :ty, :v, 70, 'high', 'amber', 'internal', "
                    " :s, :s, true, false, :s, :s)"
                ),
                {"id": str(iid), "t": str(tid), "ty": ioc_type, "v": value, "s": stamp},
            )

    yield {
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "collections": collections,
        "base": base,
    }

    async with admin_engine.begin() as conn:
        for tid in (tenant_a, tenant_b):
            await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(tid)})


def _user(tenant_id: uuid.UUID):
    from app.api.v1.deps import CurrentUser

    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id,
        role="threat_hunter",
        email="hunter@example.com",
    )


@pytest_asyncio.fixture(loop_scope="module")
async def session(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s


async def _objects(session, user, collection_ref, **kwargs):
    """Call the real route function and decode its TAXII envelope."""
    import json

    from app.api.v1.endpoints.taxii import API_ROOT, get_objects

    response = await get_objects(
        api_root=API_ROOT,
        collection_ref=str(collection_ref),
        current_user=user,
        db=session,
        **kwargs,
    )
    assert response.media_type == "application/taxii+json;version=2.1"
    return json.loads(response.body), response


# ---------------------------------------------------------------------------
# Tenant scoping. A collection id is the one value a third party holds.
# ---------------------------------------------------------------------------


class TestTenantScoping:
    async def test_another_tenants_collection_is_not_found_by_id(self, session, world):
        from app.api.v1.endpoints.taxii import API_ROOT, get_collection
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await get_collection(
                api_root=API_ROOT,
                collection_ref=str(world["collections"]["b"]),
                current_user=_user(world["tenant_a"]),
                db=session,
            )
        assert exc.value.status_code == 404

    async def test_another_tenants_collection_is_not_found_by_alias(self, session, world):
        from app.api.v1.endpoints.taxii import API_ROOT, get_collection
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await get_collection(
                api_root=API_ROOT,
                collection_ref="b",
                current_user=_user(world["tenant_a"]),
                db=session,
            )
        assert exc.value.status_code == 404

    async def test_listing_shows_only_the_callers_collections(self, session, world):
        import json

        from app.api.v1.endpoints.taxii import API_ROOT, list_collections

        response = await list_collections(api_root=API_ROOT, current_user=_user(world["tenant_a"]), db=session)
        titles = {c["title"] for c in json.loads(response.body)["collections"]}
        assert titles == {"Everything", "IPs only"}
        assert "Tenant B" not in titles

    async def test_no_other_tenants_indicator_appears_in_a_page(self, session, world):
        body, _ = await _objects(session, _user(world["tenant_a"]), world["collections"]["all"])
        patterns = " ".join(o["pattern"] for o in body["objects"])
        assert "203.0.113.9" not in patterns


# ---------------------------------------------------------------------------
# Projection against real rows.
# ---------------------------------------------------------------------------


class TestProjection:
    async def test_the_collection_publishes_its_tenants_publishable_indicators(self, session, world):
        body, _ = await _objects(session, _user(world["tenant_a"]), world["collections"]["all"])
        # Four publishable rows; the CVE is excluded because no STIX
        # pattern exists for it.
        assert len(body["objects"]) == 4
        assert all(o["type"] == "indicator" for o in body["objects"])
        assert "CVE-2026-9999" not in " ".join(o["pattern"] for o in body["objects"])

    async def test_a_collection_filter_narrows_what_is_published(self, session, world):
        body, _ = await _objects(session, _user(world["tenant_a"]), world["collections"]["ips"])
        assert len(body["objects"]) == 2
        assert all("ipv4-addr" in o["pattern"] for o in body["objects"])

    async def test_the_envelope_carries_the_headers_a_client_bookmarks(self, session, world):
        _, response = await _objects(session, _user(world["tenant_a"]), world["collections"]["all"])
        assert response.headers["X-TAXII-Date-Added-First"].endswith("Z")
        assert response.headers["X-TAXII-Date-Added-Last"].endswith("Z")

    async def test_an_empty_page_omits_the_boundary_headers(self, session, world):
        # Setting them to "now" on an empty page makes a client record a
        # boundary no row was ever written at, so anything landing in
        # between is skipped forever.
        future = (world["base"] + timedelta(days=365)).isoformat()
        _, response = await _objects(
            session,
            _user(world["tenant_a"]),
            world["collections"]["all"],
            added_after=future,
        )
        assert "X-TAXII-Date-Added-Last" not in response.headers


# ---------------------------------------------------------------------------
# Pagination. The part that silently loses indicators.
# ---------------------------------------------------------------------------


class TestPagination:
    async def test_paging_one_at_a_time_yields_every_indicator_exactly_once(self, session, world):
        """The whole point of the (updated_at, id) cursor.

        Two of these rows share ``updated_at`` to the microsecond. With a
        timestamp-only cursor, paging at size 1 either repeats one of them
        forever or skips it — this walk is what distinguishes the two.
        """
        seen: list[str] = []
        token = None
        for _ in range(10):
            body, _r = await _objects(
                session,
                _user(world["tenant_a"]),
                world["collections"]["all"],
                limit=1,
                next_token=token,
            )
            seen.extend(o["id"] for o in body["objects"])
            if not body["more"]:
                break
            token = body["next"]
        else:
            pytest.fail("pagination did not terminate")

        assert len(seen) == 4, f"walked {len(seen)} objects in single-row pages"
        assert len(set(seen)) == 4, "an object was returned twice"

    async def test_more_is_false_on_the_last_page(self, session, world):
        body, _ = await _objects(session, _user(world["tenant_a"]), world["collections"]["all"], limit=100)
        assert body["more"] is False
        assert "next" not in body

    async def test_added_after_excludes_what_the_client_already_has(self, session, world):
        boundary = (world["base"] + timedelta(seconds=1)).isoformat()
        body, _ = await _objects(
            session,
            _user(world["tenant_a"]),
            world["collections"]["all"],
            added_after=boundary,
        )
        # Only the row at base+2s is strictly after the boundary among the
        # publishable ones.
        assert len(body["objects"]) == 1

    async def test_a_corrupt_next_token_is_a_400_not_a_silent_restart(self, session, world):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _objects(
                session,
                _user(world["tenant_a"]),
                world["collections"]["all"],
                next_token="2026-10-11T09:00:00+00:00|" + str(uuid.uuid4()) + "|deadbeef",
            )
        assert exc.value.status_code == 400

    async def test_the_manifest_pages_by_the_same_cursor_as_objects(self, session, world):
        import json

        from app.api.v1.endpoints.taxii import API_ROOT, get_manifest

        response = await get_manifest(
            api_root=API_ROOT,
            collection_ref=str(world["collections"]["all"]),
            current_user=_user(world["tenant_a"]),
            db=session,
        )
        manifest = json.loads(response.body)
        body, _ = await _objects(session, _user(world["tenant_a"]), world["collections"]["all"])
        # Two orderings would let a client hold a manifest entry it can
        # never reach through objects.
        assert [e["id"] for e in manifest["objects"]] == [o["id"] for o in body["objects"]]


# ---------------------------------------------------------------------------
# Posture.
# ---------------------------------------------------------------------------


class TestWritesAreRefused:
    async def test_a_write_is_403_and_says_why(self, session, world):
        import json

        from app.api.v1.endpoints.taxii import API_ROOT, refuse_write

        response = await refuse_write(api_root=API_ROOT, collection_ref=str(world["collections"]["all"]))
        assert response.status_code == 403
        body = json.loads(response.body)
        assert "does not accept" in body["description"]

    async def test_every_collection_advertises_can_write_false(self, session, world):
        import json

        from app.api.v1.endpoints.taxii import API_ROOT, list_collections

        response = await list_collections(api_root=API_ROOT, current_user=_user(world["tenant_a"]), db=session)
        for collection in json.loads(response.body)["collections"]:
            assert collection["can_write"] is False
