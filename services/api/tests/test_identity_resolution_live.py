"""Identity resolution against real Postgres (depth plan wave 2, Phase 3.1).

Live because every property is a schema or SQL fact a stand-in invents: the
ordered-pair CHECK that stores a link once however it was discovered, the
unique index that makes a re-resolution an update, the merge-strength filter
inside the cluster walk, and the tenant predicate on all of it.

The cluster walk is the test that matters most. A weak link must not be
traversable, and the way that breaks is a chain: three weak hops joining two
identities no single rule would join. That cannot be checked by reading the
code, because the filter is in the SQL.

Each test carries a negative control.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.services.identity_resolution import IdentityLink, ResolutionResult, resolve_links
from app.services.identity_resolution_store import cluster_for, decide_link, links_for, save_links
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e730000-0000-0000-0000-0000000000c1")
OTHER_TENANT = uuid.UUID("0e730000-0000-0000-0000-0000000000c2")
USER = uuid.UUID("0e730000-0000-0000-0000-0000000000c3")


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for tid, slug in ((TENANT, "idres-live-a"), (OTHER_TENANT, "idres-live-b")):
            await session.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
                {"id": tid, "name": f"Identity resolution {slug}", "slug": slug},
            )
        await session.commit()
        yield session
        await session.rollback()
        await session.execute(
            text("DELETE FROM identity_links WHERE tenant_id IN (:a, :b)"),
            {"a": TENANT, "b": OTHER_TENANT},
        )
        await session.commit()
    await engine.dispose()


def _result(*links: IdentityLink) -> ResolutionResult:
    return ResolutionResult(links=list(links))


def _strong(left: str, right: str, rule: str = "verified_email_match") -> IdentityLink:
    return IdentityLink(left=left, right=right, confidence=0.98, rule=rule, evidence=["same verified address"])


def _weak(left: str, right: str) -> IdentityLink:
    return IdentityLink(left=left, right=right, confidence=0.45, rule="local_part_only", evidence=["local part only"])


@pytest.mark.asyncio
async def test_a_pair_is_stored_once_however_it_was_discovered(db) -> None:
    """The ordered-pair CHECK, which a writer could otherwise bypass."""
    await save_links(db, tenant_id=TENANT, result=_result(_strong("aws:z", "okta:a")), mirror_to_graph=False)
    await save_links(db, tenant_id=TENANT, result=_result(_strong("okta:a", "aws:z")), mirror_to_graph=False)
    await db.commit()

    count = (await db.execute(text("SELECT count(*) FROM identity_links WHERE tenant_id = :t"), {"t": TENANT})).scalar_one()
    assert count == 1

    # Negative control: the constraint is real, not merely respected by the
    # writer. An out-of-order insert must be refused by the database.
    with pytest.raises(Exception) as excinfo:
        await db.execute(
            text("INSERT INTO identity_links (tenant_id, left_key, right_key, confidence, rule) VALUES (:t, 'zzz', 'aaa', 0.99, 'manual')"),
            {"t": TENANT},
        )
        await db.commit()
    assert "identity_links_ordered_check" in str(excinfo.value)
    await db.rollback()


@pytest.mark.asyncio
async def test_weak_links_are_stored_and_returned_but_not_walked(db) -> None:
    """Three weak hops must not merge what no single rule would join."""
    await save_links(
        db,
        tenant_id=TENANT,
        result=_result(_weak("a:1", "b:2"), _weak("b:2", "c:3"), _weak("c:3", "d:4")),
        mirror_to_graph=False,
    )
    await db.commit()

    shown = await links_for(db, tenant_id=TENANT, key="a:1")
    assert shown, "the weak link was dropped; it must be stored and shown"
    assert all(link["merged"] is False for link in shown)
    assert await cluster_for(db, tenant_id=TENANT, key="a:1") == []

    # Positive control: the walk works at all. Without this, a cluster_for
    # that always returned [] would pass the assertion above.
    await save_links(db, tenant_id=TENANT, result=_result(_strong("a:1", "z:9")), mirror_to_graph=False)
    await db.commit()
    assert await cluster_for(db, tenant_id=TENANT, key="a:1") == ["z:9"]


@pytest.mark.asyncio
async def test_a_strong_chain_does_traverse(db) -> None:
    """Transitivity over strong links is intended and must actually work."""
    await save_links(
        db,
        tenant_id=TENANT,
        result=_result(_strong("a:1", "b:2"), _strong("b:2", "c:3")),
        mirror_to_graph=False,
    )
    await db.commit()
    assert await cluster_for(db, tenant_id=TENANT, key="a:1") == ["b:2", "c:3"]


@pytest.mark.asyncio
async def test_the_walk_is_bounded(db) -> None:
    """A bounded wrong answer is recoverable; an unbounded one is not."""
    chain = [_strong(f"n:{i}", f"n:{i + 1}") for i in range(6)]
    await save_links(db, tenant_id=TENANT, result=_result(*chain), mirror_to_graph=False)
    await db.commit()

    shallow = await cluster_for(db, tenant_id=TENANT, key="n:0", max_depth=1)
    deep = await cluster_for(db, tenant_id=TENANT, key="n:0", max_depth=6)
    assert len(shallow) < len(deep)
    assert "n:1" in shallow


@pytest.mark.asyncio
async def test_a_human_decision_overrides_the_rule_both_ways(db) -> None:
    await save_links(db, tenant_id=TENANT, result=_result(_weak("a:1", "b:2")), mirror_to_graph=False)
    await db.commit()
    weak = (await links_for(db, tenant_id=TENANT, key="a:1"))[0]
    assert weak["merged"] is False

    confirmed = await decide_link(db, tenant_id=TENANT, link_id=uuid.UUID(weak["id"]), decision="confirmed", user_id=USER)
    await db.commit()
    assert confirmed is not None
    assert confirmed["merged"] is True
    # The confidence is untouched: the rule did not become more certain, a
    # human disagreed with it, and the two facts stay separable.
    assert confirmed["confidence"] == weak["confidence"]
    assert await cluster_for(db, tenant_id=TENANT, key="a:1") == ["b:2"]

    # And the other direction: rejecting a strong link removes it from the walk.
    await save_links(db, tenant_id=TENANT, result=_result(_strong("a:1", "c:3")), mirror_to_graph=False)
    await db.commit()
    strong = next(link for link in await links_for(db, tenant_id=TENANT, key="a:1") if link["right"] == "c:3")
    await decide_link(db, tenant_id=TENANT, link_id=uuid.UUID(strong["id"]), decision="rejected", user_id=USER)
    await db.commit()
    assert "c:3" not in await cluster_for(db, tenant_id=TENANT, key="a:1")


@pytest.mark.asyncio
async def test_another_tenants_links_are_invisible(db) -> None:
    await save_links(db, tenant_id=OTHER_TENANT, result=_result(_strong("a:1", "b:2")), mirror_to_graph=False)
    await db.commit()

    assert await links_for(db, tenant_id=TENANT, key="a:1") == []
    assert await cluster_for(db, tenant_id=TENANT, key="a:1") == []
    assert await links_for(db, tenant_id=OTHER_TENANT, key="a:1")


@pytest.mark.asyncio
async def test_the_resolver_and_the_store_agree_end_to_end(db) -> None:
    """The pure half and the stored half must produce the same verdict.

    Without this the resolver could be correct and the store could persist
    something else, which is the shape where two components are each right
    and the product is wrong.
    """
    result = resolve_links(
        [
            {"source": "idp", "id": "alice@example.com", "email": "alice@example.com", "email_verified": True},
            {
                "source": "cloud_principal",
                "id": "arn:aws:iam::1:user/alice",
                "email": "alice@example.com",
                "email_verified": True,
            },
            {"source": "workspace", "id": "alice@contoso.com"},
        ]
    )
    await save_links(db, tenant_id=TENANT, result=result, mirror_to_graph=False)
    await db.commit()

    in_memory = {frozenset(c) for c in result.clusters_for_merge()}
    stored = await cluster_for(db, tenant_id=TENANT, key="idp:alice@example.com")
    assert {frozenset({"idp:alice@example.com", *stored})} == in_memory

    # The weak cross-domain link is stored and visible, and is not in the cluster.
    shown = await links_for(db, tenant_id=TENANT, key="workspace:alice@contoso.com")
    assert shown and all(link["merged"] is False for link in shown)
    assert "workspace:alice@contoso.com" not in stored
