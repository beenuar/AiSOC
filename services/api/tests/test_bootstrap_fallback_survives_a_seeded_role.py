"""A seeded role is not a configured tenant, and an admin must keep its grant.

What broke
----------
`resolve_permissions` falls back to the static `ROLE_PERMISSIONS` map only on
the bootstrap path -- a tenant that has nothing for the database to answer
with. Everywhere else the database is authoritative, so that removing a
user's roles actually removes their access instead of quietly restoring their
static ones.

`_tenant_has_rbac` decided which path a request was on by counting rows in
`roles`. Migration `091_sso_policy.sql` then seeded the new `infosec` role
into *every* tenant with a single statement::

    INSERT INTO roles (tenant_id, name, description, is_system)
    SELECT t.id, 'infosec', ... FROM tenants t

From the moment it ran, every tenant in the world had a role row, so the
predicate answered True everywhere and the bootstrap path stopped existing.
An `admin` whose permissions came from the static map resolved to the empty
set and **every authorized route answered 403** -- on a fresh install, before
anyone had configured anything. The golden-pipeline job caught it as
``the API refused the read (HTTP 403)`` after a successful mint.

Why this test runs against live Postgres
----------------------------------------
The unit tests for this resolver drive a `_FakeSession` whose `scalar()`
returns a `tenant_role_count` the test supplies. That double answers the
count query *as the test imagines it* -- so it cannot distinguish "counts
role rows" from "counts grants", and it has no migrations, which is where the
seed lives. Both of those are exactly the boundary the defect sat on, and
both unit tests passed throughout. Only a database with the real migration
chain applied can tell the difference.

Skips when no database answers so a local run stays green, but cannot skip
where it is meant to run: `integration.yml` sets `MSSP_ISOLATION_REQUIRED=1`
and an unreachable database is then a failure.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.core.permission_cache import _tenant_has_rbac, grants, reset_for_tests, resolve_permissions
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e110000-0000-0000-0000-00000000000b")
ADMIN = uuid.UUID("0e110000-0000-0000-0000-0000000000a1")
COLLEAGUE = uuid.UUID("0e110000-0000-0000-0000-0000000000a2")


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
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the bootstrap-fallback proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _seed(session)
        try:
            yield session
        finally:
            await _clear_grants(session)
    await engine.dispose()


async def _seed(session) -> None:
    """A tenant carrying the seeded role and two users, neither granted anything.

    This is the shape migration 091 leaves behind on a tenant nobody has
    administered: one `roles` row that no operator asked for, and no grants.
    """
    await session.rollback()
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'bootstrap-proof', :s) ON CONFLICT DO NOTHING"),
        {"t": str(TENANT), "s": f"bootstrap-proof-{TENANT.hex[:8]}"},
    )
    for uid, email in ((ADMIN, "bootstrap-admin@example.com"), (COLLEAGUE, "bootstrap-colleague@example.com")):
        await session.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :e, 'x', 'admin', true) ON CONFLICT DO NOTHING"
            ),
            {"i": str(uid), "t": str(TENANT), "e": email},
        )
    # The seed migration 091 performs, reproduced for this tenant so the test
    # does not depend on having been created before that migration ran.
    await session.execute(
        text(
            "INSERT INTO roles (tenant_id, name, description, is_system) "
            "VALUES (CAST(:t AS uuid), 'infosec', 'seeded by migration 091', TRUE) ON CONFLICT DO NOTHING"
        ),
        {"t": str(TENANT)},
    )
    await session.commit()
    reset_for_tests()


async def _clear_grants(session) -> None:
    await session.rollback()
    await session.execute(
        text("DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE tenant_id = CAST(:t AS uuid))"),
        {"t": str(TENANT)},
    )
    await session.commit()
    reset_for_tests()


@pytest.mark.asyncio
class TestASeededRoleIsNotAConfiguredTenant:
    async def test_the_seeded_role_alone_does_not_make_the_tenant_configured(self, db) -> None:
        """The predicate itself, stated directly.

        A role row exists. Nobody has been granted anything. That is a
        bootstrap tenant, and reading it as a configured one is what took
        the fallback away.
        """
        assert await _tenant_has_rbac(db, TENANT) is False

    async def test_an_admin_keeps_its_permissions_on_a_freshly_migrated_tenant(self, db) -> None:
        """The 403 a user would have hit, as an assertion.

        Before the fix this resolved to `frozenset()` and the console was
        locked out of a deployment nobody had misconfigured.
        """
        resolved = await resolve_permissions(db, tenant_id=TENANT, user_id=ADMIN, static_role="admin")
        assert resolved, "an admin on a freshly migrated tenant resolved to no permissions at all"
        assert grants(resolved, "alerts:read")

    async def test_a_real_grant_still_ends_the_bootstrap_path(self, db) -> None:
        """The hole the predicate exists to close, proven still closed.

        Once anyone in the tenant holds a grant, access is being
        administered, and a user without one has been *left* without one.
        Handing them their static role back would undo the deprovisioning,
        which is the defect the original predicate was written for.
        """
        role_id = await db.scalar(text("SELECT id FROM roles WHERE tenant_id = CAST(:t AS uuid) LIMIT 1"), {"t": str(TENANT)})
        await db.execute(
            text("INSERT INTO user_roles (user_id, role_id) VALUES (CAST(:u AS uuid), :r) ON CONFLICT DO NOTHING"),
            {"u": str(COLLEAGUE), "r": role_id},
        )
        await db.commit()
        reset_for_tests()

        assert await _tenant_has_rbac(db, TENANT) is True
        resolved = await resolve_permissions(db, tenant_id=TENANT, user_id=ADMIN, static_role="admin")
        assert resolved == frozenset(), "a user with no grant was handed their static role back"
