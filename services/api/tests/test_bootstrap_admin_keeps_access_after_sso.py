"""Activating SSO must not lock the administrator who activated it out.

Discussion #1568: an operator enabled SSO OIDC and the admin account
immediately lost access — 403 on `/api/v1/alerts/queue`, on
`/api/v1/admin/users`, on investigations. Nothing about the admin changed; a
*different* user signing in did.

The mechanism, proven by `test_bootstrap_fallback_survives_a_seeded_role.py`
(whose last case asserts, correctly, that an ungranted user in a configured
tenant resolves to nothing): `resolve_permissions` falls back to the static
`ROLE_PERMISSIONS` map only while a tenant holds *zero* `user_roles` grants.
The bootstrap admin is created by `bootstrap_admin.py`, which runs after
migration 092's membership backfill, so it alone carries `users.role = admin`
with no `user_roles` row. That is harmless — until the first SSO sign-in
provisions a user and grants it a role. That first grant flips the tenant to
database-backed RBAC, and from that instant the ungranted admin resolves to
the empty set and every authorized route answers 403.

The fix does not touch the resolver (its deprovisioning semantics are
correct and separately pinned). It ensures the break-glass admin *has* its
catalog grant, so it is never the ungranted user. This test reproduces the
lockout, applies the fix exactly as `bootstrap_admin` now does, and asserts
access is restored — with the pre-fix lockout standing as the negative
control.

Live Postgres, same rationale as the sibling file: a fake session cannot tell
"counts grants" from "counts roles", and the migration chain is where the
catalog lives. Skips when no database answers, but cannot skip where
`integration.yml` requires it.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.core.permission_cache import grants, reset_for_tests, resolve_permissions
from app.core.rbac_catalog import seed_tenant_catalog, sync_user_catalog_role
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("55081568-0000-0000-0000-00000000000b")
ADMIN = uuid.UUID("55081568-0000-0000-0000-0000000000a1")
SSO_USER = uuid.UUID("55081568-0000-0000-0000-0000000000a2")


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
                f"the SSO-lockout proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _seed(session)
        try:
            yield session
        finally:
            await _teardown(session)
    await engine.dispose()


async def _seed(session) -> None:
    """A tenant whose catalog is seeded, an admin created *after* that seed
    (so it has no grant), and an SSO user who does hold one.

    `seed_tenant_catalog` runs before any user exists, so its membership
    backfill grants nobody — which is the production shape: the admin is
    created later by `bootstrap_admin`, and the SSO user later still.
    """
    await session.rollback()
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'sso-lockout', :s) ON CONFLICT DO NOTHING"),
        {"t": str(TENANT), "s": f"sso-lockout-{TENANT.hex[:8]}"},
    )
    await seed_tenant_catalog(session, TENANT)
    await session.commit()

    for uid, email, role in ((ADMIN, "sso-lockout-admin@example.com", "admin"), (SSO_USER, "sso-lockout-user@example.com", "viewer")):
        await session.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :e, 'x', :r, true) ON CONFLICT DO NOTHING"
            ),
            {"i": str(uid), "t": str(TENANT), "e": email, "r": role},
        )
    await session.commit()
    reset_for_tests()


async def _teardown(session) -> None:
    await session.rollback()
    await session.execute(
        text("DELETE FROM user_roles WHERE user_id IN (CAST(:a AS uuid), CAST(:u AS uuid))"),
        {"a": str(ADMIN), "u": str(SSO_USER)},
    )
    await session.execute(text("DELETE FROM users WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()
    reset_for_tests()


@pytest.mark.asyncio
class TestSsoActivationDoesNotLockOutTheAdmin:
    async def test_the_first_sso_grant_locks_out_an_ungranted_admin(self, db) -> None:
        """The reported 403, as an assertion — the negative control for the fix.

        The admin holds no grant. The moment the SSO user is granted a role,
        the tenant is database-backed and the admin resolves to nothing.
        """
        await sync_user_catalog_role(db, tenant_id=TENANT, user_id=SSO_USER, role_name="viewer")
        await db.commit()
        reset_for_tests()

        resolved = await resolve_permissions(db, tenant_id=TENANT, user_id=ADMIN, static_role="admin")
        assert resolved == frozenset(), (
            "expected the pre-fix lockout: an ungranted admin should resolve to nothing once the tenant is DB-backed"
        )

    async def test_granting_the_admin_its_catalog_role_restores_access(self, db) -> None:
        """The fix: `bootstrap_admin` grants the admin its catalog role, so it
        is never the ungranted user when the SSO grant flips the tenant."""
        await sync_user_catalog_role(db, tenant_id=TENANT, user_id=SSO_USER, role_name="viewer")
        await db.commit()
        reset_for_tests()
        # Precondition: locked out, exactly as the control above.
        assert await resolve_permissions(db, tenant_id=TENANT, user_id=ADMIN, static_role="admin") == frozenset()

        # This is what bootstrap_admin now does on every startup.
        await sync_user_catalog_role(db, tenant_id=TENANT, user_id=ADMIN, role_name="admin")
        await db.commit()
        reset_for_tests()

        resolved = await resolve_permissions(db, tenant_id=TENANT, user_id=ADMIN, static_role="admin")
        assert grants(resolved, "users:read"), "the admin cannot see the user list after the fix"
        assert grants(resolved, "alerts:read"), "the admin cannot read the alert queue after the fix"
        assert grants(resolved, "anything:at:all"), "the admin wildcard did not resolve"
