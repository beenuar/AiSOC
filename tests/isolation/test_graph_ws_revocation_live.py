"""A revoked session cannot hold the graph WebSocket open. Real Postgres.

GHSA-25fh-rxp8-67j8.

The reporter's proof of concept, executed
----------------------------------------
Preconditions: an account whose `users.sessions_revoked_at` is set, and an
unexpired access token minted before that moment.

1. The HTTP dependency answers **401 Session revoked**.
2. The WebSocket resolver answered **101 Switching Protocols** and kept
   streaming.

Step 2 is the vulnerability, and the two steps use the same token. The test
below drives both resolvers against the same real row, which is the only way to
show that they now agree -- a source-reading test can show that the WebSocket
*calls* the shared function, and this shows what the shared function does with
a revoked principal.

Why this needs a live database
------------------------------
`token_is_revoked` compares the token's `iat` against a timestamp column, and
`resolve_permissions` reads `user_roles`. A fake session that answers any query
returns a user for both, which is precisely the double that let the original
defect ship: the offline suite could not tell a working revocation check from
an absent one.
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
        not os.environ.get("ISOLATION_WS_AUTH_DSN", "").strip(),
        reason="ISOLATION_WS_AUTH_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_WS_AUTH_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_WS_AUTH_DSN is not set")
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


@pytest_asyncio.fixture(loop_scope="module")
async def revoked_admin(engine):
    """An active admin, a token minted for it, and *then* a revocation.

    The sequence is the real one and runs in that order: `create_access_token`
    stamps `iat` as now, so the token is minted first and the revocation
    recorded a moment later, exactly as a de-provisioning does.

    `is_active` stays true on purpose. The point of the revocation column is
    that it ends a session *without* relying on the active flag, and a
    deactivated user would be refused by a check that was never at fault.
    """
    from app.core.security import create_access_token
    from sqlalchemy import text

    tenant = uuid.uuid4()
    user = uuid.uuid4()
    slug = f"wsrev-{tenant.hex[:8]}"

    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tenant, "n": slug, "s": slug},
        )
        await conn.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active)
                VALUES (:id, :t, :e, :e, 'x', 'admin', true)
                """
            ),
            {"id": user, "t": tenant, "e": f"{slug}@example.test"},
        )

    token = create_access_token({"sub": str(user), "tenant_id": str(tenant), "role": "admin", "email": f"{slug}@example.test"})

    # Then the de-provisioning. A minute later, so the comparison is not
    # decided by `iat`'s one-second resolution.
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET sessions_revoked_at = :r WHERE id = :id"),
            {"r": datetime.now(UTC) + timedelta(minutes=1), "id": user},
        )

    try:
        yield {"tenant_id": tenant, "user_id": user, "token": token}
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user})
            await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant})


class TestTheRevokedTokenIsRefusedOnBothSurfaces:
    async def test_the_shared_resolver_refuses_it(self, engine, revoked_admin) -> None:
        from app.api.v1.deps import resolve_jwt_principal
        from fastapi import HTTPException
        from sqlalchemy.ext.asyncio import AsyncSession

        token = revoked_admin["token"]

        async with AsyncSession(engine) as session:
            with pytest.raises(HTTPException) as caught:
                await resolve_jwt_principal(token, session)

        assert caught.value.status_code == 401
        assert "revoked" in str(caught.value.detail).lower(), caught.value.detail

    async def test_the_websocket_closes_rather_than_streaming(self, engine, revoked_admin) -> None:
        """The vulnerability itself: this used to return a principal and the
        stream stayed open."""
        from app.api.v1.endpoints.graph_ws import _authenticate_ws
        from sqlalchemy.ext.asyncio import AsyncSession

        closed: dict[str, object] = {}

        class _Socket:
            async def close(self, code: int, reason: str = "") -> None:
                closed["code"] = code
                closed["reason"] = reason

        token = revoked_admin["token"]

        async with AsyncSession(engine) as session:
            principal = await _authenticate_ws(_Socket(), token, session)

        assert principal is None, "the websocket accepted a revoked session"
        assert closed.get("code") == 1008, closed
        assert "revoked" in str(closed.get("reason", "")).lower(), closed


class TestAValidSessionStillWorks:
    """The negative control. A resolver that refused everything would pass
    every test above and take the product down."""

    @pytest_asyncio.fixture(loop_scope="module")
    async def live_admin(self, engine):
        from sqlalchemy import text

        tenant = uuid.uuid4()
        user = uuid.uuid4()
        slug = f"wsok-{tenant.hex[:8]}"
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": tenant, "n": slug, "s": slug},
            )
            await conn.execute(
                text(
                    """
                    INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                       role, is_active)
                    VALUES (:id, :t, :e, :e, 'x', 'admin', true)
                    """
                ),
                {"id": user, "t": tenant, "e": f"{slug}@example.test"},
            )
        try:
            yield {"tenant_id": tenant, "user_id": user}
        finally:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user})
                await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant})

    async def test_an_unrevoked_session_opens_the_socket(self, engine, live_admin) -> None:
        from app.api.v1.endpoints.graph_ws import _authenticate_ws
        from app.core.security import create_access_token
        from sqlalchemy.ext.asyncio import AsyncSession

        class _Socket:
            async def close(self, code: int, reason: str = "") -> None:
                raise AssertionError(f"closed a valid session: {code} {reason}")

        token = create_access_token(
            {
                "sub": str(live_admin["user_id"]),
                "tenant_id": str(live_admin["tenant_id"]),
                "role": "admin",
                "email": "x@example.test",
            }
        )

        async with AsyncSession(engine) as session:
            principal = await _authenticate_ws(_Socket(), token, session)

        assert principal is not None
        assert principal.user_id == live_admin["user_id"]

    async def test_the_principal_carries_database_permissions(self, engine, live_admin) -> None:
        """The second half of the advisory: `resolved_permissions` was `None`,
        so `require_permission` fell back to the static role map and a wildcard
        role passed unconditionally."""
        from app.api.v1.endpoints.graph_ws import _authenticate_ws
        from app.core.security import create_access_token
        from sqlalchemy.ext.asyncio import AsyncSession

        class _Socket:
            async def close(self, code: int, reason: str = "") -> None:
                raise AssertionError(f"closed a valid session: {code} {reason}")

        token = create_access_token(
            {
                "sub": str(live_admin["user_id"]),
                "tenant_id": str(live_admin["tenant_id"]),
                "role": "admin",
                "email": "x@example.test",
            }
        )

        async with AsyncSession(engine) as session:
            principal = await _authenticate_ws(_Socket(), token, session)

        assert principal is not None
        assert principal.resolved_permissions is not None, (
            "the websocket principal still carries no database permissions, so require_permission falls back to the static role map"
        )
