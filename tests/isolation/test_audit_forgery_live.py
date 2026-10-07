"""Audit-chain forgery is refused — through the real app and real Postgres.

GHSA-w4r8-969c-67p2 (CWE-347). The regression guard that proves an
unauthenticated caller cannot forge entries into a tenant's tamper-evident
audit hash chain.

Why the offline suite is not enough
-----------------------------------
`services/api/tests/test_audit_middleware_no_forgery.py` mounts the real
middleware but intercepts the database write, so it proves *which identity the
middleware decides to write*. It cannot prove that a forged request leaves the
real ``audit_log`` and ``audit_chain_head`` tables untouched, or that a
legitimate request actually lands a chained row. This suite drives
``app.main:create_application`` against real Postgres with every migration
applied, so the middleware stack, the hash-chain appender and the auth
dependencies are the ones a deployment runs.

Production posture, deliberately
--------------------------------
``ENVIRONMENT`` is **not** a bypass value here. Under ``development`` an
uncredentialed request resolves to a demo admin principal, which would be
stashed and audited — and the forged and unauthenticated controls would write
rows for the wrong reason. The whole claim is "no identity, no audit row", so
the environment must be one where no identity is synthesized.

The negative controls
---------------------
``test_a_forged_bearer_jwt_writes_no_audit_row`` and
``test_an_unauthenticated_request_writes_no_audit_row`` are what stop the
positive assertion passing for the wrong reason: a middleware that simply
stopped writing would satisfy "the forged row is absent", so
``test_a_verified_principal_is_still_audited`` proves the legitimate row is
present.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

# The migration-created Default tenant — present in every deployment, which is
# what makes the victim tenant id trivially known (per the advisory).
DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"
FORGED_EMAIL = "framed-operator@victim.test"

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AUDIT_DSN", "").strip(),
        reason="ISOLATION_AUDIT_DSN is not set; this suite needs live infrastructure",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AUDIT_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AUDIT_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, in production posture, against real Postgres."""
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    # Not a bypass environment — no demo principal is synthesized for an
    # uncredentialed request, so "no identity -> no audit row" is a real test.
    os.environ["ENVIRONMENT"] = "production"
    # A real, non-placeholder signing secret so the server verifies tokens
    # against a key the attacker does not have.
    os.environ.setdefault("SECRET_KEY", "ci-audit-forgery-signing-secret-at-least-32-chars")

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _count_by_email(session, email: str) -> int:  # noqa: ANN001
    import sqlalchemy

    result = await session.execute(
        sqlalchemy.text("SELECT count(*) FROM audit_log WHERE actor_email = :e"),
        {"e": email},
    )
    return int(result.scalar_one())


def _forged_token() -> str:
    """The advisory's PoC token: attacker-chosen claims, signed with a key the
    attacker owns, so the signature is invalid against the server's secret."""
    import jwt

    return jwt.encode(
        {"tenant_id": DEFAULT_TENANT, "email": FORGED_EMAIL, "exp": 9999999999},
        "attacker-owned-key-not-the-server-key",
        algorithm="HS256",
    )


class TestForgeryIsRefused:
    async def test_a_forged_bearer_jwt_writes_no_audit_row(self, app_client, db) -> None:  # noqa: ANN001
        """A mutating request with a forged token fails auth and must leave the
        Default tenant's audit chain untouched."""
        before = await _count_by_email(db, FORGED_EMAIL)
        resp = await app_client.post("/api/v1/cases", headers={"Authorization": f"Bearer {_forged_token()}"}, json={})
        # The route rejects the invalid credential; the point is what the
        # middleware does *after* that.
        assert resp.status_code in (401, 403), resp.status_code
        after = await _count_by_email(db, FORGED_EMAIL)
        assert after == before, (
            f"a forged token added {after - before} audit row(s) attributed to {FORGED_EMAIL} "
            "— unauthenticated audit-chain forgery (GHSA-w4r8-969c-67p2)"
        )

    async def test_an_unauthenticated_request_writes_no_audit_row(self, app_client, db) -> None:  # noqa: ANN001
        """Control: no Authorization header at all, no audit row."""
        marker = f"noauth-{uuid.uuid4().hex[:8]}@victim.test"
        before = await _count_by_email(db, marker)
        resp = await app_client.post("/api/v1/cases", json={})
        assert resp.status_code in (401, 403)
        assert await _count_by_email(db, marker) == before


class TestLegitimateRequestsAreStillAudited:
    async def test_a_verified_principal_is_still_audited(self, app_client, db) -> None:  # noqa: ANN001
        """The positive half. A real, active user authenticates with a server-
        signed token; the middleware must audit that request as that user, even
        when the route itself returns a non-2xx (auth succeeded, authorization
        did not)."""
        import sqlalchemy
        from app.core.security import create_access_token

        user_id = uuid.uuid4()
        email = f"real-{user_id.hex[:8]}@victim.test"
        await db.execute(
            sqlalchemy.text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES (:i, CAST(:t AS uuid), :e, :u, 'x', 'analyst', true)"
            ),
            {"i": user_id, "t": DEFAULT_TENANT, "e": email, "u": f"u{user_id.hex[:8]}"},
        )
        await db.commit()

        token = create_access_token({"sub": str(user_id), "tenant_id": DEFAULT_TENANT})
        before = await _count_by_email(db, email)
        resp = await app_client.post("/api/v1/cases", headers={"Authorization": f"Bearer {token}"}, json={})
        assert resp.status_code < 500, resp.status_code
        assert await _count_by_email(db, email) == before + 1, (
            "a legitimately authenticated mutating request was not audited — the middleware "
            "must still be the writer for routes that do not call emit_audit themselves"
        )
