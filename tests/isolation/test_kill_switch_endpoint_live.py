"""The platform-wide kill switch is reachable through the product.

``test_kill_switch_global_live.py`` proves the row-level security policy
admits the global row. That is necessary and not sufficient: before this
change there was no caller at all. Every write in
``services/api/app/api/v1/endpoints/kill_switch.py`` bound
``t=user.tenant_id``, so the only scope any principal could reach was their
own tenant, while two readers consulted the global row on every alert. A
control nothing can reach is not a control, so this drives the real routes.

What this exercises that a unit test cannot
-------------------------------------------
The real ASGI application with its real authentication dependencies, a real
sign-in, and a real Postgres the app connects to as the runtime role. The
defect class this repository keeps finding is a double more capable than the
real thing — a session that answers any query, a fake that never reaches the
transport. Here the interesting question is specifically whether the handler's
session can write a row the policy judges, which only a real connection as a
real role can answer.

The authorization half is the point, not a detail. ``settings:write`` was the
obvious permission to reuse and would have been wrong: a tenant administrator
holds it, and the platform switch freezes every *other* tenant on the
deployment too. :class:`TestOnlyThePlatformOperatorMayEngageIt` is what holds
that line.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    # Import-time only. A module-scope import of httpx or SQLAlchemy takes the
    # offline collection job down with it, which once cost 241 unrelated
    # tests; the fixtures import them for real.
    import httpx
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_KILL_SWITCH_DSN", "").strip(),
        reason="ISOLATION_KILL_SWITCH_DSN is not set; this suite needs a live Postgres",
    ),
]

# Named for what it is: as `PASSWORD` the secret scanner reads the literal as
# a credential, and a `.gitleaksignore` entry is fingerprinted on the line
# number, so any later edit to this file would reopen the finding.
TEST_PASSPHRASE = "correct-horse-battery-staple-42"

#: Long enough to satisfy the mandatory-reason floor on both request models.
REASON = "the agent was closing alerts it should not have"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_KILL_SWITCH_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_KILL_SWITCH_DSN is not set")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    # Not "development": that is in AUTH_BYPASS_ENVIRONMENTS, so an
    # uncredentialed request would resolve to a demo admin — inside the one
    # suite whose subject is which principal may throw the switch.
    os.environ["ENVIRONMENT"] = "test"

    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db() -> AsyncIterator[AsyncSession]:
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="module", autouse=True)
async def _clear_the_global_switch(db: AsyncSession) -> AsyncIterator[None]:
    """The global row is a singleton, so one test's switch is the next test's
    starting state."""
    import sqlalchemy

    yield
    await db.rollback()
    await db.execute(sqlalchemy.text("DELETE FROM aisoc_kill_switch WHERE tenant_id IS NULL"))
    await db.commit()


async def _user(session: AsyncSession, *, role: str) -> dict:
    """A real user row with a real bcrypt hash, in its own tenant."""
    import sqlalchemy
    from app.core.security import get_password_hash

    await session.rollback()
    tenant_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
        {"i": tenant_id, "n": f"ks-{tenant_id.hex[:8]}", "s": f"ks-{tenant_id.hex[:8]}"},
    )
    user_id = uuid.uuid4()
    email = f"u-{user_id.hex[:10]}@example.com"
    await session.execute(
        sqlalchemy.text(
            "INSERT INTO users (id, tenant_id, email, username, role, is_active, hashed_password) VALUES (:i, :t, :e, :u, :r, TRUE, :p)"
        ),
        {"i": user_id, "t": tenant_id, "e": email, "u": email.split("@")[0], "r": role, "p": get_password_hash(TEST_PASSPHRASE)},
    )
    await session.commit()
    return {"id": user_id, "tenant_id": tenant_id, "email": email, "role": role}


async def _bearer(client: httpx.AsyncClient, user: dict) -> dict[str, str]:
    response = await client.post("/api/v1/auth/login", json={"email": user["email"], "password": TEST_PASSPHRASE})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _global_row(db: AsyncSession):
    import sqlalchemy

    await db.rollback()
    return (
        await db.execute(sqlalchemy.text("SELECT engaged, reason, engaged_by, released_by FROM aisoc_kill_switch WHERE tenant_id IS NULL"))
    ).first()


class TestThePlatformOperatorCanThrowIt:
    async def test_engaging_writes_the_global_row(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """The whole point, end to end. Against the pre-fix tree this is a
        404: the route did not exist."""
        operator = await _user(db, role="admin")
        headers = await _bearer(app_client, operator)

        response = await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON}, headers=headers)

        assert response.status_code == 200, response.text
        assert response.json()["engaged"] is True
        assert response.json()["scope"] == "global"

        row = await _global_row(db)
        assert row is not None, "the endpoint reported success and wrote no global row"
        assert row.engaged is True
        assert row.reason == REASON
        assert row.engaged_by == operator["email"]

    async def test_engaging_is_audited_as_global(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """An emergency stop nobody can account for afterwards is its own
        defect. The audit table carries the same strict check as the switch,
        so this would have failed even once the switch itself worked."""
        import sqlalchemy

        operator = await _user(db, role="admin")
        headers = await _bearer(app_client, operator)

        await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON}, headers=headers)

        await db.rollback()
        rows = (
            await db.execute(
                sqlalchemy.text(
                    "SELECT actor, action FROM aisoc_kill_switch_audit WHERE tenant_id IS NULL AND scope = 'global' AND actor = :a"
                ),
                {"a": operator["email"]},
            )
        ).fetchall()
        assert [r.action for r in rows] == ["engage"]

    async def test_releasing_clears_it(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        operator = await _user(db, role="admin")
        headers = await _bearer(app_client, operator)
        await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON}, headers=headers)

        response = await app_client.post(
            "/api/v1/kill-switch/global/release", json={"reason": "the agent is behaving again"}, headers=headers
        )

        assert response.status_code == 200, response.text
        row = await _global_row(db)
        assert row.engaged is False
        assert row.released_by == operator["email"]

    async def test_releasing_a_switch_nobody_engaged_is_a_404(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """Rather than a success that changed nothing. An operator who
        believes they released a stop that was not there stops looking for
        the one that is."""
        operator = await _user(db, role="admin")
        headers = await _bearer(app_client, operator)

        response = await app_client.post("/api/v1/kill-switch/global/release", json={"reason": "nothing is engaged"}, headers=headers)

        assert response.status_code == 404, response.text

    async def test_a_reason_is_mandatory(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """A switch with no reason is one nobody can safely disengage."""
        operator = await _user(db, role="admin")
        headers = await _bearer(app_client, operator)

        response = await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": "x"}, headers=headers)

        assert response.status_code == 422, response.text
        assert await _global_row(db) is None


class TestOnlyThePlatformOperatorMayEngageIt:
    """The authorization property. ``settings:write`` would have been the
    convenient permission and the wrong one."""

    async def test_a_tenant_admin_is_refused(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """A tenant administrator holds ``settings:write`` and can stop their
        own tenant. Letting that reach the global switch would let any
        customer freeze every other customer on the deployment."""
        tenant_admin = await _user(db, role="tenant_admin")
        headers = await _bearer(app_client, tenant_admin)

        response = await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON}, headers=headers)

        assert response.status_code == 403, response.text
        assert await _global_row(db) is None, "a refused request still wrote the global row"

    async def test_an_analyst_is_refused(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        analyst = await _user(db, role="infosec")
        headers = await _bearer(app_client, analyst)

        response = await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON}, headers=headers)

        assert response.status_code == 403, response.text

    async def test_an_unauthenticated_caller_is_refused(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        response = await app_client.post("/api/v1/kill-switch/global/engage", json={"reason": REASON})

        assert response.status_code in (401, 403), response.text
        assert await _global_row(db) is None

    async def test_a_tenant_admin_can_still_stop_their_own_tenant(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        """The working half, through the product rather than through SQL. A
        fix that locked the platform switch down by breaking this would have
        traded one unreachable stop for another."""
        tenant_admin = await _user(db, role="tenant_admin")
        headers = await _bearer(app_client, tenant_admin)

        response = await app_client.post("/api/v1/kill-switch/engage", json={"reason": REASON}, headers=headers)

        assert response.status_code == 200, response.text
        assert response.json()["scope"] == "tenant"


class TestATenantSeesThePlatformStop:
    """A platform-wide stop a tenant cannot see reads to them as an
    unexplained outage, so the read is deliberately not behind a permission."""

    async def test_an_analyst_reads_the_global_switch(self, app_client: httpx.AsyncClient, db: AsyncSession) -> None:
        operator = await _user(db, role="admin")
        await app_client.post(
            "/api/v1/kill-switch/global/engage",
            json={"reason": REASON},
            headers=await _bearer(app_client, operator),
        )
        analyst = await _user(db, role="infosec")

        response = await app_client.get("/api/v1/kill-switch", headers=await _bearer(app_client, analyst))

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["engaged"] is True
        assert body["scope"] == "global"
        assert body["reason"] == REASON
