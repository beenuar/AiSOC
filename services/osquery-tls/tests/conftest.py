"""Shared pytest fixtures for the osquery-tls service tests.

Uses an in-memory SQLite database for speed.  SQLite doesn't support every
Postgres feature but it is sufficient for the ORM-level tests here.
"""

from __future__ import annotations

import os

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Override env before importing the app so settings resolves without secrets.
os.environ.setdefault("AISOC_OSQUERY_TLS_ENROLL_SECRET", "test-enroll-secret")
os.environ.setdefault("AISOC_OSQUERY_TLS_API_TOKEN", "test-api-token")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
# The internal (non-osqueryd) routes take a tenant, so they resolve one from
# the caller's credential. Production reaches them with the shared service
# token; the tests do the same rather than bypassing the check they exist to
# keep honest.
os.environ.setdefault("AISOC_SERVICE_TOKEN", "test-service-token")

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

# The canonical seed tenant from the platform's migration 001. This service
# shares the platform database in every real deployment (`DATABASE_URL` points
# at the same `aisoc` database), and `tenant_resolver` reads `tenants` to turn
# an enrolling node's tenant ref into the platform UUID. The harness only ever
# created this service's own tables, so it modelled a deployment that does not
# exist; the two-column stand-in below is the minimum that makes the tests
# describe the real topology.
CANONICAL_TENANT_ID = "00000000-0000-0000-0000-000000000001"


@pytest_asyncio.fixture(scope="function")
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, slug TEXT, name TEXT)"))
        # Seeded with slug 'demo', not 'default': the demo seed renames it,
        # and resolving the literal 'default' by slug is exactly the lookup
        # that used to match nothing. The resolver must find this row by its
        # stable UUID instead.
        await conn.execute(
            text("INSERT INTO tenants (id, slug, name) VALUES (:id, 'demo', 'Demo Tenant')"),
            {"id": CANONICAL_TENANT_ID},
        )
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(engine):
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(engine):
    """HTTP test client with the DB overridden to the in-memory engine."""
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
def service_auth() -> dict[str, str]:
    """Headers a trusted service presents: the token, plus the tenant it acts for.

    The tenant is asserted explicitly because the token identifies a service,
    not a tenant. Omitting the header is a 403, not a wildcard.
    """
    return {
        "Authorization": "Bearer test-service-token",
        "X-AiSOC-Tenant-ID": CANONICAL_TENANT_ID,
    }
