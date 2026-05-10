"""Shared pytest fixtures for the osquery-tls service tests.

Uses an in-memory SQLite database for speed.  SQLite doesn't support every
Postgres feature but it is sufficient for the ORM-level tests here.
"""

from __future__ import annotations

import os

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Override env before importing the app so settings resolves without secrets.
os.environ.setdefault("AISOC_OSQUERY_TLS_ENROLL_SECRET", "test-enroll-secret")
os.environ.setdefault("AISOC_OSQUERY_TLS_API_TOKEN", "test-api-token")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest_asyncio.fixture(scope="function")
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
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
