"""Async SQLAlchemy session factory for the osquery-tls service."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

_engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
)

_SessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with _SessionLocal() as session:
        yield session
