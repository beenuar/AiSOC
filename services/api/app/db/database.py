"""Database connection management."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


def _normalize_async_pg_url(url: str) -> str:
    """Coerce common Postgres URL forms into the SQLAlchemy 2.x async dialect.

    Fly.io's ``flyctl postgres attach`` (and Heroku, and most managed
    hosts) writes ``DATABASE_URL=postgres://...``. SQLAlchemy 2.x dropped
    the bare ``postgres`` scheme alias, so passing it straight to
    ``create_async_engine`` raises ``NoSuchModuleError: postgres``.

    Likewise, ``postgresql://...`` without an explicit driver suffix
    selects the synchronous ``psycopg2`` dialect, which the async engine
    rejects ("the asyncio extension requires an async driver").

    This shim rewrites both forms to ``postgresql+asyncpg://``, which is
    what we actually run. It is a no-op for URLs that already specify a
    driver (``postgresql+asyncpg``, ``postgresql+psycopg``, etc.), so
    operators who want to override the driver via secret can still do so.
    """
    if url.startswith("postgres://"):
        return "postgresql+asyncpg://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        # No driver specified -> default to asyncpg (the only async driver
        # we ship with). Anything matching "postgresql+<driver>://" already
        # has an explicit choice and we leave it alone.
        return "postgresql+asyncpg://" + url[len("postgresql://") :]
    return url


engine = create_async_engine(
    _normalize_async_pg_url(str(settings.DATABASE_URL)),
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    echo=settings.DEBUG,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
