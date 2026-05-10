"""Database connection management."""

from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# libpq sslmode values -> what asyncpg's `ssl` kwarg expects.
# asyncpg accepts: "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
# but NOT under the libpq query-string name `sslmode=`. We pop it from the URL
# and forward it as a connect_arg so asyncpg sees it on the right hand.
_SSLMODE_PASSTHROUGH = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}


def _normalize_async_pg_url(url: str) -> tuple[str, dict[str, Any]]:
    """Coerce common Postgres URL forms into the SQLAlchemy 2.x async dialect.

    Fly.io's ``flyctl postgres attach`` (and Heroku, and most managed
    hosts) writes ``DATABASE_URL=postgres://...``. SQLAlchemy 2.x dropped
    the bare ``postgres`` scheme alias, so passing it straight to
    ``create_async_engine`` raises ``NoSuchModuleError: postgres``.

    Likewise, ``postgresql://...`` without an explicit driver suffix
    selects the synchronous ``psycopg2`` dialect, which the async engine
    rejects ("the asyncio extension requires an async driver").

    Managed Postgres providers also append ``?sslmode=require`` (libpq
    syntax) which asyncpg's ``connect()`` rejects with
    ``TypeError: connect() got an unexpected keyword argument 'sslmode'``.
    We strip the param and translate it into an explicit ``connect_args``
    payload that asyncpg understands.

    Returns the normalized URL plus a ``connect_args`` dict that callers
    forward to ``create_async_engine``.
    """
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://") :]
    elif url.startswith("postgresql://"):
        # No driver specified -> default to asyncpg (the only async driver
        # we ship with). Anything matching "postgresql+<driver>://" already
        # has an explicit choice and we leave it alone.
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]

    # Translate libpq-style query params that asyncpg can't parse.
    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    connect_args: dict[str, Any] = {}
    remaining: list[tuple[str, str]] = []
    for key, value in query_pairs:
        if key == "sslmode":
            mode = value.lower().strip()
            if mode in _SSLMODE_PASSTHROUGH:
                # asyncpg understands the libpq mode names via `ssl=`.
                connect_args["ssl"] = mode if mode != "disable" else False
            continue
        if key == "channel_binding":
            # libpq-only; asyncpg negotiates SCRAM channel binding itself.
            continue
        remaining.append((key, value))

    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(remaining), parts.fragment))
    return new_url, connect_args


_normalized_url, _connect_args = _normalize_async_pg_url(str(settings.DATABASE_URL))

engine = create_async_engine(
    _normalized_url,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    echo=settings.DEBUG,
    future=True,
    connect_args=_connect_args,
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
