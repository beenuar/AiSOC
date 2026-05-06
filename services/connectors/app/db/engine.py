"""Async SQLAlchemy engine for the connectors microservice.

We keep the engine creation in its own module so:

  * The scheduler can import ``get_engine`` without dragging in the
    ``connectors_table`` definition (and vice versa).
  * Tests can call ``set_engine`` to inject a fixture engine without monkey
    patching module-level state.

The engine connects to the *same* Postgres the API service uses; we read from
and write to the ``connectors`` table directly. We do not own the schema —
migrations live in the API service.
"""

from __future__ import annotations

import os
from threading import Lock

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

_engine: AsyncEngine | None = None
_engine_lock = Lock()


def _resolve_database_url() -> str:
    """Pick up DATABASE_URL with a sensible fallback.

    docker-compose.yml passes ``DATABASE_URL=postgresql+asyncpg://...`` which
    is what we want. If a deployment ships a plain ``postgresql://`` URL we
    rewrite the driver prefix to use asyncpg, since the connectors service
    only uses async I/O.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set; the connectors service requires it to read the connectors table.")
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]
    elif url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://") :]
    return url


def get_engine() -> AsyncEngine:
    """Return the lazily-constructed process-wide async engine."""
    global _engine
    if _engine is not None:
        return _engine
    with _engine_lock:
        if _engine is not None:  # pragma: no cover - racing init
            return _engine
        url = _resolve_database_url()
        # ``pool_pre_ping`` so we don't hand the scheduler a dead conn after
        # a Postgres restart; ``echo`` stays off — connector polling is high
        # frequency and we don't want SQL spam in prod logs.
        _engine = create_async_engine(url, pool_pre_ping=True, echo=False)
        return _engine


def set_engine(engine: AsyncEngine | None) -> None:
    """Test helper: install a fixture engine (or clear it)."""
    global _engine
    with _engine_lock:
        _engine = engine


async def dispose_engine() -> None:
    """Close the engine on shutdown so we don't leak connections."""
    global _engine
    if _engine is None:
        return
    engine, _engine = _engine, None
    await engine.dispose()


__all__ = ["dispose_engine", "get_engine", "set_engine"]
