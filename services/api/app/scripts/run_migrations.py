"""Apply raw SQL migrations under ``services/api/migrations``.

This is a lightweight, idempotent migration runner. Each migration is executed
in its own asyncpg connection and tracked in an ``aisoc_schema_migrations``
table so it will not be re-applied on subsequent runs. Migrations themselves
are written defensively (``CREATE TABLE IF NOT EXISTS``, ``ALTER TABLE … ADD
COLUMN IF NOT EXISTS``) so partial re-applies are safe.

Why a dedicated asyncpg connection (not SQLAlchemy)?
----------------------------------------------------
The migration files frequently contain multi-statement SQL scripts
(``BEGIN; … COMMIT;``, multiple ``CREATE TABLE`` statements, etc.). SQLAlchemy
+ asyncpg routes everything through asyncpg's *prepared statement* protocol,
which raises ``cannot insert multiple commands into a prepared statement``.
We previously worked around this by reaching for the underlying asyncpg
connection inside ``engine.begin()``. That fixed the multi-statement issue,
but mixing raw ``Connection.execute()`` with SQLAlchemy's transaction
management left pool connections in an inconsistent state — every later
request that landed on a poisoned connection failed with ``cannot use
Connection.transaction() in a manually started transaction``. Using a
fresh, short-lived asyncpg connection (closed before the API starts serving
traffic) avoids both problems.

Run standalone via:

    python -m app.scripts.run_migrations
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import asyncpg

from app.core.config import settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

# libpq sslmode → asyncpg ssl kwarg. Mirrors the mapping in
# ``app.db.database._normalize_async_pg_url`` so this script can be run
# standalone without depending on SQLAlchemy's connection plumbing.
_SSLMODE_PASSTHROUGH = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}

CREATE_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS aisoc_schema_migrations (
    name        TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def _asyncpg_dsn(url: str) -> tuple[str, dict]:
    """Strip SQLAlchemy/libpq adornments and return (DSN, asyncpg connect kwargs).

    asyncpg accepts only the bare ``postgres://`` / ``postgresql://`` scheme,
    no ``+asyncpg`` suffix. It also rejects libpq-only query params like
    ``sslmode`` and ``channel_binding``.
    """
    if url.startswith("postgresql+asyncpg://"):
        url = "postgresql://" + url[len("postgresql+asyncpg://") :]
    elif url.startswith("postgres+asyncpg://"):
        url = "postgres://" + url[len("postgres+asyncpg://") :]

    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    kwargs: dict = {}
    remaining: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == "sslmode":
            mode = value.lower().strip()
            if mode in _SSLMODE_PASSTHROUGH:
                kwargs["ssl"] = False if mode == "disable" else mode
            continue
        if key == "channel_binding":
            continue
        remaining.append((key, value))

    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(f"{k}={v}" for k, v in remaining), parts.fragment))
    return new_url, kwargs


async def _connect() -> asyncpg.Connection:
    """Open a fresh asyncpg connection, retrying on transient connect errors.

    On Fly, the migration ``release_command`` runs the moment a new app VM
    boots. The Postgres app it talks to may have just woken from
    autostop / be mid-failover / be reachable but still completing its
    own boot. asyncpg surfaces these as ``ConnectionDoesNotExistError``,
    ``ConnectionResetError``, or ``OSError`` raised *inside the initial
    handshake* — i.e. before the connection is ever usable. A single
    failed connect would crash the entire deploy, which made the
    "Deploy API to Fly" workflow look like a code regression when it
    was really just a cold-start race.

    We retry on the small set of connect-time exceptions that are
    actually transient. Anything authentication- or schema-related
    (``InvalidPasswordError``, ``InvalidCatalogNameError``, …) is
    intentionally **not** retried — those need human attention, not
    more attempts.
    """
    dsn, kwargs = _asyncpg_dsn(str(settings.DATABASE_URL))
    last_exc: Exception | None = None
    for attempt in range(1, 7):  # ~30 s total at the back-off schedule below
        try:
            return await asyncpg.connect(dsn, **kwargs)
        except (
            asyncpg.exceptions.ConnectionDoesNotExistError,
            asyncpg.exceptions.CannotConnectNowError,
            ConnectionResetError,
            OSError,
        ) as exc:
            last_exc = exc
            delay = min(2 ** (attempt - 1), 8)
            logger.warning(
                "asyncpg.connect failed on attempt %d (%s: %s); retrying in %ds",
                attempt,
                type(exc).__name__,
                exc,
                delay,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None  # for type narrowing
    raise last_exc


async def _applied(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch("SELECT name FROM aisoc_schema_migrations")
    return {row["name"] for row in rows}


async def _apply_one(conn: asyncpg.Connection, name: str, sql: str) -> tuple[str, bool, str | None]:
    """Apply a single migration.

    The migration files manage their own transactions (most start with
    ``BEGIN;`` and end with ``COMMIT;``). Where they don't, asyncpg
    auto-commits after each statement. Either way, after the script returns
    the connection is in a clean state so subsequent migrations don't
    interfere.
    """
    try:
        await conn.execute(sql)
        await conn.execute(
            "INSERT INTO aisoc_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
            name,
        )
        return name, True, None
    except Exception as exc:  # noqa: BLE001 — we intentionally continue on failure
        # Make sure the connection isn't left mid-transaction after a failure
        # (e.g. ``BEGIN`` succeeded but a subsequent statement raised).
        try:
            await conn.execute("ROLLBACK")
        except Exception:
            pass
        return name, False, str(exc)


async def main() -> None:
    if not MIGRATIONS_DIR.exists():
        logger.warning("migrations dir not found: %s", MIGRATIONS_DIR)
        return

    files = sorted(p for p in MIGRATIONS_DIR.iterdir() if p.suffix == ".sql")
    logger.info("Found %d migration files", len(files))

    conn = await _connect()
    try:
        await conn.execute(CREATE_MIGRATIONS_TABLE)
        already = await _applied(conn)
        pending = [p for p in files if p.name not in already]
        logger.info("%d migrations already applied; %d pending", len(already), len(pending))

        failures: list[tuple[str, str]] = []
        for path in pending:
            sql = path.read_text(encoding="utf-8")
            name, ok, err = await _apply_one(conn, path.name, sql)
            if ok:
                logger.info("✓ applied %s", name)
            else:
                logger.error("✗ failed %s: %s", name, err)
                failures.append((name, err or ""))

        if failures:
            logger.warning("%d migrations failed; see logs above", len(failures))
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
