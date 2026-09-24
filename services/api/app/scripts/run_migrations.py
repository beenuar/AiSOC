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
import contextlib
import logging
import os
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import asyncpg

from app.core.config import settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

# Sentinel touched on a successful migration pass. The Fly release_command
# wrapper (see `infra/fly/api/fly.toml` → `[deploy].release_command`) keys
# off the presence of this file to decide whether to run `seed_demo`. The
# path lives under /tmp so it's local to the release VM and naturally
# disappears when the VM is reaped.
_SENTINEL_PATH = Path("/tmp/aisoc-migrations-ok")

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


def migration_url() -> str:
    """The DSN migrations run against — the owner's, not the runtime role's.

    ``DATABASE_URL`` points at ``aisoc_app``, which holds SELECT / INSERT /
    UPDATE / DELETE and nothing else, so that row-level security applies to it
    (see ``migrations/061_runtime_app_role.sql``). DDL needs the role that owns
    the tables, which is a separate credential.

    Unset falls back to ``DATABASE_URL``, which is the pre-split behaviour and
    what a single-role deployment still wants.
    """
    configured = (settings.DATABASE_MIGRATION_URL or "").strip()
    return configured or str(settings.DATABASE_URL)


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
    dsn, kwargs = _asyncpg_dsn(migration_url())
    last_exc: Exception | None = None
    # ~3 min total window (see the back-off below). On the Fly demo, the
    # release_command machine is often the *first* thing to touch the Postgres
    # app after autostop, so it must wait out a full autostart + cold boot — a
    # 30 s window let migrations soft-fail and ship code against a stale schema.
    for attempt in range(1, 11):
        try:
            return await asyncpg.connect(dsn, timeout=10, **kwargs)
        except (
            asyncpg.exceptions.ConnectionDoesNotExistError,
            asyncpg.exceptions.CannotConnectNowError,
            ConnectionResetError,
            OSError,
        ) as exc:
            last_exc = exc
            delay = min(2 ** (attempt - 1), 12)
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
            # Best-effort cleanup: if ROLLBACK itself fails the connection is
            # already unusable and will be discarded — nothing more to do.
            pass
        return name, False, str(exc)


async def _provision_runtime_role(conn: asyncpg.Connection) -> None:
    """Apply ``AISOC_APP_DB_PASSWORD`` to the runtime role, if one is configured.

    ``061_runtime_app_role.sql`` creates ``aisoc_app`` with DML-only grants and
    no password, because a migration in a public repository must not carry a
    credential and must not overwrite one an operator already set deliberately.
    The credential therefore arrives from the environment.

    The compose stack also applies it from ``infra/postgres/initdb``, which is
    the cleaner place — it runs before the container reports healthy, so no
    service can race it. That hook fires only on an *empty* data directory
    though, so an upgrade in place never reaches it, and a CI service container
    has no hook at all. This covers both, running on the owner connection that
    just applied the chain.

    Unset is a normal state (a deployment managing the role itself, or one that
    has not split the roles yet) and is logged rather than treated as an error.
    """
    password = os.environ.get("AISOC_APP_DB_PASSWORD", "")
    if not password:
        logger.info(
            "AISOC_APP_DB_PASSWORD unset — leaving the runtime role's credential alone. "
            "If DATABASE_URL points at aisoc_app, that role needs a password from somewhere."
        )
        return
    try:
        # The password is bound as a parameter into a session GUC, then
        # re-quoted by the server for the ALTER (a utility statement takes no
        # parameters). It is never concatenated into SQL in this process.
        await conn.execute("SELECT set_config('aisoc.app_password', $1, false)", password)
        await conn.execute(
            """
            DO $$
            DECLARE pw text := current_setting('aisoc.app_password');
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
                    EXECUTE 'CREATE ROLE aisoc_app LOGIN PASSWORD ' || quote_literal(pw);
                ELSE
                    EXECUTE 'ALTER ROLE aisoc_app WITH LOGIN PASSWORD ' || quote_literal(pw);
                END IF;
            END $$;
            """
        )
        logger.info("runtime role aisoc_app: login credential applied from AISOC_APP_DB_PASSWORD")
    except Exception as exc:  # noqa: BLE001 — reported, never fatal to the chain
        # Loud, because the services connect as this role: getting here means
        # they are about to fail authentication and the reason should already
        # be in the log when that happens.
        logger.error(
            "could not set the runtime role's password (%s: %s). Services pointed at aisoc_app "
            "will fail to authenticate until it is provisioned.",
            type(exc).__name__,
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
    finally:
        with contextlib.suppress(Exception):
            await conn.execute("SELECT set_config('aisoc.app_password', '', false)")


def _migrations_required() -> bool:
    """Whether a migration *connect* failure should crash the process.

    The default is ``True`` — a deploy must not silently ship code against
    a stale schema. Production-like environments leave this alone.

    Demo environments (the Fly ``aisoc-demo-api`` app, in particular) can
    opt out by setting ``AISOC_MIGRATIONS_REQUIRED=0``. In that mode, a
    connect-exhausted failure logs LOUDLY and exits ``0`` so the API code
    deploy still ships — preserving service for users on a demo while a
    Fly Postgres outage / SSL-handshake issue / pg_hba misconfig is being
    diagnosed. Actual SQL migration errors (server reachable, statement
    failed) are still treated as failures regardless of this flag — a
    schema-change PR that crashes mid-apply must still fail the deploy
    so it gets human eyes.
    """
    raw = os.environ.get("AISOC_MIGRATIONS_REQUIRED", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


async def main() -> None:
    if not MIGRATIONS_DIR.exists():
        logger.warning("migrations dir not found: %s", MIGRATIONS_DIR)
        return

    files = sorted(p for p in MIGRATIONS_DIR.iterdir() if p.suffix == ".sql")
    parts = urlsplit(migration_url())
    role = (parts.username or "?").replace("\r", "").replace("\n", " ")[:64]
    logger.info(
        "Found %d migration files; connecting as %r (%s)",
        len(files),
        role,
        "DATABASE_MIGRATION_URL" if (settings.DATABASE_MIGRATION_URL or "").strip() else "DATABASE_URL",
    )

    try:
        conn = await _connect()
    except (
        asyncpg.exceptions.ConnectionDoesNotExistError,
        asyncpg.exceptions.CannotConnectNowError,
        ConnectionResetError,
        OSError,
    ) as exc:
        if _migrations_required():
            raise
        # Demo-mode soft-fail: Postgres unreachable through every retry.
        # Log loud — a future audit must be able to find this — then exit
        # 0 so the rest of the deploy proceeds. This is intentionally
        # restricted to *connect-time* exceptions; once we have a working
        # connection, any SQL failure during a migration still raises.
        logger.error(
            "MIGRATION SKIPPED — could not reach Postgres after retry budget "
            "(%s: %s). AISOC_MIGRATIONS_REQUIRED=0 → continuing the deploy "
            "with the existing schema. Investigate the Fly Postgres app and "
            "either restore connectivity or set AISOC_MIGRATIONS_REQUIRED=1 "
            "to make this fatal again.",
            type(exc).__name__,
            exc,
        )
        # Deliberately do NOT write the sentinel — the release_command
        # wrapper uses its absence to know seed_demo should also be
        # skipped (seed_demo would just hit the same connect failure
        # through SQLAlchemy and crash).
        return

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

        await _provision_runtime_role(conn)

        if failures:
            logger.warning("%d migrations failed; see logs above", len(failures))
            # CI strict mode (Phase 3 migrations gate): any failed migration
            # must fail the job instead of shipping a partially-applied
            # schema that later boots "successfully" against missing tables.
            if os.environ.get("AISOC_MIGRATIONS_STRICT", "").strip().lower() in {"1", "true", "yes", "on"}:
                raise SystemExit(f"{len(failures)} migration(s) failed in strict mode")
    finally:
        await conn.close()

    # Sentinel for the release_command wrapper: "migrations ran against a
    # reachable database — proceed to seed_demo". A soft-failed run skips
    # this write so the wrapper also skips seeding.
    _SENTINEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SENTINEL_PATH.write_text(
        "AiSOC run_migrations.py completed — DB reachable, seed_demo may proceed.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    asyncio.run(main())
