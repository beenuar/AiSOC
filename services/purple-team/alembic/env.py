"""Alembic migration environment for Purple Team service.

Which credential applies the chain
----------------------------------
Alembic issues DDL, and ``services/api/migrations/061_runtime_app_role.sql``
deliberately left the runtime role without any: ``aisoc_app`` holds ``USAGE``
on schema public and not ``CREATE``, precisely so it cannot
``ALTER TABLE … NO FORCE ROW LEVEL SECURITY`` and switch off the policies
``0003_tenant_rls`` installs. A service that migrates and serves under one
credential has not split those roles at all, whatever the deployment surface
says.

So the migration credential is read first and the runtime one is only a
fallback. The fallback stays — a deployment that has not split the roles
behaves exactly as it did before — but it is announced, because both ways of
getting this wrong are otherwise silent:

* point this at the runtime role and ``alembic upgrade`` dies on the first
  ``CREATE TABLE`` with ``permission denied for schema public``;
* point the *service* at the owner and every policy in this chain stops
  filtering, with nothing in any log to say so.

``scripts/check_runtime_db_role.py`` is what keeps the deployment surfaces
honest about which variable carries which role.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from app.models.purple_team import Base
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

#: Owner credentials, most specific first. Any variable ending in
#: ``DATABASE_MIGRATION_URL`` is recognised as a migration DSN by the gate.
MIGRATION_URL_VARS = ("PURPLE_TEAM_DATABASE_MIGRATION_URL", "DATABASE_MIGRATION_URL")

#: Runtime credentials. Same order the service's own settings resolve them in,
#: so the fallback below lands on exactly what the service connects as.
RUNTIME_URL_VARS = ("DATABASE_URL", "PURPLE_TEAM_DATABASE_URL")

DEFAULT_URL = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"


def _first_env(names: tuple[str, ...]) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _resolve_dsn() -> str:
    migration = _first_env(MIGRATION_URL_VARS)
    if migration:
        return migration
    print(
        "alembic: none of "
        + ", ".join(MIGRATION_URL_VARS)
        + " is set, so this chain is being applied as the runtime credential. That works only "
        "while the two are the same role; under the DML-only runtime role the first CREATE TABLE "
        "fails with 'permission denied for schema public'.",
        file=sys.stderr,
    )
    return _first_env(RUNTIME_URL_VARS) or DEFAULT_URL


DATABASE_URL = _resolve_dsn()


#: Alembic's default version table is ``alembic_version``, and four services in
#: this repository run their own chain against **one** database — compose gives
#: ueba, honeytokens, purple-team and osquery-tls the same ``aisoc``. They also
#: number their revisions identically (``0001``, ``0002``, …), so the shared
#: table made the second chain to run believe it was already at head.
#:
#: Measured against ``postgres:16`` on the sequence ``apps/docs/docs/quickstart.md``
#: prints: after ``ueba`` reached ``0002``, ``honeytokens alembic upgrade head``
#: ran **zero** migrations and ``purple-team`` failed applying its RLS revision
#: to tables that had never been created. Two services' tenant policies did not
#: exist in the default deployment and nothing said so.
VERSION_TABLE = "alembic_version_purple_team"

#: The table those chains shared. Read once, never written: see
#: :func:`_adopt_legacy_version`.
LEGACY_VERSION_TABLE = "alembic_version"


def _adopt_legacy_version(connection) -> None:  # type: ignore[no-untyped-def]
    """Carry a version recorded in the shared table into this chain's own.

    Without this, moving to a per-chain version table reads to alembic as a
    database that has never been migrated, and the first ``CREATE TABLE``
    fails because the table is already there.

    Three conditions, all required, so the adoption cannot claim a revision
    belonging to a sibling chain:

    * this chain has no version table yet;
    * at least one table **this chain maps** already exists, which is the only
      evidence that this chain — rather than a sibling — is what the shared
      row records;
    * the recorded id is a revision in this chain's own script directory.

    The shared table is left alone. A sibling that has not adopted yet still
    needs it, and once every chain has, it is inert rather than wrong.

    ``CREATE TABLE IF NOT EXISTS`` appears below and is reached only after the
    probe says the table is absent. Postgres checks the schema ACL *before* the
    existence test, so the statement raises ``permission denied for schema
    public`` on a role without ``CREATE`` even when the table is already there
    — the trap that took two stores in ``services/agents`` down to a
    ``logger.debug``. Here the whole function runs on the **migration**
    connection, but the probe-first order costs nothing and keeps the shape
    right if that ever stops being true.
    """
    inspector = sa.inspect(connection)
    if inspector.has_table(VERSION_TABLE) or not inspector.has_table(LEGACY_VERSION_TABLE):
        return
    if not any(inspector.has_table(name) for name in target_metadata.tables):
        return
    recorded = connection.execute(sa.text(f"SELECT version_num FROM {LEGACY_VERSION_TABLE}")).scalar()  # noqa: S608
    if recorded is None or recorded not in {rev.revision for rev in context.script.walk_revisions()}:
        return
    connection.execute(
        sa.text(
            f"CREATE TABLE IF NOT EXISTS {VERSION_TABLE} ("  # noqa: S608
            f"version_num VARCHAR(32) NOT NULL, "
            f"CONSTRAINT {VERSION_TABLE}_pkc PRIMARY KEY (version_num))"
        )
    )
    connection.execute(sa.text(f"INSERT INTO {VERSION_TABLE} (version_num) VALUES (:v)"), {"v": recorded})  # noqa: S608
    print(f"alembic: adopted {recorded!r} from {LEGACY_VERSION_TABLE} into {VERSION_TABLE}", file=sys.stderr)


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


#: Serialises the four chains that share one database against each other.
#:
#: They are started simultaneously by ``docker compose up``, and while each
#: now owns its own version table, they do not own their own *database*: the
#: legacy-version probe below reads a table a sibling may be creating, and
#: ``000N_runtime_role_grants`` issues ``GRANT`` statements that take
#: catalog locks on ``pg_class``. Two chains arriving together deadlocked
#: rather than queued.
#:
#: ``pg_advisory_xact_lock`` and not the session form: it is released by the
#: commit or rollback that ends the upgrade, so a chain that dies mid-apply
#: cannot leave the other three waiting on a lock nobody holds a connection
#: for. The key is an arbitrary constant, shared by every chain on purpose —
#: the point is mutual exclusion, not per-chain exclusion.
MIGRATION_LOCK_KEY = 0x4149_5354


def do_run_migrations(connection):  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata, version_table=VERSION_TABLE)
    with context.begin_transaction():
        connection.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        # Inside ``begin_transaction()``, not before it. Alembic's
        # ``begin_transaction`` is a no-op when the connection is *already* in a
        # transaction, and in SQLAlchemy 2.0 any execute on a plain ``connect()``
        # starts one implicitly — so probing the schema first left the whole
        # upgrade inside a transaction nobody committed. Measured: the chain
        # printed every "Running upgrade" line and the database came back empty.
        _adopt_legacy_version(connection)
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
