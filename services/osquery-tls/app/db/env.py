"""Alembic migration environment for the osquery-tls service.

Supports async migrations via asyncio run_sync().

Which credential applies the chain
----------------------------------
Alembic issues DDL, and ``services/api/migrations/061_runtime_app_role.sql``
deliberately left the runtime role without any: ``aisoc_app`` holds ``USAGE``
on schema public and not ``CREATE``, precisely so it cannot
``ALTER TABLE … NO FORCE ROW LEVEL SECURITY`` and switch off the policies
``004_tenant_rls`` installs. A service that migrates and serves under one
credential has not split those roles at all, whatever the deployment surface
says.

So the migration credential is read first and ``settings.database_url`` — what
the service itself connects as — is only a fallback. The fallback stays, but
it is announced, because both ways of getting this wrong are otherwise silent:

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
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

import app.models as _models  # noqa: F401 — side-effect: register ORM models with Base.metadata
from app.core.config import settings
from app.db.base import Base

# Explicitly reference the import so static analysis tools don't flag it as unused.
_ = _models

#: Owner credentials, most specific first. Any variable ending in
#: ``DATABASE_MIGRATION_URL`` is recognised as a migration DSN by the gate.
MIGRATION_URL_VARS = ("AISOC_OSQUERY_TLS_DATABASE_MIGRATION_URL", "DATABASE_MIGRATION_URL")


def _resolve_dsn() -> str:
    for name in MIGRATION_URL_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    print(
        "alembic: none of "
        + ", ".join(MIGRATION_URL_VARS)
        + " is set, so this chain is being applied as the runtime credential. That works only "
        "while the two are the same role; under the DML-only runtime role the first CREATE TABLE "
        "fails with 'permission denied for schema public'.",
        file=sys.stderr,
    )
    return settings.database_url


DATABASE_URL = _resolve_dsn()

config = context.config
config.set_main_option("sqlalchemy.url", DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


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
VERSION_TABLE = "alembic_version_osquery_tls"

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
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
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


def do_run_migrations(connection):
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


async def run_async_migrations() -> None:
    engine = create_async_engine(DATABASE_URL, poolclass=pool.NullPool)
    # ``begin()`` rather than ``connect()``: the three sibling chains all use it,
    # and it is what commits. On a bare ``connect()`` the outer transaction is
    # rolled back at close unless something inside commits, which makes a
    # successful-looking upgrade a no-op.
    async with engine.begin() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
