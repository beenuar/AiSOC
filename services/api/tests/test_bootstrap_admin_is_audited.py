"""Minting the first administrator must leave a trace.

The defect (issue #1246)
------------------------
``app/scripts/bootstrap_admin.py`` contained no occurrence of the word "audit"
in 352 lines. ``AuditMiddleware`` is HTTP middleware, so a CLI run bypasses it
entirely, and every other privileged identity operation in this service —
``admin.users.role_added``, ``admin.users.disabled``, ``api_keys:create`` —
emits through ``emit_audit``. The single most privileged act a deployment ever
performs, creating the account that holds ``*`` over the tenant, was the one
with no record at all, and ``--reset-password`` on that account was equally
silent.

Why a live database rather than the SQLite the sibling file uses
-----------------------------------------------------------------
``tests/test_bootstrap_admin.py`` builds its schema from ``Base.metadata``,
which has no ``audit_chain_head`` table and none of the chain's triggers.
``emit_audit`` is deliberately forgiving there: it catches a failed chain
computation, writes the row *unchained*, and increments a counter. A SQLite
run would therefore pass while proving only that a row was inserted — the
hash link, the dense ``chain_index`` and the unique successor index would all
be untested, and those are the properties that make the row evidence rather
than a log line. So this runs the real migration chain.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import socket
import subprocess
import sys
import uuid
from collections.abc import Iterator
from urllib.parse import urlparse, urlunparse

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ALERT_AUDIT_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason=(
        "needs a live PostgreSQL with the migration chain applied — on a schema built "
        "from Base.metadata the audit chain degrades to an unchained row and the test "
        "would pass without proving anything"
    ),
)

#: A password that satisfies the script's own length rules and is obviously a
#: fixture rather than anything anyone would deploy.
FIXTURE_PASSWORD = "bootstrap-audit-fixture-pw"


def _with_database(dsn: str, database: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path=f"/{database}"))


async def _run_sql_outside_a_transaction(dsn: str, statement: str) -> None:
    """CREATE/DROP DATABASE cannot run inside a transaction block."""
    conn = await asyncpg.connect(_with_database(dsn, "postgres").replace("postgresql+asyncpg://", "postgresql://"))
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


@pytest.fixture(scope="module")
def scratch_database() -> Iterator[str]:
    """A database of this module's own, carrying the full migration chain.

    Not a shared one, because ``bootstrap()`` refuses to mint a second
    administrator when an *active admin exists anywhere* — not in the tenant,
    anywhere — which is the right behaviour for the command and makes its
    precondition "a deployment with no administrator yet". A test database
    other suites have written to cannot offer that, and the resulting failure
    would depend on execution order rather than on the code under test.

    Synchronous on purpose: pytest-asyncio gives every test its own event
    loop, so a module-scoped async fixture would hand connections across
    loops. ``asyncio.run`` here opens and closes its own.
    """
    name = f"aisoc_bootstrap_audit_{uuid.uuid4().hex[:12]}"
    try:
        asyncio.run(_run_sql_outside_a_transaction(_DSN, f'CREATE DATABASE "{name}"'))
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        if _REQUIRED:
            pytest.fail(f"ALERT_AUDIT_PROOF_REQUIRED is set but a scratch database could not be created: {type(exc).__name__}: {exc}")
        pytest.skip(f"cannot CREATE DATABASE on this server ({type(exc).__name__}) — runs in alert-audit-live.yml")

    dsn = _with_database(_DSN, name)
    migrate = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "app.scripts.run_migrations"],
        cwd=SERVICE_ROOT,
        env={**os.environ, "DATABASE_URL": dsn, "DATABASE_MIGRATION_URL": dsn},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if migrate.returncode != 0:
        asyncio.run(_run_sql_outside_a_transaction(_DSN, f'DROP DATABASE IF EXISTS "{name}"'))
        pytest.fail(f"the migration chain did not apply to the scratch database:\n{migrate.stdout}\n{migrate.stderr}")

    yield dsn
    asyncio.run(_run_sql_outside_a_transaction(_DSN, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest_asyncio.fixture
async def bootstrap_env(monkeypatch, scratch_database):
    """Point ``bootstrap_admin`` at a tenant of its own on the real schema.

    Yields ``(maker, tenant_id, email)``. Users are cleared first so each test
    sees the no-administrator precondition the command is written for; the
    audit rows are left, because ``audit_log`` is append-only by database
    trigger and every assertion below is scoped to this test's tenant anyway.
    """
    from app.scripts import bootstrap_admin as ba

    engine = create_async_engine(scratch_database)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    async with maker() as db:
        await db.execute(text("DELETE FROM users"))
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"bootstrap-{suffix}", "s": f"bootstrap-{suffix}"},
        )
        await db.commit()

    monkeypatch.setattr(ba, "AsyncSessionLocal", maker)
    monkeypatch.setattr(ba, "DEFAULT_TENANT_ID", tenant_id)

    yield maker, tenant_id, f"admin-{suffix}@example.com"
    await engine.dispose()


async def _audit_rows(maker, tenant_id: uuid.UUID) -> list[dict]:
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    text(
                        """
                        SELECT action, resource, resource_id, actor_id, actor_email,
                               changes, metadata, prev_hash, entry_hash, chain_index
                        FROM audit_log WHERE tenant_id = :t
                        ORDER BY chain_index ASC NULLS LAST, created_at ASC
                        """
                    ),
                    {"t": tenant_id},
                )
            )
            .mappings()
            .all()
        )
    out = []
    for row in rows:
        record = dict(row)
        for column in ("changes", "metadata"):
            if isinstance(record[column], str):
                record[column] = json.loads(record[column])
        out.append(record)
    return out


class TestTheFirstAdministratorIsRecorded:
    async def test_creating_one_writes_an_audit_row(self, bootstrap_env) -> None:
        """The reproduction. Before the fix this table stayed empty."""
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        created_email, is_new = await ba.bootstrap(
            email=email,
            password=FIXTURE_PASSWORD,
            username="admin",
            reset_password=False,
        )
        assert (created_email, is_new) == (email, True)

        rows = await _audit_rows(maker, tenant_id)
        assert rows, (
            "the first administrator — the account holding '*' over this tenant — was "
            "created with no audit row at all. AuditMiddleware is HTTP middleware, so "
            "nothing covers a CLI run."
        )

    async def test_the_row_names_the_account_it_created(self, bootstrap_env) -> None:
        """A row saying only "a bootstrap happened" is the same gap one level
        in: which address, under which name, with which role."""
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="first-admin", reset_password=False)

        async with maker() as db:
            user_id = (await db.execute(text("SELECT id FROM users WHERE email = :e"), {"e": email})).scalar_one()

        rows = await _audit_rows(maker, tenant_id)
        assert len(rows) == 1, f"expected exactly one row, got {[r['action'] for r in rows]}"
        row = rows[0]

        assert row["resource"] == "user"
        assert row["resource_id"] == str(user_id)
        assert row["changes"], "the row carries no changes payload"
        assert row["changes"].get("email") == email
        assert row["changes"].get("username") == "first-admin"
        assert row["changes"].get("role") == "admin"

    async def test_the_actor_is_recorded_as_unknown_rather_than_invented(self, bootstrap_env) -> None:
        """A shell command has no platform principal, and naming one would be
        a lie an investigator acts on.

        Writing the new administrator's own address into ``actor_id`` /
        ``actor_email`` would read as "this person signed in and created
        themselves", which did not happen and is the opposite of useful on the
        one account that holds ``*``. The honest record is no actor plus the
        provenance that tells the reader where to look instead — the host's
        shell history, not this table. ``autonomy_grants`` already writes an
        actorless row for the same reason.
        """
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)

        row = (await _audit_rows(maker, tenant_id))[0]
        assert row["actor_id"] is None
        assert row["actor_email"] is None
        assert row["changes"].get("invoked_via") == "bootstrap_admin CLI", f"the row does not say where it came from: {row['changes']}"

    async def test_the_row_is_chain_linked(self, bootstrap_env) -> None:
        """An unchained row is outside the tamper-evidence claim the audit log
        makes, and ``emit_audit`` writes one rather than failing the caller —
        so "a row exists" and "the chain covers it" are separate assertions."""
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)

        row = (await _audit_rows(maker, tenant_id))[0]
        assert row["entry_hash"], "the row was written unchained"
        assert row["chain_index"] == 0
        assert row["prev_hash"] is None, "the first row of a new tenant's chain has no predecessor"

        async with maker() as db:
            head = (
                (
                    await db.execute(
                        text("SELECT head_hash, next_index FROM audit_chain_head WHERE tenant_id = :t"),
                        {"t": tenant_id},
                    )
                )
                .mappings()
                .one()
            )
        assert head["head_hash"] == row["entry_hash"]
        assert int(head["next_index"]) == 1

    async def test_the_password_is_nowhere_in_the_row(self, bootstrap_env) -> None:
        """``audit_log`` is immutable by database trigger and readable by every
        tenant administrator. A secret written there cannot be taken back."""
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)

        serialised = json.dumps(await _audit_rows(maker, tenant_id), default=str)
        assert FIXTURE_PASSWORD not in serialised
        assert "$2b$" not in serialised, "the bcrypt hash of the password reached the audit log"


class TestAResetIsRecordedToo:
    async def test_replacing_the_credential_writes_its_own_row(self, bootstrap_env) -> None:
        """Taking over the administrator account is at least as interesting to
        an investigator as creating it."""
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)
        await ba.bootstrap(
            email=email,
            password=FIXTURE_PASSWORD + "-rotated",
            username="admin",
            reset_password=True,
        )

        rows = await _audit_rows(maker, tenant_id)
        assert len(rows) == 2, f"the reset left no row of its own: {[r['action'] for r in rows]}"
        assert rows[0]["action"] != rows[1]["action"], (
            "creating an administrator and resetting its password are different events and "
            f"must not share an action label: {rows[0]['action']}"
        )
        assert rows[1]["chain_index"] == 1
        assert rows[1]["prev_hash"] == rows[0]["entry_hash"]


class TestARunThatChangesNothingRecordsNothing:
    """The other direction, and the one that keeps the trail readable.

    ``make bootstrap`` is documented as safe to re-run. Auditing every
    invocation would pad the log with rows for an operation that did not
    happen, which is the same failure as the missing row wearing the opposite
    sign: an auditor cannot tell the events apart from the noise.
    """

    async def test_a_second_run_adds_no_row(self, bootstrap_env) -> None:
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)
        before = len(await _audit_rows(maker, tenant_id))

        _email, is_new = await ba.bootstrap(
            email=email,
            password=FIXTURE_PASSWORD,
            username="admin",
            reset_password=False,
        )
        assert is_new is False, "the fixture is wrong: the second run created something"

        after = len(await _audit_rows(maker, tenant_id))
        assert after == before, f"a no-op re-run appended {after - before} audit row(s)"


class TestTheAccountStillGetsCreated:
    """A control.

    The audit write shares the script's transaction, so a mistake in it does
    not merely lose the row — it loses the administrator, on the one command a
    new deployment cannot do without.
    """

    async def test_the_user_row_lands_with_the_audit_row(self, bootstrap_env) -> None:
        from app.core.security import verify_password
        from app.scripts import bootstrap_admin as ba

        maker, tenant_id, email = bootstrap_env

        await ba.bootstrap(email=email, password=FIXTURE_PASSWORD, username="admin", reset_password=False)

        async with maker() as db:
            row = (
                (
                    await db.execute(
                        text("SELECT tenant_id, role, is_active, hashed_password FROM users WHERE email = :e"),
                        {"e": email},
                    )
                )
                .mappings()
                .one()
            )
        assert row["tenant_id"] == tenant_id
        assert row["role"] == "admin"
        assert row["is_active"] is True
        assert verify_password(FIXTURE_PASSWORD, row["hashed_password"])
