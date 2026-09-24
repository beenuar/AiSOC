"""A clean install has to end with an account somebody can actually sign into.

It did not. `make up` and `make smoke` both passed and then login was
impossible, for three independent reasons at once:

* the only account was `admin@aisoc.local`, and `LoginRequest.email` is a
  pydantic `EmailStr`, which rejects RFC 6761 special-use domains with a 422
  *before* the password is compared;
* the bcrypt hash migration 001 seeded matched neither the `changeme` four
  documentation pages published nor the `admin` its own inline comment claimed
  — checked with this service's `verify_password`, every candidate was False;
* nothing existed to create a user with.

So these tests assert the outcome, not the implementation: run the documented
command, and the credential it reports back authenticates. The email check runs
the real validator rather than a copy of its reserved-domain list, so if a
future `email_validator` release reclassifies the default domain this goes red
here instead of at a stranger's login form.
"""

from __future__ import annotations

import argparse
import io
import pathlib
import re
import uuid

import pytest
import pytest_asyncio
from app.core.security import verify_password
from app.db.database import Base
from app.models.tenant import Tenant, User
from app.scripts import bootstrap_admin as ba
from pydantic import BaseModel, EmailStr, ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

MIGRATIONS = pathlib.Path(__file__).resolve().parents[1] / "migrations"

# The hash migration 001 used to seed. Kept here so the test can prove the
# claim rather than restate it.
ORPHAN_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3EEbF7FtRS"


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


class _LoginRequest(BaseModel):
    """The shape `POST /api/v1/auth/login` validates against."""

    email: EmailStr


@pytest_asyncio.fixture
async def session_factory(monkeypatch):
    """An in-memory database wired in where the script reads its sessions.

    The contract under test is "an account exists and its password verifies",
    which is dialect-independent. Postgres-only column types are compiled down
    above.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Only the two tables this touches. A whole-metadata create_all drags
        # in models using Postgres ARRAY, which SQLite cannot render.
        await conn.run_sync(Base.metadata.create_all, tables=[Tenant.__table__, User.__table__])
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(ba, "AsyncSessionLocal", factory)
    yield factory
    await engine.dispose()


async def _load_user(factory, email: str) -> User | None:
    async with factory() as session:
        result = await session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()


# ─── The defect this all exists for ──────────────────────────────────────────


def test_the_address_migration_001_seeded_could_never_have_logged_in() -> None:
    with pytest.raises(ValidationError):
        _LoginRequest(email="admin@aisoc.local")


def test_the_hash_migration_001_seeded_matched_no_documented_password() -> None:
    for candidate in ("admin", "changeme", "password", "aisoc", "admin@aisoc.local"):
        assert not verify_password(candidate, ORPHAN_HASH), (
            f"{candidate!r} verifies against the orphaned seed hash — if a password for it "
            "is known, the history in migration 059 needs correcting"
        )


def test_migration_001_no_longer_seeds_an_administrator() -> None:
    sql = (MIGRATIONS / "001_init.sql").read_text()
    statements = re.findall(r"INSERT\s+INTO\s+users\b", sql, flags=re.IGNORECASE)
    assert not statements, (
        "001_init.sql seeds a user again. A password hash committed here is a default "
        "credential on every deployment that clones this repository; the first "
        "administrator is created by app.scripts.bootstrap_admin instead."
    )


def test_no_migration_inserts_a_password_hash() -> None:
    offenders = [
        path.name
        for path in sorted(MIGRATIONS.glob("*.sql"))
        # 059 retires the orphan and has to name its hash to match only that row.
        if path.name != "059_retire_unusable_seed_admin.sql" and re.search(r"\$2[aby]\$\d\d\$", path.read_text())
    ]
    assert not offenders, f"migrations carrying a bcrypt hash: {offenders}"


# ─── The default the tool hands out ──────────────────────────────────────────


def test_the_default_address_passes_the_validator_the_login_route_uses() -> None:
    """Runs the real validator, so a reclassification of `.internal` fails here.

    Asserting against a copied list of reserved domains would pass forever
    while the route it is meant to mirror started rejecting the address.
    """
    assert _LoginRequest(email=ba.DEFAULT_ADMIN_EMAIL).email == ba.DEFAULT_ADMIN_EMAIL


def test_a_reserved_domain_is_refused_here_rather_than_at_the_login_form() -> None:
    with pytest.raises(ba.BootstrapError) as exc:
        ba.validate_admin_email("admin@aisoc.local")
    assert "cannot be used to sign in" in str(exc.value)


def test_generated_passwords_are_unique_and_transcribable() -> None:
    generated = {ba.generate_password() for _ in range(64)}
    assert len(generated) == 64, "generated passwords collided"
    for password in generated:
        assert len(password) >= ba.MIN_PASSWORD_LENGTH
        # Characters an operator reads off a terminal and retypes.
        assert not set(password) & set("O0lI1")


def test_a_password_bcrypt_would_silently_truncate_is_refused() -> None:
    with pytest.raises(ba.BootstrapError):
        ba.validate_password("x" * (ba.MAX_PASSWORD_LENGTH + 1))


# ─── The acceptance test, in miniature ───────────────────────────────────────


async def test_the_printed_credential_authenticates(session_factory) -> None:
    password = ba.generate_password()

    email, is_new = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=password,
        username="admin",
        reset_password=False,
    )

    assert is_new
    user = await _load_user(session_factory, email)
    assert user is not None
    assert user.role == "admin"
    assert user.is_active
    # The whole point: this is what `POST /auth/login` does with the password.
    assert verify_password(password, user.hashed_password)
    # And this is what it does with the address first.
    assert _LoginRequest(email=user.email).email == email


async def test_the_administrator_lands_in_the_tenant_the_migration_seeded(
    session_factory,
) -> None:
    """An admin of a brand-new tenant would see none of the existing alerts."""
    async with session_factory() as session:
        session.add(Tenant(id=ba.DEFAULT_TENANT_ID, name="Default", slug="default", plan="enterprise"))
        await session.commit()

    email, _ = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    user = await _load_user(session_factory, email)
    assert user is not None
    assert user.tenant_id == ba.DEFAULT_TENANT_ID


async def test_it_creates_the_tenant_when_the_database_has_none(session_factory) -> None:
    await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )
    async with session_factory() as session:
        tenants = (await session.execute(select(Tenant))).scalars().all()
    assert len(tenants) == 1


async def test_it_adopts_an_existing_tenant_rather_than_adding_a_second(
    session_factory,
) -> None:
    other = uuid.uuid4()
    async with session_factory() as session:
        session.add(Tenant(id=other, name="Acme", slug="acme", plan="starter"))
        await session.commit()

    email, _ = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    user = await _load_user(session_factory, email)
    assert user is not None and user.tenant_id == other
    async with session_factory() as session:
        assert len((await session.execute(select(Tenant))).scalars().all()) == 1


# ─── Re-running it ───────────────────────────────────────────────────────────


async def test_rerunning_reports_the_account_and_changes_nothing(session_factory) -> None:
    """`make up` calls this every time, so a second run must be inert."""
    first = ba.generate_password()
    await ba.bootstrap(email=ba.DEFAULT_ADMIN_EMAIL, password=first, username="admin", reset_password=False)
    before = await _load_user(session_factory, ba.DEFAULT_ADMIN_EMAIL)
    assert before is not None
    original_hash = before.hashed_password

    _, is_new = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    assert is_new is False, "a second run reported a password it did not set"
    after = await _load_user(session_factory, ba.DEFAULT_ADMIN_EMAIL)
    assert after is not None and after.hashed_password == original_hash
    assert verify_password(first, after.hashed_password)


async def test_a_second_run_under_a_new_address_does_not_mint_a_second_admin(
    session_factory,
) -> None:
    await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    email, is_new = await ba.bootstrap(
        email="someone.else@example.com",
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    assert is_new is False
    assert email == ba.DEFAULT_ADMIN_EMAIL
    async with session_factory() as session:
        assert len((await session.execute(select(User))).scalars().all()) == 1


async def test_an_existing_address_in_another_case_is_the_same_account(
    session_factory,
) -> None:
    """Postgres `UNIQUE` on email is case-sensitive; two rows would be two admins."""
    await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )

    _, is_new = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL.upper(),
        password=ba.generate_password(),
        username="admin",
        reset_password=False,
    )
    assert is_new is False
    async with session_factory() as session:
        assert len((await session.execute(select(User))).scalars().all()) == 1


async def test_reset_password_replaces_the_credential(session_factory) -> None:
    old = ba.generate_password()
    await ba.bootstrap(email=ba.DEFAULT_ADMIN_EMAIL, password=old, username="admin", reset_password=False)

    new = ba.generate_password()
    _, is_new = await ba.bootstrap(email=ba.DEFAULT_ADMIN_EMAIL, password=new, username="admin", reset_password=True)

    assert is_new is True
    user = await _load_user(session_factory, ba.DEFAULT_ADMIN_EMAIL)
    assert user is not None
    assert verify_password(new, user.hashed_password)
    assert not verify_password(old, user.hashed_password)


async def test_a_deactivated_orphan_does_not_block_the_first_administrator(
    session_factory,
) -> None:
    """Migration 059 deactivates the row 001 seeded; bootstrap must ignore it.

    Otherwise an upgraded deployment is told an administrator already exists,
    and the one it means is the one nobody can log into.
    """
    async with session_factory() as session:
        session.add(Tenant(id=ba.DEFAULT_TENANT_ID, name="Default", slug="default"))
        session.add(
            User(
                id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
                tenant_id=ba.DEFAULT_TENANT_ID,
                email="admin@aisoc.local",
                username="admin",
                hashed_password=ORPHAN_HASH,
                role="admin",
                is_active=False,
                is_verified=True,
            )
        )
        await session.commit()

    password = ba.generate_password()
    email, is_new = await ba.bootstrap(
        email=ba.DEFAULT_ADMIN_EMAIL,
        password=password,
        username="admin",
        reset_password=False,
    )

    assert is_new is True
    assert email == ba.DEFAULT_ADMIN_EMAIL
    user = await _load_user(session_factory, ba.DEFAULT_ADMIN_EMAIL)
    assert user is not None and verify_password(password, user.hashed_password)


# ─── How the password gets in ────────────────────────────────────────────────


def _args(**kw) -> argparse.Namespace:
    return argparse.Namespace(password_stdin=False, **kw)


def test_an_explicit_password_is_not_reported_as_generated(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_ADMIN_PASSWORD", "a-password-the-operator-chose")
    password, generated = ba.resolve_password(_args())
    assert password == "a-password-the-operator-chose"
    assert generated is False


def test_without_one_it_generates(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_ADMIN_PASSWORD", raising=False)
    password, generated = ba.resolve_password(_args())
    assert generated is True
    assert len(password) == ba._GENERATED_PASSWORD_LENGTH


def test_a_too_short_supplied_password_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_ADMIN_PASSWORD", "short")
    with pytest.raises(ba.BootstrapError):
        ba.resolve_password(_args())


def test_a_supplied_password_is_never_echoed_back(capsys) -> None:
    """Only a password the operator cannot otherwise know is worth disclosing.

    Printing one they gave us puts a secret into scrollback and any CI log for
    nothing.
    """
    ba._print_credentials("admin@aisoc.internal", "the-operators-own-secret", generated=False)
    out = capsys.readouterr().out
    assert "the-operators-own-secret" not in out
    assert "admin@aisoc.internal" in out


def test_a_generated_password_is_printed_because_it_exists_nowhere_else(capsys) -> None:
    password = ba.generate_password()
    ba._print_credentials("admin@aisoc.internal", password, generated=True)
    out = capsys.readouterr().out
    assert password in out
    assert "not stored anywhere" in out


def test_stdin_wins_over_the_environment(monkeypatch) -> None:
    """So a password never has to appear in shell history or `ps` output."""
    monkeypatch.setenv("AISOC_ADMIN_PASSWORD", "from-the-environment")
    monkeypatch.setattr("sys.stdin", io.StringIO("from-standard-input\n"))
    password, generated = ba.resolve_password(argparse.Namespace(password_stdin=True))
    assert password == "from-standard-input"
    assert generated is False
