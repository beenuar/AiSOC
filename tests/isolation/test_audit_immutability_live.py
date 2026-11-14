"""audit_log immutability: the FK SET NULL exemption stays pinned to actor_id.

Migration 101_audit_immutable_nullify.sql relaxed trg_audit_log_immutable
just enough for ON DELETE SET NULL to fire when an admin hard-deletes a
user. Review on #1231 showed a value->NULL exemption that does not name the
column lets one UPDATE strip every forensic column at once (actor_email,
actor_ip, resource, changes, metadata) while the trigger stays silent.

Migration 119 (issue #1330, ADR-0014) added the second exemption: the
cascade from ``DELETE FROM tenants``, without which tenant offboarding — the
path a GDPR erasure request takes — could never complete. The erasure cases
here are the acceptance tests that issue named, and they commit real rows in
a tenant of their own; every other case runs inside a transaction that
ROLLBACKs, so no shared audit row is ever durably mutated, not even in the
legal case.

The suite drives two connections, because the two refusal layers bind
different roles: ``ISOLATION_AUDIT_DSN`` is the DML-only runtime role
(``aisoc_app``), refused by privilege since migration 117 revoked its
DELETE; ``ISOLATION_AUDIT_OWNER_DSN`` is the table owner, for whom only the
trigger stands. Proving both keeps the control two-layered rather than
quietly privilege-only.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AUDIT_DSN", "").strip(),
        reason="ISOLATION_AUDIT_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AUDIT_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AUDIT_DSN is not set")
    return value.replace("postgresql://", "postgresql+asyncpg://", 1) if value.startswith("postgresql://") else value


def _owner_dsn() -> str:
    """The table owner's DSN — required, not optional, once the suite runs.

    The trigger-layer cases can only be proven by a role that holds the
    DELETE privilege, and a live suite that silently skips them would read
    as the control passing. So an unset owner DSN is a failure with the
    remedy in the message, never a skip.
    """
    value = os.environ.get("ISOLATION_AUDIT_OWNER_DSN", "").strip()
    if not value:
        pytest.fail(
            "ISOLATION_AUDIT_DSN is set but ISOLATION_AUDIT_OWNER_DSN is not: the trigger-layer "
            "cases need the audit_log table owner (the role that applies migrations), and "
            "skipping them would prove the privilege layer only"
        )
    return value.replace("postgresql://", "postgresql+asyncpg://", 1) if value.startswith("postgresql://") else value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def owner_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_owner_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def row(engine):
    """A fresh audit row to attack, deleted on teardown. Its actor is then
    deleted too, so the FK SET NULL path is exercised for real."""
    import uuid

    from sqlalchemy import text

    aid = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tenant_id, "n": f"imm-{aid[:8]}", "s": f"imm-{aid[:8]}"},
        )
        await conn.execute(
            text("INSERT INTO users (id, tenant_id, email, username, hashed_password) VALUES (:id, :t, :e, :u, :h)"),
            {
                "id": user_id,
                "t": tenant_id,
                "e": f"imm-{aid[:8]}@test.local",
                "u": f"imm-{aid[:8]}",
                "h": "!locked-by-test-no-login",
            },
        )
        await conn.execute(
            text(
                "INSERT INTO audit_log (id, tenant_id, actor_id, actor_email, "
                "actor_ip, action, resource, resource_id, changes, metadata) "
                "VALUES (:id, :t, :a, :e, :i, :ac, :r, :ri, :c, :m)"
            ),
            {
                "id": aid,
                "t": tenant_id,
                "a": user_id,
                "e": "operator@corp.example",
                "i": "203.0.113.7",
                "ac": "roles:grant",
                "r": "role/infosec",
                "ri": "00000000-0000-0000-0000-000000000009",
                "c": '{"role": "infosec"}',
                "m": '{"via": "console"}',
            },
        )
    yield {"id": aid, "user_id": user_id, "tenant_id": tenant_id}
    async with engine.begin() as conn:
        # Teardown goes through the two legal paths rather than around them.
        # Deleting the user first fires ON DELETE SET NULL on actor_id through
        # the trigger — exactly the path migration 101 exists for — and
        # deleting the tenant then erases the audit row by cascade, the path
        # migration 119 exists for. The previous teardown deleted the audit
        # row directly, which 117's trigger refuses; it only looked fine while
        # this suite ran in no workflow at all.
        await conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})


async def _attempt(engine, sql: str, params: dict) -> str:
    """Run a mutating UPDATE inside a rolled-back transaction.
    Returns 'ALLOWED' or 'REFUSED (<message>)'."""
    from sqlalchemy import text

    conn = await engine.connect()
    try:
        trans = await conn.begin()
        try:
            await conn.execute(text(sql), params)
            outcome = "ALLOWED"
        finally:
            await trans.rollback()
        return outcome
    except Exception as exc:  # trigger raise
        orig = getattr(exc, "orig", exc)
        return f"REFUSED ({orig})"
    finally:
        await conn.close()


class TestAuditImmutabilityExemption:
    async def test_actor_id_nullify_is_allowed(self, engine, row) -> None:
        """The FK case: ON DELETE SET NULL on actor_id must pass."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_id = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome == "ALLOWED", outcome

    async def test_single_other_column_nullify_is_refused(self, engine, row) -> None:
        """The review's hole: stripping actor_email (nullable, no SET NULL
        FK) must raise, not pass silently."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_email = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome.startswith("REFUSED"), outcome
        assert "actor_email" in outcome

    async def test_multi_column_strip_is_refused(self, engine, row) -> None:
        """The exact statement from the review evidence: every forensic
        column NULLed in one UPDATE. This is the case that was silent
        before the column-name guard."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_email = NULL, actor_ip = NULL, "
            "resource = NULL, resource_id = NULL, changes = NULL, "
            "metadata = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome.startswith("REFUSED"), outcome

    async def test_content_mutation_still_refused(self, engine, row) -> None:
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET action = :a WHERE id = :id",
            {"id": row["id"], "a": "roles:revoke"},
        )
        assert outcome.startswith("REFUSED"), outcome

    async def test_actor_id_value_change_is_refused(self, engine, row) -> None:
        """Only value -> NULL is exempt on actor_id; swapping actors is
        still attribution forgery."""
        import uuid

        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_id = :other WHERE id = :id",
            {"id": row["id"], "other": str(uuid.uuid4())},
        )
        assert outcome.startswith("REFUSED"), outcome

    async def test_delete_is_still_refused_loudly(self, owner_engine, row) -> None:
        """The trigger is BEFORE UPDATE **OR DELETE** and both arms run this
        one function, so rewriting it for the UPDATE shape has to keep the
        DELETE arm working.

        Without the `TG_OP = 'DELETE'` guard the loop over
        `jsonb_object_keys(NEW)` iterates zero times — there is no NEW on a
        delete — and `RETURN NEW` returns NULL, which in a BEFORE trigger
        silently *cancels* the statement. The row survives, so immutability
        holds by accident, but the caller is told nothing and reads
        `DELETE 0` as success. Refusing loudly is the behaviour migration
        004 shipped and the one an operator can act on.

        Runs as the **owner**, deliberately: the runtime role is stopped one
        layer earlier by 117's privilege revoke (the case below), so only a
        role holding DELETE can prove the trigger arm still works — and the
        tenant is alive here, so 119's cascade arm must not open the door.

        Asserted both ways round: the statement raises, and the row is
        still there afterwards.
        """
        outcome = await _attempt(owner_engine, "DELETE FROM audit_log WHERE id = :id", {"id": row["id"]})
        assert outcome.startswith("REFUSED"), outcome
        assert "DELETE" in outcome, outcome

        # Imported in the function, as every other case here does: a
        # module-scope import of a service dependency has taken 241
        # unrelated tests down in the offline collection job.
        from sqlalchemy import text

        async with owner_engine.connect() as conn:
            remaining = (
                await conn.execute(
                    text("SELECT count(*) FROM audit_log WHERE id = :id"),
                    {"id": row["id"]},
                )
            ).scalar()
        assert remaining == 1, "the row was removed even though the statement was refused"

    async def test_delete_as_the_runtime_role_is_refused_by_privilege(self, engine, row) -> None:
        """The privilege layer, proven on the role the product actually runs as.

        Migration 117 revoked DELETE on `audit_log` from `aisoc_app`, so the
        runtime role is refused before the trigger is ever consulted. Either
        message proves the row cannot be removed; which one arrives says
        which layer answered, and on this connection it must be the
        privilege layer unless a deployment re-granted DELETE — in which
        case the trigger still stands, so `immutable` is accepted too.
        """
        outcome = await _attempt(engine, "DELETE FROM audit_log WHERE id = :id", {"id": row["id"]})
        assert outcome.startswith("REFUSED"), outcome
        assert "permission denied" in outcome or "immutable" in outcome, outcome

        from sqlalchemy import text

        async with engine.connect() as conn:
            remaining = (
                await conn.execute(
                    text("SELECT count(*) FROM audit_log WHERE id = :id"),
                    {"id": row["id"]},
                )
            ).scalar()
        assert remaining == 1, "the row was removed even though the statement was refused"


class TestTenantErasureIsTheOnePathThrough:
    """Issue #1330's acceptance tests, verbatim: deleting a tenant that holds
    audit rows must succeed and take the rows with it, while a direct DELETE
    on those same rows stays refused for as long as the tenant exists."""

    async def test_deleting_the_tenant_erases_its_audit_rows(self, engine) -> None:
        """`DELETE FROM tenants` completes as the runtime role, and the
        cascade crosses both refusal layers.

        This is the exact statement `tenant_deletion.py` ends with, run as
        the role the product runs as. It proves two things no unit test can:
        that 119's trigger arm recognises the cascade (the parent is already
        gone when the child's BEFORE trigger runs), and that the referential
        action carries the table owner's privilege — `aisoc_app` holds no
        DELETE on `audit_log`, yet its DELETE on `tenants` must still erase
        the audit rows. Before 119 this statement raised `immutable` for any
        tenant that had ever written an audit row, which is every tenant.

        Committed rather than rolled back, in a tenant of its own: erasure
        that only happens inside an aborted transaction proves nothing.
        """
        import uuid

        from sqlalchemy import text

        tenant_id = str(uuid.uuid4())
        marker = f"erasure-{tenant_id[:8]}"
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": tenant_id, "n": marker, "s": marker},
            )
            for action in ("case:create", "case:close"):
                await conn.execute(
                    text("INSERT INTO audit_log (id, tenant_id, action, resource) VALUES (:id, :t, :a, 'case/1')"),
                    {"id": str(uuid.uuid4()), "t": tenant_id, "a": action},
                )

        # The negative control first, while the tenant is alive: the same
        # rows the cascade is about to erase cannot be deleted directly.
        outcome = await _attempt(engine, "DELETE FROM audit_log WHERE tenant_id = :t", {"t": tenant_id})
        assert outcome.startswith("REFUSED"), outcome

        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})

        async with engine.connect() as conn:
            survivors = (
                await conn.execute(
                    text("SELECT count(*) FROM audit_log WHERE tenant_id = :t"),
                    {"t": tenant_id},
                )
            ).scalar()
            tenant_rows = (
                await conn.execute(
                    text("SELECT count(*) FROM tenants WHERE id = :t"),
                    {"t": tenant_id},
                )
            ).scalar()
        assert tenant_rows == 0, "the tenant row survived its own deletion"
        assert survivors == 0, "the tenant is gone but its audit rows survived — the cascade was refused or skipped"
