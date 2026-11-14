"""An enforced audit retention window that leaves the chain verifiable.

Depth 8.1, the remainder of parity 4.4.

What was missing
----------------
`retention_policies.audit_days` had been storable since the table existed
and was purged by nothing. The retention worker said so in its own module
docstring and said why: `audit_log` is an append-only hash chain whose
entire value is that no row was deleted, reordered or rewritten, so a
plain `DELETE` of the oldest rows leaves the new first row naming a
predecessor that is gone. `verify_chain_breaks` replays from
`prev_hash = NULL` and reports a mismatch at index 0 -- an intact chain
reads as tampered with, which is the worst answer a control like this can
give, because it is indistinguishable from the real thing.

Migration `111` is the missing piece: `audit_retention_truncate` writes a
checkpoint recording the cutoff, the count, the hash of the last row
removed and the predecessor the oldest survivor names, and only then
deletes -- in one transaction. Verification re-anchors on the checkpoint.

Why this suite is live rather than offline
------------------------------------------
Every control here is enforced by Postgres and by nothing in Python:
a `SECURITY DEFINER` function, a `REVOKE DELETE` on the application role,
a `BEFORE DELETE` trigger reading a transaction-local setting, and two RLS
policies. A fake session answers whatever the handler asks, so an offline
test of this would be a test of the double. In particular
`test_the_runtime_role_cannot_delete_an_audit_row_directly` can only fail
against a real server holding real grants, and it is the assertion the
whole design rests on: without it the trigger's setting is a comment,
because a custom GUC can be set by anybody.

`ENVIRONMENT=test`, never `development`, which is in
`AUTH_BYPASS_ENVIRONMENTS`.

The connection is the DML-only `aisoc_app` role, not the owner. A
superuser ignores every RLS policy even under FORCE ROW LEVEL SECURITY
and holds DELETE on everything, so this suite would pass as the owner
with the privilege control removed -- which is the sibling defect that
has shipped here before.

The negative control
--------------------
`test_without_the_anchor_the_same_chain_reads_as_broken` replays the
surviving rows from the genesis `prev_hash = NULL` instead of from the
checkpoint. It must report a break. Without it,
"the truncated chain verifies" would pass equally well against a
verifier that had stopped checking `prev_hash` at all.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AUDIT_RETENTION_DSN", "").strip(),
        reason="ISOLATION_AUDIT_RETENTION_DSN is not set; this suite needs a live Postgres",
    ),
]

#: How many rows the fixture chain carries, and where the cutoff falls.
#: Four old and three recent, so a cutoff that removes "the oldest" is
#: removing several links rather than one, and an off-by-one in the
#: boundary (`<` against `<=`) changes the count rather than hiding in it.
OLD_ROWS = 4
RECENT_ROWS = 3


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AUDIT_RETENTION_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AUDIT_RETENTION_DSN is not set")
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    # Imported inside the fixture. One module-scope import of a service
    # took 241 unrelated tests down in the offline collection job, which
    # installs minimal dependencies.
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


async def _chain_rows(conn, tenant_id: str) -> list[dict]:
    """Every audit row for a tenant, oldest first, in replay shape."""
    from sqlalchemy import text

    result = await conn.execute(
        text(
            "SELECT id, tenant_id, actor_id, actor_email, action, resource, "
            "       resource_id, changes, metadata, created_at, prev_hash, "
            "       entry_hash, chain_index "
            "  FROM audit_log WHERE tenant_id = :t "
            " ORDER BY created_at ASC, chain_index ASC"
        ),
        {"t": tenant_id},
    )
    return [dict(r) for r in result.mappings().all()]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def chained_tenant(engine):
    """A tenant whose audit log is a chain with rows on both sides of a cutoff.

    Every `prev_hash` and `entry_hash` is computed by the product's own
    `compute_entry_hash`, so the chain under test is linked exactly as the
    writer links it and the verifier is checking real hashes rather than
    ones this file knows how to satisfy.

    What this fixture does *not* use is `emit_audit`, and the reason is
    worth stating because it looks like the weaker choice. `created_at` is
    one of the hashed fields, deliberately, and `emit_audit` stamps it
    `now()`. A retention window needs rows older than the cutoff, and the
    immutability trigger refuses an `UPDATE` of `created_at` -- which it
    should, and which this suite confirms from the other direction in
    `TestTheOnlyWayOutIsTheFunction`. There is no supported way to write a
    historical audit row, so the rows are inserted with their timestamps
    and their hashes computed together, which is what `emit_audit` itself
    does. Only the `INSERT` differs.
    """
    from app.services.audit_hash import compute_entry_hash
    from sqlalchemy import text

    tenant_id = str(uuid.uuid4())
    tag = tenant_id[:8]
    now = datetime.now(UTC)

    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tenant_id, "n": f"ret-{tag}", "s": f"ret-{tag}"},
        )

        prev_hash: str | None = None
        for n in range(OLD_ROWS + RECENT_ROWS):
            # The first OLD_ROWS sit well behind any sane cutoff; the rest
            # are minutes old. Ordering is strictly increasing either way,
            # which is what the replay assumes.
            created_at = now - (timedelta(days=400 - n) if n < OLD_ROWS else timedelta(minutes=OLD_ROWS + RECENT_ROWS - n))
            row_id = uuid.uuid4()
            changes = {"seq": n}
            entry_hash = compute_entry_hash(
                prev_hash=prev_hash,
                row_id=row_id,
                tenant_id=uuid.UUID(tenant_id),
                actor_id=None,
                actor_email=f"operator-{n}@corp.example",
                actor_ip=None,
                action="cases:update",
                resource="case",
                resource_id=f"case-{n}",
                changes=changes,
                metadata=None,
                created_at=created_at,
            )
            await conn.execute(
                text(
                    "INSERT INTO audit_log (id, tenant_id, actor_email, action, resource, "
                    "                       resource_id, changes, created_at, prev_hash, "
                    "                       entry_hash, chain_index) "
                    "VALUES (:id, :t, :ae, :a, :r, :ri, CAST(:c AS jsonb), :ca, :ph, :eh, :ci)"
                ),
                {
                    "id": str(row_id),
                    "t": tenant_id,
                    "ae": f"operator-{n}@corp.example",
                    "a": "cases:update",
                    "r": "case",
                    "ri": f"case-{n}",
                    "c": json.dumps(changes),
                    "ca": created_at,
                    "ph": prev_hash,
                    "eh": entry_hash,
                    "ci": n,
                },
            )
            prev_hash = entry_hash

    yield tenant_id

    async with engine.begin() as conn:
        # Through the sanctioned function, not by cascade. `audit_log` has
        # `ON DELETE CASCADE` from `tenants`, but the immutability trigger
        # refuses the cascaded DELETE like any other -- so a plain
        # `DELETE FROM tenants` raises for any tenant that has ever written
        # an audit row. Clearing the rows first is the only way out, and it
        # is also the one this suite is about.
        await conn.execute(
            text("SELECT audit_retention_truncate(:t, :c, :d)"),
            {"t": tenant_id, "c": datetime.now(UTC) + timedelta(days=1), "d": 0},
        )
        await conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def truncated(engine, chained_tenant):
    """Run the real truncation once, and hand back what it reported."""
    from sqlalchemy import text

    cutoff = datetime.now(UTC) - timedelta(days=90)
    async with engine.begin() as conn:
        before = await _chain_rows(conn, chained_tenant)
        removed = (
            await conn.execute(
                text("SELECT audit_retention_truncate(:t, :c, :d)"),
                {"t": chained_tenant, "c": cutoff, "d": 90},
            )
        ).scalar()
        after = await _chain_rows(conn, chained_tenant)
        checkpoint = (
            (
                await conn.execute(
                    text(
                        "SELECT truncated_before, window_days, rows_removed, last_removed_hash, "
                        "       first_retained_prev_hash, first_retained_hash "
                        "  FROM aisoc_audit_checkpoints WHERE tenant_id = :t "
                        " ORDER BY created_at DESC LIMIT 1"
                    ),
                    {"t": chained_tenant},
                )
            )
            .mappings()
            .first()
        )
    return {"removed": removed, "before": before, "after": after, "checkpoint": dict(checkpoint) if checkpoint else None}


class TestTheWindowIsEnforced:
    async def test_the_rows_past_the_window_are_gone(self, truncated):
        assert truncated["removed"] == OLD_ROWS
        assert len(truncated["before"]) == OLD_ROWS + RECENT_ROWS
        assert len(truncated["after"]) == RECENT_ROWS

    async def test_the_checkpoint_records_what_went_and_under_which_policy(self, truncated):
        """Both, because they answer different questions.

        "Everything before 13 July went" and "a 90-day window was in
        force" are not the same fact, and an auditor asks the second.
        """
        cp = truncated["checkpoint"]
        assert cp is not None, "truncation removed rows and wrote no checkpoint"
        assert cp["rows_removed"] == OLD_ROWS
        assert cp["window_days"] == 90

    async def test_the_checkpoint_agrees_with_the_rows_it_describes(self, truncated):
        """The anchor must be the hash of the last row actually removed.

        Stored twice on purpose -- `last_removed_hash` from the removed
        side and `first_retained_prev_hash` from the surviving side -- so
        the checkpoint can be checked against itself. On an untampered
        chain they are equal; a checkpoint that disagrees with itself is
        evidence in its own right.
        """
        cp = truncated["checkpoint"]
        last_removed = truncated["before"][OLD_ROWS - 1]
        first_kept = truncated["after"][0]

        assert cp["last_removed_hash"] == last_removed["entry_hash"]
        assert cp["first_retained_prev_hash"] == first_kept["prev_hash"]
        assert cp["first_retained_hash"] == first_kept["entry_hash"]
        assert cp["last_removed_hash"] == cp["first_retained_prev_hash"]


class TestTheRemainderStillVerifies:
    async def test_the_surviving_chain_replays_clean_from_the_checkpoint(self, truncated):
        from app.services.audit_hash import verify_chain_breaks

        breaks = verify_chain_breaks(
            truncated["after"],
            anchor_prev_hash=truncated["checkpoint"]["first_retained_prev_hash"],
        )
        assert breaks == [], f"a lawfully truncated chain reported {len(breaks)} break(s): {breaks}"

    async def test_verify_chain_agrees_with_the_full_replay(self, truncated):
        from app.services.audit_hash import verify_chain

        ok, index, reason = verify_chain(
            truncated["after"],
            anchor_prev_hash=truncated["checkpoint"]["first_retained_prev_hash"],
        )
        assert ok, f"verify_chain reported a break at {index}: {reason}"

    async def test_without_the_anchor_the_same_chain_reads_as_broken(self, truncated):
        """The negative control.

        Replaying the survivors from the genesis `prev_hash = NULL` is
        what the verifier did before this item, and it is why a retention
        purge could not be built. It must still report a break here --
        otherwise "the truncated chain verifies" would pass equally well
        against a verifier that had stopped checking `prev_hash`.
        """
        from app.services.audit_hash import verify_chain_breaks

        breaks = verify_chain_breaks(truncated["after"])
        assert breaks, "replaying a truncated chain from genesis reported no break; the anchor is proving nothing"
        assert breaks[0]["index"] == 0


class TestTheOnlyWayOutIsTheFunction:
    async def test_the_runtime_role_cannot_delete_an_audit_row_directly(self, engine, chained_tenant):
        """The privilege half, and the one the whole design rests on.

        The trigger refuses a DELETE unless a transaction-local setting
        says a retention purge is in progress, and a custom GUC can be
        set by anybody -- so on its own that is a comment, not a control.
        `REVOKE DELETE ON audit_log FROM aisoc_app` is what makes the
        function the only path, and only a real server holding real
        grants can demonstrate it.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, ProgrammingError

        with pytest.raises((ProgrammingError, DBAPIError)) as caught:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": chained_tenant})
        assert "permission denied" in str(caught.value).lower()

    async def test_setting_the_purge_flag_by_hand_does_not_help(self, engine, chained_tenant):
        """Defence in depth, in the order that matters.

        Postgres checks the privilege before the trigger runs, so a
        caller who guesses the setting's name is refused one layer below
        the one they were aiming at.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, ProgrammingError

        with pytest.raises((ProgrammingError, DBAPIError)) as caught:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT set_config('app.audit_retention_purge', 'on', true)"))
                await conn.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": chained_tenant})
        assert "permission denied" in str(caught.value).lower()

    async def test_a_no_op_window_writes_no_checkpoint(self, engine, chained_tenant):
        """A table of "removed 0 rows" entries every tick buries the ones
        that mean something."""
        from sqlalchemy import text

        async with engine.begin() as conn:
            before = (
                await conn.execute(text("SELECT count(*) FROM aisoc_audit_checkpoints WHERE tenant_id = :t"), {"t": chained_tenant})
            ).scalar()
            removed = (
                await conn.execute(
                    text("SELECT audit_retention_truncate(:t, :c, :d)"),
                    {"t": chained_tenant, "c": datetime.now(UTC) - timedelta(days=3650), "d": 3650},
                )
            ).scalar()
            after = (
                await conn.execute(text("SELECT count(*) FROM aisoc_audit_checkpoints WHERE tenant_id = :t"), {"t": chained_tenant})
            ).scalar()

        assert removed == 0
        assert after == before


class TestTheRecordOfTheRemovalIsItselfARecord:
    async def test_a_checkpoint_cannot_be_updated(self, engine, chained_tenant, truncated):
        """A record of what was deleted which can be edited is not a record."""
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, ProgrammingError

        with pytest.raises((ProgrammingError, DBAPIError)) as caught:
            async with engine.begin() as conn:
                await conn.execute(
                    text("UPDATE aisoc_audit_checkpoints SET rows_removed = 0 WHERE tenant_id = :t"),
                    {"t": chained_tenant},
                )
        assert "immutable" in str(caught.value).lower()

    async def test_a_checkpoint_cannot_be_deleted(self, engine, chained_tenant, truncated):
        """Refused first and unconditionally.

        On DELETE there is no NEW, and `RETURN NEW` in a BEFORE trigger
        returns NULL -- which silently *cancels* the statement and
        reports "DELETE 0" as success. That is the shape migration 101
        had to repair on `audit_log` itself.
        """
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, ProgrammingError

        with pytest.raises((ProgrammingError, DBAPIError)) as caught:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM aisoc_audit_checkpoints WHERE tenant_id = :t"), {"t": chained_tenant})
        assert "immutable" in str(caught.value).lower()

    async def test_the_cascade_from_its_tenant_is_the_one_exception(self, engine):
        """And the foreign key means it, which an unconditional trigger did not.

        `tenant_id` is declared `ON DELETE CASCADE`. A trigger that refused
        every DELETE made that a lie -- the tenant delete raised instead of
        cascading, so the row could never be removed by any means. That is
        the shape already blocking `DELETE FROM tenants` on `audit_log`
        itself, and this table must not add a second one.

        The exception is narrow by construction: a cascade is told apart
        from a direct DELETE by whether the parent is still there, and the
        case above proves the direct one is still refused while this
        tenant's row exists. Erasing a checkpoint therefore costs the whole
        tenant -- every alert, case and credential with it -- which is not
        selective erasure in any useful sense.
        """
        from sqlalchemy import text

        tenant_id = str(uuid.uuid4())
        tag = tenant_id[:8]
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": tenant_id, "n": f"casc-{tag}", "s": f"casc-{tag}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO aisoc_audit_checkpoints   (tenant_id, truncated_before, window_days, rows_removed) VALUES (:t, :c, 90, 1)"
                ),
                {"t": tenant_id, "c": datetime.now(UTC)},
            )

        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})
            left = (
                await conn.execute(text("SELECT count(*) FROM aisoc_audit_checkpoints WHERE tenant_id = :t"), {"t": tenant_id})
            ).scalar()
        assert left == 0
