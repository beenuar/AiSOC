"""Two audit writers must not be able to fork the chain.

What was observed
-----------------
`POST /api/v1/alerts/{id}/explain` produced two audit rows from one request —
the handler's `emit_audit` on the request session, and `audit_middleware` on a
session of its own — two milliseconds apart, both resolving the same head::

    alerts:create   entry=dabf5207f866  prev=-
    alerts.explain  entry=66eed8144cee  prev=dabf5207f866
    alerts:create   entry=ca30ed264f98  prev=dabf5207f866   <- fork

`verify_chain` calls that broken and is right to: a fork is indistinguishable
from a removed row.

Why these tests run a real load rather than reading the source
--------------------------------------------------------------
A fork is a lost-update race, and a race is not a shape in a file. The
previous attempt at this — a transaction-scoped advisory lock — would have
passed any structural assertion ("the writer takes a lock") while dropping the
middleware's audit row on a timeout, which is worse than the fork it replaced.
So the assertions here drive concurrent writers against a real PostgreSQL and
then replay the chain.

`TestThePreFixWriterForks` is a **control**, and it is the reason the rest
means anything. It reimplements the pre-074 writer — scan `audit_log` for the
head, then insert — and asserts it *does* fork under the same load. If that
assertion ever stops holding, the load has stopped being concurrent and every
"the chain is intact" assertion below has quietly become vacuous. Proving a
gate against the pre-fix tree once, by hand, does not catch that later; a
control that runs on every invocation does.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.models.audit import AuditLog
from app.services.audit import CHAIN_EPOCH, _append_to_chain
from app.services.audit_hash import compute_entry_hash, verify_chain_breaks
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

#: Parallel "requests". Each contributes the two writers a single request had
#: before the fix, so the load is twice this number of concurrent appends.
REQUESTS = int(os.environ.get("AUDIT_CHAIN_PROOF_REQUESTS", "60"))

#: The owner DSN. The runtime role is DML-only, and these tests create a
#: scratch tenant; same resolution as `test_audit_chain_survives_a_failed_write`.
_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("AUDIT_CHAIN_CONCURRENCY_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    """Whether something actually answers on the DSN's host and port.

    A DSN is a statement of intent. The unit-test job exports a
    `postgres://…localhost:5432` URL with no server behind it, so a string
    check decides the test should run and it dies on `Connect call failed`.
    """
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


_HAVE_POSTGRES = "postgres" in _DSN and _postgres_is_listening()

pytestmark = pytest.mark.skipif(
    not _HAVE_POSTGRES and not _REQUIRED,
    reason=(
        "needs a live PostgreSQL — a lost-update race between two sessions has no "
        "SQLite equivalent, and the invariant under test is a unique index"
    ),
)


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def chain_env():
    """A scratch tenant on the real schema, with the real index and triggers.

    Deliberately the real `audit_log`, not a probe table: the property under
    test is `uq_audit_log_chain_successor`, and a copy of the table would be a
    copy of the constraint — the shape of gate this repository has been bitten
    by before.

    No teardown of the audit rows. `audit_log` is append-only by DB trigger, so
    a test that could clean up after itself would be evidence the immutability
    control was missing. The scratch tenant is left too, since deleting it
    cascades into `audit_log` and the trigger correctly refuses.
    """
    engine = create_async_engine(_DSN, pool_size=25, max_overflow=25)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"chain-proof-{suffix}", "s": f"chain-proof-{suffix}"},
        )
    yield maker, tenant_id
    await engine.dispose()


async def _replay(maker, tenant_id: uuid.UUID) -> list[dict]:
    """Read the tenant's chain in the order the writer chained it."""
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    text(
                        """
                        SELECT id, tenant_id, actor_id, actor_email, actor_ip, action,
                               resource, resource_id, changes, metadata, created_at,
                               prev_hash, entry_hash, chain_index, chain_epoch
                        FROM audit_log WHERE tenant_id = :t
                        ORDER BY chain_index ASC NULLS LAST, created_at ASC, id ASC
                        """
                    ),
                    {"t": tenant_id},
                )
            )
            .mappings()
            .all()
        )
    return [dict(r) for r in rows]


async def _duplicate_predecessors(maker, tenant_id: uuid.UUID) -> int:
    """Rows sharing a `(tenant_id, prev_hash)` — the literal definition of a fork.

    Counted directly rather than inferred from `verify_chain`, so the two
    measurements are independent: one replays hashes, this one asks the table.
    """
    async with maker() as db:
        return int(
            (
                await db.execute(
                    text(
                        """
                        SELECT coalesce(sum(n - 1), 0) FROM (
                          SELECT count(*) AS n FROM audit_log
                          WHERE tenant_id = :t AND entry_hash IS NOT NULL
                          GROUP BY tenant_id, coalesce(prev_hash, '')
                          HAVING count(*) > 1
                        ) d
                        """
                    ),
                    {"t": tenant_id},
                )
            ).scalar_one()
        )


# ── The control: the writer this change replaces ────────────────────────────


_SCAN_FOR_HEAD = text(
    """
    SELECT entry_hash FROM audit_log
    WHERE tenant_id = :t AND entry_hash IS NOT NULL
    ORDER BY created_at DESC, id DESC LIMIT 1
    """
)


async def _pre_fix_append(maker, tenant_id: uuid.UUID, action: str) -> None:
    """The pre-074 writer: resolve the head by scanning, then insert.

    Kept as an explicit reimplementation rather than by reverting the real one,
    so the control and the subject can both run in the same process and be
    compared under identical load.
    """
    async with maker() as db:
        prev = (await db.execute(_SCAN_FOR_HEAD, {"t": tenant_id})).scalar_one_or_none()
        # The window the race lives in. Real code spends time here redacting
        # the payload and building the row; yielding makes the race
        # reproducible rather than luck-dependent, and changes nothing about
        # whether it is possible.
        await asyncio.sleep(0.004)
        created_at = datetime.now(UTC)
        row_id = uuid.uuid4()
        await db.execute(
            text(
                """
                INSERT INTO audit_log (id, tenant_id, action, created_at, prev_hash,
                                       entry_hash, chain_epoch)
                VALUES (:id, :t, :a, :c, :p, :e, 1)
                """
            ),
            {
                "id": row_id,
                "t": tenant_id,
                "a": action,
                "c": created_at,
                "p": prev,
                "e": compute_entry_hash(
                    prev_hash=prev,
                    row_id=row_id,
                    tenant_id=tenant_id,
                    actor_id=None,
                    actor_email=None,
                    actor_ip=None,
                    action=action,
                    resource=None,
                    resource_id=None,
                    changes=None,
                    metadata=None,
                    created_at=created_at,
                ),
            },
        )
        await db.commit()


async def _serialized_append(maker, tenant_id: uuid.UUID, action: str) -> None:
    """The shipped writer, through the real `_append_to_chain`."""
    async with maker() as db:
        event = AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            action=action,
            created_at=datetime.now(UTC),
        )
        await _append_to_chain(db, event)
        await asyncio.sleep(0.004)  # the identical window
        db.add(event)
        await db.commit()


def _two_writers_per_request(fn, maker, tenant_id: uuid.UUID) -> list:
    """The shape that forked: two writers per request, every request at once."""
    tasks = []
    for _ in range(REQUESTS):
        tasks.append(fn(maker, tenant_id, "alerts.explain"))  # the handler's row
        tasks.append(fn(maker, tenant_id, "alerts:create"))  # the middleware's
    return tasks


@pytest.mark.asyncio
class TestThePreFixWriterForks:
    """The control. If this stops failing, nothing below proves anything."""

    async def test_scanning_for_the_head_forks_under_concurrency(self, chain_env) -> None:
        maker, tenant_id = chain_env
        await asyncio.gather(*_two_writers_per_request(_pre_fix_append, maker, tenant_id))

        rows = await _replay(maker, tenant_id)
        assert len(rows) == REQUESTS * 2, "every writer must have landed; this is not a test of dropped rows"

        duplicates = await _duplicate_predecessors(maker, tenant_id)
        breaks = verify_chain_breaks(rows)
        assert duplicates > 0, (
            "the pre-fix writer did not fork, so the load is not actually concurrent and the post-fix assertions are vacuous"
        )
        assert breaks, "a forked chain must fail replay"


@pytest.mark.asyncio
class TestTheSerializedWriterCannotFork:
    async def test_the_chain_replays_intact_under_the_same_load(self, chain_env) -> None:
        maker, tenant_id = chain_env
        await asyncio.gather(*_two_writers_per_request(_serialized_append, maker, tenant_id))

        rows = await _replay(maker, tenant_id)
        assert len(rows) == REQUESTS * 2, "no row may be dropped — that is worse than the fork"

        assert await _duplicate_predecessors(maker, tenant_id) == 0
        breaks = verify_chain_breaks(rows)
        assert breaks == [], f"chain broken at {breaks[:3]}"

    async def test_positions_are_dense_and_the_head_agrees(self, chain_env) -> None:
        """A gap in `chain_index` is a lost row; a head that disagrees with the
        last row means the next append will chain off something that is not the
        tip."""
        maker, tenant_id = chain_env
        await asyncio.gather(*_two_writers_per_request(_serialized_append, maker, tenant_id))

        rows = await _replay(maker, tenant_id)
        assert [r["chain_index"] for r in rows] == list(range(len(rows)))
        assert {r["chain_epoch"] for r in rows} == {CHAIN_EPOCH}

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
        assert head["head_hash"] == rows[-1]["entry_hash"]
        assert int(head["next_index"]) == len(rows)


@pytest.mark.asyncio
class TestAForkIsUnrepresentable:
    """The invariant must not depend on any application code being used.

    Serialization makes the second writer wait. This makes a fork impossible to
    store at all: if `_append_to_chain`, the middleware change and the lock were
    every one of them removed, the database would still refuse the row.
    """

    async def test_raw_sql_cannot_insert_a_second_row_with_the_same_predecessor(self, chain_env) -> None:
        maker, tenant_id = chain_env
        await _serialized_append(maker, tenant_id, "alerts:create")
        await _serialized_append(maker, tenant_id, "alerts:update")
        rows = await _replay(maker, tenant_id)
        victim = rows[-1]

        with pytest.raises(Exception, match="(?i)unique|duplicate key"):
            async with maker() as db:
                await db.execute(
                    text(
                        """
                        INSERT INTO audit_log (id, tenant_id, action, created_at,
                                               prev_hash, entry_hash, chain_epoch)
                        VALUES (:id, :t, 'forged', NOW(), :p, :e, 2)
                        """
                    ),
                    {"id": uuid.uuid4(), "t": tenant_id, "p": victim["prev_hash"], "e": "f" * 64},
                )
                await db.commit()

    async def test_a_genesis_row_is_also_covered(self, chain_env) -> None:
        """`prev_hash IS NULL` is the case a plain UNIQUE index would miss,
        because PostgreSQL treats NULLs as distinct. Two genesis rows are a
        forged restart of the chain, which is the most valuable fork to forge."""
        maker, tenant_id = chain_env
        await _serialized_append(maker, tenant_id, "alerts:create")

        with pytest.raises(Exception, match="(?i)unique|duplicate key"):
            async with maker() as db:
                await db.execute(
                    text(
                        """
                        INSERT INTO audit_log (id, tenant_id, action, created_at,
                                               prev_hash, entry_hash, chain_epoch)
                        VALUES (:id, :t, 'forged-genesis', NOW(), NULL, :e, 2)
                        """
                    ),
                    {"id": uuid.uuid4(), "t": tenant_id, "e": "e" * 64},
                )
                await db.commit()


@pytest.mark.asyncio
class TestHistoryIsContinuedNotRewritten:
    async def test_the_first_serialized_append_continues_the_existing_chain(self, chain_env) -> None:
        """A tenant with pre-074 rows must not get a second genesis row.

        Migration 074 seeds `audit_chain_head` from the history that already
        exists. Without that seeding the first append reads no head row,
        concludes the tenant has no history, and restarts the chain from
        genesis — which is exactly what a forged truncation looks like.

        Simulated here by deleting the tenant's head row, which is the state a
        tenant is in immediately after the migration if the seed missed it.
        """
        maker, tenant_id = chain_env
        await _serialized_append(maker, tenant_id, "alerts:create")
        await _serialized_append(maker, tenant_id, "alerts:update")
        before = await _replay(maker, tenant_id)

        # Re-seed exactly as migration 074 does, from audit_log alone.
        async with maker() as db:
            await db.execute(text("DELETE FROM audit_chain_head WHERE tenant_id = :t"), {"t": tenant_id})
            await db.execute(
                text(
                    """
                    INSERT INTO audit_chain_head (tenant_id, head_hash, next_index)
                    SELECT :t,
                           (SELECT a.entry_hash FROM audit_log a
                             WHERE a.tenant_id = :t AND a.entry_hash IS NOT NULL
                             ORDER BY a.created_at DESC, a.id DESC LIMIT 1),
                           (SELECT count(*) FROM audit_log a
                             WHERE a.tenant_id = :t AND a.entry_hash IS NOT NULL)
                    """
                ),
                {"t": tenant_id},
            )
            await db.commit()

        await _serialized_append(maker, tenant_id, "alerts:delete")
        after = await _replay(maker, tenant_id)

        assert len(after) == len(before) + 1
        assert after[-1]["prev_hash"] == before[-1]["entry_hash"], "the chain restarted instead of continuing"
        assert verify_chain_breaks(after) == []
        assert sum(1 for r in after if r["prev_hash"] is None) == 1, "a second genesis row is a forged truncation"
