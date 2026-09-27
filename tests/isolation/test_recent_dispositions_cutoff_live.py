"""Live-Postgres proof that the recent-decisions cutoff actually filters.

Gap-closure Phase 6.3, and the sibling of
``test_kb_retrieval_cutoff_live.py``. Same reasoning, and this source needs it
more: a decision recorded inside a replay's test window is literally an
analyst's answer to an alert in that window, so a cutoff that silently did
nothing would grade the agent against the labels it is about to be marked on.

Every offline test of that freeze stubs the route, so every one of them proves
the reader *asks* for a cutoff and none of them proves the store applies one.
The statement is PostgreSQL (``FILTER (WHERE ...)``, ``LEFT JOIN LATERAL``,
``context ->> 'rule_id'``, ``ANY(CAST(... AS text[]))``), so it does not parse
in the API's SQLite suite at all.

It runs ``recent_dispositions_sql`` itself rather than a copy. The knowledge
base's version of this test first carried its own copy of the cutoff clause
and kept passing after the clause was deleted from the route, which is why the
builder is a function with two callers.

Skips when no database answers; ``DISPOSITIONS_CUTOFF_LIVE_REQUIRED=1`` turns
an unreachable database into a failure where it is supposed to run.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "services" / "api"))

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("DISPOSITIONS_CUTOFF_LIVE_REQUIRED", "").strip() not in ("", "0", "false")

pytestmark = pytest.mark.skipif(
    "postgres" not in DSN and not REQUIRED,
    reason="needs a live Postgres with the migration chain applied (integration.yml)",
)

TENANT = uuid.UUID("0c000000-0000-0000-0000-0000000000d1")
OTHER_TENANT = uuid.UUID("0c000000-0000-0000-0000-0000000000d2")

SPLIT = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
BEFORE = datetime(2026, 4, 1, 0, 0, tzinfo=UTC)
AFTER = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)

RULE = "rule-encoded-powershell"
HOST = "fin-app-03"


def _asyncpg_dsn(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


async def _seed(conn) -> None:
    await conn.execute("DELETE FROM aisoc_analyst_feedback WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
    rows = [
        # Matched by rule, before the split.
        (TENANT, "known_admin_tool", "rule", RULE, "Before the split.", BEFORE, RULE),
        # Matched by rule, inside the test window. This is the leak.
        (TENANT, "known_admin_tool", "rule", RULE, "Decided inside the test window.", AFTER, RULE),
        # Matched by entity rather than by rule, before the split. Present so
        # the entity arm of the predicate is exercised rather than assumed.
        (TENANT, "expected_service_account", "entity", HOST, "Entity-scoped, before the split.", BEFORE, "rule-other"),
        # Another tenant's decision on the same rule.
        (OTHER_TENANT, "known_admin_tool", "rule", RULE, "Another tenant's decision.", BEFORE, RULE),
    ]
    for tenant, reason, scope, scope_value, note, created, rule_id in rows:
        await conn.execute(
            """
            INSERT INTO aisoc_analyst_feedback
                (id, tenant_id, alert_id, ai_disposition, analyst_disposition, reason_code,
                 scope, scope_value, analyst_id, note, context, created_at)
            VALUES ($1, $2, $3, 'true_positive', 'benign_true_positive', $4, $5, $6, 'analyst-1', $7, $8::jsonb, $9)
            """,
            uuid.uuid4(),
            tenant,
            uuid.uuid4(),
            reason,
            scope,
            scope_value,
            note,
            f'{{"rule_id": "{rule_id}"}}',
            created,
        )


async def _fetch(conn, *, as_of: datetime | None, tenant: uuid.UUID = TENANT) -> list:
    from app.api.v1.endpoints.feedback import recent_dispositions_sql

    sql = recent_dispositions_sql(cutoff=as_of is not None)
    args: list = [tenant, RULE, [HOST], 10]
    if as_of is not None:
        args.append(as_of)

    for name, position in ((":tenant_id", "$1"), (":rule_id", "$2"), (":entities", "$3"), (":limit", "$4"), (":as_of", "$5")):
        if name in sql:
            sql = sql.replace(name, position)
        elif name != ":as_of":
            raise AssertionError(f"{name} is no longer a parameter of the recent-dispositions statement")
    return await conn.fetch(sql, *args)


@pytest.mark.asyncio
async def test_the_cutoff_filters_and_reports_what_it_refused() -> None:
    import asyncpg

    conn = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        await _seed(conn)

        # 1. No cutoff: both of this tenant's matching decisions, by rule and
        #    by entity, and neither of the other tenant's. Run first, so an
        #    empty table cannot make the scoped read below pass for the wrong
        #    reason.
        live = await _fetch(conn, as_of=None)
        notes = sorted(r["note"] for r in live if r["note"] is not None)
        assert notes == ["Before the split.", "Decided inside the test window.", "Entity-scoped, before the split."], notes
        assert live[0]["excluded_after_cutoff"] == 0

        # 2. With the cutoff: only the decisions that existed at the split.
        frozen = await _fetch(conn, as_of=SPLIT)
        frozen_notes = sorted(r["note"] for r in frozen if r["note"] is not None)
        assert frozen_notes == ["Before the split.", "Entity-scoped, before the split."], frozen_notes

        # 3. And the count says the freeze did something.
        assert frozen[0]["excluded_after_cutoff"] == 1
        assert frozen[0]["without_timestamp"] == 0

        # The rule match outranks the entity match, because a decision tagged
        # against this rule is the more specific claim.
        assert frozen[0]["note"] == "Before the split."

        # A cutoff before everything returns no rows and still returns counts.
        empty = await _fetch(conn, as_of=datetime(2020, 1, 1, tzinfo=UTC))
        assert [r for r in empty if r["note"] is not None] == []
        assert len(empty) == 1
        assert empty[0]["excluded_after_cutoff"] == 3
    finally:
        await conn.execute("DELETE FROM aisoc_analyst_feedback WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
        await conn.close()


@pytest.mark.asyncio
async def test_one_tenants_decisions_never_reach_another() -> None:
    import asyncpg

    conn = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        await _seed(conn)

        mine = await _fetch(conn, as_of=None, tenant=TENANT)
        theirs = await _fetch(conn, as_of=None, tenant=OTHER_TENANT)

        # Both tenants hold a decision on this rule, so neither read is empty
        # and "returned nothing" cannot be mistaken for "isolated".
        assert [r["note"] for r in theirs if r["note"] is not None] == ["Another tenant's decision."]
        assert all(r["note"] != "Another tenant's decision." for r in mine if r["note"] is not None)
    finally:
        await conn.execute("DELETE FROM aisoc_analyst_feedback WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
        await conn.close()
