"""Live-Postgres proof that the runbook retrieval cutoff actually filters.

Gap-closure Phase 6.3.

Why this is not a unit test
--------------------------
The knowledge base is frozen at a replay's split point by a predicate in SQL,
not by a captured set in Python. Every other test of that freeze stubs the
route, so every one of them proves the *reader* asks for a cutoff and none of
them proves the store applies one. The API's own suite runs on SQLite, where
``to_tsvector``, ``plainto_tsquery``, ``ts_rank``, ``FILTER (WHERE ...)`` and
``LEFT JOIN LATERAL`` do not exist, so the statement under test cannot even
parse there.

So this runs the module's own ``_TRIAGE_RETRIEVAL_SQL``, character for
character, against a real Postgres holding real rows. Importing the constant
rather than restating it is the point: a test carrying its own copy of the SQL
would keep passing after the route's copy changed, which is the shape this
programme keeps finding.

Three properties, and the third is the one a report depends on:

1. With no cutoff, both documents come back. A scoped read that returns
   nothing on an empty table passes for the wrong reason, so this runs first.
2. With a cutoff, only the document that existed then comes back.
3. ``excluded_after_cutoff`` reports the one that was refused. Without it, a
   cutoff that matched nothing and a cutoff that threw away every document
   are the same empty list, and a replay's method note would be describing a
   freeze it never demonstrated.

Skips when no database answers, so a local ``pytest tests/isolation`` stays
green, and ``KB_CUTOFF_LIVE_REQUIRED=1`` turns an unreachable database into a
failure where it is supposed to run. A gate that quietly declines to run looks
identical to one that passed.
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
REQUIRED = os.environ.get("KB_CUTOFF_LIVE_REQUIRED", "").strip() not in ("", "0", "false")

pytestmark = pytest.mark.skipif(
    "postgres" not in DSN and not REQUIRED,
    reason="needs a live Postgres with the migration chain applied (integration.yml)",
)

TENANT = uuid.UUID("0c000000-0000-0000-0000-0000000000cb")
OTHER_TENANT = uuid.UUID("0c000000-0000-0000-0000-0000000000cc")

SPLIT = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
BEFORE = datetime(2026, 4, 1, 0, 0, tzinfo=UTC)
AFTER = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)


def _asyncpg_dsn(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


async def _seed(conn) -> None:
    await conn.execute("DELETE FROM aisoc_kb_documents WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
    # Both of this tenant's documents have to match the query on their
    # *content*, because that is the column the index and the predicate read.
    # A fixture whose first document matched on its title only would drop out
    # of every result set here and the cutoff would look like it had filtered.
    rows = [
        (TENANT, "Password spray runbook", "On a password spray, check whether the source address is in the VPN pool.", BEFORE),
        (TENANT, "Post-incident writeup", "The password spray in April came from the VPN pool.", AFTER),
        # A third tenant's document, matching the same query. The cutoff is
        # not the only predicate that has to hold, and a retrieval that leaked
        # across tenants would be a worse defect than one that leaked across
        # time.
        (OTHER_TENANT, "Another tenant password spray runbook", "Their own password spray procedure.", BEFORE),
    ]
    for tenant, title, content, created in rows:
        await conn.execute(
            """
            INSERT INTO aisoc_kb_documents
                (id, tenant_id, title, doc_kind, source_url, content, tags,
                 chunk_index, chunk_total, created_at, updated_at, created_by)
            VALUES ($1, $2, $3, 'runbook', NULL, $4, ARRAY[]::text[], 0, 1, $5, $5, 'test')
            """,
            uuid.uuid4(),
            tenant,
            title,
            content,
            created,
        )


async def _retrieve(conn, *, as_of: datetime | None, tenant: uuid.UUID = TENANT) -> list:
    """Run the route's own statement, built the way the route builds it."""
    from app.api.v1.endpoints.knowledge_base import _TRIAGE_DOC_KINDS, triage_retrieval_sql

    # The route's own builder, not this file's idea of what it builds. The
    # first version of this test formatted the template itself and therefore
    # kept passing after the cutoff predicate was deleted from the route,
    # which is the whole reason `triage_retrieval_sql` is a function.
    sql = triage_retrieval_sql(cutoff=as_of is not None)
    args: list = [tenant, list(_TRIAGE_DOC_KINDS), "password spray", 5]
    if as_of is not None:
        args.append(as_of)

    # asyncpg is positional; the route's SQLAlchemy `text()` is named. The
    # substitution is mechanical and the predicate structure, which is what
    # this file is about, is untouched.
    for name, position in ((":tenant_id", "$1"), (":kinds", "$2"), (":q", "$3"), (":limit", "$4"), (":as_of", "$5")):
        if name in sql:
            sql = sql.replace(name, position)
        elif name != ":as_of":
            # A parameter that vanished from the statement is a change this
            # file has to notice rather than silently stop binding.
            raise AssertionError(f"{name} is no longer a parameter of the retrieval statement")
    return await conn.fetch(sql, *args)


@pytest.mark.asyncio
async def test_the_cutoff_filters_and_reports_what_it_refused() -> None:
    import asyncpg

    conn = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        await _seed(conn)

        # 1. No cutoff: both of this tenant's documents, and neither of the
        #    other tenant's. Run first, so an empty table cannot make the
        #    scoped read below pass for the wrong reason.
        live = await _retrieve(conn, as_of=None)
        titles = sorted(r["title"] for r in live if r["id"] is not None)
        assert titles == ["Password spray runbook", "Post-incident writeup"], titles
        assert live[0]["excluded_after_cutoff"] == 0

        # 2. With the cutoff: only the document that existed at the split.
        frozen = await _retrieve(conn, as_of=SPLIT)
        frozen_titles = [r["title"] for r in frozen if r["id"] is not None]
        assert frozen_titles == ["Password spray runbook"], frozen_titles

        # 3. And the count says the freeze did something, rather than a reader
        #    inferring it from a shorter list.
        assert frozen[0]["excluded_after_cutoff"] == 1
        assert frozen[0]["without_timestamp"] == 0

        # A cutoff before everything returns no rows at all, and the counts
        # still arrive. This is the case the LATERAL exists for: without it
        # the whole result set is empty and the refusal count is lost exactly
        # when it matters most.
        empty = await _retrieve(conn, as_of=datetime(2020, 1, 1, tzinfo=UTC))
        assert [r for r in empty if r["id"] is not None] == []
        assert len(empty) == 1
        assert empty[0]["excluded_after_cutoff"] == 2
    finally:
        await conn.execute("DELETE FROM aisoc_kb_documents WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
        await conn.close()


@pytest.mark.asyncio
async def test_retrieval_never_reaches_another_tenants_runbooks() -> None:
    """The query-layer predicate, proven the same way every other store's is."""
    import asyncpg

    conn = await asyncpg.connect(_asyncpg_dsn(DSN))
    try:
        await _seed(conn)

        mine = await _retrieve(conn, as_of=None, tenant=TENANT)
        theirs = await _retrieve(conn, as_of=None, tenant=OTHER_TENANT)

        # Both tenants hold a document matching this query, so neither read is
        # empty and "returned nothing" cannot be mistaken for "isolated".
        assert [r["title"] for r in theirs if r["id"] is not None] == ["Another tenant password spray runbook"]
        assert all("Another tenant" not in r["title"] for r in mine if r["id"] is not None)
    finally:
        await conn.execute("DELETE FROM aisoc_kb_documents WHERE tenant_id = $1 OR tenant_id = $2", TENANT, OTHER_TENANT)
        await conn.close()
