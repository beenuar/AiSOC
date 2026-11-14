"""A write the console makes, read back by the reader triage actually calls.

``test_triage_questions.py`` grades the compiler and the answerer as pure
functions over 21 cases and passes. What it cannot see is whether anything
ever *writes* a row: ``triage_questions`` had a reader on the hot path of
every alert and **no writer anywhere**, so ``for_tenant()`` returned empty for
every tenant forever and the prompt block was always absent. A unit test of
either half passes whether or not the other one exists, which is why this
suite runs both halves against one database.

The write goes in as the API route writes it — same statement, same casts,
same closed-schema columns — and the read comes out through
``TriageQuestionStore``, the module the triage worker calls on every alert.

    AISOC_TEST_POSTGRES=postgresql://aisoc:...@127.0.0.1:5432/aisoc \\
        pytest tests/integration/test_triage_questions_round_trip.py
"""

from __future__ import annotations

import json
import os
import uuid

import pytest
import pytest_asyncio
from app.context.triage_questions_store import TriageQuestionStore

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip().replace("postgresql+asyncpg://", "postgresql://")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES=postgresql://... (migrations applied) to run the round trip"),
    pytest.mark.asyncio,
]

#: Verbatim from `services/api/app/api/v1/endpoints/triage_questions.py`.
#: Copied rather than imported because the two services do not share a Python
#: path and both name their package `app`; the statement is pinned by
#: `test_triage_question_write_surface.py` on the API side.
_INSERT = """
    INSERT INTO triage_questions (tenant_id, alert_type, label, field, op, value, enabled, created_by)
    VALUES (
        CAST($1 AS uuid), $2, $3, $4, $5,
        CAST($6 AS jsonb), $7, NULL
    )
"""


async def _connect(tenant_id: str):  # noqa: ANN202
    import asyncpg

    conn = await asyncpg.connect(DSN, timeout=5.0)
    # `app.current_tenant_id` is what `current_tenant_id()` reads, so RLS
    # genuinely applies to these statements as the DML-only runtime role.
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", tenant_id)
    return conn


@pytest_asyncio.fixture
async def tenant_id():  # noqa: ANN201
    tid = uuid.uuid4()
    conn = await _connect(str(tid))
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
            tid,
            f"tq-{tid.hex[:8]}",
            f"tq-{tid.hex[:8]}",
        )
    finally:
        await conn.close()
    yield str(tid)
    conn = await _connect(str(tid))
    try:
        await conn.execute("DELETE FROM tenants WHERE id = $1", tid)
    finally:
        await conn.close()


async def test_a_written_question_is_what_the_triage_reader_loads(tenant_id: str) -> None:
    conn = await _connect(tenant_id)
    try:
        await conn.execute(
            _INSERT,
            tenant_id,
            "*",
            "Is this IP a known office address?",
            "network.ip.is_office",
            "eq",
            json.dumps(True),
            True,
        )
    finally:
        await conn.close()

    store = TriageQuestionStore()
    store.clear_cache()
    os.environ["DATABASE_DSN"] = DSN
    questions = await store.for_tenant(tenant_id)

    assert len(questions) == 1, "the reader on the triage hot path loaded nothing that was written"
    assert questions[0].label == "Is this IP a known office address?"
    assert questions[0].field == "network.ip.is_office"
    assert questions[0].op == "eq"


async def test_a_disabled_question_is_not_loaded(tenant_id: str) -> None:
    """The column the reader filters on has to mean something on the write side."""
    conn = await _connect(tenant_id)
    try:
        await conn.execute(_INSERT, tenant_id, "*", "Disabled question", "identity.travel.in_progress", "eq", json.dumps(True), False)
    finally:
        await conn.close()

    store = TriageQuestionStore()
    store.clear_cache()
    os.environ["DATABASE_DSN"] = DSN

    assert await store.for_tenant(tenant_id) == []


async def test_another_tenants_question_is_not_loaded(tenant_id: str) -> None:
    """RLS plus the query predicate, measured rather than assumed."""
    other = uuid.uuid4()
    conn = await _connect(str(other))
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
            other,
            f"tq-{other.hex[:8]}",
            f"tq-{other.hex[:8]}",
        )
        await conn.execute(_INSERT, str(other), "*", "Another tenant's question", "network.ip.is_office", "eq", json.dumps(True), True)
    finally:
        await conn.close()

    store = TriageQuestionStore()
    store.clear_cache()
    os.environ["DATABASE_DSN"] = DSN
    try:
        assert await store.for_tenant(tenant_id) == []
    finally:
        conn = await _connect(str(other))
        try:
            await conn.execute("DELETE FROM tenants WHERE id = $1", other)
        finally:
            await conn.close()


async def test_a_comparator_the_product_does_not_implement_cannot_be_stored(tenant_id: str) -> None:
    """`neq` is the recorded instance: it parses, saves, and never matches.

    The migration's CHECK is what makes that a write error naming the column
    rather than a question answering "no" to everything forever, and this
    asserts the constraint is really there on a live schema rather than in the
    migration file.
    """
    import asyncpg

    conn = await _connect(tenant_id)
    try:
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(_INSERT, tenant_id, "*", "Bad comparator", "network.ip.is_office", "neq", json.dumps(True), True)
    finally:
        await conn.close()
