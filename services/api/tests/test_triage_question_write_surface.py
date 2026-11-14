"""The write surface for ``triage_questions``, against the real table.

``triage_questions`` had a reader on the triage hot path of every alert and
**no writer anywhere** — no route, no ORM model, no console page, no seed — so
``for_tenant()`` returned empty for every tenant forever. Its claim row was
GATED on 21 cases exercising the compiler and the answerer as pure functions,
which pass whether or not a row can ever exist.

So these drive the real route handlers against real Postgres: the real
statements with their real casts, the real validation, and the table's own
CHECK constraints. A handler test with a mocked session would pass against a
table that is not there, which is the shape that let this ship.

    AISOC_TEST_POSTGRES=postgresql+asyncpg://aisoc:...@127.0.0.1:5432/aisoc \\
        pytest tests/test_triage_question_write_surface.py
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from app.api.v1.endpoints import triage_questions as endpoint
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip()
pytestmark = [
    pytest.mark.skipif(
        not DSN,
        reason="set AISOC_TEST_POSTGRES=postgresql+asyncpg://... (migrations applied) to run the write-surface proof",
    ),
    pytest.mark.asyncio,
]


def _user(tenant_id: uuid.UUID) -> SimpleNamespace:
    async def _allow(_perm: str, _db: Any) -> None:
        return None

    return SimpleNamespace(tenant_id=tenant_id, user_id=uuid.uuid4(), role="admin", require_permission_db=_allow)


@pytest_asyncio.fixture
async def session():  # noqa: ANN201
    engine = create_async_engine(DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    async with maker() as db:
        await db.execute(text("SELECT set_config('aisoc.tenant_id', :t, false)"), {"t": str(tenant_id)})
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), :n, :s) ON CONFLICT (id) DO NOTHING"),
            {"t": str(tenant_id), "n": f"tqw-{tenant_id.hex[:8]}", "s": f"tqw-{tenant_id.hex[:8]}"},
        )
        await db.commit()
        yield db, tenant_id
        await db.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(tenant_id)})
        await db.commit()
    await engine.dispose()


async def test_a_question_is_written_and_read_back(session) -> None:  # noqa: ANN001
    db, tenant_id = session
    user = _user(tenant_id)

    created = await endpoint.upsert_triage_question(
        endpoint.QuestionIn(
            alert_type="aws.cloudtrail",
            label="Is this IP a known office address?",
            field="network.ip.is_office",
            op="eq",
            value=True,
        ),
        user,
        db,
    )

    assert created.id
    assert created.field_path == "network.ip.is_office"

    listed = await endpoint.list_triage_questions(user, db)
    assert [q.label for q in listed] == ["Is this IP a known office address?"]


async def test_re_posting_a_lookup_edits_it_rather_than_duplicating(session) -> None:  # noqa: ANN001
    """Two identical lookups under different labels read as corroboration."""
    db, tenant_id = session
    user = _user(tenant_id)
    payload = endpoint.QuestionIn(label="First wording", field="network.ip.is_office", op="eq", value=True)
    first = await endpoint.upsert_triage_question(payload, user, db)

    second = await endpoint.upsert_triage_question(
        endpoint.QuestionIn(label="Second wording", field="network.ip.is_office", op="eq", value=True), user, db
    )

    assert second.id == first.id
    listed = await endpoint.list_triage_questions(user, db)
    assert [q.label for q in listed] == ["Second wording"]


async def test_a_unary_comparator_stores_no_value(session) -> None:  # noqa: ANN001
    """The table's CHECK requires NULL here; the route must not fight it."""
    db, tenant_id = session
    created = await endpoint.upsert_triage_question(
        endpoint.QuestionIn(label="Did the session carry MFA?", field="identity.mfa", op="exists", value="ignored"),
        _user(tenant_id),
        db,
    )
    assert created.value is None


async def test_a_comparator_the_product_does_not_implement_is_refused() -> None:
    """`neq` parses, saves and silently never matches. It is a 422 here."""
    with pytest.raises(ValueError, match="op must be one of"):
        endpoint.QuestionIn(label="Bad", field="network.ip.is_office", op="neq", value=True)


async def test_a_field_that_is_not_a_path_is_refused() -> None:
    with pytest.raises(ValueError, match="is not an evidence field path"):
        endpoint.QuestionIn(label="Bad", field="network ip; DROP TABLE alerts", op="eq", value=True)


async def test_deleting_another_tenants_question_is_a_404(session) -> None:  # noqa: ANN001
    """404 and not 403: a 403 makes the route an existence oracle."""
    db, tenant_id = session
    with pytest.raises(HTTPException) as caught:
        await endpoint.delete_triage_question(str(uuid.uuid4()), _user(tenant_id), db)
    assert caught.value.status_code == 404


async def test_deleting_removes_it_from_what_the_reader_would_load(session) -> None:  # noqa: ANN001
    db, tenant_id = session
    user = _user(tenant_id)
    created = await endpoint.upsert_triage_question(
        endpoint.QuestionIn(label="Temporary", field="network.ip.is_office", op="eq", value=True), user, db
    )

    await endpoint.delete_triage_question(created.id, user, db)

    assert await endpoint.list_triage_questions(user, db) == []
