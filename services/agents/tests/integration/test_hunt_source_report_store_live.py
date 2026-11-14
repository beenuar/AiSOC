"""`hunt_source_reports` has a writer, and its approval gate is enforced.

Migration 155 stated the property: *"Nothing is hunted from a report until
this is set, so NULL must never be rendered as approved."* The producing route
computed exactly the table's columns and returned them in the HTTP response
without persisting anything, so ``approved_at`` and ``approved_by`` had no
writer and there was no approve endpoint. The sentence described an intention.

These run against the real table, because the claim is about rows.

    AISOC_TEST_POSTGRES=postgresql://aisoc:...@127.0.0.1:5432/aisoc \\
        pytest tests/integration/test_hunt_source_report_store_live.py
"""

from __future__ import annotations

import os
import uuid

import pytest
from app.hunt import source_report_store

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip().replace("postgresql+asyncpg://", "postgresql://")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES=postgresql://... (migrations applied) to run the provenance proof"),
    pytest.mark.asyncio,
]

_DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def _dsn_in_env():  # noqa: ANN202
    previous = os.environ.get("DATABASE_DSN")
    os.environ["DATABASE_DSN"] = DSN
    yield
    if previous is None:
        os.environ.pop("DATABASE_DSN", None)
    else:
        os.environ["DATABASE_DSN"] = previous


async def _tenant() -> str:
    import asyncpg

    tid = uuid.uuid4()
    conn = await asyncpg.connect(DSN, timeout=5.0)
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
            tid,
            f"hsr-{tid.hex[:8]}",
            f"hsr-{tid.hex[:8]}",
        )
    finally:
        await conn.close()
    return str(tid)


async def _drop(tenant_id: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(DSN, timeout=5.0)
    try:
        await conn.execute("DELETE FROM tenants WHERE id = $1", uuid.UUID(tenant_id))
    finally:
        await conn.close()


async def test_a_draft_is_recorded_and_starts_unapproved() -> None:
    tenant_id = await _tenant()
    try:
        report_id = await source_report_store.record_report(
            tenant_id=tenant_id,
            url="https://vendor.example/report",
            fetched_by=None,
            byte_size=2048,
            content_sha256=_DIGEST,
            truncated=False,
            indicator_count=4,
            technique_count=2,
        )
        assert report_id is not None, "the draft route's provenance write stored nothing"

        stored = await source_report_store.get_report(tenant_id=tenant_id, report_id=report_id)
        assert stored is not None
        assert stored["approved_at"] is None
        # The property the migration names, asserted rather than described.
        assert await source_report_store.is_approved(tenant_id=tenant_id, report_id=report_id) is False
    finally:
        await _drop(tenant_id)


async def test_approval_is_recorded_once_and_is_idempotent() -> None:
    tenant_id = await _tenant()
    try:
        report_id = await source_report_store.record_report(
            tenant_id=tenant_id,
            url="https://vendor.example/report",
            fetched_by=None,
            byte_size=1,
            content_sha256=_DIGEST,
            truncated=True,
            indicator_count=1,
            technique_count=0,
        )
        assert report_id is not None

        assert await source_report_store.approve_report(tenant_id=tenant_id, report_id=report_id, approved_by=None) is True
        first = await source_report_store.get_report(tenant_id=tenant_id, report_id=report_id)
        assert first is not None and first["approved_at"] is not None

        # A second approval must not move the timestamp: the review that
        # counts is the one that happened.
        assert await source_report_store.approve_report(tenant_id=tenant_id, report_id=report_id, approved_by=None) is False
        second = await source_report_store.get_report(tenant_id=tenant_id, report_id=report_id)
        assert second is not None and second["approved_at"] == first["approved_at"]
        assert await source_report_store.is_approved(tenant_id=tenant_id, report_id=report_id) is True
    finally:
        await _drop(tenant_id)


async def test_another_tenants_report_is_neither_readable_nor_approvable() -> None:
    owner = await _tenant()
    stranger = await _tenant()
    try:
        report_id = await source_report_store.record_report(
            tenant_id=owner,
            url="https://vendor.example/private",
            fetched_by=None,
            byte_size=10,
            content_sha256=_DIGEST,
            truncated=False,
            indicator_count=1,
            technique_count=1,
        )
        assert report_id is not None

        assert await source_report_store.get_report(tenant_id=stranger, report_id=report_id) is None
        assert await source_report_store.approve_report(tenant_id=stranger, report_id=report_id, approved_by=None) is False
        # And the owner's record is untouched by the attempt.
        assert await source_report_store.is_approved(tenant_id=owner, report_id=report_id) is False
    finally:
        await _drop(owner)
        await _drop(stranger)


async def test_an_unknown_report_is_not_approved_rather_than_unknown() -> None:
    """Fail-closed. An absent row is not an approval and must not read as one."""
    tenant_id = await _tenant()
    try:
        assert await source_report_store.is_approved(tenant_id=tenant_id, report_id=str(uuid.uuid4())) is False
    finally:
        await _drop(tenant_id)
