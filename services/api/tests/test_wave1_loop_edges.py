"""Wave 1 - close-the-loop edges on the API side.

Covers the hunt-finding -> detection-proposal bridge (W1.5) and the
disposition-history -> tuning-record mapping that gives the previously-orphaned
``suggest_tuning`` a real caller (W1.4). Both use lightweight mocks (no DB) so
they run fast and deterministically.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from app.api.v1.endpoints.rule_tuning import _disposition_records
from app.workers import hunt_scheduler


def _hunt():
    return SimpleNamespace(
        id=uuid4(),
        tenant_id=uuid4(),
        name="Iran inbound auth failures",
        nl_query="did we get auth failures from Iran?",
        language="esql",
        translated_query={"esql": "FROM logs | WHERE country == 'IR'"},
    )


# ── W1.5: hunt finding -> detection proposal ────────────────────────────────


@pytest.mark.asyncio
async def test_hunt_hits_open_a_detection_proposal(monkeypatch):
    monkeypatch.setenv("AISOC_HUNT_TO_DETECTION", "true")
    db = AsyncMock()
    await hunt_scheduler._propose_detection_from_hunt(db, _hunt(), 5)
    assert db.execute.await_count == 1
    sql = str(db.execute.await_args.args[0])
    assert "detection_rule_proposals" in sql


@pytest.mark.asyncio
async def test_no_proposal_without_hits(monkeypatch):
    monkeypatch.setenv("AISOC_HUNT_TO_DETECTION", "true")
    db = AsyncMock()
    await hunt_scheduler._propose_detection_from_hunt(db, _hunt(), 0)
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_hunt_to_detection_flag_disables_bridge(monkeypatch):
    monkeypatch.setenv("AISOC_HUNT_TO_DETECTION", "false")
    db = AsyncMock()
    await hunt_scheduler._propose_detection_from_hunt(db, _hunt(), 9)
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_default_callback_opens_case_and_proposal(monkeypatch):
    monkeypatch.setenv("AISOC_HUNT_TO_DETECTION", "true")
    db = AsyncMock()
    db.add = lambda *_a, **_k: None  # sync add
    await hunt_scheduler._on_hunt_hits(db, _hunt(), 3)
    # the proposal INSERT went through db.execute
    assert db.execute.await_count == 1


# ── W1.4: disposition history -> tuner input ────────────────────────────────


def test_disposition_records_mapping_and_skips_null_rule():
    rows = [
        SimpleNamespace(rule_id="det-1", disposition="false_positive", entity="host-a"),
        SimpleNamespace(rule_id="det-1", disposition="true_positive", entity="host-b"),
        SimpleNamespace(rule_id=None, disposition="false_positive", entity="host-c"),  # skipped
    ]
    records = _disposition_records(rows)
    assert len(records) == 2  # the rule_id=None row is dropped
    assert {r.rule_id for r in records} == {"det-1"}
    assert all(r.human_verified is False for r in records)
