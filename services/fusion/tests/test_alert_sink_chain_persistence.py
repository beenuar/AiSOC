"""The incident and the attack story survive the write.

Fusion already does the hard part twice over. ``Correlator.correlate``
groups alerts into an incident, and ``AttackChainGrouper`` orders them into
a kill-chain story with a position and a stage. Both results reached the
alert row's *narrative text* and the Kafka envelope, and neither reached a
column — the incident lives in Redis under a one-hour TTL and the story in
``FusedAlert.enrichments``, so an hour later nothing in Postgres could say
which alerts belonged to the same incident.

That is the whole reason a case timeline had to re-derive relationships
from scratch with a graph walk over ``affected_*``. These columns make the
grouping fusion already computed durable, and the values are honest about
absence: an alert fusion did not place in a story has no chain, and writes
NULL rather than a position of zero in a chain of one.
"""

from __future__ import annotations

import uuid

import pytest
from app.models.alert import FusionDecision
from app.services.alert_sink import AlertSink, PersistOutcome

from tests.test_alert_sink_issue_1244 import (
    _column_value,
    _fused,
    _insert_statement,
    _StubPool,
)

INCIDENT = uuid.UUID("00000000-0000-0000-0000-00000000beef")


def _chain_enrichment(**overrides):
    base = {
        "chain_id": "chain-7f3a",
        "is_new_chain": False,
        "position": 3,
        "stage": "lateral-movement",
        "entity": "host:WIN-DC01",
        "prior_alert_ids": ["a1", "a2"],
        "member_count": 3,
        "joined_by_kind": "session_id",
        "joined_by_strength": "strong",
        "story_severity": "critical",
        "escalation_reason": "three distinct kill-chain stages",
        "stage_span": 3,
        "actor_mode": "interactive",
    }
    base.update(overrides)
    return base


async def _persist(fused):
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.INSERTED
    return _insert_statement(pool)


@pytest.mark.asyncio
async def test_the_incident_id_reaches_a_column() -> None:
    fused = _fused(FusionDecision.CORRELATED)
    fused.incident_id = INCIDENT

    sql, args = await _persist(fused)
    assert str(_column_value(sql, args, "incident_id")) == str(INCIDENT)


@pytest.mark.asyncio
async def test_the_attack_story_reaches_its_columns() -> None:
    fused = _fused(FusionDecision.CORRELATED)
    fused.incident_id = INCIDENT
    fused.enrichments["attack_chain"] = _chain_enrichment()

    sql, args = await _persist(fused)
    assert _column_value(sql, args, "chain_id") == "chain-7f3a"
    assert _column_value(sql, args, "chain_position") == 3
    assert _column_value(sql, args, "chain_stage") == "lateral-movement"


@pytest.mark.asyncio
async def test_an_alert_in_no_story_writes_null_not_a_fabricated_position() -> None:
    """Absence is NULL. A position of 0 or 1 would read as a real placement."""
    fused = _fused(FusionDecision.NEW_ALERT)

    sql, args = await _persist(fused)
    assert _column_value(sql, args, "incident_id") is None
    assert _column_value(sql, args, "chain_id") is None
    assert _column_value(sql, args, "chain_position") is None
    assert _column_value(sql, args, "chain_stage") is None


@pytest.mark.asyncio
async def test_a_malformed_enrichment_is_skipped_rather_than_crashing_the_write() -> None:
    """The enrichment is produced by another service; losing the alert
    because its story metadata was the wrong shape is never the trade."""
    fused = _fused(FusionDecision.CORRELATED)
    fused.enrichments["attack_chain"] = "not-a-mapping"

    sql, args = await _persist(fused)
    assert _column_value(sql, args, "chain_id") is None
    assert _column_value(sql, args, "chain_position") is None


@pytest.mark.asyncio
async def test_a_non_integer_position_does_not_reach_the_integer_column() -> None:
    fused = _fused(FusionDecision.CORRELATED)
    fused.enrichments["attack_chain"] = _chain_enrichment(position="third")

    sql, args = await _persist(fused)
    assert _column_value(sql, args, "chain_id") == "chain-7f3a"
    assert _column_value(sql, args, "chain_position") is None


@pytest.mark.asyncio
async def test_long_story_values_are_bounded_like_every_other_text_column() -> None:
    fused = _fused(FusionDecision.CORRELATED)
    fused.enrichments["attack_chain"] = _chain_enrichment(chain_id="c" * 500, stage="s" * 500)

    sql, args = await _persist(fused)
    assert len(_column_value(sql, args, "chain_id")) <= 128
    assert len(_column_value(sql, args, "chain_stage")) <= 64
