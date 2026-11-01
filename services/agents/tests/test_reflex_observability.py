"""The reflex path reports where its time went and what shape its decision takes.

Driven through the production worker (`FusedAlertTriageWorker.triage`) over
the shadow sinks — the same construction the replay runner uses — so the
fields asserted here are the fields a replay decision and a live summary
actually carry, not the fields a helper would carry if something called it.

What each test blocks:

* a summary with no stage timings — "triage is slow" stays unsplittable into
  queue, context fetch, model, verification and persistence;
* a queue delay invented for an envelope that carries no `fused_at` — a
  replayed historical finding has none, and a plausible-looking number on a
  measurement nobody took is the repository's named failure shape;
* a decision contract whose "signal never ran" and "signal ran and found
  nothing" collapse into each other — the deterministic tier makes no prose
  claims, so its supporting-evidence field must be None, never [].
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.state import InvestigationState
from app.replay.shadow import ContextSnapshot, FrozenTriageContextReader, ShadowTriageWriter
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from app.workers.reflex_observability import StageTimer, decision_contract, queue_delay_ms

TENANT = "00000000-0000-0000-0000-0000000000de"


def _worker() -> FusedAlertTriageWorker:
    return FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=FrozenTriageContextReader(ContextSnapshot(split_at=datetime(2026, 1, 1, tzinfo=UTC))),
    )


def _message(*, fused_at: str | None = None) -> dict:
    alert = {
        "id": str(uuid.uuid4()),
        "title": "Impossible travel for alice",
        "rule_id": "idp-impossible-travel",
        "severity": "medium",
        "username": "alice",
        "raw_event": {"source_geo": "SE", "second_geo": "BR", "gap_minutes": 11},
    }
    message = {"tenant_id": TENANT, "id": str(uuid.uuid4()), "alert": alert}
    if fused_at is not None:
        message["fused_at"] = fused_at
    return message


async def test_summary_carries_stage_timings_and_the_decision_contract() -> None:
    summary = await _worker().triage(_message())

    assert summary is not None
    timings = summary["stage_timings_ms"]
    assert timings["total"] >= 0.0
    assert "decide" in timings, "the verdict stage must be measured; it is where the model time goes"
    assert "persist" in timings
    assert "verification" in timings

    contract = summary["decision_contract"]
    assert contract["verdict"] == summary["verdict"]
    assert contract["operational_disposition"] in {
        "auto_closed",
        "escalated_to_investigation",
        "queued_for_review",
        "suppressed_repeat",
    }
    # The deterministic tier runs no claim-support review: None, never [],
    # because an empty list says the review ran and found nothing.
    assert contract["supporting_evidence"] is None
    assert contract["contradictory_evidence"] is None
    assert any("deterministic" in item for item in contract["missing_prerequisites"])
    if contract["operational_disposition"] != "auto_closed":
        assert contract["escalation_reason"], "an alert that did not close says why it escalated"


async def test_queue_delay_is_measured_from_fused_at_and_never_invented() -> None:
    fused = (datetime.now(UTC) - timedelta(seconds=2)).isoformat()
    with_delay = await _worker().triage(_message(fused_at=fused))
    assert with_delay is not None
    assert with_delay["queue_delay_ms"] is not None
    assert with_delay["queue_delay_ms"] >= 1500.0

    without = await _worker().triage(_message())
    assert without is not None
    assert without["queue_delay_ms"] is None, "no fused_at on the envelope means no delay was measured, not a delay of zero"


def test_queue_delay_parses_the_shapes_the_envelope_actually_carries() -> None:
    now = datetime.now(UTC)
    assert queue_delay_ms({"fused_at": now.isoformat()}) is not None
    assert queue_delay_ms({"fused_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}) is not None
    assert queue_delay_ms({"fused_at": "not a timestamp"}) is None
    assert queue_delay_ms({}) is None
    assert queue_delay_ms(None) is None


def test_stage_timer_accumulates_repeated_stages() -> None:
    timer = StageTimer()
    with timer.measure("decide"):
        pass
    with timer.measure("decide"):
        pass
    millis = timer.as_millis()
    assert "decide" in millis
    assert millis["total"] >= millis["decide"]


def test_contract_reports_claim_review_structure_when_it_ran() -> None:
    """The LLM path's claim review reaches the contract as lists, and the
    escalation reason names the block that caused it."""
    state = InvestigationState(
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="s",
        raw_alert={"id": "a-1"},
    )
    state.claim_review = {
        "scored": True,
        "score": 0.5,
        "supported": ["the rule counts distinct ports"],
        "unsupported": ["this is our approved scanner"],
        "contradicted": [],
        "contradicted_by": [],
        "reason": "1 decisive claim lacks support",
    }
    state.add_finding("Auto-close blocked: 1 decisive claim lacks support. Routed to manual review.")

    contract = decision_contract(
        state,
        verdict="false_positive",
        confidence=0.97,
        tier="llm",
        auto_closed=False,
        escalated=True,
    )

    assert contract["supporting_evidence"] == ["the rule counts distinct ports"]
    assert contract["contradictory_evidence"] == []
    assert contract["operational_disposition"] == "escalated_to_investigation"
    assert contract["escalation_reason"].startswith("Auto-close blocked")
    assert contract["blocked_or_demoted_by"]
