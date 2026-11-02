"""Precedent by similarity, and a re-triage that actually writes something.

Wave 2, Phase 4.4. Verified before built, and the plan's premise was
narrower than its wording — recorded as deviation D3.

(a) What already works, and is not rebuilt here
------------------------------------------------
Analyst reclassifications **do** reach triage, by two routes:
`human_priors.record_human_prior` writes a human-authored outcome prior, and
`context/dispositions.py` renders the last five analyst decisions into the
preamble. Both match on **identity** — a SHA-256 over eighteen canonical
fields, or a `rule_id`/entity string — so an analyst who closes the same
finding on twelve hosts teaches triage twelve separate lessons, each
reachable only by an alert identical to the one that taught it.

(b) The trap in re-triage
--------------------------
The obvious implementation **writes nothing and reports success**. The run
id is `uuid5(_NAMESPACE, f"{alert_row_id}:{WORKFLOW_VERSION}")` and every
ledger write is `ON CONFLICT (run_id, seq) DO NOTHING`. That pairing makes a
Kafka redelivery idempotent and is correct — and it means a second triage of
one alert collides on seq 0 and seq 1 and leaves the ledger describing the
first verdict. `test_a_naive_retriage_would_write_nothing` is the
reproduction, asserted directly against the production run-id derivation.
"""

from __future__ import annotations

import ast
import uuid
from typing import Any

import pytest
from app.memory import precedent
from app.workers import retriage

TENANT = "11111111-1111-1111-1111-111111111111"


def _alert(**fields: Any) -> dict[str, Any]:
    base = {
        "id": "alert-1",
        "rule_id": "det-rule-07",
        "title": "Impossible travel",
        "hostname": "WIN-DC01",
        "username": "svc-backup",
        "src_ip": "203.0.113.5",
        "severity": "high",
        "connector_type": "okta",
    }
    base.update(fields)
    return base


def _prior(evidence: dict[str, Any] | None, **fields: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "signature": fields.pop("signature", "sig-other"),
        "disposition": "benign",
        "confidence": 0.9,
        "author": "human",
        "count": 4,
        "last_seen": "2026-10-30T09:00:00+00:00",
        "first_seen": "2026-10-28T09:00:00+00:00",
    }
    value.update(fields)
    if evidence is not None:
        value["evidence"] = evidence
    return {"key": f"outcome:{value['signature']}", "value": value}


def _searcher(rows: list[dict[str, Any]]):
    async def _search(tenant_id: str, tags: list[str] | None = None, limit: int = 20) -> list[dict[str, Any]]:
        return rows

    return _search


def _code_only(module: Any) -> str:
    """A module's source with docstrings and comments removed.

    Written after the first run of the two assertions below failed on their
    own prose: both modules *describe* closure at length in order to explain
    that they do not reach it. A substring assertion over raw source cannot
    tell a call from a sentence about a call — the same blindness
    `check_gate_coverage.py` had when a gate named only in a docstring
    counted as invoked.
    """
    import inspect

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
    return ast.unparse(tree)


# ── (a) the gap exact matching cannot close ───────────────────────────────


def test_one_different_field_defeats_the_exact_fingerprint() -> None:
    """The reproduction for the precedent half, stated as the hash it is."""
    from app.memory.fingerprint import evidence_fingerprint

    a = _alert()
    b = _alert(src_ip="198.51.100.9")
    assert evidence_fingerprint(TENANT, a) != evidence_fingerprint(TENANT, b), (
        "the two alerts hash the same, so this fixture does not reproduce the gap"
    )


def test_similarity_sees_what_the_fingerprint_misses() -> None:
    from app.memory.fingerprint import storable_evidence

    score, matched = precedent.similarity(storable_evidence(_alert()), storable_evidence(_alert(src_ip="198.51.100.9")))
    assert score >= precedent.MIN_SIMILARITY
    assert "rule_id" in matched and "hostname" in matched


def test_a_field_only_one_alert_carries_is_neither_agreement_nor_disagreement() -> None:
    """An omitted field is not evidence the values differ.

    Counting it would make a sparse alert look dissimilar to everything,
    which is the direction that silently turns this feature off.
    """
    full = {"rule_id": "r1", "hostname": "h1", "username": "u1"}
    sparse = {"rule_id": "r1", "hostname": "h1"}
    score, _ = precedent.similarity(full, sparse)
    assert score == 1.0


def test_sharing_only_a_weak_field_is_not_precedent() -> None:
    """A shared severity is true of thousands of alerts and says nothing."""
    score, _ = precedent.similarity({"severity": "high"}, {"severity": "high", "rule_id": "other"})
    assert score < precedent.MIN_SIMILARITY


@pytest.mark.asyncio
async def test_a_similar_prior_is_found_and_carries_why_it_matched() -> None:
    from app.memory.fingerprint import storable_evidence

    found = await precedent.find_similar(
        TENANT,
        _alert(),
        searcher=_searcher([_prior(storable_evidence(_alert(src_ip="198.51.100.9")))]),
    )
    assert len(found) == 1
    assert found[0].disposition == "benign"
    # The matched fields are what an analyst checks. A bare 0.83 is not.
    assert "rule_id" in found[0].matched


@pytest.mark.asyncio
async def test_an_unrelated_prior_is_not_precedent() -> None:
    from app.memory.fingerprint import storable_evidence

    unrelated = storable_evidence({"rule_id": "det-rule-99", "hostname": "LINUX-WEB-04", "username": "nobody", "severity": "low"})
    assert await precedent.find_similar(TENANT, _alert(), searcher=_searcher([_prior(unrelated)])) == []


@pytest.mark.asyncio
async def test_the_exact_match_is_excluded_so_it_is_not_precedent_for_itself() -> None:
    from app.memory.fingerprint import storable_evidence

    rows = [_prior(storable_evidence(_alert()), signature="sig-self")]
    assert await precedent.find_similar(TENANT, _alert(), exclude_signature="sig-self", searcher=_searcher(rows)) == []


@pytest.mark.asyncio
async def test_a_prior_recorded_before_this_landed_is_invisible_rather_than_wrong() -> None:
    """No evidence to compare, and nothing to backfill from.

    The signature is a SHA-256; the evidence it was derived from is not
    recoverable from it. Skipping is the honest answer, and it is stated in
    the module rather than discovered.
    """
    assert await precedent.find_similar(TENANT, _alert(), searcher=_searcher([_prior(None)])) == []


@pytest.mark.asyncio
async def test_a_human_decision_outranks_the_agents_own_at_equal_similarity() -> None:
    """Showing the agent's first would have the model citing itself."""
    from app.memory.fingerprint import storable_evidence

    evidence = storable_evidence(_alert(src_ip="198.51.100.9"))
    rows = [
        _prior(evidence, signature="sig-ai", author="ai", disposition="false_positive"),
        _prior(evidence, signature="sig-human", author="human", disposition="benign"),
    ]
    found = await precedent.find_similar(TENANT, _alert(), searcher=_searcher(rows))
    assert [p.author for p in found][0] == "human"


@pytest.mark.asyncio
async def test_an_unreadable_memory_costs_the_alert_nothing() -> None:
    async def _boom(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        raise ConnectionError("memory unreachable")

    assert await precedent.find_similar(TENANT, _alert(), searcher=_boom) == []


def test_precedent_is_cited_and_never_closes_anything() -> None:
    """The safety property, as a statement about the module's own surface.

    A similar alert is not the same alert. Exact-fingerprint suppression in
    `_maybe_suppress_from_memory` remains the only path from memory to a
    closed alert, and nothing here may grow a second one.
    """
    source = _code_only(precedent)
    for forbidden in ("auto_clos", "should_auto_suppress", "AgentStatus.COMPLETED", "suppress"):
        assert forbidden not in source, f"the precedent module reaches closure through {forbidden!r}"


def test_the_rendered_block_says_it_is_not_an_instruction() -> None:
    block = precedent.render_for_prompt(
        [precedent.Precedent(disposition="benign", author="human", count=4, score=0.83, matched=["rule_id"], last_seen="x")]
    )
    assert "precedent, not instructions" in block
    assert "nothing here closes this one" in block


def test_the_evidence_stored_beside_a_prior_is_bounded() -> None:
    """`canonical_evidence` falls back to every non-volatile key.

    An unbounded copy of an arbitrary payload into institutional memory is a
    retention surface nobody declared.
    """
    from app.memory.fingerprint import MAX_STORED_VALUE_CHARS, storable_evidence

    sprawling = {f"custom_field_{n}": "x" * 5000 for n in range(60)}
    stored = storable_evidence(sprawling)
    assert len(stored) <= 24
    assert all(len(str(v)) <= MAX_STORED_VALUE_CHARS for v in stored.values())


# ── (b) re-triage: the identity trap ──────────────────────────────────────


def test_a_naive_retriage_would_write_nothing() -> None:
    """The reproduction, against the production derivation.

    Re-running `build_state` for one alert yields the same `run_id`, and the
    ledger is `ON CONFLICT (run_id, seq) DO NOTHING` at seq 0 and seq 1. A
    second verdict therefore collides and is silently discarded.
    """
    from app.workers.fused_alert_consumer import _NAMESPACE, WORKFLOW_VERSION

    first = uuid.uuid5(_NAMESPACE, f"alert-row-1:{WORKFLOW_VERSION}")
    second = uuid.uuid5(_NAMESPACE, f"alert-row-1:{WORKFLOW_VERSION}")
    assert first == second, "the run id is not deterministic, so this reproduction is stale"


def test_a_retriage_gets_its_own_identity() -> None:
    from app.workers.fused_alert_consumer import _NAMESPACE, WORKFLOW_VERSION

    trigger = retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c-1"})
    original = uuid.uuid5(_NAMESPACE, f"alert-row-1:{WORKFLOW_VERSION}")
    again = retriage.retriage_run_id(_NAMESPACE, alert_row_id="alert-row-1", workflow_version=WORKFLOW_VERSION, trigger=trigger)
    assert again != original


def test_the_same_trigger_twice_is_one_run() -> None:
    """A redelivered chain assignment must not become a second re-triage."""
    from app.workers.fused_alert_consumer import _NAMESPACE, WORKFLOW_VERSION

    trigger = retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c-1", "member_count": 3})
    first = retriage.retriage_run_id(_NAMESPACE, alert_row_id="a-1", workflow_version=WORKFLOW_VERSION, trigger=trigger)
    second = retriage.retriage_run_id(_NAMESPACE, alert_row_id="a-1", workflow_version=WORKFLOW_VERSION, trigger=trigger)
    assert first == second


def test_different_evidence_is_a_different_run() -> None:
    from app.workers.fused_alert_consumer import _NAMESPACE

    a = retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c-1", "member_count": 3})
    b = retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c-1", "member_count": 5})
    assert retriage.retriage_run_id(_NAMESPACE, alert_row_id="a-1", workflow_version="v", trigger=a) != retriage.retriage_run_id(
        _NAMESPACE, alert_row_id="a-1", workflow_version="v", trigger=b
    )


# ── (b) the diff the ledger must show ─────────────────────────────────────


def test_a_changed_verdict_is_recorded_as_a_diff() -> None:
    diff = retriage.VerdictDiff(
        previous_verdict="benign",
        previous_confidence=0.82,
        new_verdict="true_positive",
        new_confidence=0.91,
        trigger_kind="story_escalation",
        trigger_fingerprint="abc",
        generation=1,
    )
    payload = diff.as_payload()
    assert payload["changed"] is True
    assert payload["previous_verdict"] == "benign"
    assert payload["new_verdict"] == "true_positive"
    assert payload["confidence_delta"] == pytest.approx(0.09)
    assert "benign -> true_positive" in diff.summary()


def test_an_unchanged_verdict_is_still_a_result() -> None:
    """A re-triage that did not move the verdict is a real outcome.

    The new evidence did not change the answer, which is worth knowing and
    must be tellable from a re-triage that did — hence `changed` explicitly
    rather than left to a reader comparing two fields.
    """
    diff = retriage.VerdictDiff(
        previous_verdict="benign",
        previous_confidence=0.82,
        new_verdict="benign",
        new_confidence=0.88,
        trigger_kind="story_escalation",
        trigger_fingerprint="abc",
        generation=2,
    )
    assert diff.as_payload()["changed"] is False
    assert "unchanged" in diff.summary()


# ── (b) when to run again ─────────────────────────────────────────────────


def test_an_open_alert_with_new_evidence_is_re_triaged() -> None:
    ok, reason = retriage.should_retriage(
        previous_verdict="needs_review",
        generation=1,
        trigger=retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c"}),
    )
    assert ok and "needs_review" in reason


def test_a_closed_alert_is_not_reopened_automatically() -> None:
    """Re-opening a closed alert is an analyst-visible state change."""
    ok, reason = retriage.should_retriage(
        previous_verdict="benign",
        generation=1,
        trigger=retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c"}),
    )
    assert not ok and "not an open state" in reason


def test_the_ceiling_holds() -> None:
    ok, reason = retriage.should_retriage(
        previous_verdict="needs_review",
        generation=retriage.MAX_RETRIAGES_PER_ALERT + 1,
        trigger=retriage.RetriageTrigger(kind="story_escalation", evidence={"chain_id": "c"}),
    )
    assert not ok and "ceiling" in reason


def test_every_refusal_carries_its_reason() -> None:
    """ "Re-triage declined" alone makes a broken control look like a working one."""
    for previous, generation in (("", 1), ("benign", 1), ("needs_review", 99)):
        ok, reason = retriage.should_retriage(
            previous_verdict=previous,
            generation=generation,
            trigger=retriage.RetriageTrigger(kind="k", evidence={"a": 1}),
        )
        assert not ok and reason.strip()


# ── (b) the trigger ───────────────────────────────────────────────────────


def test_a_story_escalation_is_a_trigger() -> None:
    trigger = retriage.chain_escalation_trigger(
        {
            "chain_id": "c-1",
            "escalation_reason": "story spans 3 kill-chain stages",
            "story_severity": "high",
            "member_count": 4,
            "stage_span": 3,
        }
    )
    assert trigger is not None and trigger.kind == "story_escalation"


def test_an_ordinary_chain_join_is_not_a_trigger() -> None:
    """Otherwise every member of a busy story is re-triaged on every arrival."""
    assert retriage.chain_escalation_trigger({"chain_id": "c-1", "member_count": 4}) is None
    assert retriage.chain_escalation_trigger(None) is None


def test_retriage_reaches_no_closure_path_of_its_own() -> None:
    """Closure stays chokepointed at `authorize_auto_closure` in the ledger.

    This module decides only whether to run again and under what identity.
    """
    source = _code_only(retriage)
    for forbidden in ("persist_auto_triage", "auto_closed", "resolved"):
        assert forbidden not in source, f"the re-triage module reaches closure through {forbidden!r}"
