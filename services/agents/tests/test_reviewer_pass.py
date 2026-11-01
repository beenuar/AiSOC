"""The reviewer pass, and the measurement that keeps it switched off.

Wave 2, Phase 4.2. The plan's condition is binding: *"Ship it only if it
improves balanced accuracy or auto-close precision on the corpus without
lowering malicious recall; otherwise record the measurement and leave it
off."*

It was measured. It did not improve either figure. It is off, and these
tests pin both the behaviour and the fact that it is off — a feature
disabled by a measurement is only honest for as long as something stops it
quietly being switched on without a new one.

The measured result, from `scripts/run_verdict_eval.py --deterministic`:

    reviewer off   balanced accuracy 0.2500   auto-close precision  not measured
    reviewer on    balanced accuracy 0.2500   auto-close precision  not measured
                   malicious recall  0.0000   (unchanged)

The reason is legible rather than mysterious, and is itself worth recording:
the deterministic scorer makes no prose claims, so `supporting_evidence`,
`contradictory_evidence` and `groundedness` are `None` on every item — the
contract correctly reports them as *not evaluated* — and a reviewer whose
inputs are all absent has nothing to act on. It abstains on all 72.

That measures the reviewer **on the only path available to measure it**, not
the idea. `auto_close_precision` stays *not measured* rather than `0`
because the deterministic path closed nothing, so there is no denominator.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any

import pytest
from app.agents import reviewer


def _contract(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "verdict": "benign",
        "supporting_evidence": None,
        "contradictory_evidence": None,
        "groundedness": None,
        "missing_prerequisites": [],
    }
    base.update(fields)
    return base


# ── off by default, and off for a reason ──────────────────────────────────


def test_the_reviewer_is_off_unless_an_operator_turned_it_on(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_TRIAGE_REVIEWER", raising=False)
    assert reviewer.enabled() is False
    monkeypatch.setenv("AISOC_TRIAGE_REVIEWER", "true")
    assert reviewer.enabled() is True
    monkeypatch.setenv("AISOC_TRIAGE_REVIEWER", "0")
    assert reviewer.enabled() is False


def test_the_measurement_that_keeps_it_off_is_recorded_beside_the_code() -> None:
    """A feature disabled by a measurement needs the measurement written down.

    Otherwise "it is off" decays into "nobody remembers why", and the next
    reader switches it on without taking a new one.
    """
    doc = reviewer.__doc__ or ""
    assert "0.2500" in doc, "the measured balanced accuracy is not recorded in the module"
    assert "not measured" in doc, "auto-close precision must read 'not measured', never 0"
    assert "stays off" in doc or "it is off" in doc.lower()


# ── it may never close ────────────────────────────────────────────────────


def _code_only(module: Any) -> str:
    """Source with docstrings stripped.

    The module explains closure at length in order to say it does not reach
    it; a raw substring assertion cannot tell a call from a sentence about
    one — the blindness `check_gate_coverage.py` had when a gate named only
    in a docstring counted as invoked.
    """
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
    return ast.unparse(tree)


def test_the_reviewer_reaches_no_closure_path() -> None:
    source = _code_only(reviewer)
    for forbidden in ("persist_auto_triage", "AgentStatus", "resolved", "authorize_auto_closure"):
        assert forbidden not in source, f"the reviewer reaches closure through {forbidden!r}"


def test_the_action_vocabulary_cannot_express_closing() -> None:
    """One direction only, as a property of the values it can return."""
    # Annotated, because the values are heterogeneous and an inferred
    # element type would be the join of `list[str]`, `float` and `str`,
    # which is not a type `_contract(**case)` accepts.
    cases: tuple[dict[str, Any], ...] = (
        {},
        {"contradictory_evidence": ["x"]},
        {"supporting_evidence": []},
        {"groundedness": 0.1},
        {"verdict": "true_positive", "contradictory_evidence": ["x"]},
    )
    actions = {reviewer.review(_contract(**case)).action for case in cases}
    assert actions <= {"abstain", "demote", "escalate"}
    assert "close" not in actions


@pytest.mark.parametrize("auto_closed", [True, False])
def test_apply_review_can_only_take_closure_away(auto_closed: bool) -> None:
    """The flag can go True -> False and never False -> True."""
    opened, _ = reviewer.apply_review(_contract(contradictory_evidence=["a claim the evidence denies"]), auto_closed=auto_closed)
    assert opened is False if auto_closed else opened is False

    unchanged, _ = reviewer.apply_review(_contract(), auto_closed=auto_closed)
    assert unchanged is auto_closed, "an abstaining reviewer changed the closure flag"


def test_an_abstention_never_turns_closure_on() -> None:
    reopened, review = reviewer.apply_review(_contract(), auto_closed=False)
    assert reopened is False
    assert review.action == "abstain"


# ── what it acts on ───────────────────────────────────────────────────────


def test_a_contradicted_claim_demotes_a_closeable_verdict() -> None:
    result = reviewer.review(_contract(contradictory_evidence=["the host was not isolated"]))
    assert result.action == "demote"
    assert "contradicted" in result.summary()


def test_claim_support_that_ran_and_found_nothing_is_acted_on() -> None:
    """An empty list is a result; `None` is not.

    Collapsing "the signal did not run" into "the signal found nothing" is
    the distinction the decision contract's own docstring exists to protect,
    and a reviewer that got it wrong would demote every deterministic
    verdict in the product.
    """
    assert reviewer.review(_contract(supporting_evidence=[])).action == "demote"
    assert reviewer.review(_contract(supporting_evidence=None)).action == "abstain"


def test_a_not_evaluated_signal_is_never_treated_as_a_negative_result() -> None:
    """The whole contract absent means abstain, not demote everything."""
    assert reviewer.review(_contract()).action == "abstain"
    assert reviewer.review(None).action == "abstain"
    assert reviewer.review({}).action == "abstain"


def test_low_groundedness_demotes_only_a_closeable_verdict() -> None:
    assert reviewer.review(_contract(groundedness=0.4)).action == "demote"
    # `needs_review` is already with a human; moving it would be noise.
    assert reviewer.review(_contract(verdict="needs_review", groundedness=0.4)).action == "abstain"


def test_the_groundedness_floor_matches_the_existing_gate() -> None:
    """A second opinion about groundedness would be two controls disagreeing.

    The quieter one would win silently, which is how a control stops being a
    control.
    """
    assert reviewer.GROUNDEDNESS_FLOOR == 0.75
    assert reviewer.review(_contract(groundedness=0.75)).action == "abstain"
    assert reviewer.review(_contract(groundedness=0.74)).action == "demote"


def test_a_true_positive_with_contradicted_evidence_escalates() -> None:
    result = reviewer.review(_contract(verdict="true_positive", contradictory_evidence=["x"]))
    assert result.action == "escalate"


def test_every_record_says_the_reviewer_ran_including_abstentions() -> None:
    """A reviewer that has silently stopped firing must not look like one
    that ran and found nothing."""
    payload = reviewer.review(_contract()).as_payload()
    assert payload["reviewed"] is True
    assert payload["action"] == "abstain"
    assert payload["reasons"] == []


def test_a_demotion_carries_its_reason() -> None:
    payload = reviewer.review(_contract(groundedness=0.2)).as_payload()
    assert payload["reasons"], "a demotion with no reason cannot be audited from the alert"
    assert "0.20" in payload["reasons"][0]
