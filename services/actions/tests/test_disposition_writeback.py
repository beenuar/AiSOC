"""The disposition mapping is the whole safety argument for writing back.

Three properties, each one a decision somebody could reasonably get wrong:

* a confirmed true positive escalates and is never closed;
* a verdict outside the canonical taxonomy is refused, never interpreted;
* only benign / false-positive verdicts may close a finding.

The second is the subtle one. ``services/agents`` normalises an unrecognised
verdict to ``true_positive`` by design (its fail-safe is "do not auto-close").
A mapper that normalised first would turn "I have never seen this string"
into a confident claim and then act on it, so this module matches the
canonical set exactly and refuses the rest.
"""

from __future__ import annotations

import pytest
from app.services.disposition_writeback import (
    CANONICAL_DISPOSITIONS,
    CLOSEABLE_DISPOSITIONS,
    WritebackAction,
    plan_writeback,
)


@pytest.mark.parametrize("disposition", ["false_positive", "benign", "benign_true_positive"])
def test_benign_verdicts_close_the_source_finding(disposition: str) -> None:
    plan = plan_writeback(disposition)
    assert plan.action is WritebackAction.CLOSE
    assert plan.writes is True


@pytest.mark.parametrize("disposition", ["true_positive", "escalate", "TRUE POSITIVE", "True-Positive"])
def test_a_confirmed_true_positive_is_escalated_and_never_closed(disposition: str) -> None:
    plan = plan_writeback(disposition, confidence=0.99)
    assert plan.action is WritebackAction.ESCALATE
    assert plan.action is not WritebackAction.CLOSE
    assert "never auto-closed" in plan.reason


@pytest.mark.parametrize(
    "disposition",
    [
        "resolved",
        "closed",
        "malicious",
        "",
        "   ",
        None,
        123,
        "true_positive; drop table alerts",
    ],
)
def test_an_unknown_verdict_is_refused_not_guessed(disposition: object) -> None:
    plan = plan_writeback(disposition)
    assert plan.action is WritebackAction.REFUSE
    assert plan.writes is False


def test_needs_review_leaves_the_finding_exactly_as_it_was() -> None:
    plan = plan_writeback("needs_review")
    assert plan.action is WritebackAction.REFUSE
    assert plan.writes is False


def test_high_confidence_cannot_promote_a_true_positive_to_a_close() -> None:
    """Confidence is an approval axis, not a licence to close a real incident."""
    for confidence in (0.0, 0.5, 0.999, 1.0):
        assert plan_writeback("true_positive", confidence=confidence).action is WritebackAction.ESCALATE


def test_closeable_set_is_a_strict_subset_of_the_taxonomy() -> None:
    assert CLOSEABLE_DISPOSITIONS < CANONICAL_DISPOSITIONS
    assert "true_positive" not in CLOSEABLE_DISPOSITIONS


def test_taxonomy_mirrors_the_agents_service() -> None:
    """The two vocabularies are mirrored, not imported. Assert they agree.

    ``services/agents`` and ``services/actions`` are independently deployable,
    so this module copies the disposition strings rather than importing them —
    the same trade-off ``live_actions.capabilities`` makes for the connectors
    ``Capability`` enum, and the same reason it needs a gate.
    """
    import ast
    from pathlib import Path

    source = Path(__file__).resolve().parents[3] / "services" / "agents" / "app" / "agents" / "dispositions.py"
    if not source.exists():  # pragma: no cover - monorepo layout only
        pytest.skip("agents service not present in this checkout")

    tree = ast.parse(source.read_text(encoding="utf-8"))

    # Module-level `NAME = "literal"` bindings, so the constant references
    # inside CANONICAL_DISPOSITIONS can be resolved to the strings that
    # actually travel on the wire.
    literals: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    literals[target.id] = node.value.value

    agents_dispositions: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign) and not isinstance(node, ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else list(node.targets)
        if not any(isinstance(t, ast.Name) and t.id == "CANONICAL_DISPOSITIONS" for t in targets):
            continue
        for ref in ast.walk(node.value) if node.value is not None else []:
            if isinstance(ref, ast.Name) and ref.id in literals:
                agents_dispositions.add(literals[ref.id])
            elif isinstance(ref, ast.Constant) and isinstance(ref.value, str):
                agents_dispositions.add(ref.value)

    assert agents_dispositions, "could not parse CANONICAL_DISPOSITIONS out of the agents service"
    assert agents_dispositions == set(CANONICAL_DISPOSITIONS), (
        f"the agents taxonomy is {sorted(agents_dispositions)} and the writeback mirror is "
        f"{sorted(CANONICAL_DISPOSITIONS)}; a verdict present on one side only is refused at "
        f"writeback while the agent believes it decided."
    )
