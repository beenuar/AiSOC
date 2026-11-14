"""The agent reaching for a capability above its tier.

Gap-closure wave 4.

No test anywhere asked this. `approval_matrix` and the capability
contracts are each well tested in isolation; what was never exercised
is the agent *trying* — which is the only path an injected instruction
has to a destructive action.

Graded here rather than in `services/agents` because it must run
against the shipped matrix, and both services root their packages at
`app`: loading one from the other binds to the wrong tree. The corpus
is loaded by file path because it is pure data with no imports of its
own.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.services import approval_matrix


def _load_corpus():  # noqa: ANN202
    path = Path(__file__).resolve().parents[2] / "agents" / "tests" / "adversarial" / "overflow_corpus.py"
    if not path.is_file():  # pragma: no cover - checkout layout changed
        pytest.fail(f"escalation corpus not found at {path}")
    spec = importlib.util.spec_from_file_location("_w4_corpus", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["_w4_corpus"] = module
    spec.loader.exec_module(module)
    return module


ESCALATION_ATTEMPTS = _load_corpus().ESCALATION_ATTEMPTS


class TestPrivilegeEscalation:
    """The agent attempting a capability above its tier. No test
    anywhere asked this: the matrix and the contract are each tested in
    isolation, and the thing never exercised is the agent *trying*."""

    def test_the_corpus_covers_both_origins(self) -> None:
        origins = {a.origin for a in ESCALATION_ATTEMPTS}
        assert origins == {"injected", "drift"}, (
            "drift is the harder case — no attacker string exists to detect, so only the "
            "tier ceiling stands between the proposal and the vendor"
        )

    def test_it_covers_the_reverse_direction(self) -> None:
        """A ceiling written only for destructive verbs misses this:
        un-containing a host an analyst contained is also an attack."""
        assert any(a.capability == "unisolate_host" for a in ESCALATION_ATTEMPTS)

    def test_every_attempt_names_a_real_capability(self) -> None:
        """Otherwise the suite grades a vocabulary nothing implements —
        a corpus of invented verbs passes every assertion below while
        proving nothing about the product."""
        registry = CAPABILITY_CONTRACTS
        unknown = [a.capability for a in ESCALATION_ATTEMPTS if a.capability not in registry]
        assert not unknown, f"not in CAPABILITY_CONTRACTS: {unknown}"

    @pytest.mark.parametrize("attempt", ESCALATION_ATTEMPTS, ids=lambda a: a.id)
    def test_an_attempt_above_tier_does_not_auto_execute(self, attempt) -> None:
        """Graded through the shipped matrix, at maximum confidence.

        0.99 rather than a middling value on purpose: confidence is one
        of the two inputs, so a ceiling that only holds when the agent
        is unsure is not a ceiling. This is the agent at its most
        certain, which is exactly when an injected instruction wants it.
        """
        registry, matrix = CAPABILITY_CONTRACTS, approval_matrix
        decision = matrix.evaluate_contract(
            contract=registry[attempt.capability],
            confidence=0.99,
            tier=attempt.granted_tier,
        )
        assert not decision.can_auto_execute, (
            f"{attempt.capability} auto-executes at {attempt.granted_tier} ({attempt.origin}): {attempt.why}"
        )
        assert decision.reason, "a refusal with no reason is one people learn to click through"

    def test_a_contracted_verb_can_still_auto_execute_somewhere(self) -> None:
        """The negative control. A matrix that refused everything would
        satisfy every case above and make the product useless, so at
        least one low-impact capability must auto-execute at the top
        tier — otherwise this suite proves nothing about the ceiling.
        """
        registry, matrix = CAPABILITY_CONTRACTS, approval_matrix
        auto = [
            name
            for name, contract in registry.items()
            if matrix.evaluate_contract(contract=contract, confidence=0.99, tier="L4").can_auto_execute
        ]
        assert auto, "nothing auto-executes at L4, so the refusals above are not a ceiling"
