"""A rate over a signal that never appeared is unmeasured, not zero.

Gap-closure wave 3.

The live behavioural path was repointed at the real agent — it had been
importing `InvestigatorAgent` from `app.investigator`, a class that
exists only in the historical prototype under `plans/`, so it could
never have measured anything. The hosted-key check ran first, which is
why the broken import was never reached and the failure read as "no key
configured" indefinitely.

Once it ran, it published this:

    Unsafe action proposal rate | live model | 0.0% (0/54)

which reads as "the agent resisted every payload" and meant "the agent
proposed no actions at all". `auto_triage` populates neither
`proposed_actions` nor `tools_used`, so the figure was 0-out-of-0 with a
pair count substituted for the denominator.

Verdict flip was a real 9.3% on the same run, from the same pairs. That
is the whole argument for three denominators rather than one: two of the
three signals never occurred, and sharing a denominator made them look
like clean results.
"""

from __future__ import annotations

import pytest

from tests.adversarial.injection_incidents import build_pairs
from tests.adversarial.injection_metrics import AgentOutcome, score


def _outcomes(pairs, *, actions: tuple[str, ...], tools: tuple[str, ...]):  # noqa: ANN001, ANN202
    """One outcome per pair, with the signals under test controlled."""
    out = {}
    for pair in pairs:
        clean = AgentOutcome(
            verdict="true_positive",
            proposed_actions=actions,
            tool_calls=tools,
            action_targets=(),
        )
        injected = AgentOutcome(
            verdict="true_positive",
            proposed_actions=actions,
            tool_calls=tools,
            action_targets=(),
        )
        out[pair.pair_id] = (clean, injected)
    return out


def _score(pairs, *, actions: tuple[str, ...], tools: tuple[str, ...]):  # noqa: ANN001, ANN202
    """Score with the guard credited everywhere, so only the behavioural
    rates are under test."""
    return score(
        pairs,
        {p.pair_id: True for p in pairs},
        "test-digest",
        outcomes=_outcomes(pairs, actions=actions, tools=tools),
        live_reason="test",
    )


@pytest.fixture(scope="module")
def pairs():  # noqa: ANN201
    return build_pairs()


class TestASignalThatNeverAppearedIsNotAZeroRate:
    def test_unsafe_action_refuses_when_no_action_was_proposed(self, pairs) -> None:  # noqa: ANN001
        score = _score(pairs, actions=(), tools=())

        assert not score.unsafe_action.measured, "published a rate for unsafe actions when the agent proposed none — 0 out of 0 is not 0%"
        assert "proposed no actions" in (score.unsafe_action.reason or "")

    def test_tool_deviation_refuses_when_no_tool_was_called(self, pairs) -> None:  # noqa: ANN001
        score = _score(pairs, actions=(), tools=())

        assert not score.tool_deviation.measured
        assert "no tool calls" in (score.tool_deviation.reason or "")

    def test_verdict_flip_is_still_measured_on_the_same_run(self, pairs) -> None:  # noqa: ANN001
        """The negative control. If the fix had made all three unmeasured
        it would satisfy the two tests above and destroy the one rate
        that genuinely works — which is what happened on the live run:
        9.3% verdict flip beside two signals that never occurred.
        """
        score = _score(pairs, actions=(), tools=())

        assert score.verdict_flip.measured, "verdict flip must still report; it does not need an action"
        assert score.verdict_flip.denominator == score.adversarial


class TestTheRatesReportWhenTheSignalIsThere:
    """The other direction. A metric that refused everything would pass
    the class above and measure nothing ever again."""

    def test_unsafe_action_reports_once_an_action_is_proposed(self, pairs) -> None:  # noqa: ANN001
        score = _score(pairs, actions=("isolate_host",), tools=())
        assert score.unsafe_action.measured
        assert score.unsafe_action.denominator == score.adversarial

    def test_tool_deviation_reports_once_a_tool_is_called(self, pairs) -> None:  # noqa: ANN001
        score = _score(pairs, actions=(), tools=("search_siem",))
        assert score.tool_deviation.measured
        assert score.tool_deviation.denominator == score.adversarial
