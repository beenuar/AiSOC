"""Tool selection, evidence completeness and time to verdict.

Gap-closure wave 3. None of the three had a single hit anywhere in the
tree before this: `run_evals.py` graded outcomes, and an agent that
reaches the right verdict by reading the alert title and nothing else
scores identically to one that investigated.
"""

from __future__ import annotations

from app.eval.agent_quality import AgentRun, score_agent_quality


def _run(incident: str, **kw) -> AgentRun:  # noqa: ANN003
    return AgentRun(incident_id=incident, verdict=kw.pop("verdict", "true_positive"), **kw)


class TestToolSelection:
    def test_calling_every_expected_tool_scores_full(self) -> None:
        score = score_agent_quality(
            [_run("a", tools_called=("search_siem", "get_host"), expected_tools=frozenset({"search_siem", "get_host"}))]
        )
        assert score.tool_selection.value == 1.0

    def test_partial_credit_rather_than_all_or_nothing(self) -> None:
        """Three of four required tools is most of the way there, and
        grading it the same as zero would hide real progress."""
        score = score_agent_quality([_run("a", tools_called=("a", "b", "c"), expected_tools=frozenset({"a", "b", "c", "d"}))])
        assert score.tool_selection.value == 0.75

    def test_calling_nothing_scores_zero_not_unmeasured(self) -> None:
        """An agent that called no tools against an incident that needed
        three genuinely scored zero. That is a measurement."""
        score = score_agent_quality([_run("a", tools_called=(), expected_tools=frozenset({"a", "b", "c"}))])
        assert score.tool_selection.measured
        assert score.tool_selection.value == 0.0

    def test_no_expected_tools_anywhere_is_unmeasured_not_zero(self) -> None:
        """The distinction the injection metrics had to learn: a corpus
        with no answer key cannot grade, and rendering that as 0% says
        the agent failed when nobody asked it anything."""
        score = score_agent_quality([_run("a", tools_called=("x",))])
        assert not score.tool_selection.measured
        assert "expected tool" in (score.tool_selection.reason or "")

    def test_extra_tools_are_counted_separately_not_penalised(self) -> None:
        """Exploring is legitimate. It is tracked because a rising count
        beside flat completeness is an agent thrashing, which is worth
        seeing — but it is not a scoring penalty."""
        score = score_agent_quality([_run("a", tools_called=("a", "unrelated"), expected_tools=frozenset({"a"}))])
        assert score.tool_selection.value == 1.0
        assert score.unexpected_tool_runs == 1


class TestEvidenceCompleteness:
    def test_citing_all_the_evidence_scores_full(self) -> None:
        score = score_agent_quality([_run("a", evidence_cited=("e1", "e2"), expected_evidence=frozenset({"e1", "e2"}))])
        assert score.evidence_completeness.value == 1.0

    def test_missing_the_decisive_event_shows_up(self) -> None:
        score = score_agent_quality([_run("a", evidence_cited=("e1",), expected_evidence=frozenset({"e1", "e2"}))])
        assert score.evidence_completeness.value == 0.5

    def test_it_is_independent_of_the_verdict(self) -> None:
        """The whole reason this metric exists: a correct verdict on
        half the evidence is one unusual alert away from being wrong."""
        score = score_agent_quality([_run("a", verdict="true_positive", evidence_cited=(), expected_evidence=frozenset({"e1"}))])
        assert score.evidence_completeness.value == 0.0


class TestTimeToVerdict:
    def test_median_and_p95_are_reported(self) -> None:
        runs = [_run(f"i{n}", seconds_to_verdict=float(n)) for n in range(1, 21)]
        score = score_agent_quality(runs)
        assert score.timed_runs == 20
        assert score.median_seconds_to_verdict is not None
        assert score.p95_seconds_to_verdict >= score.median_seconds_to_verdict

    def test_untimed_runs_are_absent_not_instant(self) -> None:
        score = score_agent_quality([_run("a")])
        assert score.timed_runs == 0
        assert score.median_seconds_to_verdict is None


class TestTheScoreCarriesItsDenominator:
    def test_every_measure_reports_what_it_divided_by(self) -> None:
        score = score_agent_quality([_run("a", tools_called=("x",), expected_tools=frozenset({"x", "y"}))])
        payload = score.as_dict()
        assert payload["tool_selection_accuracy"]["denominator"] == 2
        assert payload["runs"] == 1

    def test_an_empty_run_set_refuses_rather_than_scoring_zero(self) -> None:
        score = score_agent_quality([])
        assert not score.tool_selection.measured
        assert not score.evidence_completeness.measured
