"""The benchmark must be gameable in no direction that matters.

A benchmark's value is entirely in what it refuses to reward. These tests
are mostly about the ways a scoring harness quietly hands out credit:

* abstaining to raise accuracy
* citing indicators nobody can check
* returning a crash that scores as a wrong answer rather than a crash
* self-reporting a flattering latency
* publishing a figure without saying the corpus was synthetic

Each of those is a way for a vendor to look better than they are, and the
benchmark is only a standard if it closes them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from aisoc_benchmark.adapter import AgentVerdict, BenchmarkIncident, HTTPAgent
from aisoc_benchmark.metrics import (
    aggregate,
    is_checkable_indicator,
    score_incident,
)
from aisoc_benchmark.runner import CorpusError, format_report, load_corpus, run_benchmark

INCIDENT = BenchmarkIncident(
    incident_id="INC-1",
    title="Suspicious PowerShell on WS-42",
    description="cmd.exe spawned from a macro; beacon to 203.0.113.9",
    severity="high",
    raw_alert={"host": "WS-42"},
    telemetry=[{"process": "powershell.exe", "dest_ip": "203.0.113.9"}],
)
TRUTH = {
    "disposition": "malicious",
    "techniques": ["T1059.001", "T1566.001"],
    "actions": ["block_ip", "isolate_host"],
}


class StubAgent:
    name = "stub"
    version = "1.0"

    def __init__(self, verdict: AgentVerdict | Exception) -> None:
        self._verdict = verdict
        self.calls = 0

    async def investigate(self, incident: BenchmarkIncident) -> AgentVerdict:
        self.calls += 1
        if isinstance(self._verdict, Exception):
            raise self._verdict
        return self._verdict


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    path = tmp_path / "corpus.json"
    path.write_text(
        json.dumps(
            {
                "incidents": [
                    {
                        "id": "INC-1",
                        "provenance": "synthetic",
                        "title": INCIDENT.title,
                        "description": INCIDENT.description,
                        "severity": "high",
                        "telemetry": INCIDENT.telemetry,
                        "expected_disposition": "malicious",
                        "expected_techniques": ["T1059.001"],
                        "expected_actions": ["block_ip"],
                    }
                ]
            }
        )
    )
    return path


class TestAbstentionCannotBuyAccuracy:
    def test_accuracy_is_over_answered_incidents_only(self) -> None:
        """Dividing by the whole corpus lets an agent score higher by
        abstaining more, which is the opposite of what we want to reward."""
        answered = score_incident(INCIDENT, AgentVerdict(disposition="malicious"), TRUTH)
        abstained = score_incident(INCIDENT, AgentVerdict(abstained=True), TRUTH)

        result = aggregate("a", "1", [answered, abstained])
        assert result.disposition_accuracy == 1.0
        assert result.abstention_rate == 0.5

    def test_abstention_rate_is_published_beside_accuracy(self) -> None:
        """So the two cannot be traded off invisibly."""
        scores = [score_incident(INCIDENT, AgentVerdict(abstained=True), TRUTH)] * 4
        result = aggregate("a", "1", scores)
        assert result.abstention_rate == 1.0
        report = format_report(result)
        assert "abstention rate" in report

    def test_abstaining_is_not_scored_as_wrong(self) -> None:
        """Punishing 'I do not know' trains agents to guess."""
        score = score_incident(INCIDENT, AgentVerdict(abstained=True), TRUTH)
        assert score.abstained
        assert not score.disposition_correct
        result = aggregate("a", "1", [score])
        assert result.disposition_accuracy == 0.0
        assert result.incidents == 1


class TestHallucination:
    def test_an_invented_indicator_is_caught(self) -> None:
        """The single most dangerous thing an analyst-replacement can do."""
        verdict = AgentVerdict(
            disposition="malicious",
            cited_indicators=["203.0.113.9", "198.51.100.77"],
        )
        score = score_incident(INCIDENT, verdict, TRUTH)
        assert score.cited_checkable == 2
        assert score.hallucinated_indicators == ["198.51.100.77"]

    def test_indicators_present_in_evidence_are_not_flagged(self) -> None:
        verdict = AgentVerdict(cited_indicators=["203.0.113.9", "WS-42"])
        score = score_incident(INCIDENT, verdict, TRUTH)
        assert score.hallucinated_indicators == []

    def test_unverifiable_claims_are_not_counted_either_way(self) -> None:
        """Scoring 'the process behaved suspiciously' would measure phrasing."""
        verdict = AgentVerdict(cited_indicators=["it looked suspicious", "very bad"])
        score = score_incident(INCIDENT, verdict, TRUTH)
        assert score.cited_checkable == 0
        assert score.hallucinated_indicators == []

    def test_hallucination_is_graded_on_abstention_too(self) -> None:
        """Declining to conclude while inventing an address is still inventing it."""
        verdict = AgentVerdict(abstained=True, cited_indicators=["198.51.100.77"])
        score = score_incident(INCIDENT, verdict, TRUTH)
        assert score.hallucinated_indicators == ["198.51.100.77"]

        result = aggregate("a", "1", [score])
        assert result.hallucination_rate == 1.0

    def test_no_citations_is_a_zero_rate_not_a_divide_by_zero(self) -> None:
        score = score_incident(INCIDENT, AgentVerdict(disposition="benign"), TRUTH)
        result = aggregate("a", "1", [score])
        assert result.hallucination_rate == 0.0
        assert result.indicators_checked == 0

    @pytest.mark.parametrize(
        ("value", "checkable"),
        [
            ("10.0.0.1", True),
            ("a" * 64, True),
            ("evil.example.com", True),
            ("", False),
            ("something happened", False),
            ("high", False),
        ],
    )
    def test_checkability_detection(self, value: str, checkable: bool) -> None:
        assert is_checkable_indicator(value) is checkable


class TestCalibration:
    def test_a_confident_wrong_answer_shows_in_the_gap(self) -> None:
        right = score_incident(INCIDENT, AgentVerdict(disposition="malicious", confidence=0.6), TRUTH)
        wrong = score_incident(INCIDENT, AgentVerdict(disposition="benign", confidence=0.99), TRUTH)
        result = aggregate("a", "1", [right, wrong])
        assert result.calibration_gap < 0, "the agent was more confident when wrong; the gap must be negative"

    def test_a_well_calibrated_agent_shows_a_positive_gap(self) -> None:
        right = score_incident(INCIDENT, AgentVerdict(disposition="malicious", confidence=0.95), TRUTH)
        wrong = score_incident(INCIDENT, AgentVerdict(disposition="benign", confidence=0.4), TRUTH)
        result = aggregate("a", "1", [right, wrong])
        assert result.calibration_gap > 0


class TestContainment:
    def test_any_matching_action_counts(self) -> None:
        """Requiring an exact set would grade an agent on matching our verbs
        rather than on containing the incident."""
        verdict = AgentVerdict(disposition="malicious", proposed_actions=["isolate_host"])
        assert score_incident(INCIDENT, verdict, TRUTH).containment_correct is True

    def test_a_wrong_action_is_wrong(self) -> None:
        verdict = AgentVerdict(disposition="malicious", proposed_actions=["send_email"])
        assert score_incident(INCIDENT, verdict, TRUTH).containment_correct is False

    def test_no_expected_actions_means_not_graded(self) -> None:
        """Not the same as graded and failed."""
        verdict = AgentVerdict(disposition="malicious", proposed_actions=["anything"])
        score = score_incident(INCIDENT, verdict, {"disposition": "malicious"})
        assert score.containment_correct is None

        result = aggregate("a", "1", [score])
        assert result.containment_accuracy is None


class TestProvenance:
    async def test_an_unlabelled_corpus_is_refused(self, tmp_path: Path) -> None:
        """An unlabelled corpus lets a reader assume the generous answer."""
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"incidents": [{"id": "x", "title": "t"}]}))
        with pytest.raises(CorpusError, match="provenance"):
            load_corpus(path)

    async def test_an_invented_provenance_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"incidents": [{"id": "x", "provenance": "definitely-real"}]}))
        with pytest.raises(CorpusError, match="provenance"):
            load_corpus(path)

    async def test_provenance_travels_with_the_result(self, corpus: Path) -> None:
        """So a downstream consumer cannot publish the number without it."""
        agent = StubAgent(AgentVerdict(disposition="malicious"))
        result = await run_benchmark(agent, corpus)
        assert result.corpus_provenance == {"synthetic": 1}

    async def test_the_report_leads_with_provenance(self, corpus: Path) -> None:
        """A reader who sees 0.94 before 'synthetic' has already formed an
        impression the caveat will not undo."""
        agent = StubAgent(AgentVerdict(disposition="malicious"))
        result = await run_benchmark(agent, corpus)
        report = format_report(result)
        assert report.index("synthetic") < report.index("disposition accuracy")

    def test_the_shipped_corpus_is_labelled(self) -> None:
        shipped = Path(__file__).resolve().parent.parent / "corpus" / "soc-agent-benchmark-v1.json"
        if not shipped.exists():
            pytest.skip("corpus not built in this checkout")
        incidents, _, provenance = load_corpus(shipped)
        assert incidents and provenance
        assert sum(provenance.values()) == len(incidents)


class TestRunnerRobustness:
    async def test_an_agent_that_raises_is_an_abstention_not_a_crash(self, corpus: Path) -> None:
        """A harness that dies on one bad response grades nothing, and the
        entrant assumes the fault is ours."""
        agent = StubAgent(RuntimeError("boom"))
        result = await run_benchmark(agent, corpus)
        assert result.incidents == 1
        assert result.abstention_rate == 1.0

    async def test_latency_is_measured_not_trusted(self, corpus: Path) -> None:
        """The one number an entrant has an incentive to shade."""
        agent = StubAgent(AgentVerdict(disposition="malicious", latency_ms=0))
        result = await run_benchmark(agent, corpus)
        assert result.per_incident[0].latency_ms >= 0
        assert "latency" in format_report(result)

    async def test_a_self_reported_latency_is_kept_when_given(self, corpus: Path) -> None:
        agent = StubAgent(AgentVerdict(disposition="malicious", latency_ms=1234))
        result = await run_benchmark(agent, corpus)
        assert result.per_incident[0].latency_ms == 1234

    async def test_limit_truncates_without_misreporting_the_count(self, corpus: Path) -> None:
        agent = StubAgent(AgentVerdict(disposition="malicious"))
        result = await run_benchmark(agent, corpus, limit=1)
        assert result.incidents == 1 == agent.calls


class TestHTTPAdapter:
    async def test_an_unreachable_agent_abstains_with_the_reason(self) -> None:
        agent = HTTPAgent("http://127.0.0.1:9/nope", timeout_seconds=1.0)
        verdict = await agent.investigate(INCIDENT)
        assert verdict.abstained
        assert "adapter error" in verdict.narrative

    def test_a_partial_response_defaults_rather_than_raising(self) -> None:
        """An adapter under development should score badly, not crash the run."""
        verdict = AgentVerdict.from_dict({"disposition": "MALICIOUS"})
        assert verdict.disposition == "malicious"
        assert verdict.confidence == 0.0
        assert verdict.techniques == []

    def test_techniques_are_normalised(self) -> None:
        verdict = AgentVerdict.from_dict({"techniques": ["t1059.001", "T1566"]})
        assert verdict.techniques == ["T1059.001", "T1566"]


def test_protocol_accepts_a_minimal_implementation() -> None:
    """Twenty lines against a vendor's own API is the bar."""
    from aisoc_benchmark.adapter import SOCAgent

    class Minimal:
        name = "minimal"
        version = "0.1"

        async def investigate(self, incident: BenchmarkIncident) -> AgentVerdict:
            return AgentVerdict(disposition="benign")

    assert isinstance(Minimal(), SOCAgent)


def test_aggregate_of_nothing_does_not_divide_by_zero() -> None:
    result = aggregate("a", "1", [])
    assert result.incidents == 0
    assert result.disposition_accuracy == 0.0
    assert result.hallucination_rate == 0.0


def test_result_omits_per_incident_detail_by_default() -> None:
    """A 200-entry array in every published payload is noise."""
    score = score_incident(INCIDENT, AgentVerdict(disposition="malicious"), TRUTH)
    result = aggregate("a", "1", [score])
    assert "per_incident" not in result.as_dict()
    assert "per_incident" in result.as_dict(include_per_incident=True)


async def test_limit_recounts_provenance_over_the_slice(tmp_path: Path) -> None:
    """Reporting the full corpus provenance beside a truncated run overstates
    what was graded — the same class of error the labelling prevents."""
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps({"incidents": [{"id": f"INC-{n}", "provenance": "synthetic", "title": "t"} for n in range(5)]}))
    agent = StubAgent(AgentVerdict(disposition="benign"))
    result = await run_benchmark(agent, path, limit=2)
    assert result.incidents == 2
    assert result.corpus_provenance == {"synthetic": 2}
