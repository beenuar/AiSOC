"""The recursive investigation must pivot, and must not lie when it cannot.

``run_with_tools`` shipped working, guarded and instrumented, with zero
production callers, so the platform's deepest capability was reachable only
from tests. That is the failure this covers: not "does the loop work" but
"does anything call it, does it take real pivots, and does a failed or
shallow run report itself as such".

The most important assertions here are the negative ones. A tool that
reports its data class is not ingested must not count as a pivot, or an
investigation reaches its depth floor by asking four questions nobody can
answer. And a failed run must not produce findings that read like a
completed one.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.investigator import deep_investigation as module
from app.investigator.deep_investigation import (
    DeepInvestigationResult,
    _classify_pivots,
    _summarise_alert,
    run_deep_investigation,
)
from app.investigator.strategies import (
    FALLBACK,
    KNOWN_PIVOTS,
    STRATEGIES,
    get_strategy,
    select_strategy,
)


class FakeState:
    def __init__(self, **kw: Any) -> None:
        self.tenant_id = kw.get("tenant_id", "tenant-1")
        self.alert_summary = kw.get("summary", "suspicious powershell on WS-42")
        self.mitre_mappings = kw.get("techniques", ["T1059.001"])
        self.raw_alert = kw.get("raw_alert", {"src_hostname": "WS-42", "user_name": "j.doe"})


def _trace(*entries: tuple[str, bool]) -> list[dict[str, Any]]:
    """Build a tool trace. ``True`` means the tool answered with data."""
    return [
        {
            "tool": name,
            "args": {},
            "result_preview": str({"tool": name, "available": available, "rows": []}),
        }
        for name, available in entries
    ]


class StubLoop:
    """Stands in for run_with_tools; records how it was called."""

    def __init__(self, trace: list[dict[str, Any]], *, content: str = "narrative", truncated: bool = False) -> None:
        self.trace = trace
        self.content = content
        self.truncated = truncated
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, llm: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "content": self.content,
            "tool_trace": self.trace,
            "iterations": max(1, len(self.trace)),
            "truncated": self.truncated,
        }


class TestStrategySelection:
    @pytest.mark.parametrize(
        ("summary", "techniques", "expected"),
        [
            ("powershell spawned a child process", ["T1059.001"], "endpoint-suspicious-process"),
            ("impossible travel for j.doe", ["T1078"], "identity-account-takeover"),
            ("user opened a phishing attachment", ["T1566.001"], "phishing-payload"),
            ("regular outbound beacon detected", ["T1071"], "c2-beaconing"),
            ("smb lateral movement observed", ["T1021"], "lateral-movement"),
            ("assumerole from an unusual address", ["T1078.004"], "cloud-credential-abuse"),
            ("large upload to an external host", ["T1041"], "data-exfiltration"),
            ("user added to domain admins", ["T1098"], "privilege-escalation"),
            ("new scheduled task created", ["T1053"], "persistence-established"),
        ],
    )
    def test_selection_discriminates(self, summary: str, techniques: list[str], expected: str) -> None:
        assert select_strategy(summary=summary, techniques=techniques).id == expected

    def test_subtechnique_matches_its_parent_strategy(self) -> None:
        """T1078.004 is still an identity problem."""
        assert select_strategy(summary="", techniques=["T1078.004"]).id in {
            "identity-account-takeover",
            "cloud-credential-abuse",
        }

    def test_technique_outranks_keyword(self) -> None:
        """An ATT&CK mapping is a classification; a keyword is incidental."""
        chosen = select_strategy(
            summary="the analyst mentioned email and phishing in the notes",
            techniques=["T1021"],
        )
        assert chosen.id == "lateral-movement"

    def test_no_match_falls_back_rather_than_returning_none(self) -> None:
        """Without a fallback an unmatched alert reverts to summarising text."""
        chosen = select_strategy(summary="zzzz", techniques=[])
        assert chosen is FALLBACK
        assert chosen.expected_pivots


class TestStrategyLibrary:
    def test_every_expected_pivot_is_a_real_tool(self) -> None:
        for strategy in STRATEGIES:
            for pivot in strategy.expected_pivots:
                assert pivot in KNOWN_PIVOTS, f"{strategy.id} expects unknown {pivot}"

    def test_no_strategy_can_pass_by_calling_one_tool(self) -> None:
        for strategy in STRATEGIES:
            assert strategy.min_pivots >= 2, strategy.id

    def test_no_strategy_sets_an_unreachable_floor(self) -> None:
        for strategy in STRATEGIES:
            assert strategy.min_pivots <= len(strategy.expected_pivots), strategy.id

    def test_guidance_tells_the_model_not_to_stop_early(self) -> None:
        """The single most load-bearing sentence in the prompt."""
        guidance = STRATEGIES[0].system_guidance()
        assert "Do not stop at the first tool result" in guidance
        assert "not ingested" in guidance

    def test_guidance_permits_skipping_dead_branches(self) -> None:
        """A numbered imperative list makes the model call tools pointlessly."""
        assert "skip steps whose inputs came back empty" in STRATEGIES[0].system_guidance()


class TestPivotClassification:
    def test_unavailable_tools_do_not_count_as_pivots(self) -> None:
        """Otherwise depth is reachable by asking unanswerable questions."""
        pivots, unavailable = _classify_pivots(
            _trace(
                ("process_tree", False),
                ("mailbox_activity", False),
                ("oauth_grants", False),
                ("persistence_mechanisms", False),
            )
        )
        assert pivots == []
        assert len(unavailable) == 4

    def test_real_pivots_are_counted(self) -> None:
        pivots, unavailable = _classify_pivots(_trace(("process_activity", True), ("historical_execution", True)))
        assert pivots == ["process_activity", "historical_execution"]
        assert unavailable == []

    def test_mixed_trace_splits_correctly(self) -> None:
        pivots, unavailable = _classify_pivots(_trace(("process_activity", True), ("process_tree", False)))
        assert pivots == ["process_activity"]
        assert unavailable == ["process_tree"]


class TestDepthAccounting:
    async def test_repeated_calls_to_one_tool_are_one_pivot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Calling the same tool five times is not five pivots."""
        loop = StubLoop(_trace(*[("process_activity", True)] * 5))
        monkeypatch.setattr(module, "run_with_tools", loop)
        result = await run_deep_investigation(FakeState(), llm=object())

        assert len(result.pivots) == 5
        assert result.distinct_pivots == 1
        assert not result.reached_depth

    async def test_reaching_the_floor_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        loop = StubLoop(
            _trace(
                ("process_activity", True),
                ("historical_execution", True),
                ("network_connections", True),
            )
        )
        monkeypatch.setattr(module, "run_with_tools", loop)
        result = await run_deep_investigation(FakeState(), llm=object())

        assert result.strategy_id == "endpoint-suspicious-process"
        assert result.distinct_pivots == 3
        assert result.reached_depth

    async def test_unavailable_only_run_does_not_reach_depth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        loop = StubLoop(_trace(("process_tree", False), ("mailbox_activity", False), ("oauth_grants", False)))
        monkeypatch.setattr(module, "run_with_tools", loop)
        result = await run_deep_investigation(FakeState(), llm=object())

        assert not result.reached_depth
        assert len(result.unavailable_data) == 3


class TestFailuresAreLegible:
    async def test_a_failed_run_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("model unreachable")

        monkeypatch.setattr(module, "run_with_tools", boom)
        result = await run_deep_investigation(FakeState(), llm=object())

        assert result.error
        findings = result.findings()
        assert any("did not complete" in f for f in findings)
        assert not any("Investigation depth" in f for f in findings), "a failed run produced depth findings, which reads as a completed one"

    async def test_a_failure_returns_rather_than_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """This runs inside a working deterministic investigation."""

        async def boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise ValueError("bad response")

        monkeypatch.setattr(module, "run_with_tools", boom)
        result = await run_deep_investigation(FakeState(), llm=object())
        assert isinstance(result, DeepInvestigationResult)

    async def test_budget_overrun_is_reported_as_partial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import asyncio

        async def slow(*args: Any, **kwargs: Any) -> dict[str, Any]:
            await asyncio.sleep(2)
            return {}

        monkeypatch.setattr(module, "run_with_tools", slow)
        monkeypatch.setattr(module, "BUDGET_SECONDS", 0.05)
        result = await run_deep_investigation(FakeState(), llm=object())

        assert result.over_budget and result.error

    async def test_disabled_reports_disabled_not_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "ENABLED", False)
        result = await run_deep_investigation(FakeState(), llm=object())
        assert result.error and "disabled" in result.error


class TestFindings:
    def test_coverage_gaps_are_never_stated_as_absence(self) -> None:
        """The whole reason the unavailable tools exist."""
        result = DeepInvestigationResult(strategy_id="endpoint-suspicious-process")
        result.pivots = ["process_activity", "historical_execution"]
        result.distinct_pivots = 2
        result.unavailable_data = ["mailbox_activity"]

        text = "\n".join(result.findings())
        assert "Coverage gap" in text
        assert "unknown rather than clear" in text

    def test_truncation_is_reported(self) -> None:
        result = DeepInvestigationResult(strategy_id="generic-triage", truncated=True)
        result.pivots = ["entity_timeline"]
        result.distinct_pivots = 1
        assert any("not exhausted" in f for f in result.findings())

    def test_depth_is_recorded_in_the_findings(self) -> None:
        result = DeepInvestigationResult(strategy_id="generic-triage")
        result.pivots = ["entity_timeline", "fleet_ioc_hunt"]
        result.distinct_pivots = 2
        result.iterations = 3
        text = "\n".join(result.findings())
        assert "2 distinct pivots" in text and "3 reasoning steps" in text


class TestPromptConstruction:
    async def test_the_strategy_reaches_the_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        loop = StubLoop(_trace(("process_activity", True)))
        monkeypatch.setattr(module, "run_with_tools", loop)
        await run_deep_investigation(FakeState(), llm=object())

        system = loop.calls[0]["system"]
        assert "Suspicious process on an endpoint" in system
        assert "Do not answer from the alert text alone" in system

    async def test_the_investigation_tools_are_bound(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without this the loop runs with enrichment tools only."""
        loop = StubLoop([])
        monkeypatch.setattr(module, "run_with_tools", loop)
        await run_deep_investigation(FakeState(), llm=object())

        names = set(loop.calls[0]["registry"].names())
        assert {"process_activity", "fleet_ioc_hunt", "entity_timeline"} <= names
        # And the original enrichment tools are still there.
        assert "enrich_ioc" in names

    def test_alert_summary_does_not_dump_raw_payloads(self) -> None:
        state = FakeState(
            raw_alert={
                "src_hostname": "WS-42",
                "raw_payload": "A" * 10_000,
                "user_name": "j.doe",
            }
        )
        rendered = _summarise_alert(state)
        assert "WS-42" in rendered and "j.doe" in rendered
        assert "AAAA" not in rendered, "raw payload leaked into the prompt"


def test_strategy_lookup_by_id() -> None:
    assert get_strategy("lateral-movement") is not None
    assert get_strategy("no-such-strategy") is None
