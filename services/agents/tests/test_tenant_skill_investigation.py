"""A tenant skill changes the plan, and the run records which version changed it.

Gap-closure Phase 6.1 and 6.2 gate, agents half.

The phase's "done when" has three clauses and the first and third are here:
a skill authored in the console **changes the investigation plan on matching
alerts**, and **replay shows the delta**. The second, the backtest report
being attached to the activation, is asserted in
``services/api/tests/test_tenant_skills.py`` where the lifecycle lives.

What makes these tests non-vacuous
-----------------------------------
Each one holds everything constant except the skill and asserts on **what the
model was handed**, not on what it answered. A verdict can be unchanged by a
plan that did change, and a plan can look changed because a scripted model was
scripted differently. So the system prompt is captured at the boundary and
compared between two runs of the same alert, and the built-in strategy the
alert would otherwise have selected is asserted by name, so "the skill won"
and "nothing selected anything" are told apart.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.context import tenant_skills as skills_module
from app.context.tenant_skills import ResolvedSkill, select_skill
from app.investigator import deep_investigation as deep_module
from app.investigator.strategies import KNOWN_PIVOTS, select_strategy
from app.models.state import InvestigationState

_TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")


def _row(
    skill_id: str = "finance-batch-powershell",
    *,
    version: int = 3,
    techniques: list[str] | None = None,
    rule_ids: list[str] | None = None,
    keywords: list[str] | None = None,
    sources: list[str] | None = None,
    plan: list[str] | None = None,
    pivots: list[str] | None = None,
) -> dict[str, Any]:
    """One row in the shape ``GET /tenant-skills/resolved/active`` serves."""
    return {
        "skill_id": skill_id,
        "version": version,
        "activated_at": "2026-09-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "body": {
            "id": skill_id,
            "name": "Finance nightly reconciliation batch",
            "owner": "soc-leads@example.invalid",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "applies_when": "Encoded PowerShell names svc_batch on a FIN-APP host.",
            "match": {
                "techniques": techniques if techniques is not None else ["T1059.001"],
                "rule_ids": rule_ids or [],
                "sources": sources or [],
                "keywords": keywords or [],
            },
            "guidance": "Finance runs a nightly reconciliation batch on FIN-APP-01 to FIN-APP-06 between 02:00 and 04:00 UTC.",
            "verdict_guidance": "Encoded PowerShell from svc_batch on a FIN-APP host inside the window is a benign true positive.",
            "required_evidence": ["The parent process is the scheduled task, not a browser."],
            "escalate_when": ["The host is not one of FIN-APP-01 to FIN-APP-06."],
            # ``if ... is None`` rather than ``or``: an empty list is a case
            # these tests deliberately construct, and ``or`` would silently
            # hand it the default instead.
            "plan": plan if plan is not None else ["Establish the process lineage, which decides this alert on its own."],
            "expected_pivots": pivots if pivots is not None else ["process_tree", "authentication_events"],
            "min_pivots": 2,
        },
    }


def _state() -> InvestigationState:
    return InvestigationState(
        incident_id=uuid.uuid4(),
        tenant_id=_TENANT,
        alert_summary="Encoded PowerShell launched on FIN-APP-03",
        raw_alert={"rule_id": "rule-encoded-powershell", "connector_type": "crowdstrike", "hostname": "FIN-APP-03"},
        mitre_mappings=["T1059.001"],
    )


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


class TestSelection:
    def test_a_rule_id_outranks_a_technique_which_outranks_a_source(self) -> None:
        """A rule id is the most specific claim an author can make.

        Scored rather than ordered, so the answer does not depend on which
        skill the API happened to return first.
        """
        rows = [
            _row("by-source", techniques=[], sources=["crowdstrike"]),
            _row("by-technique", techniques=["T1059.001"]),
            _row("by-rule", techniques=[], rule_ids=["rule-encoded-powershell"]),
        ]
        chosen = select_skill(
            rows,
            summary="Encoded PowerShell launched on FIN-APP-03",
            techniques=["T1059.001"],
            rule_id="rule-encoded-powershell",
            source="crowdstrike",
        )
        assert chosen is not None and chosen.skill_id == "by-rule"

    def test_a_sub_technique_alert_matches_a_skill_written_against_the_parent(self) -> None:
        chosen = select_skill([_row(techniques=["T1059"])], techniques=["T1059.001"])
        assert chosen is not None

    def test_nothing_matches_when_no_condition_holds(self) -> None:
        """No match must be no skill, not the first one in the list.

        A resolver that fell back to "any skill" would replace the strategy
        library for every alert in the tenant, which is exactly what the
        authoring-time refusal of an empty match block exists to prevent.
        """
        assert select_skill([_row(techniques=["T1566"])], techniques=["T1078"], summary="impossible travel") is None

    def test_a_tie_breaks_on_skill_id_and_not_on_list_order(self) -> None:
        """The same alert triaged twice must produce the same plan."""
        rows = [_row("zulu", techniques=["T1059.001"]), _row("alpha", techniques=["T1059.001"])]
        first = select_skill(rows, techniques=["T1059.001"])
        second = select_skill(list(reversed(rows)), techniques=["T1059.001"])
        assert first is not None and second is not None
        assert first.skill_id == second.skill_id == "alpha"

    def test_a_row_with_no_version_is_refused(self) -> None:
        """Provenance that resolves to nothing is worse than none.

        ``skill@v0`` would be recorded on the verdict and the version history
        would have no such row, so the record would look like provenance and
        answer nothing.
        """
        row = _row(version=0)
        assert select_skill([row], techniques=["T1059.001"]) is None

    def test_a_row_with_no_plan_is_refused(self) -> None:
        row = _row(plan=[])
        assert select_skill([row], techniques=["T1059.001"]) is None


# ---------------------------------------------------------------------------
# The skill as a strategy
# ---------------------------------------------------------------------------


class TestStrategyConversion:
    def test_the_skill_becomes_a_real_strategy_so_nothing_downstream_needs_a_special_case(self) -> None:
        skill = select_skill([_row()], techniques=["T1059.001"])
        assert skill is not None
        strategy = skill.strategy()
        assert strategy.expected_pivots == ("process_tree", "authentication_events")
        assert strategy.min_pivots == 2
        # Namespaced, so a skill called "generic-triage" cannot occupy the
        # fallback's identity in the depth cache or in a log line.
        assert strategy.id == "tenant:finance-batch-powershell"
        assert set(strategy.expected_pivots) <= KNOWN_PIVOTS

    def test_the_guidance_is_advisory_and_says_so(self) -> None:
        """A skill is a reason to consider a verdict, never a reason to stop looking.

        The wording is the control. Skill text is first-party, so it is not
        nonce-fenced; what stops it functioning as an instruction that
        overrides telemetry is that the block says it does not.
        """
        skill = select_skill([_row()], techniques=["T1059.001"])
        assert skill is not None
        block = skill.triage_guidance()
        assert "advisory" in block
        assert "never overrides direct evidence of compromise" in block
        # The evidence bar and the escalation conditions both reach the model,
        # or "the evidence required before a verdict" is a field nothing reads.
        assert "parent process is the scheduled task" in block
        assert "Escalate to a human" in block

    def test_the_provenance_carries_the_owner_beside_the_version(self) -> None:
        skill = select_skill([_row()], techniques=["T1059.001"])
        assert skill is not None
        assert skill.as_provenance() == {
            "skill_id": "finance-batch-powershell",
            "version": 3,
            "ref": "finance-batch-powershell@v3",
            "owner": "soc-leads@example.invalid",
            "activated_at": "2026-09-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }


# ---------------------------------------------------------------------------
# "Done when": the plan actually changes
# ---------------------------------------------------------------------------


class _ScriptedModel:
    """A model that calls nothing and answers once, capturing what it was handed."""

    def __init__(self) -> None:
        self.system: str = ""

    async def ainvoke(self, messages: Any, **_: Any) -> Any:  # pragma: no cover - not the path used
        raise AssertionError("the tool loop drives this model, not ainvoke")


@pytest.fixture
def _captured_system(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture the system prompt the tool loop is given, and answer immediately."""
    seen: list[str] = []

    async def _fake_loop(model: Any, *, system: str, user: str, registry: Any, max_iters: int) -> dict[str, Any]:
        seen.append(system)
        return {"content": "nothing to add", "tool_trace": [], "iterations": 1, "truncated": False}

    monkeypatch.setattr(deep_module, "run_with_tools", _fake_loop)
    monkeypatch.setattr(deep_module, "make_chat_model", lambda *a, **k: _ScriptedModel())
    return seen


def _no_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _empty(tenant_id: str, **_: Any) -> Any:
        class _Toolset:
            nonce = "AISOC-test"
            tools: list[Any] = []
            refusals: list[Any] = []

        return _Toolset()

    monkeypatch.setattr(deep_module, "build_mcp_toolset", _empty)


@pytest.mark.asyncio
async def test_done_when_a_skill_changes_the_investigation_plan_on_a_matching_alert(
    monkeypatch: pytest.MonkeyPatch,
    _captured_system: list[str],
) -> None:
    """The phase's acceptance clause, run twice over one alert.

    Everything is held constant except whether the tenant has an active skill.
    The assertion is on the plan the model was handed, because that is what
    "changes the investigation plan" means, and because a verdict could be
    identical either way.

    The built-in strategy is named explicitly so this cannot pass by the alert
    selecting nothing: without the skill this alert selects
    ``endpoint-suspicious-process``, and that is asserted rather than assumed.
    """
    _no_mcp(monkeypatch)
    state = _state()

    builtin = select_strategy(summary=state.alert_summary, techniques=list(state.mitre_mappings))
    assert builtin.id == "endpoint-suspicious-process"

    async def _no_skills(tenant_id: str) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(skills_module, "fetch_skills", _no_skills)
    before = await deep_module.run_deep_investigation(state, llm=_ScriptedModel())

    async def _one_skill(tenant_id: str) -> list[dict[str, Any]]:
        return [_row()]

    monkeypatch.setattr(skills_module, "fetch_skills", _one_skill)
    after = await deep_module.run_deep_investigation(_state(), llm=_ScriptedModel())

    # 1. The strategy that drove the run changed.
    assert before.strategy_id == "endpoint-suspicious-process"
    assert after.strategy_id == "tenant:finance-batch-powershell"

    # 2. The plan the model was handed changed, and specifically to the
    #    tenant's own steps rather than to some other built-in.
    assert len(_captured_system) == 2
    plan_before, plan_after = _captured_system
    assert "Establish the process lineage, which decides this alert on its own." in plan_after
    assert "Establish the process lineage, which decides this alert on its own." not in plan_before
    assert "Finance runs a nightly reconciliation batch" in plan_after

    # 3. The run records which version guided it, which is what makes a
    #    verdict explainable six months later.
    assert before.tenant_skill is None
    assert after.tenant_skill is not None
    assert after.tenant_skill["ref"] == "finance-batch-powershell@v3"
    assert after.as_dict()["tenant_skill"]["owner"] == "soc-leads@example.invalid"
    assert any("finance-batch-powershell@v3" in finding for finding in after.findings())


@pytest.mark.asyncio
async def test_an_unmatched_alert_leaves_strategy_selection_exactly_as_it_was(
    monkeypatch: pytest.MonkeyPatch,
    _captured_system: list[str],
) -> None:
    """A tenant with skills must not have every alert steered by one.

    The regression this guards is a resolver that returns "the only skill" for
    an alert nothing matched, which would silently replace the whole strategy
    library for that tenant.
    """
    _no_mcp(monkeypatch)

    async def _unrelated(tenant_id: str) -> list[dict[str, Any]]:
        return [_row("phishing-only", techniques=["T1566"])]

    monkeypatch.setattr(skills_module, "fetch_skills", _unrelated)
    result = await deep_module.run_deep_investigation(_state(), llm=_ScriptedModel())

    assert result.strategy_id == "endpoint-suspicious-process"
    assert result.tenant_skill is None


@pytest.mark.asyncio
async def test_an_unreachable_skill_store_falls_back_to_the_built_in_library(
    monkeypatch: pytest.MonkeyPatch,
    _captured_system: list[str],
) -> None:
    """Guidance is advisory; the investigation is not.

    Asserted rather than assumed because the obvious implementation lets the
    exception escape, and the symptom would be every investigation failing on
    a store that is merely slow.
    """
    _no_mcp(monkeypatch)

    async def _boom(tenant_id: str) -> list[dict[str, Any]]:
        raise RuntimeError("the API is down")

    monkeypatch.setattr(skills_module, "fetch_skills", _boom)
    result = await deep_module.run_deep_investigation(_state(), llm=_ScriptedModel())

    assert result.error is None
    assert result.strategy_id == "endpoint-suspicious-process"
    assert result.tenant_skill is None


@pytest.mark.asyncio
async def test_the_investigation_pins_the_version_triage_already_used(
    monkeypatch: pytest.MonkeyPatch,
    _captured_system: list[str],
) -> None:
    """One alert must not be triaged under v3 and investigated under v4.

    The fetch is cached, so a cache expiry between the two reads is exactly
    the window in which an activation splits them, and the verdict would then
    be explained by text that did not produce it.
    """
    _no_mcp(monkeypatch)

    async def _both_versions(tenant_id: str) -> list[dict[str, Any]]:
        return [_row(version=3), _row(version=4)]

    monkeypatch.setattr(skills_module, "fetch_skills", _both_versions)

    state = _state()
    state.tenant_skill = {"skill_id": "finance-batch-powershell", "version": 3, "ref": "finance-batch-powershell@v3"}
    result = await deep_module.run_deep_investigation(state, llm=_ScriptedModel())

    assert result.tenant_skill is not None
    assert result.tenant_skill["version"] == 3


def test_the_resolved_payload_reader_tolerates_a_bad_shape() -> None:
    """A malformed registry answer must not take an investigation down."""
    assert skills_module.skills_from_payload(None) == []
    assert skills_module.skills_from_payload({"skills": "not a list"}) == []
    assert skills_module.skills_from_payload({"skills": [_row(), "junk"]}) == [_row()]


def test_a_resolved_skill_renders_nothing_when_it_says_nothing_a_verdict_uses() -> None:
    """An empty block, not a heading saying the tenant has no conventions.

    Same reasoning as ``organisation_memory.render_for_prompt``: a heading
    reading "organisation skill: none" is a claim, and an absence of one is
    not.
    """
    bare = ResolvedSkill(
        skill_id="bare",
        version=1,
        name="Bare",
        owner="soc@example.invalid",
        plan=("Look at the host.",),
        expected_pivots=("process_activity",),
    )
    assert bare.triage_guidance() == ""
    # The plan still reaches the investigation: a skill with no prose is a
    # plan, which is the minimum a skill can be.
    assert "Look at the host." in bare.system_guidance()
