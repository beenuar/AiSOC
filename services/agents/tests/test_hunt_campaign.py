"""Bounded campaigns: budgets gate steps, questions must be new.

Driven through the real campaign loop with a scripted ``invoke`` — the same
injection seam the single-hunt suite uses — and the real plan validator, so
every plan in here is one the platform would actually compile. The model
never writes query text anywhere in this file, which is also what
``scripts/check_hunt_agent_boundary.py`` holds for the modules themselves.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.hunt import agent as hunt_agent
from app.hunt.campaign import (
    CampaignBudgets,
    build_step_messages,
    run_campaign,
    summarize_findings,
)
from app.hunt.plan import validate_plan
from app.privacy import Pseudonymizer

TENANT = "11111111-1111-1111-1111-111111111111"

PLAN_A = {
    "clauses": [{"field": "user_name", "operator": "eq", "value": "svc-backup"}],
    "lookback_hours": 24,
}
PLAN_B = {
    "clauses": [{"field": "dst_port", "operator": "eq", "value": 4444}],
    "lookback_hours": 24,
}


def _scripted_invoke(replies: list[str]):
    calls: list[list[dict[str, str]]] = []

    async def _invoke(messages: list[dict[str, str]]) -> str:
        calls.append(messages)
        return replies[min(len(calls) - 1, len(replies) - 1)]

    _invoke.calls = calls  # type: ignore[attr-defined]
    return _invoke


def _executor(rows_by_call: list[list[dict[str, Any]]]):
    """Stub the API leg only: the plan is still the validator's output."""
    executed: list[Any] = []

    async def _execute(plan, *, ledger=None, run_id=None, tenant_id=""):
        executed.append(plan)
        rows = rows_by_call[min(len(executed) - 1, len(rows_by_call) - 1)]
        result = hunt_agent.HuntAgentResult(hypothesis=plan.hypothesis, plan=plan)
        result.checked = True
        result.findings = rows
        result.rows_scanned = len(rows)
        return result

    _execute.executed = executed  # type: ignore[attr-defined]
    return _execute


@pytest.mark.asyncio
async def test_a_two_step_campaign_carries_summaries_not_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),  # step 1: the single hunt's plan
            json.dumps({"question": "which destinations did that account reach?", "plan": PLAN_B}),
            json.dumps({"done": True, "reason": "destinations identified"}),
        ]
    )
    execute = _executor(
        [
            [{"user_name": "svc-backup", "src_hostname": "fin-ws-07.corp.example.com"}] * 3,
            [{"dst_port": 4444}] * 2,
        ]
    )
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("did svc-backup log in interactively?", invoke=invoke, tenant_id=TENANT)

    assert result.outcome == "leads"
    assert [s.findings for s in result.steps] == [3, 2]
    assert result.leads[0]["findings"] == 3, "leads rank by finding count"
    # The second step's prompt carried the first step's SUMMARY — counts and
    # scrubbed top values — and not the rows.
    second_prompt = json.dumps(invoke.calls[1])
    assert "row_count" in second_prompt
    assert "fin-ws-07.corp.example.com" not in second_prompt, "the hostname reached the model raw; the egress pseudonymizer is the boundary"
    assert result.coverage["fields_searched"] == ["dst_port", "user_name"]
    assert result.coverage["rows_scanned"] == 5


@pytest.mark.asyncio
async def test_an_exhausted_step_budget_prevents_the_step(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),
            json.dumps({"question": "a second question?", "plan": PLAN_B}),
        ]
    )
    execute = _executor([[{"user_name": "svc-backup"}]])
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT, budgets=CampaignBudgets(max_steps=1))
    assert len(result.steps) == 1, "the budget gates BEFORE the step, so step two never ran"
    assert "step budget exhausted" in result.stop_reason
    assert len(execute.executed) == 1


@pytest.mark.asyncio
async def test_a_repeated_question_stops_the_campaign(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),
            json.dumps({"question": "HYPOTHESIS", "plan": PLAN_B}),
        ]
    )
    execute = _executor([[{"user_name": "x"}]])
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT)
    assert "repeated an already-asked question" in result.stop_reason
    assert len(result.steps) == 1


@pytest.mark.asyncio
async def test_an_identical_plan_under_a_new_question_stops_too(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),
            json.dumps({"question": "genuinely new words, same plan?", "plan": PLAN_A}),
        ]
    )
    execute = _executor([[{"user_name": "x"}]])
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT)
    assert "identical to an earlier step's" in result.stop_reason


@pytest.mark.asyncio
async def test_no_finding_carries_the_coverage_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),
            json.dumps({"done": True, "reason": "nothing further to ask"}),
        ]
    )
    execute = _executor([[]])
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT)
    assert result.outcome == "no_finding"
    assert result.coverage["sources"] == ["event lake (aisoc.raw_events) via the governed hunt-plan executor"]
    assert result.coverage["fields_searched"] == ["user_name"]
    assert result.coverage["max_lookback_hours"] == 24, "a no-finding without what was searched is 'clean', which nobody measured"


@pytest.mark.asyncio
async def test_a_failed_first_step_is_could_not_check(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = _scripted_invoke(["this reply has no json at all", "still none"])
    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT)
    assert result.outcome == "could_not_check"
    assert result.unavailable_reason


@pytest.mark.asyncio
async def test_two_refused_step_plans_in_a_row_hold_the_one_correction_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_plan = {"clauses": [{"field": "not_a_real_field", "operator": "eq", "value": "x"}], "lookback_hours": 24}
    invoke = _scripted_invoke(
        [
            json.dumps(PLAN_A),
            json.dumps({"question": "q2?", "plan": bad_plan}),
            json.dumps({"question": "q3?", "plan": bad_plan}),
        ]
    )
    execute = _executor([[{"user_name": "x"}]])
    monkeypatch.setattr(hunt_agent, "execute_plan", execute)

    result = await run_campaign("hypothesis", invoke=invoke, tenant_id=TENANT)
    assert "one-correction rule" in result.stop_reason
    assert len(result.steps) == 1


def test_summaries_scrub_values_and_keep_counts() -> None:
    plan = validate_plan(PLAN_A, hypothesis="h")
    rows = [{"user_name": "mallory@example.com"}] * 4 + [{"user_name": "alice@example.com"}]
    summary = summarize_findings(plan, rows, scrubber=Pseudonymizer(tenant_id=TENANT))
    assert summary["row_count"] == 5
    rendered = json.dumps(summary)
    assert "mallory@example.com" not in rendered
    top = summary["top_values"]["user_name"]
    assert top[0][1] == 4, "counts survive scrubbing; a count is not an entity"


def test_step_messages_keep_the_untrusted_fence() -> None:
    messages = build_step_messages("hypothesis text", [])
    assert messages[0]["role"] == "system"
    assert "UNTRUSTED INPUT" in messages[1]["content"]
