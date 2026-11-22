"""The hypothesis scheduler selects, records, gates and marks (WS6.2–6.4).

Driven with a scripted asyncpg double and a stubbed campaign runner: what
this file pins is the SELECTION machinery — the per-tenant opt-in, the
approval gate (an unapproved request is never selected — WS6.3's
requirement carried into campaigns), the reason recorded BEFORE the
campaign, the once-only `campaigned_at` marking, the per-tick cap, and the
leads → verification → proposal hand-off order.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.hunt import hypothesis_scheduler as sched
from app.hunt.campaign import CampaignResult

TENANT = str(uuid.uuid4())
REQUEST_ID = str(uuid.uuid4())


class _FakeConn:
    """Answers the scheduler's four statements from scripted rows."""

    def __init__(self, policies: list[dict[str, Any]], requests: list[dict[str, Any]]) -> None:
        self.policies = policies
        self.requests = requests
        self.executed: list[tuple[str, tuple]] = []

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        if "hunt_campaign_policies" in sql:
            return self.policies
        if "hunt_source_reports" in sql:
            # The SQL itself carries the approval gate; the double honours it
            # the way the database would.
            limit = args[-1]
            eligible = [r for r in self.requests if r["approved_at"] and not r["campaigned_at"]]
            return eligible[: int(limit)]
        raise AssertionError(f"unexpected fetch: {sql[:60]}")

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append((sql.strip().split()[0] + " " + sql.strip().split()[2], args))
        if "campaigned_at = NOW()" in sql:
            for r in self.requests:
                if str(r["id"]) == str(args[1]):
                    r["campaigned_at"] = "now"

    async def close(self) -> None:
        return None


def _policy(max_per_tick: int = 2) -> dict[str, Any]:
    return {
        "tenant_id": TENANT,
        "cadence_minutes": 60,
        "budgets": {"max_steps": 2},
        "max_per_tick": max_per_tick,
    }


def _request(approved: bool = True, campaigned: bool = False) -> dict[str, Any]:
    # The real table's columns: provenance, never the report body.
    return {
        "id": REQUEST_ID,
        "url": "https://vendor.example/report/certutil-campaign",
        "content_sha256": "a" * 64,
        "indicator_count": 7,
        "technique_count": 3,
        "approved_at": "2026-11-20" if approved else None,
        "campaigned_at": "done" if campaigned else None,
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_DSN", "postgresql://scripted/by-the-fake")
    monkeypatch.setattr(sched.ledger_module, "record_event", AsyncMock())


def _campaign_result(outcome: str = "leads") -> CampaignResult:
    result = CampaignResult(hypothesis="h", outcome=outcome)
    if outcome == "leads":
        result.leads = [{"step": 1, "question": "h", "findings": 3, "sample": []}]
    return result


@pytest.mark.asyncio
async def test_an_approved_request_runs_once_with_its_reason_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _FakeConn([_policy()], [_request(approved=True)])
    run = AsyncMock(return_value=_campaign_result("no_finding"))
    monkeypatch.setattr(sched, "run_campaign", run)
    monkeypatch.setattr(sched, "make_chat_model", lambda *a, **k: object())

    async def _connect(_dsn: str) -> _FakeConn:
        return conn

    summary = await sched.run_once(connect=_connect)
    assert summary.campaigns_run == 1
    # The reason was recorded BEFORE the campaign ran.
    recorded = sched.ledger_module.record_event.await_args_list[0].kwargs  # type: ignore[attr-defined]  # the autouse fixture installed an AsyncMock
    assert recorded["kind"] == "campaign_selected"
    assert "approved this report-sourced hunt request" in recorded["payload"]["reason"]
    assert "vendor.example/report" in recorded["payload"]["hypothesis"], (
        "the hypothesis is composed from the report row's own provenance columns"
    )
    # The request was marked, so the next tick selects nothing.
    second = await sched.run_once(connect=_connect)
    assert second.campaigns_run == 0


@pytest.mark.asyncio
async def test_an_unapproved_request_is_never_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    """WS6.3's gate carried into campaigns: approval precedes execution."""
    conn = _FakeConn([_policy()], [_request(approved=False)])
    run = AsyncMock()
    monkeypatch.setattr(sched, "run_campaign", run)

    async def _connect(_dsn: str) -> _FakeConn:
        return conn

    summary = await sched.run_once(connect=_connect)
    assert summary.selected == 0
    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_per_tick_cap_bounds_launches(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = [dict(_request(), id=str(uuid.uuid4())) for _ in range(5)]
    conn = _FakeConn([_policy(max_per_tick=2)], requests)
    run = AsyncMock(return_value=_campaign_result("no_finding"))
    monkeypatch.setattr(sched, "run_campaign", run)
    monkeypatch.setattr(sched, "make_chat_model", lambda *a, **k: object())

    async def _connect(_dsn: str) -> _FakeConn:
        return conn

    summary = await sched.run_once(connect=_connect)
    assert summary.campaigns_run == 2


@pytest.mark.asyncio
async def test_leads_flow_to_verification_then_proposal(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConn([_policy()], [_request()])
    order: list[str] = []
    run = AsyncMock(return_value=_campaign_result("leads"))
    monkeypatch.setattr(sched, "run_campaign", run)
    monkeypatch.setattr(sched, "make_chat_model", lambda *a, **k: object())

    async def _verify(result: CampaignResult, *, tenant_id: str, llm: Any = None) -> list:
        order.append("verify")
        return result.leads

    async def _propose(result: CampaignResult, *, tenant_id: str) -> str:
        order.append("propose")
        result.proposal_id = "p-1"
        return "p-1"

    monkeypatch.setattr(sched, "verify_leads", _verify)
    monkeypatch.setattr(sched, "propose_detection", _propose)

    async def _connect(_dsn: str) -> _FakeConn:
        return conn

    summary = await sched.run_once(connect=_connect)
    assert order == ["verify", "propose"], "leads are verified before anything is proposed"
    assert summary.proposals_opened == 1


@pytest.mark.asyncio
async def test_verify_leads_caps_the_investigator(monkeypatch: pytest.MonkeyPatch) -> None:
    result = CampaignResult(hypothesis="h", outcome="leads")
    result.leads = [{"step": n, "question": f"q{n}", "findings": 10 - n, "sample": []} for n in range(6)]
    launched: list[Any] = []

    async def _fake_investigation(state: Any, *, llm: Any = None) -> Any:
        launched.append(state)

        class _R:
            strategy_id = "test"

        return _R()

    verified = await sched.verify_leads(result, tenant_id=TENANT, runner=_fake_investigation)
    assert len(launched) == sched.MAX_LEADS_VERIFIED
    assert all(lead["verification"]["run"] for lead in verified)
    assert "HUNT LEAD" in launched[0].alert_summary
