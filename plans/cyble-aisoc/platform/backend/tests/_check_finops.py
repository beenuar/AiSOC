"""Smoke test for t5-finops.

Coverage:
  1. ``finops_rollup`` aggregates trace spend per day / agent / model.
  2. ``set_budget`` round-trips, rejects bad input.
  3. ``budget_status`` reports utilisation, threshold, projection.
  4. ``GET /finops/rollup`` returns a non-empty per-tenant payload.
  5. ROI math: cases resolved -> hours saved -> ROI dollars.
  6. ``GET /finops/leaderboard`` is MSSP-gated and ranks by cost-per-case.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

# ─── Hermetic setup ─────────────────────────────────────────────────
_TMP = tempfile.NamedTemporaryFile(prefix="aisoc-finops-", suffix=".db", delete=False)
_TMP.close()
os.environ["AISOC_DB_PATH"] = _TMP.name
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
os.environ.setdefault(
    "AISOC_JWT_SECRET_KEY", "test-secret-finops-do-not-use-in-prod"
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _bad(msg: str, *details: object) -> None:
    print(f"FAIL: {msg}")
    for d in details:
        print(f"  -> {d}")


def main() -> int:
    from fastapi.testclient import TestClient

    from app.db import init_db, session_scope
    from app.finops import (
        budget_status,
        finops_rollup,
        set_budget,
    )
    from app.main import app
    from app.models.case import Case, CaseStatus, Severity, Verdict
    from app.models.trace import AgentName, AgentTrace, TraceStep
    from app.mssp import add_tenant_link, upsert_partner
    from app.security.jwt import issue_tenant_token

    init_db()
    client = TestClient(app)

    tenant_a = "finops-tenant-a"
    tenant_b = "finops-tenant-b"
    mssp_tid = "finops-mssp"

    # Seed: traces for tenant_a (Sonnet + mini), 2 closed cases.
    now = datetime.now(timezone.utc)
    with session_scope() as s:
        case_tp = Case(
            tenant_id=tenant_a,
            title="closed-tp",
            severity=Severity.HIGH,
            status=CaseStatus.CLOSED_TRUE_POSITIVE,
            verdict=Verdict.TRUE_POSITIVE,
        )
        case_fp = Case(
            tenant_id=tenant_a,
            title="closed-fp",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_FALSE_POSITIVE,
            verdict=Verdict.FALSE_POSITIVE,
        )
        case_open = Case(
            tenant_id=tenant_a,
            title="still-open",
            severity=Severity.MEDIUM,
            status=CaseStatus.INVESTIGATING,
            verdict=Verdict.UNKNOWN,
        )
        # tenant_b: cheap mini-only, lots of resolved cases (good ROI).
        case_b1 = Case(
            tenant_id=tenant_b,
            title="b1",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_BENIGN,
            verdict=Verdict.BENIGN,
        )
        case_b2 = Case(
            tenant_id=tenant_b,
            title="b2",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_BENIGN,
            verdict=Verdict.BENIGN,
        )
        s.add_all([case_tp, case_fp, case_open, case_b1, case_b2])
        s.commit()
        s.refresh(case_tp)
        s.refresh(case_fp)
        s.refresh(case_open)
        s.refresh(case_b1)
        s.refresh(case_b2)

        # tenant_a traces: Sonnet (expensive) + mini (cheap)
        s.add_all(
            [
                AgentTrace(
                    case_id=case_tp.id,
                    tenant_id=tenant_a,
                    agent=AgentName.INVESTIGATOR,
                    step=TraceStep.DECISION,
                    summary="",
                    detail={"provider": "anthropic", "model": "claude-3-5-sonnet-20241022"},
                    tokens_in=4000,
                    tokens_out=1500,
                    latency_ms=2300,
                ),
                AgentTrace(
                    case_id=case_fp.id,
                    tenant_id=tenant_a,
                    agent=AgentName.TRIAGER,
                    step=TraceStep.DECISION,
                    summary="",
                    detail={"provider": "openai", "model": "gpt-4o-mini"},
                    tokens_in=1500,
                    tokens_out=400,
                    latency_ms=400,
                ),
                AgentTrace(
                    case_id=case_open.id,
                    tenant_id=tenant_a,
                    agent=AgentName.RESPONDER,
                    step=TraceStep.DECISION,
                    summary="",
                    detail={"provider": "openai", "model": "gpt-4o-mini"},
                    tokens_in=600,
                    tokens_out=200,
                    latency_ms=300,
                ),
            ]
        )
        # tenant_b: tiny mini calls only — cheap.
        s.add_all(
            [
                AgentTrace(
                    case_id=case_b1.id,
                    tenant_id=tenant_b,
                    agent=AgentName.TRIAGER,
                    step=TraceStep.DECISION,
                    summary="",
                    detail={"provider": "openai", "model": "gpt-4o-mini"},
                    tokens_in=300,
                    tokens_out=80,
                    latency_ms=200,
                ),
                AgentTrace(
                    case_id=case_b2.id,
                    tenant_id=tenant_b,
                    agent=AgentName.TRIAGER,
                    step=TraceStep.DECISION,
                    summary="",
                    detail={"provider": "openai", "model": "gpt-4o-mini"},
                    tokens_in=300,
                    tokens_out=80,
                    latency_ms=200,
                ),
            ]
        )
        s.commit()

    # ── 1. finops_rollup ──────────────────────────────────────────
    rollup = finops_rollup(tenant_a, window_days=30)
    if rollup.cost_usd_total <= 0:
        _bad("rollup cost should be > 0", rollup.cost_usd_total)
        return 1
    if rollup.tokens_in_total != 6100:
        _bad("tokens_in_total mismatch", rollup.tokens_in_total)
        return 1
    if not rollup.daily:
        _bad("daily breakdown empty")
        return 1
    if not rollup.by_agent or not rollup.by_model:
        _bad("missing by_agent/by_model")
        return 1
    # By-model should rank Sonnet (much higher per-token price) above mini.
    top_model = rollup.by_model[0]
    if top_model.provider != "anthropic":
        _bad("expected anthropic to be the top-cost model", rollup.by_model)
        return 1
    # Investigator is the only Sonnet user => most expensive agent.
    top_agent = rollup.by_agent[0]
    if top_agent.agent != "investigator":
        _bad("expected investigator to be top-cost agent", rollup.by_agent)
        return 1

    # ── 2. ROI math ────────────────────────────────────────────────
    # 2 closed cases @ 0.75 hrs each = 1.5 hrs saved.
    if abs(rollup.roi.human_hours_saved - 1.5) > 1e-6:
        _bad("ROI hours_saved", rollup.roi.human_hours_saved)
        return 1
    if rollup.roi.cases_resolved != 2:
        _bad("cases_resolved", rollup.roi.cases_resolved)
        return 1

    # ── 3. set_budget round-trip + validation ─────────────────────
    bad_budget_caught = False
    try:
        set_budget(tenant_id=tenant_a, monthly_usd=-5.0)
    except ValueError:
        bad_budget_caught = True
    if not bad_budget_caught:
        _bad("negative monthly_usd should ValueError")
        return 1
    set_budget(
        tenant_id=tenant_a,
        monthly_usd=10.0,
        alert_threshold=0.5,
        analyst_hourly_usd=200.0,
        alert_target="slack:#sec-finops",
    )
    status = budget_status(tenant_a)
    if status is None:
        _bad("budget_status returned None after set_budget")
        return 1
    if status.monthly_usd != 10.0:
        _bad("budget monthly_usd not persisted", status)
        return 1
    # The seed costs sit well below $10 and won't trip the cap.
    if status.over_cap:
        _bad("seed should not have blown the cap", status.spent_usd)
        return 1

    # Force a tiny budget to trigger over_threshold + over_cap.
    set_budget(tenant_id=tenant_a, monthly_usd=0.001, alert_threshold=0.5)
    status_tight = budget_status(tenant_a)
    if not status_tight.over_threshold:
        _bad("tight budget should be over threshold", status_tight)
        return 1

    # ── 4. /finops/rollup endpoint ────────────────────────────────
    resp = client.get(
        "/finops/rollup?window_days=30",
        headers={"X-AISOC-Tenant": tenant_a} if False else {},
    )
    if resp.status_code != 200:
        _bad("/finops/rollup did not 200", resp.status_code, resp.text)
        return 1
    body = resp.json()
    if "cost_usd_total" not in body or "roi" not in body or "budget" not in body:
        _bad("missing rollup keys", list(body.keys()))
        return 1

    # ── 5. /finops/budget GET + PUT ───────────────────────────────
    upsert = client.put(
        "/finops/budget",
        json={
            "monthly_usd": 100.0,
            "alert_threshold": 0.6,
            "analyst_hourly_usd": 90.0,
        },
    )
    if upsert.status_code != 200:
        _bad("budget PUT did not 200", upsert.status_code, upsert.text)
        return 1
    get_resp = client.get("/finops/budget").json()
    if get_resp.get("monthly_usd") != 100.0:
        _bad("budget GET did not return updated value", get_resp)
        return 1

    # 5a. Bad request: alert_threshold > 1.
    bad = client.put(
        "/finops/budget",
        json={"alert_threshold": 1.5},
    )
    if bad.status_code != 422:
        _bad("alert_threshold > 1 should 422", bad.status_code)
        return 1

    # ── 6. /finops/leaderboard MSSP gating ────────────────────────
    no_mssp = client.get("/finops/leaderboard")
    if no_mssp.status_code != 403:
        _bad("non-MSSP leaderboard should 403", no_mssp.status_code, no_mssp.text)
        return 1

    # Build a real MSSP that can see both tenants.
    upsert_partner(tenant_id=mssp_tid, display_name="FinOps MSSP", tenant_quota=10)
    add_tenant_link(mssp_tenant_id=mssp_tid, customer_tenant_id=tenant_a)
    add_tenant_link(mssp_tenant_id=mssp_tid, customer_tenant_id=tenant_b)
    mssp_token = issue_tenant_token(
        tenant_id=tenant_a,
        subject="mssp-analyst@finops",
        roles=["analyst"],
        mssp_parent_tenant_id=mssp_tid,
        allowed_tenants=[tenant_a, tenant_b],
    )
    leaderboard = client.get(
        "/finops/leaderboard?window_days=30",
        headers={"Authorization": f"Bearer {mssp_token}"},
    )
    if leaderboard.status_code != 200:
        _bad("leaderboard should 200 for MSSP", leaderboard.status_code, leaderboard.text)
        return 1
    rows = leaderboard.json()["leaderboard"]
    if len(rows) != 2:
        _bad("expected 2 tenants in leaderboard", rows)
        return 1
    # Both should appear, but tenant_a (one Sonnet trace, 2 closed cases)
    # should have a higher cost-per-case than tenant_b (mini-only, 2 closed cases).
    a_row = next(r for r in rows if r["tenant_id"] == tenant_a)
    b_row = next(r for r in rows if r["tenant_id"] == tenant_b)
    if a_row["cost_per_case_usd"] is None or b_row["cost_per_case_usd"] is None:
        _bad("cost_per_case_usd should be numeric", a_row, b_row)
        return 1
    if a_row["cost_per_case_usd"] <= b_row["cost_per_case_usd"]:
        _bad(
            "tenant_a should be more expensive per case than tenant_b",
            a_row, b_row,
        )
        return 1
    # Most expensive ranked first.
    if rows[0]["tenant_id"] != tenant_a:
        _bad("leaderboard ranking", [r["tenant_id"] for r in rows])
        return 1

    print("OK t5-finops")
    print(json.dumps({
        "tenant_a_cost": rollup.cost_usd_total,
        "tenant_a_roi_hours": rollup.roi.human_hours_saved,
        "leaderboard_top": rows[0]["tenant_id"],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
