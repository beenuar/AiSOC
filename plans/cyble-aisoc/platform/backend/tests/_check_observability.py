"""Smoke test for t4-observability.

Seeds a single case with two agent traces (different providers) and a
couple of tool calls, then exercises:

- ``GET /cases/{id}/observability`` -> per-case roll-up with cost
- ``GET /cases/{id}/otel``          -> OpenTelemetry payload
- ``GET /observability/summary``    -> tenant-wide aggregate

The script is hermetic: it points the platform at a temp SQLite DB,
forces the deterministic mock LLM, and asserts on numeric output so
it can be added to CI alongside the other ``_check_*.py`` files.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

# ─── Hermetic setup ────────────────────────────────────────────────
_TMP = tempfile.NamedTemporaryFile(prefix="aisoc-obs-", suffix=".db", delete=False)
_TMP.close()
os.environ["AISOC_DB_PATH"] = _TMP.name
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"

# Make backend imports work no matter where the test is invoked from
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
    from app.main import app
    from app.models.case import Case, CaseStatus, Severity, Verdict
    from app.models.tool_call import RiskClass, ToolCall
    from app.models.trace import AgentName, AgentTrace, TraceStep

    init_db()
    tenant = "demo-tenant"

    # 1. Seed: one case, two traces with two different LLMs + two tool
    #    calls (one read, one risky/HITL).
    with session_scope() as s:
        case = Case(
            tenant_id=tenant,
            title="t4-observability seed case",
            severity=Severity.HIGH,
            status=CaseStatus.CLOSED_TRUE_POSITIVE,
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        s.add_all(
            [
                AgentTrace(
                    case_id=case.id,
                    tenant_id=tenant,
                    agent=AgentName.INVESTIGATOR,
                    step=TraceStep.DECISION,
                    summary="triage decision",
                    detail={
                        "provider": "anthropic",
                        "model": "claude-3-5-sonnet-20241022",
                    },
                    tokens_in=2400,
                    tokens_out=900,
                    latency_ms=2300,
                ),
                AgentTrace(
                    case_id=case.id,
                    tenant_id=tenant,
                    agent=AgentName.RESPONDER,
                    step=TraceStep.DECISION,
                    summary="containment plan",
                    detail={
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                    },
                    tokens_in=1200,
                    tokens_out=300,
                    latency_ms=900,
                ),
                ToolCall(
                    case_id=case.id,
                    tenant_id=tenant,
                    tool_name="cti.enrich_ioc",
                    integration="cyble-cti",
                    risk_class=RiskClass.READ,
                    success=True,
                    duration_ms=120,
                ),
                ToolCall(
                    case_id=case.id,
                    tenant_id=tenant,
                    tool_name="edr.isolate_host",
                    integration="sentinelone",
                    risk_class=RiskClass.WRITE_SIGNIFICANT,
                    success=True,
                    duration_ms=400,
                    hitl_required=True,
                ),
            ]
        )
        s.commit()
        case_id = case.id

    client = TestClient(app)

    # 2. Per-case observability
    obs = client.get(f"/cases/{case_id}/observability").json()
    if obs.get("tokens_in_total") != 3600:
        _bad("tokens_in_total mismatch", obs.get("tokens_in_total"))
        return 1
    if obs.get("tokens_out_total") != 1200:
        _bad("tokens_out_total mismatch", obs.get("tokens_out_total"))
        return 1
    if obs.get("cost_usd_total", 0) <= 0:
        _bad("cost_usd_total should be > 0", obs.get("cost_usd_total"))
        return 1
    if len(obs.get("by_agent", [])) != 2:
        _bad("expected 2 agents", obs.get("by_agent"))
        return 1
    if len(obs.get("by_tool", [])) != 2:
        _bad("expected 2 tools", obs.get("by_tool"))
        return 1

    # Investigator (Sonnet) should be more expensive than Responder (mini)
    by_agent = {a["agent"]: a for a in obs["by_agent"]}
    if by_agent["investigator"]["cost_usd"] <= by_agent["responder"]["cost_usd"]:
        _bad(
            "investigator cost should exceed responder cost",
            by_agent["investigator"]["cost_usd"],
            by_agent["responder"]["cost_usd"],
        )
        return 1

    # 3. OTel payload
    otel = client.get(f"/cases/{case_id}/otel").json()
    spans = otel["resourceSpans"][0]["scopeSpans"][0]["spans"]
    if len(spans) != 5:  # 1 root + 2 traces + 2 tools
        _bad("expected 5 OTel spans", len(spans))
        return 1
    span_names = {s["name"] for s in spans}
    if f"case.{case_id}" not in span_names:
        _bad("missing root span", span_names)
        return 1
    if "investigator.decision" not in span_names:
        _bad("missing investigator span", span_names)
        return 1
    if "edr.isolate_host" not in span_names:
        _bad("missing tool span", span_names)
        return 1
    # Each span must have a trace id and a span id
    for sp in spans:
        if not sp.get("traceId") or not sp.get("spanId"):
            _bad("span missing IDs", sp)
            return 1

    # 4. Tenant-wide summary
    summary = client.get("/observability/summary?window_hours=24").json()
    if summary.get("cases_observed") != 1:
        _bad("expected 1 case in summary", summary.get("cases_observed"))
        return 1
    if summary.get("cost_usd_total", 0) <= 0:
        _bad("summary cost should be > 0", summary.get("cost_usd_total"))
        return 1
    if summary.get("avg_cost_usd_per_case", 0) <= 0:
        _bad("avg_cost_usd_per_case should be > 0", summary.get("avg_cost_usd_per_case"))
        return 1

    # 5. Cross-tenant 404
    cross = client.get(
        f"/cases/{case_id}/observability",
        headers={"X-AISOC-Tenant": "other-tenant"},
    )
    # 403: anon mode refuses to pivot to a non-default tenant.
    # 404: in tenant-bound deployments the case isn't visible to other tenants.
    if cross.status_code not in (403, 404):
        _bad("cross-tenant should 403/404", cross.status_code, cross.text)
        return 1

    # 6. window_hours validation
    bad_window = client.get("/observability/summary?window_hours=0")
    if bad_window.status_code != 400:
        _bad("window_hours=0 should 400", bad_window.status_code)
        return 1

    print("OK t4-observability")
    print(json.dumps({
        "cost_usd": obs["cost_usd_total"],
        "spans": len(spans),
        "summary_cases": summary["cases_observed"],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
