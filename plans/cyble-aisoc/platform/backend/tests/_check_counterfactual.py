"""Smoke check for counterfactual why-not explanations (t4-counterfactual).

Drives ``app/explain/counterfactual.py`` and ``GET /cases/{id}/why-not``:

  * Returns a deterministic, evidence-grounded fact list for a case.
  * Surfaces a verdict-fact for every classified case.
  * Skipped containment tools produce a "why was this not executed?"
    fact, with the evidence list pulled from the case state.
  * A DENIED HITL request surfaces "analyst denied: <reason>".
  * Aggregates ``facts_total`` / ``facts_appropriate`` /
    ``facts_questionable`` for the audit traffic-light.
  * Returns 404 for missing or cross-tenant cases.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_counterfactual.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-cf-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_ACTOR_PROFILER_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BAS_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_EXPOSURE_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BRAND_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_SUPPLY_CHAIN_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
    os.environ["AISOC_DEFAULT_TENANT"] = "demo-tenant"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.db import init_db, session_scope  # noqa: E402
from app.explain import explain_case  # noqa: E402
from app.main import app  # noqa: E402
from app.models.case import Case, CaseStatus, Severity, Verdict  # noqa: E402
from app.models.hitl import (  # noqa: E402
    HitlChannel,
    HitlRequest,
    HitlState,
)
from app.models.tool_call import RiskClass, ToolCall  # noqa: E402
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402

init_db()


_PASSES: list[str] = []
_FAILS: list[tuple[str, str]] = []


def _ok(name: str) -> None:
    _PASSES.append(name)
    print(f"  PASS  {name}")


def _bad(name: str, msg: str) -> None:
    _FAILS.append((name, msg))
    print(f"  FAIL  {name}: {msg}")


def main() -> int:
    print(f"DB: {DB_PATH}")
    client = TestClient(app)

    # ─── Build a true-positive case with a host + a denied isolation ───
    with session_scope() as session:
        case = Case(
            tenant_id="demo-tenant",
            title="Suspicious lateral movement",
            severity=Severity.HIGH,
            status=CaseStatus.CLOSED_TRUE_POSITIVE,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.92,
            mitre_techniques=["T1021.002"],
            affected_users=["svc-deploy"],
            affected_hosts=["DESKTOP-12X3"],
            iocs=["198.51.100.42"],
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        case_id = case.id

        # An investigator THINK trace and a responder DECISION trace.
        session.add_all(
            [
                AgentTrace(
                    case_id=case_id,
                    tenant_id="demo-tenant",
                    agent=AgentName.INVESTIGATOR,
                    step=TraceStep.DECISION,
                    summary="Confirmed C2 beacon — recommend isolation",
                    detail={"confidence": 0.92},
                ),
                AgentTrace(
                    case_id=case_id,
                    tenant_id="demo-tenant",
                    agent=AgentName.RESPONDER,
                    step=TraceStep.HITL_REQUEST,
                    summary="Awaiting analyst approval to isolate",
                    detail={"tool_name": "edr.isolate_host"},
                ),
            ]
        )

        # A successful enrichment tool call (READ — should NOT show up
        # in the why-not list).
        session.add(
            ToolCall(
                tenant_id="demo-tenant",
                case_id=case_id,
                tool_name="cti.enrich_ioc",
                integration="cyble-cti",
                risk_class=RiskClass.READ,
                params={"ioc": "198.51.100.42"},
                result={"verdict": "malicious"},
                success=True,
            )
        )

        # A HITL request that the analyst DENIED for edr.isolate_host —
        # the explainer must surface "denied by <who>: <reason>".
        session.add(
            HitlRequest(
                case_id=case_id,
                tenant_id="demo-tenant",
                agent=str(AgentName.RESPONDER),
                tool_name="edr.isolate_host",
                integration="sentinelone",
                risk_class=RiskClass.WRITE_SIGNIFICANT.value,
                params={"host": "DESKTOP-12X3", "reason": "C2 beacon"},
                rationale="Confirmed C2",
                blast_radius={},
                state=HitlState.DENIED,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc),
                decided_at=datetime.now(timezone.utc),
                decided_by="analyst@acme.com",
                decided_channel=HitlChannel.CONSOLE,
                decision_reason="user already removed laptop from network manually",
                notifications=[],
            )
        )
        session.commit()

    # ─── Direct API ──────────────────────────────────────────────────
    explanation = explain_case(case_id=case_id, tenant_id="demo-tenant")
    if explanation is None:
        _bad("explain_case returns object", "got None")
        return 1
    if explanation.facts_total == 0:
        _bad("facts_total > 0", "got 0")
        return 1
    _ok(
        f"explain_case: facts_total={explanation.facts_total} "
        f"appropriate={explanation.facts_appropriate} "
        f"questionable={explanation.facts_questionable}"
    )

    # Verdict fact present
    verdict_facts = [f for f in explanation.facts if f.category == "verdict"]
    if not verdict_facts:
        _bad("verdict fact present", "no verdict fact")
        return 1
    if (
        "true positive" not in verdict_facts[0].question.lower()
        and "malicious" not in verdict_facts[0].answer.lower()
    ):
        _bad(
            "verdict fact references TP / malicious intent",
            verdict_facts[0].answer,
        )
        return 1
    _ok(f"verdict fact: '{verdict_facts[0].question}'")

    # The DENIED HITL must produce a 'tool_blocked' fact citing the analyst
    blocked_facts = [
        f for f in explanation.facts
        if f.tool_name == "edr.isolate_host" and f.category == "tool_blocked"
    ]
    if not blocked_facts:
        _bad("denied HITL surfaces tool_blocked fact", "no fact")
        return 1
    fact = blocked_facts[0]
    if "analyst@acme.com" not in fact.answer:
        _bad("decided_by surfaced in answer", fact.answer)
        return 1
    if "user already removed laptop" not in fact.answer:
        _bad("decision_reason surfaced in answer", fact.answer)
        return 1
    _ok(f"tool_blocked fact cites analyst + reason: '{fact.answer[:80]}...'")

    # ─── HTTP API ───────────────────────────────────────────────────
    print("\n[case] GET /cases/{id}/why-not")
    resp = client.get(f"/cases/{case_id}/why-not")
    if resp.status_code != 200:
        _bad("GET /cases/{id}/why-not 200", f"got {resp.status_code}: {resp.text[:200]}")
        return 1
    body = resp.json()
    required = {
        "case_id",
        "tenant_id",
        "verdict",
        "severity",
        "status",
        "facts",
        "facts_total",
        "facts_appropriate",
        "facts_questionable",
    }
    if not required.issubset(body.keys()):
        _bad("explanation shape", f"missing={required - body.keys()}")
        return 1
    _ok(f"explanation shape (facts_total={body['facts_total']})")

    # Cross-tenant 404
    print("\n[case] cross-tenant 404")
    with session_scope() as session:
        other_case = Case(
            tenant_id="other-tenant",
            title="other tenant case",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_BENIGN,
            verdict=Verdict.BENIGN,
        )
        session.add(other_case)
        session.commit()
        session.refresh(other_case)
        other_id = other_case.id
    resp = client.get(f"/cases/{other_id}/why-not")
    if resp.status_code != 404:
        _bad("cross-tenant case -> 404", f"got {resp.status_code}")
        return 1
    _ok("cross-tenant case -> 404")

    # 404 for missing
    resp = client.get("/cases/9999999/why-not")
    if resp.status_code != 404:
        _bad("missing case -> 404", f"got {resp.status_code}")
        return 1
    _ok("missing case -> 404")

    # ─── False-positive case has appropriate-only facts ─────────────
    print("\n[case] false-positive case is all-green")
    with session_scope() as session:
        fp_case = Case(
            tenant_id="demo-tenant",
            title="benign printer noise",
            severity=Severity.LOW,
            status=CaseStatus.CLOSED_FALSE_POSITIVE,
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.99,
            affected_hosts=["PRN-3F"],
        )
        session.add(fp_case)
        session.commit()
        session.refresh(fp_case)
        fp_id = fp_case.id

    fp_explanation = explain_case(case_id=fp_id, tenant_id="demo-tenant")
    if fp_explanation is None:
        _bad("FP explanation exists", "got None")
        return 1
    if fp_explanation.facts_questionable != 0:
        _bad(
            "FP case all appropriate",
            f"questionable={fp_explanation.facts_questionable} facts={[f.answer for f in fp_explanation.facts if not f.was_appropriate]}",
        )
        return 1
    _ok(
        f"FP case all-appropriate "
        f"(facts={fp_explanation.facts_total} questionable=0)"
    )

    return 0


if __name__ == "__main__":
    rc = main()
    print(f"\n{len(_PASSES)} pass, {len(_FAILS)} fail")
    if _FAILS:
        for name, msg in _FAILS:
            print(f"  FAIL: {name} — {msg}")
    sys.exit(rc)
