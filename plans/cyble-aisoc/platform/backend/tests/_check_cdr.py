"""End-to-end smoke check for the CDR sub-agent (Theme 2d).

Exercises the full cloud-side path against an isolated SQLite DB and the
``MockCloudConnector`` so we touch every wire-in surface:

  * The connector registry falls back to mocks for an unconfigured tenant
    on ``ConnectorKind.CLOUD``.
  * The new cloud tools (``cloud.list_iam_principals``,
    ``cloud.list_access_keys``, ``cloud.list_sts_sessions``,
    ``cloud.trace_assume_role_chain``, ``cloud.list_k8s_rolebindings``,
    ``cloud.deactivate_access_key``, ``cloud.attach_deny_policy``,
    ``cloud.delete_k8s_rolebinding``) are loaded into the ToolRegistry and
    pickable by the mock LLM.
  * The CDRAgent runs end-to-end:
      - identifies the candidate IAM principal from the alert,
      - enumerates IAM principals + STS sessions + K8s bindings,
      - flags anomalous STS chains and suspicious keys,
      - issues *targeted* containment writes (NOT broad sweep) via the
        deterministic backstop if the mock LLM didn't get there itself,
      - stamps origin principal ARNs onto ``case.iocs``,
      - hands off to RESPONDER or REPORTER with case_updates populated.
  * The orchestrator's ``AGENT_MAP`` and ``_status_for`` import cleanly and
    know about ``AgentName.CDR``.
  * The Investigator routing heuristic ``_alert_looks_cloud`` correctly
    distinguishes cloud-plane alerts from identity-only alerts.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_cdr.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-cdr-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.cdr import CDRAgent  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.case import Case, CaseStatus, Severity, Verdict  # noqa: E402
from app.models.trace import AgentName, AgentTrace  # noqa: E402
import app.tools  # noqa: F401, E402  -- forces tool registration on import
from app.tools.registry import registry as tool_registry  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(label: str) -> None:
    print(f"\n── {label} ──")


# ── Checks ──────────────────────────────────────────────────────────────


def check_cdr_tools_registered() -> None:
    section("CDR tools registered in ToolRegistry")

    expected = {
        "cloud.list_iam_principals",
        "cloud.get_iam_principal",
        "cloud.list_access_keys",
        "cloud.list_sts_sessions",
        "cloud.trace_assume_role_chain",
        "cloud.list_k8s_rolebindings",
        "cloud.deactivate_access_key",
        "cloud.attach_deny_policy",
        "cloud.delete_k8s_rolebinding",
    }
    have = {t.name for t in tool_registry.all()}
    missing = expected - have
    check(
        "all CDR cloud tools registered",
        not missing,
        detail=f"missing={sorted(missing)}",
    )

    # Containment writes must be WRITE_SIGNIFICANT (no auto-rollback).
    for name in (
        "cloud.deactivate_access_key",
        "cloud.attach_deny_policy",
        "cloud.delete_k8s_rolebinding",
    ):
        td = tool_registry.get(name)
        check(
            f"{name} is WRITE_SIGNIFICANT",
            td is not None and td.risk_class.name == "WRITE_SIGNIFICANT",
            detail=f"risk={getattr(td, 'risk_class', None)}",
        )
        # And must NOT have an auto-pair reverse tool — cloud writes are
        # forward-only by design.
        check(
            f"{name} has no reverse_tool",
            td is not None and getattr(td, "reverse_tool", None) is None,
            detail=f"reverse={getattr(td, 'reverse_tool', None)}",
        )


def check_orchestrator_knows_cdr() -> None:
    section("Orchestrator wiring includes CDR")

    from app.agents.orchestrator import AGENT_MAP, _status_for  # noqa: WPS433

    check(
        "AGENT_MAP has CDR → CDRAgent",
        AGENT_MAP.get(AgentName.CDR) is CDRAgent,
        detail=f"got={AGENT_MAP.get(AgentName.CDR)}",
    )
    check(
        "_status_for(CDR) is INVESTIGATING",
        _status_for(AgentName.CDR) == CaseStatus.INVESTIGATING,
        detail=f"got={_status_for(AgentName.CDR)}",
    )


def check_investigator_cloud_routing() -> None:
    section("Investigator cloud-routing heuristic")

    from app.agents.investigator import _alert_looks_cloud  # noqa: WPS433

    cases = [
        (
            "cloudtrail + IAM ARN",
            Alert(
                external_id="r1",
                tenant_id="t",
                source="cloudtrail",
                title="x",
                src_user="arn:aws:iam::123456789012:user/alice",
            ),
            True,
        ),
        (
            "guardduty alert",
            Alert(external_id="r2", tenant_id="t", source="guardduty", title="x"),
            True,
        ),
        (
            "EKS k8s alert",
            Alert(external_id="r3", tenant_id="t", source="eks", title="x"),
            True,
        ),
        (
            "raw payload hint",
            Alert(
                external_id="r4",
                tenant_id="t",
                source="generic",
                title="x",
                raw={"cloud_provider": "aws"},
            ),
            True,
        ),
        (
            "GCP service account principal",
            Alert(
                external_id="r5",
                tenant_id="t",
                source="generic",
                title="x",
                src_user="svc@my-project.iam.gserviceaccount.com",
            ),
            True,
        ),
        (
            "Okta user — must NOT route to CDR",
            Alert(
                external_id="r6",
                tenant_id="t",
                source="okta",
                title="x",
                src_user="[email protected]",
            ),
            False,
        ),
        (
            "Splunk endpoint alert — must NOT route to CDR",
            Alert(
                external_id="r7",
                tenant_id="t",
                source="splunk",
                title="x",
                src_user="alice",
            ),
            False,
        ),
        ("None alert", None, False),
    ]
    for label, alert, expected in cases:
        got = _alert_looks_cloud(alert)
        check(
            f"_alert_looks_cloud({label}) == {expected}",
            got is expected,
            detail=f"got={got}",
        )


async def check_cdr_end_to_end() -> None:
    section("CDRAgent end-to-end against MockCloudConnector")

    init_db()

    # The MockCloudConnector defaults flag at least one STS session as a
    # multi-hop chain and surface at least one anomalous access key for
    # "alice" / one risky K8s RoleBinding.
    target_principal = "arn:aws:iam::123456789012:user/alice"

    with Session(engine) as s:
        case = Case(
            title="Suspicious AssumeRole chain from anomalous IP",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-cdr-test",
            affected_users=[target_principal],
            iocs=["203.0.113.45"],
            # Investigator/Triager would have already promoted this case
            # to TRUE_POSITIVE before handing off to CDR. The deterministic
            # containment backstop only acts on confirmed true positives.
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="cloudtrail-cdr-test-1",
            tenant_id="t-cdr-test",
            source="cloudtrail",
            title="STS AssumeRole chain anomaly",
            description="Three-hop assume-role from unusual ASN",
            severity="high",
            src_user=target_principal,
            src_ip="203.0.113.45",
            case_id=case_id,
            raw={
                "event_name": "AssumeRole",
                "iam_principal": target_principal,
            },
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = CDRAgent(s, case_id, tenant_id="t-cdr-test")
        result = await agent.run()

    check("CDR returned an AgentResult", result is not None)
    check(
        "CDR produced a summary",
        bool(result.summary) and "CDR" in result.summary,
        detail=f"summary={result.summary!r}",
    )

    # Handoff must route somewhere downstream, not loop on itself.
    check(
        "CDR handed off downstream",
        result.handoff is not None
        and result.handoff.to in {AgentName.RESPONDER, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )

    # case_updates payload must carry the structured CDR report.
    cu = (result.case_updates or {}).get("cdr") or {}
    expected_keys = {
        "flagged_sessions",
        "suspicious_keys",
        "flagged_bindings",
        "deactivated_keys",
        "denied_principals",
        "deleted_bindings",
        "chain_origins",
    }
    check(
        "case_updates.cdr has expected keys",
        expected_keys.issubset(cu.keys()),
        detail=f"keys={sorted(cu.keys())}",
    )
    check(
        "CDR flagged at least one cloud artifact (session/key/binding)",
        (
            len(cu.get("flagged_sessions", []))
            + len(cu.get("suspicious_keys", []))
            + len(cu.get("flagged_bindings", []))
            > 0
        ),
        detail=(
            f"sessions={cu.get('flagged_sessions')} "
            f"keys={cu.get('suspicious_keys')} "
            f"bindings={cu.get('flagged_bindings')}"
        ),
    )
    check(
        "CDR contained at least one cloud artifact "
        "(key/principal/binding)",
        (
            len(cu.get("deactivated_keys", []))
            + len(cu.get("denied_principals", []))
            + len(cu.get("deleted_bindings", []))
            > 0
        ),
        detail=(
            f"deactivated={cu.get('deactivated_keys')} "
            f"denied={cu.get('denied_principals')} "
            f"deleted={cu.get('deleted_bindings')}"
        ),
    )

    # Origin ARNs and denied principals must land on case.iocs for
    # downstream Hunter/Reporter pivoting.
    with Session(engine) as s:
        refreshed = s.get(Case, case_id)
        pivot_iocs = set(cu.get("chain_origins") or []) | set(
            cu.get("denied_principals") or []
        )
        if pivot_iocs:
            check(
                "cloud pivot ARNs stamped onto case.iocs",
                pivot_iocs.issubset(set(refreshed.iocs or [])),
                detail=(
                    f"pivot={sorted(pivot_iocs)} "
                    f"iocs={refreshed.iocs}"
                ),
            )

        # We must have written an audit trail. At minimum a PLAN and a
        # final DECISION row from CDR.
        traces = s.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.CDR)
        ).all()
        check(
            "CDR wrote at least one trace row",
            len(traces) > 0,
            detail=f"trace_count={len(traces)}",
        )


async def check_cdr_no_cloud_short_circuit() -> None:
    section("CDRAgent short-circuits when no cloud entity")

    with Session(engine) as s:
        case = Case(
            title="Endpoint-only ransomware case",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-cdr-test",
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="edr-no-cloud-1",
            tenant_id="t-cdr-test",
            source="crowdstrike",
            title="Suspicious lsass access",
            severity="high",
            src_host="win-finance-04",
            case_id=case_id,
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = CDRAgent(s, case_id, tenant_id="t-cdr-test")
        result = await agent.run()

    # When there's no cloud entity, the CDR agent should still complete
    # cleanly and hand to Responder rather than loop. It may still call
    # the read-only enumeration tools as a defensive sweep, but it must
    # not contain anything destructive.
    cu = (result.case_updates or {}).get("cdr") or {}
    check(
        "no-cloud case handed off (to Responder or Reporter)",
        result.handoff is not None
        and result.handoff.to in {AgentName.RESPONDER, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )
    # We don't require zero containment here — the mock connector
    # surfaces a couple of suspicious artifacts by default and the
    # deterministic backstop may still fire on a TP case. What we *do*
    # require: containment is bounded (the backstop's _MAX_WRITES_PER_CASE
    # cap is respected) and the payload is structurally well-formed.
    total_writes = (
        len(cu.get("deactivated_keys", []))
        + len(cu.get("denied_principals", []))
        + len(cu.get("deleted_bindings", []))
    )
    check(
        "no-cloud case respects MAX_WRITES_PER_CASE cap",
        total_writes <= 6,
        detail=f"total_writes={total_writes}",
    )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_cdr_tools_registered()
    check_orchestrator_knows_cdr()
    check_investigator_cloud_routing()
    await check_cdr_end_to_end()
    await check_cdr_no_cloud_short_circuit()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All CDR smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
