"""End-to-end smoke check for the SaaS Posture sub-agent (Theme 2e).

Exercises the full SaaS Posture path against an isolated SQLite DB and the
``MockSaaSConnector`` so we touch every wire-in surface:

  * The connector registry falls back to mocks for an unconfigured tenant
    on ``ConnectorKind.SAAS``.
  * The new SaaS SSPM tools (``saas.list_applications``,
    ``saas.list_misconfigurations``, ``saas.list_external_shares``,
    ``saas.list_third_party_integrations``,
    ``saas.revoke_third_party_integration``,
    ``saas.restrict_external_share``,
    ``saas.remove_external_collaborator``) are loaded into the
    ToolRegistry and pickable by the mock LLM.
  * The SaaSPostureAgent runs end-to-end:
      - identifies candidate SaaS providers from the alert,
      - enumerates third-party grants + apps + shares + misconfigs,
      - flags high-risk OAuth grants and public/external shares,
      - issues *targeted* containment writes (NOT tenant-wide sweep) via
        the deterministic backstop if the mock LLM didn't get there,
      - stamps unverified-publisher app names onto ``case.iocs``,
      - hands off to RESPONDER or REPORTER with case_updates populated.
  * The orchestrator's ``AGENT_MAP`` and ``_status_for`` import cleanly
    and know about ``AgentName.SAAS_POSTURE``.
  * The Investigator routing heuristic ``_alert_looks_saas`` correctly
    distinguishes SaaS-plane alerts from identity-only / cloud-only /
    endpoint alerts.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_saas_posture.py

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
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-saas-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.saas_posture import SaaSPostureAgent  # noqa: E402
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


def check_saas_tools_registered() -> None:
    section("SaaS Posture tools registered in ToolRegistry")

    expected = {
        "saas.list_applications",
        "saas.list_misconfigurations",
        "saas.list_external_shares",
        "saas.list_third_party_integrations",
        "saas.revoke_third_party_integration",
        "saas.restrict_external_share",
        "saas.remove_external_collaborator",
    }
    have = {t.name for t in tool_registry.all()}
    missing = expected - have
    check(
        "all SaaS SSPM tools registered",
        not missing,
        detail=f"missing={sorted(missing)}",
    )

    # Containment writes must be WRITE_SIGNIFICANT (forward-only, no auto
    # rollback — re-grant / re-share / re-invite are fresh consent
    # decisions and can't be safely auto-reversed).
    for name in (
        "saas.revoke_third_party_integration",
        "saas.restrict_external_share",
        "saas.remove_external_collaborator",
    ):
        td = tool_registry.get(name)
        check(
            f"{name} is WRITE_SIGNIFICANT",
            td is not None and td.risk_class.name == "WRITE_SIGNIFICANT",
            detail=f"risk={getattr(td, 'risk_class', None)}",
        )
        check(
            f"{name} has no reverse_tool (forward-only by design)",
            td is not None and getattr(td, "reverse_tool", None) is None,
            detail=f"reverse={getattr(td, 'reverse_tool', None)}",
        )


def check_orchestrator_knows_saas_posture() -> None:
    section("Orchestrator wiring includes SaaS Posture")

    from app.agents.orchestrator import AGENT_MAP, _status_for  # noqa: WPS433

    check(
        "AGENT_MAP has SAAS_POSTURE → SaaSPostureAgent",
        AGENT_MAP.get(AgentName.SAAS_POSTURE) is SaaSPostureAgent,
        detail=f"got={AGENT_MAP.get(AgentName.SAAS_POSTURE)}",
    )
    check(
        "_status_for(SAAS_POSTURE) is INVESTIGATING",
        _status_for(AgentName.SAAS_POSTURE) == CaseStatus.INVESTIGATING,
        detail=f"got={_status_for(AgentName.SAAS_POSTURE)}",
    )


def check_investigator_saas_routing() -> None:
    section("Investigator SaaS-routing heuristic")

    from app.agents.investigator import _alert_looks_saas  # noqa: WPS433

    cases = [
        (
            "M365 OAuth grant alert",
            Alert(
                external_id="r1",
                tenant_id="t",
                source="m365",
                title="Unverified app granted Mail.Read scope",
                raw={"app_name": "ContosoDocSign"},
            ),
            True,
        ),
        (
            "Workspace public-share alert",
            Alert(
                external_id="r2",
                tenant_id="t",
                source="workspace",
                title="Drive folder shared with anyone",
                raw={"share_url": "https://drive.google.com/x"},
            ),
            True,
        ),
        (
            "Salesforce admin MFA",
            Alert(
                external_id="r3",
                tenant_id="t",
                source="salesforce",
                title="System Admin MFA disabled",
            ),
            True,
        ),
        (
            "GitHub repo secret exposure",
            Alert(
                external_id="r4",
                tenant_id="t",
                source="github",
                title="Secret committed to public repo",
                raw={"repo": "contoso/payroll-ingest"},
            ),
            True,
        ),
        (
            "Slack external bridge",
            Alert(
                external_id="r5",
                tenant_id="t",
                source="slack",
                title="ExternalChatBridge installed",
                raw={"channel": "#exec-staff"},
            ),
            True,
        ),
        (
            "Okta user — must NOT route to SaaS Posture",
            Alert(
                external_id="r6",
                tenant_id="t",
                source="okta",
                title="MFA reset",
                src_user="[email protected]",
            ),
            False,
        ),
        (
            "CloudTrail IAM — must NOT route to SaaS Posture",
            Alert(
                external_id="r7",
                tenant_id="t",
                source="cloudtrail",
                title="AssumeRole",
                src_user="arn:aws:iam::123456789012:user/alice",
            ),
            False,
        ),
        (
            "Splunk endpoint — must NOT route to SaaS Posture",
            Alert(
                external_id="r8",
                tenant_id="t",
                source="splunk",
                title="Suspicious lsass access",
                src_host="win-finance-04",
            ),
            False,
        ),
        ("None alert", None, False),
    ]
    for label, alert, expected in cases:
        got = _alert_looks_saas(alert)
        check(
            f"_alert_looks_saas({label}) == {expected}",
            got is expected,
            detail=f"got={got}",
        )


async def check_saas_posture_end_to_end() -> None:
    section("SaaSPostureAgent end-to-end against MockSaaSConnector")

    init_db()

    # The MockSaaSConnector defaults surface several illicit-consent
    # OAuth grants (M365 ContosoDocSign, Workspace DriveSyncPro, GitHub
    # MarketplaceCIBot, Slack ExternalChatBridge), several public/
    # external shares with `contains_sensitive=true`, and several
    # high/critical misconfigurations. The deterministic backstop should
    # revoke the highest-risk grants and restrict the highest-risk
    # shares.
    with Session(engine) as s:
        case = Case(
            title="Illicit-consent OAuth grant on M365 mailbox",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-saas-test",
            affected_users=["[email protected]"],
            iocs=["ContosoDocSign"],
            # Investigator/Triager would have already promoted this case
            # to TRUE_POSITIVE before handing off to SaaS Posture. The
            # deterministic containment backstop only acts on confirmed
            # true positives.
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="m365-saas-test-1",
            tenant_id="t-saas-test",
            source="m365",
            title="Unverified app granted broad mailbox scope",
            description="ContosoDocSign granted Mail.Read by single user",
            severity="high",
            src_user="[email protected]",
            case_id=case_id,
            raw={
                "app_name": "ContosoDocSign",
                "publisher": "Unverified Publisher",
                "scopes": ["Mail.Read", "Files.Read.All"],
            },
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = SaaSPostureAgent(s, case_id, tenant_id="t-saas-test")
        result = await agent.run()

    check("SaaS Posture returned an AgentResult", result is not None)
    check(
        "SaaS Posture produced a summary",
        bool(result.summary) and "SaaS Posture" in result.summary,
        detail=f"summary={result.summary!r}",
    )

    # Handoff must route somewhere downstream, not loop on itself.
    check(
        "SaaS Posture handed off downstream",
        result.handoff is not None
        and result.handoff.to in {AgentName.RESPONDER, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )

    # case_updates payload must carry the structured SaaS Posture report.
    cu = (result.case_updates or {}).get("saas_posture") or {}
    expected_keys = {
        "flagged_grants",
        "flagged_apps",
        "flagged_shares",
        "critical_misconfigs",
        "revoked_grants",
        "restricted_shares",
        "removed_collabs",
    }
    check(
        "case_updates.saas_posture has expected keys",
        expected_keys.issubset(cu.keys()),
        detail=f"keys={sorted(cu.keys())}",
    )
    check(
        "SaaS Posture flagged at least one SaaS artifact "
        "(grant/app/share/misconfig)",
        (
            len(cu.get("flagged_grants", []))
            + len(cu.get("flagged_apps", []))
            + len(cu.get("flagged_shares", []))
            + len(cu.get("critical_misconfigs", []))
            > 0
        ),
        detail=(
            f"grants={len(cu.get('flagged_grants', []))} "
            f"apps={len(cu.get('flagged_apps', []))} "
            f"shares={len(cu.get('flagged_shares', []))} "
            f"misconfigs={len(cu.get('critical_misconfigs', []))}"
        ),
    )
    check(
        "SaaS Posture contained at least one SaaS artifact "
        "(grant/share/collaborator)",
        (
            len(cu.get("revoked_grants", []))
            + len(cu.get("restricted_shares", []))
            + len(cu.get("removed_collabs", []))
            > 0
        ),
        detail=(
            f"revoked={cu.get('revoked_grants')} "
            f"restricted={cu.get('restricted_shares')} "
            f"removed={cu.get('removed_collabs')}"
        ),
    )

    # Unverified-publisher app names must land on case.iocs so the
    # Hunter/Reporter can pivot cross-tenant on attacker app names.
    with Session(engine) as s:
        refreshed = s.get(Case, case_id)
        # We expect "saas-app:" prefixed IOCs from non-Microsoft/Google
        # publishers in the flagged grants.
        saas_iocs = [
            i for i in (refreshed.iocs or []) if str(i).startswith("saas-app:")
        ]
        check(
            "unverified-publisher app names stamped onto case.iocs",
            len(saas_iocs) > 0,
            detail=f"saas_iocs={saas_iocs} all_iocs={refreshed.iocs}",
        )

        # We must have written an audit trail. At minimum a PLAN and a
        # final DECISION row from SaaS Posture.
        traces = s.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.SAAS_POSTURE)
        ).all()
        check(
            "SaaS Posture wrote at least one trace row",
            len(traces) > 0,
            detail=f"trace_count={len(traces)}",
        )


async def check_saas_posture_no_saas_short_circuit() -> None:
    section("SaaSPostureAgent stays bounded when no SaaS entity present")

    with Session(engine) as s:
        case = Case(
            title="Endpoint-only ransomware case",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-saas-test",
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="edr-no-saas-1",
            tenant_id="t-saas-test",
            source="crowdstrike",
            title="Suspicious lsass access",
            severity="high",
            src_host="win-finance-04",
            case_id=case_id,
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = SaaSPostureAgent(s, case_id, tenant_id="t-saas-test")
        result = await agent.run()

    # When there's no SaaS entity, the SaaS Posture agent should still
    # complete cleanly and hand to Responder rather than loop. It may
    # still call the read-only enumeration tools as a defensive sweep,
    # but containment must be bounded by _MAX_WRITES_PER_CASE.
    cu = (result.case_updates or {}).get("saas_posture") or {}
    check(
        "no-SaaS case handed off (to Responder or Reporter)",
        result.handoff is not None
        and result.handoff.to in {AgentName.RESPONDER, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )
    total_writes = (
        len(cu.get("revoked_grants", []))
        + len(cu.get("restricted_shares", []))
        + len(cu.get("removed_collabs", []))
    )
    check(
        "no-SaaS case respects MAX_WRITES_PER_CASE cap",
        total_writes <= 6,
        detail=f"total_writes={total_writes}",
    )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_saas_tools_registered()
    check_orchestrator_knows_saas_posture()
    check_investigator_saas_routing()
    await check_saas_posture_end_to_end()
    await check_saas_posture_no_saas_short_circuit()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All SaaS Posture smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
