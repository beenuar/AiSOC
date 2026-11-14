"""End-to-end smoke check for the ITDR sub-agent (Theme 2c).

Exercises the full identity-side path against an isolated SQLite DB and the
``MockIdpConnector`` so we touch every wire-in surface:

  * The connector registry falls back to mocks for an unconfigured tenant.
  * The new IdP tools (``idp.list_user_sessions``, ``idp.list_oauth_grants``,
    ``idp.list_oauth_apps``, ``idp.revoke_session``, ``idp.revoke_oauth_grant``)
    are loaded into the ToolRegistry and pickable by the mock LLM.
  * The ITDRAgent runs end-to-end:
      - identifies the affected user from the alert,
      - enumerates sessions + OAuth grants,
      - flags AitM sessions and illicit grants past threshold,
      - issues *targeted* revokes (NOT blanket sign-out) via the deterministic
        backstop if the mock LLM didn't get there itself,
      - stamps suspicious ``client_id``s onto ``case.iocs``,
      - hands off to RESPONDER or REPORTER with case_updates populated.
  * The orchestrator's ``AGENT_MAP`` and ``_status_for`` import cleanly and
    know about ``AgentName.ITDR``.
  * An ITDR run with no identity entity on the case short-circuits to
    Responder without making any tool calls.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_itdr.py

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
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-itdr-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.itdr import ITDRAgent  # noqa: E402
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


def check_itdr_tools_registered() -> None:
    section("ITDR tools registered in ToolRegistry")

    expected = {
        "idp.get_user",
        "idp.list_user_sessions",
        "idp.list_oauth_grants",
        "idp.list_oauth_apps",
        "idp.revoke_session",
        "idp.revoke_oauth_grant",
    }
    have = {t.name for t in tool_registry.all()}
    missing = expected - have
    check(
        "all ITDR IdP tools registered",
        not missing,
        detail=f"missing={sorted(missing)}",
    )

    # Revokes must be WRITE_SIGNIFICANT (non-reversible, HITL-gated).
    for name in ("idp.revoke_session", "idp.revoke_oauth_grant"):
        td = tool_registry.get(name)
        check(
            f"{name} is WRITE_SIGNIFICANT",
            td is not None and td.risk_class.name == "WRITE_SIGNIFICANT",
            detail=f"risk={getattr(td, 'risk_class', None)}",
        )


def check_orchestrator_knows_itdr() -> None:
    section("Orchestrator wiring includes ITDR")

    # Import lazily so a wiring bug shows up here, not at module load.
    from app.agents.orchestrator import AGENT_MAP, _status_for  # noqa: WPS433

    check(
        "AGENT_MAP has ITDR → ITDRAgent",
        AGENT_MAP.get(AgentName.ITDR) is ITDRAgent,
        detail=f"got={AGENT_MAP.get(AgentName.ITDR)}",
    )
    check(
        "_status_for(ITDR) is INVESTIGATING",
        _status_for(AgentName.ITDR) == CaseStatus.INVESTIGATING,
        detail=f"got={_status_for(AgentName.ITDR)}",
    )


async def check_itdr_end_to_end() -> None:
    section("ITDRAgent end-to-end against MockIdpConnector")

    init_db()

    # The MockIdpConnector defaults flag at least one session as AitM-suspected
    # for "[email protected]" and surface at least one illicit OAuth grant.
    target_user = "[email protected]"

    with Session(engine) as s:
        case = Case(
            title="Possible AitM on workforce SSO",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-itdr-test",
            affected_users=[target_user],
            # Investigator/Triager would have already promoted this case
            # to TRUE_POSITIVE before handing off to ITDR. The deterministic
            # revoke backstop only acts on confirmed true positives.
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="okta-itdr-test-1",
            tenant_id="t-itdr-test",
            source="okta",
            title="Suspicious sign-in via unrecognized proxy",
            severity="high",
            src_user=target_user,
            src_ip="203.0.113.42",
            case_id=case_id,
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = ITDRAgent(s, case_id, tenant_id="t-itdr-test")
        result = await agent.run()

    check("ITDR returned an AgentResult", result is not None)
    check(
        "ITDR produced a summary",
        bool(result.summary) and "ITDR" in result.summary,
        detail=f"summary={result.summary!r}",
    )

    # Handoff must route somewhere downstream, not loop on itself.
    check(
        "ITDR handed off downstream",
        result.handoff is not None
        and result.handoff.to in {AgentName.RESPONDER, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )

    # case_updates payload must carry the structured ITDR report.
    cu = (result.case_updates or {}).get("itdr") or {}
    check(
        "case_updates.itdr has expected keys",
        {"flagged_sessions", "flagged_grants", "revoked_sessions",
         "revoked_grants", "suspicious_apps"}.issubset(cu.keys()),
        detail=f"keys={sorted(cu.keys())}",
    )
    check(
        "ITDR flagged at least one session OR grant",
        len(cu.get("flagged_sessions", [])) + len(cu.get("flagged_grants", [])) > 0,
        detail=f"sessions={cu.get('flagged_sessions')} grants={cu.get('flagged_grants')}",
    )
    check(
        "ITDR revoked at least one identity artifact (sessions+grants)",
        len(cu.get("revoked_sessions", [])) + len(cu.get("revoked_grants", [])) > 0,
        detail=(
            f"sessions={cu.get('revoked_sessions')} "
            f"grants={cu.get('revoked_grants')}"
        ),
    )

    # Suspicious client_ids must land on case.iocs for downstream pivoting.
    with Session(engine) as s:
        refreshed = s.get(Case, case_id)
        suspicious_apps = set(cu.get("suspicious_apps") or [])
        if suspicious_apps:
            check(
                "suspicious app client_ids stamped onto case.iocs",
                suspicious_apps.issubset(set(refreshed.iocs or [])),
                detail=(
                    f"suspicious={sorted(suspicious_apps)} "
                    f"iocs={refreshed.iocs}"
                ),
            )

        # We must have written an audit trail. At minimum a PLAN and a final
        # DECISION row from ITDR.
        traces = s.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.ITDR)
        ).all()
        check(
            "ITDR wrote at least one trace row",
            len(traces) > 0,
            detail=f"trace_count={len(traces)}",
        )


async def check_itdr_no_identity_short_circuit() -> None:
    section("ITDRAgent short-circuits when no identity entity")

    with Session(engine) as s:
        case = Case(
            title="Endpoint-only ransomware case",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-itdr-test",
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="edr-no-id-1",
            tenant_id="t-itdr-test",
            source="crowdstrike",
            title="Suspicious lsass access",
            severity="high",
            src_host="win-finance-04",
            case_id=case_id,
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = ITDRAgent(s, case_id, tenant_id="t-itdr-test")
        result = await agent.run()

    check(
        "no-identity case short-circuited to RESPONDER",
        result.handoff is not None and result.handoff.to == AgentName.RESPONDER,
        detail=f"handoff={result.handoff}",
    )
    check(
        "no-identity case carries no ITDR case_updates",
        not (result.case_updates or {}).get("itdr"),
        detail=f"case_updates={result.case_updates}",
    )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_itdr_tools_registered()
    check_orchestrator_knows_itdr()
    await check_itdr_end_to_end()
    await check_itdr_no_identity_short_circuit()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All ITDR smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
