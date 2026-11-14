"""End-to-end smoke check for the Phishing Triage sub-agent (Theme 2f).

Exercises the full Phishing Triage path against an isolated SQLite DB so
we touch every wire-in surface:

  * The four Cyble-native phishing analysis tools
    (``phishing.deep_header_analysis``, ``phishing.unwrap_url_chain``,
    ``phishing.detonate_url``, ``phishing.brand_impersonation``) are
    loaded into the ToolRegistry as READ-class, cyble_native tools.
  * The email containment writes (``email.clawback_message``,
    ``email.block_sender``) are registered as WRITE_REVERSIBLE with
    paired reverse handlers.
  * The PhishingTriageAgent runs end-to-end:
      - extracts message_id / sender / links from the primary alert,
      - calls the deterministic READ sweep (analyze, header, unwrap,
        detonate, brand) so the audit trail is reproducible,
      - classifies the case (phishing | suspicious | benign) from tool
        results, NOT from the LLM string,
      - on phishing verdicts, the deterministic backstop issues the
        two surgical writes (clawback + block_sender), each routed
        through HITL,
      - stamps phish-domain / phish-kit / phish-landing IOCs onto the
        case so Hunter/Reporter can pivot,
      - hands off downstream (Investigator if downstream users exist,
        else Reporter).
  * The orchestrator's ``AGENT_MAP`` and ``_status_for`` know about
    ``AgentName.PHISHING_TRIAGE``.
  * The Investigator routing heuristic ``_alert_looks_phishing``
    correctly identifies email-derived alerts and ignores
    endpoint/identity/cloud-only signals.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_phishing_triage.py

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
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-phish-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.phishing_triage import PhishingTriageAgent  # noqa: E402
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


def check_phishing_tools_registered() -> None:
    section("Phishing analysis tools registered in ToolRegistry")

    expected_read = {
        "phishing.deep_header_analysis",
        "phishing.unwrap_url_chain",
        "phishing.detonate_url",
        "phishing.brand_impersonation",
    }
    have = {t.name for t in tool_registry.all()}
    missing = expected_read - have
    check(
        "all phishing analysis tools registered",
        not missing,
        detail=f"missing={sorted(missing)}",
    )

    # All four phishing analysis tools must be READ-class, cyble_native.
    # No writes — containment lives in email_tool.py.
    for name in expected_read:
        td = tool_registry.get(name)
        check(
            f"{name} is READ-class",
            td is not None and td.risk_class.name == "READ",
            detail=f"risk={getattr(td, 'risk_class', None)}",
        )
        check(
            f"{name} is cyble_native (moat tool)",
            td is not None and getattr(td, "cyble_native", False) is True,
            detail=f"cyble_native={getattr(td, 'cyble_native', None)}",
        )

    # Containment writes must be WRITE_REVERSIBLE with paired reverse
    # handlers — clawback can be reversed by put-back, block by unblock.
    for name in ("email.clawback_message", "email.block_sender"):
        td = tool_registry.get(name)
        check(
            f"{name} is WRITE_REVERSIBLE",
            td is not None and td.risk_class.name == "WRITE_REVERSIBLE",
            detail=f"risk={getattr(td, 'risk_class', None)}",
        )
        check(
            f"{name} has a paired reverse_tool",
            td is not None and getattr(td, "reverse_tool", None),
            detail=f"reverse={getattr(td, 'reverse_tool', None)}",
        )


def check_orchestrator_knows_phishing_triage() -> None:
    section("Orchestrator wiring includes Phishing Triage")

    from app.agents.orchestrator import AGENT_MAP, _status_for  # noqa: WPS433

    check(
        "AGENT_MAP has PHISHING_TRIAGE → PhishingTriageAgent",
        AGENT_MAP.get(AgentName.PHISHING_TRIAGE) is PhishingTriageAgent,
        detail=f"got={AGENT_MAP.get(AgentName.PHISHING_TRIAGE)}",
    )
    # Phishing Triage is a deep triage specialist that runs in lieu of
    # (or alongside) the generic Triager — surface as TRIAGING in the
    # operator timeline.
    check(
        "_status_for(PHISHING_TRIAGE) is TRIAGING",
        _status_for(AgentName.PHISHING_TRIAGE) == CaseStatus.TRIAGING,
        detail=f"got={_status_for(AgentName.PHISHING_TRIAGE)}",
    )


def check_investigator_phishing_routing() -> None:
    section("Investigator phishing-routing heuristic")

    from app.agents.investigator import _alert_looks_phishing  # noqa: WPS433

    cases = [
        (
            "Proofpoint reported-phish alert",
            Alert(
                external_id="r1",
                tenant_id="t",
                source="proofpoint",
                title="User-reported suspicious email",
                raw={"message_id": "<abc@proofpoint>"},
            ),
            True,
        ),
        (
            "M365 Defender phishing rule",
            Alert(
                external_id="r2",
                tenant_id="t",
                source="m365-defender",
                title="Anti-phish: high-confidence phish",
            ),
            True,
        ),
        (
            "Google Workspace mail alert",
            Alert(
                external_id="r3",
                tenant_id="t",
                source="gws-mail",
                title="Spoofing attempt blocked",
            ),
            True,
        ),
        (
            "Generic alert with email primitives in raw",
            Alert(
                external_id="r4",
                tenant_id="t",
                source="siem",
                title="Inbound message flagged",
                raw={
                    "message_id": "<x@y>",
                    "from": "[email protected]",
                    "subject": "Reset your password",
                    "spf": "fail",
                    "dkim": "fail",
                    "dmarc": "fail",
                },
            ),
            True,
        ),
        (
            "Title hint: 'credential harvest'",
            Alert(
                external_id="r5",
                tenant_id="t",
                source="siem",
                title="Credential harvest landing page",
            ),
            True,
        ),
        (
            "Title hint: 'lookalike domain'",
            Alert(
                external_id="r6",
                tenant_id="t",
                source="cti",
                title="Lookalike domain registered against acme",
            ),
            True,
        ),
        (
            "Okta MFA reset — must NOT route to Phishing Triage",
            Alert(
                external_id="r7",
                tenant_id="t",
                source="okta",
                title="MFA reset",
                src_user="[email protected]",
            ),
            False,
        ),
        (
            "CloudTrail IAM — must NOT route to Phishing Triage",
            Alert(
                external_id="r8",
                tenant_id="t",
                source="cloudtrail",
                title="AssumeRole",
                src_user="arn:aws:iam::123456789012:user/alice",
            ),
            False,
        ),
        (
            "EDR endpoint — must NOT route to Phishing Triage",
            Alert(
                external_id="r9",
                tenant_id="t",
                source="crowdstrike",
                title="Suspicious lsass access",
                src_host="win-finance-04",
            ),
            False,
        ),
        (
            "GitHub repo secret — must NOT route to Phishing Triage",
            Alert(
                external_id="r10",
                tenant_id="t",
                source="github",
                title="Secret committed to public repo",
                raw={"repo": "contoso/payroll-ingest"},
            ),
            False,
        ),
        ("None alert", None, False),
    ]
    for label, alert, expected in cases:
        got = _alert_looks_phishing(alert)
        check(
            f"_alert_looks_phishing({label}) == {expected}",
            got is expected,
            detail=f"got={got}",
        )


async def check_phishing_triage_end_to_end() -> None:
    section("PhishingTriageAgent end-to-end on a confirmed phish")

    init_db()

    # Craft a phishing email alert with:
    #   - a message_id (so the deterministic backstop can clawback),
    #   - sender on the homoglyph domain that's in the Cyble brand-intel
    #     feed (examp1e.com) — guarantees brand_impersonation verdict=phishing,
    #   - a link that resolves through the mock URL-chain to a landing
    #     page on examp1e.com — guarantees detonation verdict=phishing,
    #   - SPF/DKIM/DMARC fails — drives header suspicion to 0.7+.
    with Session(engine) as s:
        case = Case(
            title="Phishing email reported by [email protected]",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-phish-test",
            affected_users=["[email protected]"],
            iocs=[],
            # Phishing Triage backstop only contains on TRUE_POSITIVE
            # — Investigator/Triager promotes the case before handoff.
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="phish-test-1",
            tenant_id="t-phish-test",
            source="proofpoint",
            title="User-reported phishing email",
            description=(
                "Recipient reported a credential-harvest email "
                "impersonating IT Help Desk."
            ),
            severity="high",
            src_user="[email protected]",
            case_id=case_id,
            raw={
                "message_id": "<phish-001@mail>",
                "from": "[email protected]",
                "subject": "Action required: verify your account",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "links": [
                    "https://safelinks.proofpoint.com/?u=https%3A//bit.ly/3zXq9",
                ],
            },
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = PhishingTriageAgent(s, case_id, tenant_id="t-phish-test")
        result = await agent.run()

    check("Phishing Triage returned an AgentResult", result is not None)
    check(
        "Phishing Triage produced a summary",
        bool(result.summary) and "Phishing Triage" in result.summary,
        detail=f"summary={result.summary!r}",
    )

    # On a confirmed phish with affected users, route to Investigator
    # for the broader lateral / credential-reuse check.
    check(
        "phishing+affected_users hands off to INVESTIGATOR",
        result.handoff is not None
        and result.handoff.to == AgentName.INVESTIGATOR,
        detail=f"handoff={result.handoff}",
    )

    cu = (result.case_updates or {}).get("phishing_triage") or {}
    expected_keys = {
        "verdict",
        "deciding_signals",
        "message_id",
        "sender",
        "header_suspicion",
        "header_findings",
        "brand_findings",
        "detonation_findings",
        "url_chain_findings",
        "clawback_done",
        "block_sender_done",
    }
    check(
        "case_updates.phishing_triage has expected keys",
        expected_keys.issubset(cu.keys()),
        detail=f"keys={sorted(cu.keys())}",
    )
    check(
        "verdict is 'phishing'",
        cu.get("verdict") == "phishing",
        detail=f"verdict={cu.get('verdict')!r}",
    )
    check(
        "deciding_signals names at least one phish signal",
        any(
            sig in (cu.get("deciding_signals") or [])
            for sig in (
                "brand-intel-phishing",
                "detonation-credential-harvest",
            )
        ),
        detail=f"signals={cu.get('deciding_signals')}",
    )
    check(
        "header suspicion populated (>= 0.5)",
        float(cu.get("header_suspicion") or 0) >= 0.5,
        detail=f"header_suspicion={cu.get('header_suspicion')}",
    )
    check(
        "brand_findings includes at least one phishing verdict",
        any(
            f.get("verdict") == "phishing"
            for f in (cu.get("brand_findings") or [])
        ),
        detail=f"brand_findings={cu.get('brand_findings')}",
    )
    check(
        "detonation_findings includes at least one phishing verdict",
        any(
            f.get("verdict") == "phishing"
            for f in (cu.get("detonation_findings") or [])
        ),
        detail=f"detonation_findings={cu.get('detonation_findings')}",
    )
    check(
        "url_chain_findings produced at least one chain",
        len(cu.get("url_chain_findings") or []) >= 1,
        detail=f"url_chain_findings={cu.get('url_chain_findings')}",
    )

    # Surgical containment — clawback + block_sender — must fire from
    # the deterministic backstop since the mock LLM doesn't issue them.
    check(
        "clawback_done is True (deterministic backstop fired)",
        cu.get("clawback_done") is True,
        detail=f"clawback_done={cu.get('clawback_done')}",
    )
    check(
        "block_sender_done is True (deterministic backstop fired)",
        cu.get("block_sender_done") is True,
        detail=f"block_sender_done={cu.get('block_sender_done')}",
    )

    # IOC stamping — phish-domain and/or phish-kit and/or phish-landing
    # IOCs must land on the case so Hunter/Reporter can pivot.
    with Session(engine) as s:
        refreshed = s.get(Case, case_id)
        phish_iocs = [
            i
            for i in (refreshed.iocs or [])
            if str(i).startswith(("phish-domain:", "phish-kit:", "phish-landing:"))
        ]
        check(
            "phishing IOCs stamped onto case.iocs",
            len(phish_iocs) > 0,
            detail=f"phish_iocs={phish_iocs} all_iocs={refreshed.iocs}",
        )

        # Audit trail — at minimum PLAN + DECISION rows from Phishing Triage.
        traces = s.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.PHISHING_TRIAGE)
        ).all()
        check(
            "Phishing Triage wrote at least one trace row",
            len(traces) > 0,
            detail=f"trace_count={len(traces)}",
        )


async def check_phishing_triage_no_users_short_circuit() -> None:
    section("PhishingTriageAgent hands to REPORTER when no downstream users")

    # Same phishing setup but no affected_users / affected_hosts — the
    # message-layer containment is sufficient, no broader lateral check
    # needed; route straight to Reporter.
    with Session(engine) as s:
        case = Case(
            title="Phishing email — no recipient impact",
            severity=Severity.MEDIUM,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-phish-test",
            affected_users=[],
            affected_hosts=[],
            iocs=[],
            verdict=Verdict.TRUE_POSITIVE,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        alert = Alert(
            external_id="phish-test-noimpact-1",
            tenant_id="t-phish-test",
            source="proofpoint",
            title="Reported phish quarantined pre-delivery",
            severity="medium",
            src_user="[email protected]",
            case_id=case_id,
            raw={
                "message_id": "<phish-noimpact-1@mail>",
                "from": "[email protected]",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "links": [
                    "https://t.co/abc123",
                ],
            },
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = PhishingTriageAgent(s, case_id, tenant_id="t-phish-test")
        result = await agent.run()

    cu = (result.case_updates or {}).get("phishing_triage") or {}
    check(
        "no-impact phishing case still classifies as 'phishing'",
        cu.get("verdict") == "phishing",
        detail=f"verdict={cu.get('verdict')!r}",
    )
    check(
        "no-impact phishing case hands off to REPORTER",
        result.handoff is not None
        and result.handoff.to == AgentName.REPORTER,
        detail=f"handoff={result.handoff}",
    )


async def check_phishing_triage_missing_context() -> None:
    section("PhishingTriageAgent stays bounded with no email primitives")

    # Phishing Triage may be routed to a case whose alert is missing
    # explicit email primitives (e.g. an upstream Investigator just
    # smelled phishing in the title). The deterministic sweep must run
    # cleanly with synthetic defaults; no crash, no runaway writes.
    with Session(engine) as s:
        case = Case(
            title="Suspicious email — sparse alert",
            severity=Severity.LOW,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-phish-test",
            verdict=Verdict.NEEDS_HUMAN,
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id

        # No message_id, no from, no links — just a vague title.
        alert = Alert(
            external_id="phish-test-sparse-1",
            tenant_id="t-phish-test",
            source="user-reported",
            title="Suspicious email forwarded by helpdesk",
            severity="low",
            case_id=case_id,
            raw={},
        )
        s.add(alert)
        s.commit()

    with Session(engine) as s:
        agent = PhishingTriageAgent(s, case_id, tenant_id="t-phish-test")
        result = await agent.run()

    check(
        "sparse case completes without raising",
        result is not None,
    )
    # Verdict is NEEDS_HUMAN → deterministic containment backstop must
    # NOT fire (it only acts on TRUE_POSITIVE). The case may still be
    # classified by tool results as phishing, but the writes must be
    # gated. Verify clawback/block weren't auto-issued.
    cu = (result.case_updates or {}).get("phishing_triage") or {}
    check(
        "NEEDS_HUMAN case does not auto-clawback",
        cu.get("clawback_done") is False,
        detail=f"clawback_done={cu.get('clawback_done')}",
    )
    check(
        "NEEDS_HUMAN case does not auto-block sender",
        cu.get("block_sender_done") is False,
        detail=f"block_sender_done={cu.get('block_sender_done')}",
    )
    # Should still hand off cleanly somewhere downstream.
    check(
        "sparse case hands off downstream",
        result.handoff is not None
        and result.handoff.to
        in {AgentName.INVESTIGATOR, AgentName.REPORTER},
        detail=f"handoff={result.handoff}",
    )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_phishing_tools_registered()
    check_orchestrator_knows_phishing_triage()
    check_investigator_phishing_routing()
    await check_phishing_triage_end_to_end()
    await check_phishing_triage_no_users_short_circuit()
    await check_phishing_triage_missing_context()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Phishing Triage smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
