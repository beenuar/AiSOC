"""ITDR: Identity Threat Detection & Response sub-agent.

Specialized identity investigator + surgical responder. Where the
generic Investigator/Responder pair handles endpoint-centric cases
(EDR, process tree, file quarantine), the ITDR agent owns the
identity attack surface:

  * **Session graph** — pull every active SSO/OAuth session for the
    affected user, score each session for adversary-in-the-middle
    (AitM) suspicion (impossible-travel, new device, MFA-bypass tokens).
  * **OAuth consent grants** — surface illicit-consent applications
    attached to the user (the OAuth-token-theft pattern: attacker
    tricks the victim into granting `Mail.ReadWrite` + `offline_access`
    to a malicious publisher, then siphons mail indefinitely without
    needing the password).
  * **Tenant-wide app exposure** — when the affected user's grant
    looks like an emerging attacker app, scan the tenant for other
    users who consented to the same `client_id`.
  * **Targeted revoke** — surgically kill the offending session *or*
    OAuth grant. Critically, NOT a blanket `idp.revoke_sessions`
    (which logs the legit user out of every device, every time): we
    target the single hijacked session or single illicit grant. The
    legit device(s) stay signed in.

All write actions (`idp.revoke_session`, `idp.revoke_oauth_grant`)
are `WRITE_SIGNIFICANT` and route through the BaseAgent HITL gate —
the LLM never silently revokes anything.

Handoff
-------
The ITDR agent is normally invoked between Investigator and
Responder when the case has a user entity. It returns to the
orchestrator with one of:

  * ``Handoff(to=RESPONDER)`` — identity contained, but endpoint /
    network work remains.
  * ``Handoff(to=REPORTER)`` — case is identity-only and now fully
    contained (or no identity threat was found).
"""
from __future__ import annotations

import json
from typing import Any

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent, Handoff, HitlBlocked
from app.config import settings
from app.memory.scratchpad import scratchpad
from app.models.alert import Alert
from app.models.case import Case, Verdict
from app.models.trace import AgentName, TraceStep


# AitM-suspicion threshold (anomaly_score ≥ this) → eligible for revoke.
_AITM_THRESHOLD = 0.7
# Illicit-grant threshold (risk_score ≥ this) → eligible for revoke.
_ILLICIT_GRANT_THRESHOLD = 0.6
# Max actions per case, even if the LLM keeps proposing more, to bound
# blast radius.
_MAX_REVOKES_PER_CASE = 6


class ITDRAgent(BaseAgent):
    """Identity Threat Detection & Response sub-agent."""

    name = AgentName.ITDR
    role = (
        "Identity-side detection and response. Owns the session graph, "
        "OAuth consent grants, and tenant-wide illicit-app exposure. "
        "Performs targeted (single-session, single-grant) revocations — "
        "never blanket sign-outs — through the HITL-gated tool surface."
    )
    allowed_tools = [
        # READ — build the picture
        "idp.get_user",
        "idp.list_user_sessions",
        "idp.list_oauth_grants",
        "idp.list_oauth_apps",
        # WRITE_SIGNIFICANT — surgical containment (HITL-gated by base)
        "idp.revoke_session",
        "idp.revoke_oauth_grant",
        # Last-resort blanket revoke — explicitly available but the
        # system prompt discourages it. Used only when targeted revoke
        # cannot be scoped (e.g. session_id no longer enumerable).
        "idp.revoke_sessions",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        # Build the set of identity entities. Prefer alert.src_user but
        # also fold in any users the upstream investigator already
        # attached to the case.
        candidate_users: list[str] = []
        if primary and primary.src_user:
            candidate_users.append(primary.src_user)
        for u in case.affected_users or []:
            if u and u not in candidate_users:
                candidate_users.append(u)

        if not candidate_users:
            self.trace(
                TraceStep.DECISION,
                "ITDR skipped: no identity entity on case",
                detail={"alert_id": primary.id if primary else None},
            )
            return AgentResult(
                summary="No identity entity on case — ITDR skipped.",
                handoff=Handoff(
                    to=AgentName.RESPONDER,
                    reason="No identity surface; defer to standard Responder.",
                ),
            )

        self.trace(
            TraceStep.PLAN,
            f"ITDR investigation for users={candidate_users}",
            detail={
                "users": candidate_users,
                "verdict": getattr(case.verdict, "value", str(case.verdict)),
                "autonomy_level": settings.autonomy_level,
            },
        )

        case_blob = json.dumps(
            {
                "verdict": getattr(case.verdict, "value", str(case.verdict)),
                "severity": getattr(case.severity, "value", str(case.severity)),
                "confidence": case.confidence,
                "title": case.title,
                "affected_users": candidate_users,
                "affected_hosts": case.affected_hosts,
                "iocs": case.iocs,
            },
            default=str,
        )
        alert_blob = _alert_to_json(primary)

        system_prompt = (
            "You are the ITDR (Identity Threat Detection & Response) agent. "
            "Your job is to investigate identity compromise and execute "
            "SURGICAL containment — never blanket sign-outs. The platform "
            "enforces a risk gate on every write tool; do not second-guess "
            "it, just request the action.\n"
            "\n"
            "PROCEDURE for each affected user:\n"
            "  1. `idp.list_user_sessions(user=...)` — enumerate active "
            "     sessions. Flag any where `aitm_suspected=true` OR "
            "     `anomaly_score>=0.7`. Look for impossible-travel (two "
            "     sessions in distant countries inside the same hour), "
            "     untrusted devices, or MFA methods downgraded to "
            "     SMS / 'none'.\n"
            "  2. `idp.list_oauth_grants(user=...)` — enumerate consent "
            "     grants. Flag any where `risk_score>=0.6`, unverified "
            "     publisher with mail/file scopes, or recently granted "
            "     `offline_access` to an unknown app.\n"
            "  3. (Optional) `idp.list_oauth_apps()` if a suspicious "
            "     `client_id` appears — to see how many other users in "
            "     the tenant also consented to it (tenant-wide blast "
            "     radius).\n"
            "\n"
            "CONTAINMENT POLICY:\n"
            "  * For each flagged session, call `idp.revoke_session("
            "user=..., session_id=..., reason=...)`. ONE session at a "
            "time. Do NOT call `idp.revoke_sessions` (blanket) unless "
            "targeted revoke is impossible AND verdict is TRUE_POSITIVE.\n"
            "  * For each flagged grant, call `idp.revoke_oauth_grant("
            "user=..., grant_id=..., reason=...)`.\n"
            "  * Always include a one-sentence `reason` so the audit "
            "trail explains *why* this specific session/grant was "
            "killed.\n"
            "\n"
            "STOP when sessions and grants are clean OR you have already "
            "issued the targeted revokes. Return a 2–4 sentence summary "
            "naming each session_id / grant_id you revoked and why."
        )
        user_msg = (
            f"Case:\n{case_blob}\n\n"
            f"Primary alert:\n{alert_blob}\n\n"
            f"Affected users: {candidate_users}\n\n"
            "Investigate identity compromise and execute targeted "
            "containment. Stop when the identity surface is clean."
        )

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=10,
                max_tokens=1100,
            )
        except HitlBlocked as exc:
            # Analyst denied a revoke. We persist the verdict-so-far and
            # hand back to the orchestrator; this is not a crash.
            self.trace(
                TraceStep.DECISION,
                f"ITDR halted: HITL denied containment ({exc.state})",
                detail={"hitl_state": exc.state, "reason": exc.reason},
            )
            final_text = ""
        except Exception as exc:  # pragma: no cover — defensive
            self.trace(
                TraceStep.ERROR,
                f"LLM loop failed: {exc}; falling back to deterministic ITDR sweep",
                detail={"error": str(exc)},
            )
            final_text = ""
            await _deterministic_itdr_sweep(self, candidate_users)

        # Summarize what actually happened by reading the tool-result
        # scratchpad. We do NOT trust the LLM's claimed actions — we
        # trust the audit-grade tool-call ledger.
        flagged_sessions: list[dict[str, Any]] = []
        flagged_grants: list[dict[str, Any]] = []
        revoked_sessions: list[str] = []
        revoked_grants: list[str] = []
        suspicious_apps: list[str] = []

        for r in scratchpad.get(self.case_id, "tool_results", []) or []:
            tool = r["tool"]
            res = r["result"] or {}
            # The IdP list-* tools return the user at the top level
            # alongside the sessions/grants array. Fold that user back
            # onto each row so the deterministic backstop knows whose
            # session/grant it's about to revoke. Falls back to the
            # first candidate when the mock/connector omits it.
            parent_user = res.get("user") or (
                candidate_users[0] if candidate_users else None
            )
            if tool == "idp.list_user_sessions":
                for s in res.get("sessions", []) or []:
                    if s.get("aitm_suspected") or (s.get("suspected_aitm")) or (
                        s.get("anomaly_score", 0) or 0
                    ) >= _AITM_THRESHOLD:
                        enriched = dict(s)
                        enriched.setdefault("user", parent_user)
                        flagged_sessions.append(enriched)
            elif tool == "idp.list_oauth_grants":
                for g in res.get("grants", []) or []:
                    if (g.get("risk_score", 0) or 0) >= _ILLICIT_GRANT_THRESHOLD:
                        enriched = dict(g)
                        enriched.setdefault("user", parent_user)
                        flagged_grants.append(enriched)
                        if g.get("client_id"):
                            suspicious_apps.append(g["client_id"])
            elif tool == "idp.revoke_session" and res.get("revoked"):
                if res.get("session_id"):
                    revoked_sessions.append(res["session_id"])
            elif tool == "idp.revoke_oauth_grant" and res.get("revoked"):
                if res.get("grant_id"):
                    revoked_grants.append(res["grant_id"])

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_rationale": final_text},
            )

        # Deterministic backstop: if the LLM did not contain a clearly
        # malicious session (e.g. it stalled, hit max_turns, or only
        # enumerated), fall back to issuing the revoke ourselves for
        # any session/grant that crossed the threshold AND was not
        # already revoked. This is bounded by _MAX_REVOKES_PER_CASE so
        # we don't go on a rampage if the upstream enumeration returned
        # 200 sessions.
        await _deterministic_revoke_backstop(
            self,
            flagged_sessions=flagged_sessions,
            flagged_grants=flagged_grants,
            already_revoked_sessions=set(revoked_sessions),
            already_revoked_grants=set(revoked_grants),
            revoked_sessions=revoked_sessions,
            revoked_grants=revoked_grants,
        )

        # Decide handoff. ITDR has narrow scope; it never closes a case
        # on its own — that's Reporter's job.
        identity_signals = (
            bool(flagged_sessions) or bool(flagged_grants) or bool(suspicious_apps)
        )
        contained = bool(revoked_sessions) or bool(revoked_grants)

        if identity_signals and not contained:
            # We found the threat but couldn't contain (HITL denial,
            # missing tools, or below threshold). Send to Responder so
            # endpoint-side actions can still run, and so the human gets
            # full case context.
            reason = (
                "Identity threat detected but not contained from ITDR. "
                "Responder should sweep endpoint-side and analyst will "
                "decide on broader sign-out."
            )
            handoff_to = AgentName.RESPONDER
        elif identity_signals and contained:
            # Identity was the primary vector and we've revoked the
            # specific bad session/grant. Defer to Reporter unless the
            # case verdict explicitly demands endpoint response.
            if case.verdict == Verdict.TRUE_POSITIVE and case.affected_hosts:
                handoff_to = AgentName.RESPONDER
                reason = (
                    "Identity contained (targeted revoke). Endpoints "
                    "still on case — Responder for host containment."
                )
            else:
                handoff_to = AgentName.REPORTER
                reason = (
                    "Identity threat contained via targeted revoke; "
                    "no endpoint surface — report and close."
                )
        else:
            # No identity threat — clean handoff to Responder.
            handoff_to = AgentName.RESPONDER
            reason = "No identity threat surface; defer to Responder."

        self.trace(
            TraceStep.DECISION,
            (
                f"ITDR summary: {len(flagged_sessions)} suspicious sessions, "
                f"{len(flagged_grants)} illicit grants; "
                f"revoked {len(revoked_sessions)} sessions, "
                f"{len(revoked_grants)} grants"
            ),
            detail={
                "flagged_sessions": [s.get("session_id") for s in flagged_sessions],
                "flagged_grants": [g.get("grant_id") for g in flagged_grants],
                "revoked_sessions": revoked_sessions,
                "revoked_grants": revoked_grants,
                "suspicious_apps": list(set(suspicious_apps)),
                "handoff_to": handoff_to.value
                if hasattr(handoff_to, "value")
                else str(handoff_to),
            },
        )

        # Stamp suspicious oauth `client_id`s onto the case IOC list so
        # the rest of the platform (Reporter, Hunter, Detection Author)
        # can pivot on them.
        if suspicious_apps:
            case.iocs = list({*case.iocs, *suspicious_apps})
            self.db.add(case)
            self.db.commit()

        summary = (
            f"ITDR: flagged {len(flagged_sessions)} sessions / "
            f"{len(flagged_grants)} grants; "
            f"revoked {len(revoked_sessions)} sessions / "
            f"{len(revoked_grants)} grants."
        )

        return AgentResult(
            summary=summary,
            handoff=Handoff(to=handoff_to, reason=reason),
            case_updates={
                "itdr": {
                    "flagged_sessions": [
                        s.get("session_id") for s in flagged_sessions
                    ],
                    "flagged_grants": [g.get("grant_id") for g in flagged_grants],
                    "revoked_sessions": revoked_sessions,
                    "revoked_grants": revoked_grants,
                    "suspicious_apps": sorted(set(suspicious_apps)),
                }
            },
        )


# ── Helpers ────────────────────────────────────────────────────────────


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "src_user": alert.src_user,
        "src_host": alert.src_host,
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


async def _deterministic_itdr_sweep(
    agent: "ITDRAgent", users: list[str]
) -> None:
    """Fallback enumeration if the LLM loop failed before any READ call.

    Read-only; never revokes. The revoke decision is intentionally left
    to the LLM-driven path OR the deterministic backstop below, both of
    which run *after* this. This way the audit trail still shows what
    the identity surface looked like at investigation time even if the
    model crashed.
    """
    for u in users:
        try:
            await agent.call_tool("idp.list_user_sessions", {"user": u})
        except Exception:  # pragma: no cover — best-effort
            pass
        try:
            await agent.call_tool("idp.list_oauth_grants", {"user": u})
        except Exception:  # pragma: no cover — best-effort
            pass


async def _deterministic_revoke_backstop(
    agent: "ITDRAgent",
    *,
    flagged_sessions: list[dict[str, Any]],
    flagged_grants: list[dict[str, Any]],
    already_revoked_sessions: set[str],
    already_revoked_grants: set[str],
    revoked_sessions: list[str],
    revoked_grants: list[str],
) -> None:
    """If the LLM identified threats but didn't contain them, revoke
    the highest-risk items here, bounded by _MAX_REVOKES_PER_CASE.

    Each revoke still routes through `call_tool` → HITL gate → audit;
    this function is *not* a bypass, it's just deterministic glue that
    makes sure flagged threats reach the gate even if the LLM stalled.

    Only fires when verdict is TRUE_POSITIVE; for borderline / benign
    cases we leave containment to the human in the loop.
    """
    case = agent.db.get(Case, agent.case_id)
    if case.verdict != Verdict.TRUE_POSITIVE:
        return

    budget = _MAX_REVOKES_PER_CASE - (
        len(already_revoked_sessions) + len(already_revoked_grants)
    )
    if budget <= 0:
        return

    # Sessions first — kill the active hijack before the OAuth chain.
    flagged_sessions.sort(
        key=lambda s: s.get("anomaly_score") or 0, reverse=True
    )
    for s in flagged_sessions:
        if budget <= 0:
            break
        sid = s.get("session_id")
        user = s.get("user") or (s.get("user_id") if isinstance(s, dict) else None)
        if not sid or sid in already_revoked_sessions:
            continue
        try:
            res = await agent.call_tool(
                "idp.revoke_session",
                {
                    "user": user,
                    "session_id": sid,
                    "reason": "ITDR backstop: AitM-suspected session",
                },
                rationale="ITDR deterministic backstop after LLM stall",
                blast_radius={"sessions": 1, "scope": "single-session"},
            )
            if (res or {}).get("revoked"):
                revoked_sessions.append(sid)
                budget -= 1
        except HitlBlocked:
            # Analyst declined; nothing else to do.
            return
        except Exception:  # pragma: no cover — defensive
            continue

    # Then OAuth grants — kill the long-lived consent token.
    flagged_grants.sort(
        key=lambda g: g.get("risk_score") or 0, reverse=True
    )
    for g in flagged_grants:
        if budget <= 0:
            break
        gid = g.get("grant_id")
        user = g.get("user") or g.get("user_id")
        if not gid or gid in already_revoked_grants:
            continue
        try:
            res = await agent.call_tool(
                "idp.revoke_oauth_grant",
                {
                    "user": user,
                    "grant_id": gid,
                    "reason": "ITDR backstop: illicit-consent grant",
                },
                rationale="ITDR deterministic backstop after LLM stall",
                blast_radius={"grants": 1, "scope": "single-grant"},
            )
            if (res or {}).get("revoked"):
                revoked_grants.append(gid)
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue
