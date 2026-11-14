"""SaaS Posture: SaaS Security Posture Management sub-agent.

Specialized SaaS-plane investigator + surgical responder. Where ITDR
(Theme 2c) owns the IdP session/OAuth surface and CDR (Theme 2d) owns
the cloud control plane, the SaaS Posture agent (Theme 2e) owns the
SaaS application surface spanning M365, Google Workspace, Salesforce,
GitHub, and Slack:

  * **App / integration inventory** — enumerate installed third-party
    apps across all five providers. Each row carries publisher-verified
    status, granted scopes, install user count, and a heuristic risk
    score. The classic illicit-consent shape (unverified publisher,
    broad scopes, single recent installer) lights up here.
  * **CIS-style misconfigurations** — auth policies, sharing defaults,
    admin MFA, GitHub branch protection, Slack app install allowlists.
    Surface what's *configured wrong* vs what's actively being abused.
  * **External shares** — public OneDrive links, public Drive folders,
    Salesforce reports shared with off-boarded vendors, public GitHub
    repos, Slack channels still hosting external guests. This is
    where the data-leak incidents that no detection rule fires on
    actually live.
  * **Third-party OAuth grants** — the SSPM counterpart to ITDR's
    OAuth grants. Cross-provider view (M365 + Workspace + GitHub +
    Slack) so a single "ContosoDocSign-style" attacker app shows up
    in one place.
  * **Surgical SSPM containment** — three forward-only tools, never
    a tenant-wide sweep:
      - ``saas.revoke_third_party_integration`` — kill one OAuth grant.
      - ``saas.restrict_external_share`` — flip one public link to
        internal-only.
      - ``saas.remove_external_collaborator`` — remove one external
        principal from one resource.
    We do **not** expose tenant-wide knobs like "disable all external
    sharing org-wide" or "uninstall all unverified apps" — those blast
    radii are too big for an agent, even with HITL.

Containment is forward-only by design (see ``app/tools/saas.py`` for
the per-tool rationale): re-grant / re-share / re-invite are all
fresh consent decisions and can't be auto-rolled-back without
becoming phishing primitives.

Handoff
-------
The SaaS Posture agent is normally invoked between Investigator and
Responder when the case has a SaaS-plane signal (M365 / Workspace /
Salesforce / GitHub / Slack source, OAuth-grant title, public-share
title, etc.). It returns to the orchestrator with one of:

  * ``Handoff(to=RESPONDER)`` — SaaS contained, but endpoint /
    identity / network work remains.
  * ``Handoff(to=REPORTER)`` — case was SaaS-only and is now fully
    contained (or no SaaS threat was found).
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


# An installed-app risk above this is treated as illicit-consent / OAuth
# abuse pattern and is eligible for surgical revocation.
_APP_RISK_THRESHOLD = 0.7
# A third-party OAuth grant above this is eligible for revocation.
_GRANT_RISK_THRESHOLD = 0.7
# A public/external share above this is eligible for re-scoping to
# internal-only.
_SHARE_RISK_THRESHOLD = 0.75
# Misconfigurations of this severity (or higher) are flagged in the
# case file even if we don't have a write-tool for them. They surface
# in the Reporter's remediation list.
_MISCONFIG_REPORT_SEVERITIES = {"high", "critical"}
# Hard cap on writes per case so a stalled LLM (or a hallucinated
# "every share looks bad") can't unshare an entire org at once.
_MAX_WRITES_PER_CASE = 6


class SaaSPostureAgent(BaseAgent):
    """SaaS Security Posture sub-agent."""

    name = AgentName.SAAS_POSTURE
    role = (
        "SaaS-plane detection and response. Owns app inventory, "
        "misconfigurations, external shares, and third-party OAuth "
        "grants across M365, Workspace, Salesforce, GitHub, Slack. "
        "Performs surgical containment — one OAuth grant revoked, "
        "one public link restricted, one external collaborator "
        "removed — never tenant-wide sweeps. All writes route "
        "through the HITL gate."
    )
    allowed_tools = [
        # READ — build the picture
        "saas.list_applications",
        "saas.list_misconfigurations",
        "saas.list_external_shares",
        "saas.list_third_party_integrations",
        # WRITE_SIGNIFICANT — surgical containment (HITL-gated by base)
        "saas.revoke_third_party_integration",
        "saas.restrict_external_share",
        "saas.remove_external_collaborator",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        # Surface hint: try to figure out which provider(s) this case
        # is actually about, so the agent (and the deterministic
        # sweep) can prioritise their enumeration. We never hard-pin
        # the agent to a single provider — cross-provider attacker
        # apps are exactly the pattern SSPM is supposed to catch —
        # but the hint makes its first calls land somewhere useful.
        candidate_providers = _guess_providers(primary, case)

        self.trace(
            TraceStep.PLAN,
            f"SaaS Posture investigation; candidate providers={candidate_providers}",
            detail={
                "providers": candidate_providers,
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
                "affected_users": case.affected_users,
                "affected_hosts": case.affected_hosts,
                "iocs": case.iocs,
            },
            default=str,
        )
        alert_blob = _alert_to_json(primary)

        system_prompt = (
            "You are the SaaS Posture (SSPM) agent. Your job is to "
            "investigate SaaS-plane compromise across M365, Google "
            "Workspace, Salesforce, GitHub, and Slack, and execute "
            "SURGICAL containment — never tenant-wide sweeps. The "
            "platform enforces a risk gate on every write tool; do "
            "not second-guess it, just request the action.\n"
            "\n"
            "PROCEDURE:\n"
            "  1. `saas.list_third_party_integrations()` — pull "
            "     active OAuth grants across all providers. Flag any "
            f"     with `risk_score>={_GRANT_RISK_THRESHOLD}`; these "
            "     are the illicit-consent candidates.\n"
            "  2. `saas.list_applications()` — cross-check installed "
            "     apps to confirm the publisher-verified state, broad "
            "     scopes, and recent single-installer shape.\n"
            "  3. `saas.list_external_shares()` — surface public / "
            "     external resource shares. Flag any with "
            f"     `risk_score>={_SHARE_RISK_THRESHOLD}` or "
            "     `contains_sensitive=true`.\n"
            "  4. `saas.list_misconfigurations()` — pull CIS-style "
            "     findings. high/critical posture gaps go in the "
            "     case file even if you can't action them directly.\n"
            "\n"
            "CONTAINMENT POLICY:\n"
            "  * Prefer the narrowest write that resolves the threat:\n"
            "    - If a third-party OAuth grant crosses the risk "
            "      threshold, `saas.revoke_third_party_integration("
            "      provider=..., grant_id=..., reason=...)`. ONE "
            "      grant.\n"
            "    - If a public/external share crosses the risk "
            "      threshold OR contains sensitive data, "
            "      `saas.restrict_external_share(provider=..., "
            "      share_id=..., reason=...)`. ONE share.\n"
            "    - If a resource has a specific off-boarded / "
            "      external principal still attached, "
            "      `saas.remove_external_collaborator(provider=..., "
            "      resource_id=..., external_principal=..., "
            "      reason=...)`. ONE principal on ONE resource.\n"
            "  * Always include a one-sentence `reason` so the audit "
            "    trail explains *why* this specific resource was "
            "    contained.\n"
            "  * Do NOT call `saas.revoke_third_party_integration` "
            "    AND `saas.remove_external_collaborator` on the same "
            "    app+user pair — pick the narrower one (almost "
            "    always: revoke the grant).\n"
            "\n"
            "STOP when the SaaS surface is clean or you've issued "
            "the targeted writes. Return a 2–4 sentence summary "
            "naming each grant / share / collaborator you contained "
            "and why."
        )
        user_msg = (
            f"Case:\n{case_blob}\n\n"
            f"Primary alert:\n{alert_blob}\n\n"
            f"Candidate SaaS providers: {candidate_providers}\n\n"
            "Investigate SaaS-plane compromise and execute targeted "
            "containment. Stop when the SaaS surface is clean."
        )

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=12,
                max_tokens=1200,
            )
        except HitlBlocked as exc:
            # Analyst denied a containment write. Persist what we've
            # learned so far and hand back to the orchestrator — this
            # is not a crash, it's a human decision.
            self.trace(
                TraceStep.DECISION,
                f"SaaS Posture halted: HITL denied containment ({exc.state})",
                detail={"hitl_state": exc.state, "reason": exc.reason},
            )
            final_text = ""
        except Exception as exc:  # pragma: no cover — defensive
            self.trace(
                TraceStep.ERROR,
                (
                    f"LLM loop failed: {exc}; falling back to "
                    "deterministic SaaS Posture sweep"
                ),
                detail={"error": str(exc)},
            )
            final_text = ""
            await _deterministic_saas_sweep(self, candidate_providers)

        # Always run a deterministic read-only sweep with sensible
        # defaults. Same rationale as CDR: guarantees the audit trail
        # has a baseline SaaS-surface snapshot regardless of how well
        # the LLM picked tool arguments. Critical for mock-LLM runs
        # and for cases where the LLM filters too narrowly.
        await _deterministic_saas_sweep(self, candidate_providers)

        # Summarize what *actually* happened by reading the tool-call
        # scratchpad. The LLM's narration is logged as rationale, but
        # the audit trail is the ledger of tool results.
        flagged_grants: list[dict[str, Any]] = []
        flagged_apps: list[dict[str, Any]] = []
        flagged_shares: list[dict[str, Any]] = []
        critical_misconfigs: list[dict[str, Any]] = []
        revoked_grants: list[dict[str, Any]] = []
        restricted_shares: list[dict[str, Any]] = []
        removed_collabs: list[dict[str, Any]] = []

        for r in scratchpad.get(self.case_id, "tool_results", []) or []:
            tool = r["tool"]
            res = r["result"] or {}
            if tool == "saas.list_third_party_integrations":
                for g in res.get("integrations", []) or []:
                    if (g.get("risk_score") or 0) >= _GRANT_RISK_THRESHOLD:
                        flagged_grants.append(g)
            elif tool == "saas.list_applications":
                for a in res.get("applications", []) or []:
                    if (a.get("risk_score") or 0) >= _APP_RISK_THRESHOLD:
                        flagged_apps.append(a)
            elif tool == "saas.list_external_shares":
                for s in res.get("shares", []) or []:
                    if (
                        (s.get("risk_score") or 0) >= _SHARE_RISK_THRESHOLD
                        or s.get("contains_sensitive")
                    ):
                        flagged_shares.append(s)
            elif tool == "saas.list_misconfigurations":
                for f in res.get("findings", []) or []:
                    if (
                        (f.get("severity") or "").lower()
                        in _MISCONFIG_REPORT_SEVERITIES
                    ):
                        critical_misconfigs.append(f)
            elif tool == "saas.revoke_third_party_integration" and res.get("revoked"):
                revoked_grants.append(
                    {
                        "provider": res.get("provider"),
                        "grant_id": res.get("grant_id"),
                    }
                )
            elif tool == "saas.restrict_external_share" and res.get("restricted"):
                restricted_shares.append(
                    {
                        "provider": res.get("provider"),
                        "share_id": res.get("share_id"),
                    }
                )
            elif tool == "saas.remove_external_collaborator" and res.get("removed"):
                removed_collabs.append(
                    {
                        "provider": res.get("provider"),
                        "resource_id": res.get("resource_id"),
                        "external_principal": res.get("external_principal"),
                    }
                )

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_rationale": final_text},
            )

        # Deterministic backstop: if the LLM identified threats but
        # didn't contain them (stalled, hit max_turns, only enumerated),
        # request the highest-priority writes ourselves. Each call
        # still routes through the HITL gate; this is not a bypass.
        await _deterministic_contain_backstop(
            self,
            flagged_grants=flagged_grants,
            flagged_shares=flagged_shares,
            already_revoked={
                (r["provider"], r["grant_id"]) for r in revoked_grants
            },
            already_restricted={
                (r["provider"], r["share_id"]) for r in restricted_shares
            },
            revoked_grants=revoked_grants,
            restricted_shares=restricted_shares,
        )

        # Decide handoff. SaaS Posture is narrow-scope; never closes
        # a case on its own — Reporter does that.
        saas_signals = bool(
            flagged_grants
            or flagged_apps
            or flagged_shares
            or critical_misconfigs
        )
        contained = bool(
            revoked_grants or restricted_shares or removed_collabs
        )

        if saas_signals and not contained:
            handoff_to = AgentName.RESPONDER
            reason = (
                "SaaS threat detected but not contained from SaaS "
                "Posture. Responder should sweep endpoint/identity-"
                "side and analyst will decide on broader containment."
            )
        elif saas_signals and contained:
            if case.verdict == Verdict.TRUE_POSITIVE and case.affected_hosts:
                handoff_to = AgentName.RESPONDER
                reason = (
                    "SaaS contained (targeted writes). Endpoints "
                    "still on case — Responder for host containment."
                )
            else:
                handoff_to = AgentName.REPORTER
                reason = (
                    "SaaS threat contained via targeted writes; no "
                    "remaining endpoint surface — report and close."
                )
        else:
            handoff_to = AgentName.RESPONDER
            reason = "No SaaS-plane threat; defer to Responder."

        self.trace(
            TraceStep.DECISION,
            (
                f"SaaS Posture summary: {len(flagged_grants)} grants, "
                f"{len(flagged_apps)} apps, {len(flagged_shares)} shares, "
                f"{len(critical_misconfigs)} critical misconfigs; "
                f"revoked {len(revoked_grants)} grants, "
                f"restricted {len(restricted_shares)} shares, "
                f"removed {len(removed_collabs)} collaborators"
            ),
            detail={
                "flagged_grants": [
                    {"provider": g.get("provider"), "grant_id": g.get("grant_id")}
                    for g in flagged_grants
                ],
                "flagged_apps": [
                    {"provider": a.get("provider"), "app_id": a.get("app_id")}
                    for a in flagged_apps
                ],
                "flagged_shares": [
                    {"provider": s.get("provider"), "share_id": s.get("share_id")}
                    for s in flagged_shares
                ],
                "critical_misconfigs": [
                    f.get("control_id") for f in critical_misconfigs
                ],
                "revoked_grants": revoked_grants,
                "restricted_shares": restricted_shares,
                "removed_collabs": removed_collabs,
                "handoff_to": handoff_to.value
                if hasattr(handoff_to, "value")
                else str(handoff_to),
            },
        )

        # Stamp the most actionable IOCs (revoked app names / share
        # URLs) back onto the case so the Reporter / Hunter can pivot
        # on them. The grant_id alone isn't useful cross-tenant; the
        # app *name* and *publisher* are.
        new_iocs: list[str] = []
        for g in flagged_grants:
            pub = g.get("publisher")
            app_name = g.get("app_name")
            if pub and pub.lower() not in {"microsoft", "google"} and app_name:
                new_iocs.append(f"saas-app:{app_name} ({pub})")
        if new_iocs:
            case.iocs = list({*case.iocs, *new_iocs})
            self.db.add(case)
            self.db.commit()

        summary = (
            f"SaaS Posture: flagged {len(flagged_grants)} grants / "
            f"{len(flagged_shares)} shares / {len(flagged_apps)} apps / "
            f"{len(critical_misconfigs)} misconfigs; "
            f"contained {len(revoked_grants)} grants / "
            f"{len(restricted_shares)} shares / "
            f"{len(removed_collabs)} collaborators."
        )

        return AgentResult(
            summary=summary,
            handoff=Handoff(to=handoff_to, reason=reason),
            case_updates={
                "saas_posture": {
                    "flagged_grants": [
                        {
                            "provider": g.get("provider"),
                            "grant_id": g.get("grant_id"),
                            "app_name": g.get("app_name"),
                            "risk_score": g.get("risk_score"),
                        }
                        for g in flagged_grants
                    ],
                    "flagged_apps": [
                        {
                            "provider": a.get("provider"),
                            "app_id": a.get("app_id"),
                            "name": a.get("name"),
                            "risk_score": a.get("risk_score"),
                        }
                        for a in flagged_apps
                    ],
                    "flagged_shares": [
                        {
                            "provider": s.get("provider"),
                            "share_id": s.get("share_id"),
                            "resource_name": s.get("resource_name"),
                            "risk_score": s.get("risk_score"),
                        }
                        for s in flagged_shares
                    ],
                    "critical_misconfigs": [
                        {
                            "provider": f.get("provider"),
                            "control_id": f.get("control_id"),
                            "control_name": f.get("control_name"),
                            "severity": f.get("severity"),
                        }
                        for f in critical_misconfigs
                    ],
                    "revoked_grants": revoked_grants,
                    "restricted_shares": restricted_shares,
                    "removed_collabs": removed_collabs,
                }
            },
        )


# ── Helpers ────────────────────────────────────────────────────────────


# Token → provider mapping. Anything alert.source / alert.title /
# alert.description matches against. Order doesn't matter; we union.
_PROVIDER_HINTS: dict[str, tuple[str, ...]] = {
    "m365": (
        "m365",
        "office365",
        "office 365",
        "microsoft 365",
        "azuread",
        "azure ad",
        "exchange",
        "onedrive",
        "sharepoint",
        "entra",
    ),
    "workspace": (
        "workspace",
        "gworkspace",
        "google workspace",
        "gdrive",
        "drive.google",
        "gmail",
    ),
    "salesforce": ("salesforce", "sfdc", "force.com"),
    "github": ("github", "github.com"),
    "slack": ("slack",),
}


def _guess_providers(alert: Alert | None, case: Case) -> list[str]:
    """Best-effort routing hint: which SaaS providers does this case touch?

    We don't restrict the agent to these — cross-provider attacker
    apps are exactly what SSPM is supposed to catch — but the LLM /
    deterministic sweep uses them to prioritise their first calls.
    """
    haystacks: list[str] = []
    if alert is not None:
        for s in (
            alert.source,
            alert.title,
            alert.description,
            alert.src_user,
        ):
            if s:
                haystacks.append(str(s).lower())
        # Raw payload sometimes has provider-tagged fields like
        # `app_name=ContosoDocSign` or `repo=contoso/payroll-ingest`.
        for v in (alert.raw or {}).values():
            if isinstance(v, str):
                haystacks.append(v.lower())
    if case.title:
        haystacks.append(case.title.lower())
    blob = " ".join(haystacks)

    hits: list[str] = []
    for provider, tokens in _PROVIDER_HINTS.items():
        if any(tok in blob for tok in tokens):
            hits.append(provider)
    return hits


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    raw = alert.raw or {}
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "src_user": alert.src_user,
        "src_host": alert.src_host,
        "source": alert.source,
        # SSPM-relevant fields most upstream connectors stamp into raw.
        "app_name": raw.get("app_name"),
        "publisher": raw.get("publisher"),
        "scopes": raw.get("scopes"),
        "share_url": raw.get("share_url"),
        "repo": raw.get("repo"),
        "channel": raw.get("channel"),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


async def _deterministic_saas_sweep(
    agent: "SaaSPostureAgent", providers: list[str]
) -> None:
    """Fallback enumeration if the LLM loop crashed before any READ call.

    Read-only; never writes. The write decision is intentionally left
    to the LLM-driven path OR the deterministic backstop below, both
    of which run *after* this. The point of the sweep is to make sure
    the audit trail still has a snapshot of the SaaS surface even when
    the model crashes.

    Mirrors the CDR pattern: broad first calls (no provider filter) so
    we see cross-provider attacker apps, then targeted hint-driven
    calls if we picked up specific providers from the alert.
    """
    try:
        await agent.call_tool("saas.list_third_party_integrations", {})
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool("saas.list_applications", {})
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool("saas.list_external_shares", {})
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool("saas.list_misconfigurations", {})
    except Exception:  # pragma: no cover — best-effort
        pass

    # Provider-scoped follow-ups so the audit trail clearly shows the
    # agent looked at the specific provider the alert pointed at, even
    # though the broad call already covered it.
    for provider in providers[:3]:
        try:
            await agent.call_tool(
                "saas.list_third_party_integrations", {"provider": provider}
            )
        except Exception:  # pragma: no cover — best-effort
            pass
        try:
            await agent.call_tool(
                "saas.list_external_shares", {"provider": provider}
            )
        except Exception:  # pragma: no cover — best-effort
            pass


async def _deterministic_contain_backstop(
    agent: "SaaSPostureAgent",
    *,
    flagged_grants: list[dict[str, Any]],
    flagged_shares: list[dict[str, Any]],
    already_revoked: set[tuple[str | None, str | None]],
    already_restricted: set[tuple[str | None, str | None]],
    revoked_grants: list[dict[str, Any]],
    restricted_shares: list[dict[str, Any]],
) -> None:
    """Request the highest-priority writes if the LLM enumerated but
    didn't act. Each call routes through HITL → audit; this function
    is deterministic glue, not a bypass of the gate.

    Only fires when verdict is TRUE_POSITIVE; for borderline / benign
    cases we leave containment to the human in the loop.

    Backstop order matches the per-finding cost-of-rollback:
      1. Revoke the worst third-party OAuth grant (cheapest to rollback
         in a benign-case mistake — user just re-consents).
      2. Restrict the worst public share (rollback is a fresh sharing
         decision but no external party has to re-accept).
    We deliberately *do not* run `remove_external_collaborator` from
    the backstop: it requires a `resource_id` + `external_principal`
    pair, which only meaningfully comes from the LLM reasoning over a
    specific finding. If we just pick "first external principal we
    saw", we'll remove the wrong person.
    """
    case = agent.db.get(Case, agent.case_id)
    if case.verdict != Verdict.TRUE_POSITIVE:
        return

    budget = _MAX_WRITES_PER_CASE - (
        len(already_revoked) + len(already_restricted)
    )
    if budget <= 0:
        return

    # 1. Revoke top-risk OAuth grants first.
    grants_sorted = sorted(
        flagged_grants,
        key=lambda g: g.get("risk_score") or 0,
        reverse=True,
    )
    for g in grants_sorted:
        if budget <= 0:
            break
        provider = g.get("provider")
        grant_id = g.get("grant_id")
        if not provider or not grant_id:
            continue
        if (provider, grant_id) in already_revoked:
            continue
        try:
            res = await agent.call_tool(
                "saas.revoke_third_party_integration",
                {
                    "provider": provider,
                    "grant_id": grant_id,
                    "reason": (
                        "SaaS Posture backstop: high-risk OAuth grant "
                        f"({g.get('app_name') or 'unknown app'})"
                    ),
                },
                rationale="SaaS Posture deterministic backstop after LLM stall",
                blast_radius={"grants": 1, "scope": "single-grant"},
            )
            if (res or {}).get("revoked"):
                revoked_grants.append(
                    {"provider": provider, "grant_id": grant_id}
                )
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue

    # 2. Restrict top-risk public/external shares.
    shares_sorted = sorted(
        flagged_shares,
        key=lambda s: s.get("risk_score") or 0,
        reverse=True,
    )
    for s in shares_sorted:
        if budget <= 0:
            break
        provider = s.get("provider")
        share_id = s.get("share_id")
        if not provider or not share_id:
            continue
        if (provider, share_id) in already_restricted:
            continue
        try:
            res = await agent.call_tool(
                "saas.restrict_external_share",
                {
                    "provider": provider,
                    "share_id": share_id,
                    "reason": (
                        "SaaS Posture backstop: high-risk public/external "
                        f"share ({s.get('resource_name') or 'unknown resource'})"
                    ),
                },
                rationale="SaaS Posture deterministic backstop after LLM stall",
                blast_radius={"shares": 1, "scope": "single-share"},
            )
            if (res or {}).get("restricted"):
                restricted_shares.append(
                    {"provider": provider, "share_id": share_id}
                )
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue
