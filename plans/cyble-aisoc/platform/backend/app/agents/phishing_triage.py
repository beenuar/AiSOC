"""Phishing Triage: specialized sub-agent for suspicious-email cases.

The generic Triager handles every alert type, including email-derived
alerts, but for high-volume phishing reporting it under-uses Cyble's
moat. The Phishing Triage agent (Theme 2f) is the deep specialist that
takes a single suspicious-email case and runs the full proprietary
analysis stack:

  * ``email.analyze_message`` — pull raw headers, links, attachments via
    the per-tenant email connector (Proofpoint / M365 / mock).
  * ``phishing.deep_header_analysis`` — SPF/DKIM/DMARC verdict + ARC chain
    + From/Reply-To/Return-Path alignment + Received-hop routing
    anomalies. Cyble-native, in-process.
  * ``phishing.unwrap_url_chain`` — follow SafeLinks / ProofpointURL /
    url-shorteners until the terminal landing host.
  * ``phishing.detonate_url`` — sandbox the terminal landing page,
    capture forms, brand mimicry, JS obfuscation, credential-harvest
    patterns.
  * ``phishing.brand_impersonation`` — score sender + terminal hosts
    against the tenant brand registry and the Cyble brand-intel feed
    for lookalikes, homoglyphs, and known phishing kits.
  * ``email.clawback_message`` (WRITE-REVERSIBLE, HITL-gated) — pull
    the message from every recipient mailbox; paired with a put-back
    reverse handler so an analyst can undo a mistaken clawback.
  * ``email.block_sender`` (WRITE-REVERSIBLE, HITL-gated) — drop future
    mail from the same sender at the gateway; paired with an unblock
    reverse handler.

Two-stage analysis matters here:

1. **Phish/benign verdict.** Run all four READ tools and produce a
   ranked verdict with explicit signals (auth failures, alignment
   mismatches, brand-intel feed hits, kit fingerprints, cred harvest
   in the landing page). The verdict goes back to the case.
2. **Surgical containment.** If the verdict is phishing, request
   ``email.clawback_message`` for THIS message and
   ``email.block_sender`` for the spoofed sender domain. Each call
   routes through the HITL gate; we never auto-block at autonomy
   levels 1–2.

Handoff
-------
Phishing Triage replaces the Triager for email-derived cases. It
returns to the orchestrator with one of:

  * ``Handoff(to=INVESTIGATOR)`` — phishing verdict with affected
    users / hosts that still need broader investigation (lateral
    movement, credential reuse).
  * ``Handoff(to=REPORTER)`` — confirmed benign OR contained
    single-message phish with no downstream users.
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


# Suspicion score thresholds (composed across analyses).
_HEADER_PHISH_THRESHOLD = 0.55  # phishing.deep_header_analysis.suspicion_score
_BRAND_PHISH_VERDICTS = {"phishing"}
_BRAND_SUSPICIOUS_VERDICTS = {"suspicious"}
_DETONATION_PHISH_VERDICTS = {"phishing"}
# Cap on writes so a runaway plan can't clawback every email in the org.
_MAX_WRITES_PER_CASE = 4
# Statuses returned by email.clawback_message that we count as success.
# Mock + real connectors (M365 soft-delete, Proofpoint recall) settle on
# slightly different verbs; treat any non-error settled state as done.
# An explicit ``failed`` or ``error`` status means the connector refused.
_CLAWBACK_FAILED_STATUSES = {"failed", "error", "denied", "rejected"}


class PhishingTriageAgent(BaseAgent):
    """Specialized phishing-triage sub-agent."""

    name = AgentName.PHISHING_TRIAGE
    role = (
        "Phishing-triage specialist. Owns deep email header analysis, "
        "URL-chain unwrapping, sandbox detonation, and brand-impersonation "
        "scoring against the tenant brand registry + Cyble brand-intel "
        "feed. Performs surgical containment on confirmed phishing — "
        "one message clawback, one sender block — never tenant-wide "
        "policy edits. All writes route through HITL."
    )
    allowed_tools = [
        # READ — build the picture
        "email.analyze_message",
        "phishing.deep_header_analysis",
        "phishing.unwrap_url_chain",
        "phishing.detonate_url",
        "phishing.brand_impersonation",
        # WRITE — surgical containment (HITL-gated by base)
        "email.clawback_message",
        "email.block_sender",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        message_id, sender_addr, link_candidates = _extract_email_context(primary)

        self.trace(
            TraceStep.PLAN,
            (
                "Phishing triage; "
                f"message_id={message_id or 'unknown'}, "
                f"sender={sender_addr or 'unknown'}, "
                f"link_candidates={len(link_candidates)}"
            ),
            detail={
                "message_id": message_id,
                "sender": sender_addr,
                "link_candidates": link_candidates,
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
            "You are the Phishing Triage agent. Your job is to take a "
            "single suspicious-email case and produce a definitive "
            "phish/benign verdict using the deep tool stack, then "
            "execute SURGICAL containment if confirmed.\n"
            "\n"
            "READ PHASE (always do all four):\n"
            "  1. `email.analyze_message(message_id=...)` — pull raw "
            "     headers, link list, attachments, base suspicion.\n"
            "  2. `phishing.deep_header_analysis(message_id=...)` — "
            "     SPF/DKIM/DMARC + ARC + alignment + routing hop "
            "     anomalies. Flag any individual auth failure plus "
            f"     any aggregate `suspicion_score>={_HEADER_PHISH_THRESHOLD}`.\n"
            "  3. For each link in the message, "
            "     `phishing.unwrap_url_chain(url=...)` then "
            "     `phishing.detonate_url(url=<terminal_url>)`. Stop "
            "     after the first 3 unique terminal hosts.\n"
            "  4. `phishing.brand_impersonation(candidate=...)` on the "
            "     sender domain AND each unique terminal host.\n"
            "\n"
            "VERDICT POLICY:\n"
            "  * Treat as phishing if ANY of:\n"
            "    - brand impersonation verdict is `phishing` "
            "      (in Cyble feed or homoglyph against tenant brand);\n"
            "    - detonation verdict is `phishing` "
            "      (credential_harvest=true OR known kit);\n"
            "    - header analysis `suspicion_score>=0.7` AND "
            "      `from_vs_return_path` is false.\n"
            "  * Treat as suspicious (needs analyst) if EXACTLY ONE "
            "    weaker signal hit (single auth failure, single "
            "    homoglyph distance, etc.).\n"
            "  * Treat as benign if all four READs come back clean.\n"
            "\n"
            "CONTAINMENT POLICY:\n"
            "  * On phishing verdict ONLY:\n"
            "    - `email.clawback_message(message_id=...)` — pull "
            "      THIS message from every recipient. Always include "
            "      a one-sentence rationale that names the deciding "
            "      signal (brand impersonation hit / kit fingerprint / "
            "      header alignment).\n"
            "    - `email.block_sender(sender=<envelope/return-path "
            "      domain>)` — block future mail from the spoofed "
            "      domain. Prefer the bare domain over the local-part.\n"
            "  * Do NOT call any write tool on suspicious or benign "
            "    verdicts. The analyst makes that call.\n"
            "\n"
            "STOP when you've issued a verdict + (for phishing) the "
            "two targeted writes. Return a 2–4 sentence summary "
            "naming the deciding signals."
        )
        user_msg = (
            f"Case:\n{case_blob}\n\n"
            f"Primary alert:\n{alert_blob}\n\n"
            f"Message id: {message_id or 'unknown'}\n"
            f"Sender candidate: {sender_addr or 'unknown'}\n"
            f"Link candidates (first 5): {link_candidates[:5]}\n\n"
            "Produce a phish/benign verdict and execute targeted "
            "containment if phishing. Stop when verdict is committed."
        )

        # Runtime guard on top of the system prompt's CONTAINMENT POLICY:
        # only expose write tools to the LLM if the case is already a
        # confirmed phish (Verdict.TRUE_POSITIVE). On NEEDS_HUMAN /
        # SUSPICIOUS / BENIGN cases we strip the writes so a hallucinated
        # tool call (or a mock-LLM that ignores the prompt) physically
        # cannot trigger a clawback. The deterministic backstop is also
        # TRUE_POSITIVE-gated, so writes only ever happen on a confirmed
        # phish, and only via HITL.
        cls_tools = type(self).allowed_tools
        if case.verdict == Verdict.TRUE_POSITIVE:
            self.allowed_tools = list(cls_tools)
        else:
            self.allowed_tools = [
                t for t in cls_tools if not t.startswith("email.")
                or t == "email.analyze_message"
            ]

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=14,
                max_tokens=1400,
            )
        except HitlBlocked as exc:
            # Analyst denied a containment write. The verdict still
            # stands — only the write was rejected. Persist what we
            # have and hand back.
            self.trace(
                TraceStep.DECISION,
                f"Phishing Triage halted: HITL denied containment ({exc.state})",
                detail={"hitl_state": exc.state, "reason": exc.reason},
            )
            final_text = ""
        except Exception as exc:  # pragma: no cover — defensive
            self.trace(
                TraceStep.ERROR,
                (
                    f"LLM loop failed: {exc}; falling back to "
                    "deterministic phishing-triage sweep"
                ),
                detail={"error": str(exc)},
            )
            final_text = ""

        # Always run a deterministic READ sweep so the audit trail has
        # a baseline phishing-surface snapshot, no matter how the LLM
        # behaved (mock-LLM, crash, max_turns). Production-LLM runs
        # already covered most of this; the sweep is idempotent at
        # the tool layer.
        await _deterministic_phishing_sweep(
            self,
            message_id=message_id,
            sender_addr=sender_addr,
            link_candidates=link_candidates,
        )

        # Read scratchpad to reconstruct what actually happened — same
        # pattern as SaaS Posture / CDR. Tool results are the ledger;
        # the LLM's narration is rationale.
        analysis = _summarize_tool_results(
            scratchpad.get(self.case_id, "tool_results", []) or []
        )

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_rationale": final_text},
            )

        # Compute final phish/benign verdict from tool results, not
        # from the LLM string. Deterministic from the analysis trail.
        verdict_str, deciding_signals = _classify(analysis)

        self.trace(
            TraceStep.DECISION,
            (
                f"Phishing verdict={verdict_str}; signals={deciding_signals}; "
                f"clawback={analysis['clawback_done']}, "
                f"block_sender={analysis['block_sender_done']}"
            ),
            detail={
                "verdict": verdict_str,
                "deciding_signals": deciding_signals,
                "header_suspicion": analysis["header_suspicion"],
                "brand_findings": analysis["brand_findings"],
                "detonation_findings": analysis["detonation_findings"],
                "url_chain_findings": analysis["url_chain_findings"],
                "clawback_done": analysis["clawback_done"],
                "block_sender_done": analysis["block_sender_done"],
            },
        )

        # Deterministic backstop: if the verdict is phishing but the
        # LLM enumerated without containing, request the two narrow
        # writes ourselves. Each call still routes through HITL; this
        # is glue, not a bypass.
        if verdict_str == "phishing":
            await _deterministic_contain_backstop(
                self,
                analysis=analysis,
                message_id=message_id,
                sender_addr=sender_addr,
            )
            # Reload analysis after backstop writes.
            analysis = _summarize_tool_results(
                scratchpad.get(self.case_id, "tool_results", []) or []
            )

        # Stamp the deciding IOCs (terminal phishing host, sender
        # domain, kit) onto the case so downstream agents and Hunter
        # can pivot on them.
        new_iocs: list[str] = []
        for finding in analysis["brand_findings"]:
            if finding.get("verdict") == "phishing":
                dom = finding.get("candidate_domain")
                if dom:
                    new_iocs.append(f"phish-domain:{dom}")
                kit = finding.get("known_kit")
                if kit:
                    new_iocs.append(f"phish-kit:{kit}")
        for finding in analysis["detonation_findings"]:
            if finding.get("verdict") == "phishing":
                host = finding.get("host")
                if host:
                    new_iocs.append(f"phish-landing:{host}")
        if new_iocs:
            case.iocs = list({*case.iocs, *new_iocs})
            self.db.add(case)
            self.db.commit()

        # Handoff. Phishing triage is narrow — never closes a case on
        # its own. Phishing → Investigator (broader lateral check) if
        # there are affected users; otherwise → Reporter.
        if verdict_str == "phishing":
            if case.affected_users or case.affected_hosts:
                handoff_to = AgentName.INVESTIGATOR
                reason = (
                    "Phishing confirmed; affected users/hosts on case "
                    "require lateral-movement / credential-reuse check."
                )
            else:
                handoff_to = AgentName.REPORTER
                reason = (
                    "Phishing confirmed and contained at the message "
                    "layer; no downstream users — report and close."
                )
        elif verdict_str == "suspicious":
            handoff_to = AgentName.INVESTIGATOR
            reason = (
                "Suspicious email signals (single weak hit). Investigator "
                "decides whether to escalate to TRUE_POSITIVE."
            )
        else:  # benign
            handoff_to = AgentName.REPORTER
            reason = "No phishing signals; benign — report and close."

        summary = (
            f"Phishing Triage: verdict={verdict_str}; "
            f"signals={deciding_signals or 'none'}; "
            f"clawback={'yes' if analysis['clawback_done'] else 'no'}, "
            f"block_sender={'yes' if analysis['block_sender_done'] else 'no'}."
        )

        return AgentResult(
            summary=summary,
            handoff=Handoff(to=handoff_to, reason=reason),
            case_updates={
                "phishing_triage": {
                    "verdict": verdict_str,
                    "deciding_signals": deciding_signals,
                    "message_id": message_id,
                    "sender": sender_addr,
                    "header_suspicion": analysis["header_suspicion"],
                    "header_findings": analysis["header_findings"],
                    "brand_findings": analysis["brand_findings"],
                    "detonation_findings": analysis["detonation_findings"],
                    "url_chain_findings": analysis["url_chain_findings"],
                    "clawback_done": analysis["clawback_done"],
                    "block_sender_done": analysis["block_sender_done"],
                }
            },
        )


# ── Helpers ────────────────────────────────────────────────────────────


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    raw = alert.raw or {}
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_user": alert.src_user,
        "source": alert.source,
        # Email-relevant fields most upstream connectors stamp into raw.
        "message_id": raw.get("message_id"),
        "from": raw.get("from") or raw.get("sender"),
        "subject": raw.get("subject"),
        "links": raw.get("links"),
        "spf": raw.get("spf"),
        "dkim": raw.get("dkim"),
        "dmarc": raw.get("dmarc"),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


def _extract_email_context(
    alert: Alert | None,
) -> tuple[str | None, str | None, list[str]]:
    """Pull (message_id, sender, links) out of the primary alert.

    Best-effort extraction across the heterogeneous fields connectors
    stamp into ``alert.raw``. We never fail here — missing context
    just means the agent (and deterministic sweep) operate on
    whatever they have and let the connector mocks supply defaults.
    """
    if alert is None:
        return None, None, []
    raw = alert.raw or {}
    message_id = (
        raw.get("message_id")
        or raw.get("messageId")
        or raw.get("internet_message_id")
    )
    sender = (
        raw.get("from")
        or raw.get("sender")
        or raw.get("from_address")
        or alert.src_user
    )
    links_raw = raw.get("links") or raw.get("urls") or []
    if isinstance(links_raw, str):
        links_raw = [links_raw]
    links: list[str] = []
    for item in links_raw:
        if isinstance(item, str):
            links.append(item)
        elif isinstance(item, dict):
            url = item.get("url") or item.get("href")
            if url:
                links.append(str(url))
    return (
        str(message_id) if message_id else None,
        str(sender) if sender else None,
        links,
    )


def _clawback_succeeded(res: dict[str, Any]) -> bool:
    """True when an email.clawback_message result indicates the recall landed.

    Different mail providers settle on different verbs (M365 → ``soft_deleted``,
    Proofpoint → ``recalled``, mock → ``quarantined``). Treat any settled
    status as success unless it explicitly signals failure, and also honour
    the optional ``clawed_back``/``removed``/``success`` booleans some
    connectors return.
    """
    if res.get("clawed_back") or res.get("removed") or res.get("success"):
        return True
    status = str(res.get("status") or "").strip().lower()
    if status and status not in _CLAWBACK_FAILED_STATUSES:
        return True
    return False


def _summarize_tool_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Reduce the scratchpad tool-call log into a verdict-friendly shape."""
    header_suspicion = 0.0
    header_findings: list[str] = []
    brand_findings: list[dict[str, Any]] = []
    detonation_findings: list[dict[str, Any]] = []
    url_chain_findings: list[dict[str, Any]] = []
    clawback_done = False
    block_sender_done = False

    for r in results:
        tool = r.get("tool")
        res = r.get("result") or {}
        if tool == "phishing.deep_header_analysis":
            score = float(res.get("suspicion_score") or 0)
            header_suspicion = max(header_suspicion, score)
            header_findings.extend(res.get("findings") or [])
        elif tool == "phishing.brand_impersonation":
            brand_findings.append(
                {
                    "candidate": res.get("candidate"),
                    "candidate_domain": res.get("candidate_domain"),
                    "matched_brand": res.get("matched_brand"),
                    "verdict": res.get("verdict"),
                    "kind": res.get("kind"),
                    "known_kit": res.get("known_kit"),
                    "in_cyble_feed": res.get("in_cyble_feed"),
                    "confidence": res.get("confidence"),
                }
            )
        elif tool == "phishing.detonate_url":
            detonation_findings.append(
                {
                    "url": res.get("url"),
                    "host": res.get("host"),
                    "verdict": res.get("verdict"),
                    "credential_harvest": res.get("credential_harvest"),
                    "kit": res.get("kit"),
                    "title": res.get("title"),
                }
            )
        elif tool == "phishing.unwrap_url_chain":
            url_chain_findings.append(
                {
                    "url": res.get("url"),
                    "terminal_url": res.get("terminal_url"),
                    "terminal_host": res.get("terminal_host"),
                    "hop_count": res.get("hop_count"),
                    "shortener_used": res.get("shortener_used"),
                    "safelinks_used": res.get("safelinks_used"),
                }
            )
        elif tool == "email.clawback_message" and _clawback_succeeded(res):
            clawback_done = True
        elif tool == "email.block_sender" and (
            res.get("blocked") or res.get("success")
        ):
            block_sender_done = True

    return {
        "header_suspicion": round(header_suspicion, 3),
        "header_findings": header_findings,
        "brand_findings": brand_findings,
        "detonation_findings": detonation_findings,
        "url_chain_findings": url_chain_findings,
        "clawback_done": clawback_done,
        "block_sender_done": block_sender_done,
    }


def _classify(analysis: dict[str, Any]) -> tuple[str, list[str]]:
    """Deterministically classify the case from tool results.

    Returns ``("phishing" | "suspicious" | "benign", deciding_signals)``.
    """
    signals: list[str] = []

    brand_phish = any(
        f.get("verdict") in _BRAND_PHISH_VERDICTS
        for f in analysis["brand_findings"]
    )
    brand_suspicious = any(
        f.get("verdict") in _BRAND_SUSPICIOUS_VERDICTS
        for f in analysis["brand_findings"]
    )
    detonation_phish = any(
        f.get("verdict") in _DETONATION_PHISH_VERDICTS
        for f in analysis["detonation_findings"]
    )
    header_strong = analysis["header_suspicion"] >= 0.7
    header_weak = (
        _HEADER_PHISH_THRESHOLD
        <= analysis["header_suspicion"]
        < 0.7
    )
    auth_failures = [
        f for f in analysis["header_findings"]
        if f.startswith(("SPF=", "DKIM=", "DMARC=", "From/", "Envelope/"))
    ]

    if brand_phish:
        signals.append("brand-intel-phishing")
    if detonation_phish:
        signals.append("detonation-credential-harvest")
    if header_strong:
        signals.append("header-suspicion-high")
    if header_weak:
        signals.append("header-suspicion-moderate")
    if brand_suspicious:
        signals.append("brand-homoglyph")
    if auth_failures:
        signals.append(f"auth-failures:{len(auth_failures)}")

    if brand_phish or detonation_phish or (header_strong and auth_failures):
        return "phishing", signals
    if brand_suspicious or header_weak or auth_failures:
        return "suspicious", signals
    return "benign", signals


async def _deterministic_phishing_sweep(
    agent: "PhishingTriageAgent",
    *,
    message_id: str | None,
    sender_addr: str | None,
    link_candidates: list[str],
) -> None:
    """Read-only fallback so the audit trail always has a baseline.

    Mirrors the SaaS Posture / CDR pattern. We hit every READ tool in
    the allowlist with sensible defaults; the connector mocks supply
    deterministic data so the trail is reproducible.
    """
    mid = message_id or "demo-msg-001"
    sender = sender_addr or "unknown@unknown.invalid"

    try:
        await agent.call_tool("email.analyze_message", {"message_id": mid})
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool(
            "phishing.deep_header_analysis", {"message_id": mid}
        )
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool(
            "phishing.brand_impersonation", {"candidate": sender}
        )
    except Exception:  # pragma: no cover — best-effort
        pass

    # Walk the first three unique candidate links.
    seen_hosts: set[str] = set()
    for url in link_candidates[:6]:
        if not url:
            continue
        try:
            chain_res = await agent.call_tool(
                "phishing.unwrap_url_chain", {"url": url}
            )
        except Exception:  # pragma: no cover — best-effort
            continue
        host = (chain_res or {}).get("terminal_host")
        terminal_url = (chain_res or {}).get("terminal_url") or url
        if host and host in seen_hosts:
            continue
        if host:
            seen_hosts.add(host)
        try:
            await agent.call_tool(
                "phishing.detonate_url", {"url": terminal_url}
            )
        except Exception:  # pragma: no cover — best-effort
            pass
        if host:
            try:
                await agent.call_tool(
                    "phishing.brand_impersonation", {"candidate": host}
                )
            except Exception:  # pragma: no cover — best-effort
                pass
        if len(seen_hosts) >= 3:
            break


async def _deterministic_contain_backstop(
    agent: "PhishingTriageAgent",
    *,
    analysis: dict[str, Any],
    message_id: str | None,
    sender_addr: str | None,
) -> None:
    """Request clawback + block_sender if the LLM stalled on a confirmed phish.

    Each call routes through HITL → audit; this is glue, not a bypass.
    Only fires when verdict is TRUE_POSITIVE on the case. Hard cap of
    ``_MAX_WRITES_PER_CASE`` so a runaway plan can't clawback every
    email in the org.
    """
    case = agent.db.get(Case, agent.case_id)
    if case.verdict != Verdict.TRUE_POSITIVE:
        return

    budget = _MAX_WRITES_PER_CASE
    deciding_signal = (
        "Cyble brand-intel feed hit"
        if any(
            f.get("verdict") == "phishing"
            for f in analysis["brand_findings"]
        )
        else "detonation: credential harvest landing page"
        if any(
            f.get("verdict") == "phishing"
            for f in analysis["detonation_findings"]
        )
        else "header alignment + auth failures"
    )

    # 1. Clawback the message. We always do this first — it's the most
    #    surgically scoped action available (one message, every recipient).
    if message_id and not analysis["clawback_done"] and budget > 0:
        try:
            res = await agent.call_tool(
                "email.clawback_message",
                {"message_id": message_id},
                rationale=(
                    "Phishing Triage backstop: confirmed phishing; "
                    f"deciding signal = {deciding_signal}"
                ),
                blast_radius={"messages": 1, "scope": "single-message"},
            )
            if (res or {}).get("clawed_back") or (res or {}).get("success"):
                analysis["clawback_done"] = True
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            pass

    # 2. Block the sender. Prefer the bare domain over the local part —
    #    blocking a spoofed local part is meaningless. Sender candidate
    #    may already be a bare domain; the email connector mock accepts
    #    either form.
    sender_target = _normalize_sender_for_block(sender_addr)
    if sender_target and not analysis["block_sender_done"] and budget > 0:
        try:
            res = await agent.call_tool(
                "email.block_sender",
                {"sender": sender_target},
                rationale=(
                    "Phishing Triage backstop: confirmed phishing; "
                    f"blocking spoofed sender; signal = {deciding_signal}"
                ),
                blast_radius={"sender": sender_target, "scope": "single-sender"},
            )
            if (res or {}).get("blocked") or (res or {}).get("success"):
                analysis["block_sender_done"] = True
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            pass


def _normalize_sender_for_block(sender: str | None) -> str | None:
    """Return the domain portion of an email address, or the raw sender
    if it's already a bare domain. ``None`` if we can't infer anything."""
    if not sender:
        return None
    s = sender.strip().lower().strip("<>")
    if "@" in s:
        s = s.split("@", 1)[1]
    s = s.strip().strip(".")
    return s or None
