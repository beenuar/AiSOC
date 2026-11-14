"""Closed-loop Exposure agent (t3a-closed-loop).

Runs a four-phase sweep per tenant:

1.  **Exposure**  – call the Cyble CTI tool surface
    (``cti.darkweb_search``, ``cti.brand_intel``, ``cti.asm_lookup``,
    ``cti.vuln_intel``) against a per-tenant fingerprint (the domains,
    brands, identities the tenant has declared as theirs) and normalise
    every hit into an :class:`ExposureFinding`.
2.  **Detection** – cross-reference each finding against the Threat
    Graph. Anything we haven't seen before is materialised as an
    ``EXPOSURE`` node (with ``EXPOSED_AS`` edges back to the affected
    asset / identity) **and** opened as a proactive :class:`Case`.
3.  **Response**  – for findings with a deterministic containment spec
    (credential reset, takedown ticket, remediation ticket) the case is
    nudged to ``CaseStatus.RESPONDING`` and a structured action is
    recorded on ``Case.response_actions`` so the Responder picks it up
    on its next run. The Exposure agent never invokes a write tool
    itself — that ownership stays with Responder + its HITL gateway.
4.  **Verification** – any already-open exposure case whose CTI signal
    is *gone* this sweep is closed as ``CLOSED_BENIGN``; any signal
    still present after the configured verification window is
    escalated to ``ESCALATED``.

The agent is deliberately not a :class:`BaseAgent` subclass — same
reasoning as :class:`DetectionValidationAgent`: it is proactive
(scheduler-driven, not alert-driven), it owns its own tenancy, and it
opens cases instead of running inside one.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlmodel import Session, select

from app.agents.exposure.models import (
    DEFAULT_RESPONSE_TOOL,
    ExposureFinding,
    ExposureKind,
    ExposureSweepResult,
)
from app.config import settings
from app.memory.graph import (
    graph_find_nodes,
    graph_upsert_edge,
    graph_upsert_node,
)
from app.models.case import Case, CaseStatus, Severity
from app.models.graph import EdgeType, NodeType
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_created
from app.tools.registry import registry

logger = logging.getLogger("aisoc.exposure")


# Marker dropped into ``Case.response_actions[*].source`` and
# ``GraphNode.props["source"]`` so downstream consumers (Responder,
# Reporter, the UI's "where did this come from?" tooltip) can attribute
# things back to this agent without sniffing titles.
_SOURCE = "exposure-agent"


class ExposureAgent:
    """One sweep per tenant; the scheduler instantiates it per-run."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        if not tenant_id:
            # Same hard requirement as the BAS agent — every Case and
            # every Threat-Graph node we open carries tenant_id, so we
            # refuse to construct without one to keep MSSP deployments
            # from accidentally cross-contaminating.
            raise ValueError("ExposureAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id

    # ── public entry point ────────────────────────────────────────
    async def sweep(self) -> ExposureSweepResult:
        result = ExposureSweepResult(tenant_id=self.tenant_id)

        # Phase 1: pull every signal.
        findings = await self._collect(result)
        result.findings_total = len(findings)

        # Phase 4 first: re-verify open exposure cases against this
        # sweep's signal set BEFORE we open new cases for re-observed
        # signals. Cases that re-confirm are escalated; cases whose
        # signal disappeared close benign.
        current_keys = {f.key for f in findings}
        await self._verify(current_keys, result)

        # Phase 2 + 3: materialise new findings into the graph and as
        # proactive cases, then route deterministic containment to the
        # Responder via Case.response_actions.
        for f in findings:
            try:
                await self._materialise(f, result)
            except Exception as exc:  # noqa: BLE001 — sweep-wide best-effort
                logger.exception(
                    "exposure: materialise failed tenant=%s key=%s",
                    self.tenant_id,
                    f.key,
                )
                result.errors.append(f"{f.key}: {exc!s}")

        self._log_summary(result)
        return result

    # ── Phase 1: collect ──────────────────────────────────────────
    async def _collect(self, result: ExposureSweepResult) -> list[ExposureFinding]:
        """Call every CTI tool against the tenant fingerprint.

        We don't yet have a first-class "tenant fingerprint" model (the
        plan calls it out as a follow-up) so we derive a reasonable
        default from the tenant_id and let the tool layer return its
        mock hits. Whoever wires the real tenant_profile table later
        just has to replace :meth:`_fingerprint`; everything downstream
        of the findings list stays the same.
        """
        fingerprint = self._fingerprint()
        findings: list[ExposureFinding] = []

        # cti.darkweb_search — credential / corporate-access leaks
        for query in fingerprint["darkweb_queries"]:
            hit = await self._safe_call("cti.darkweb_search", query=query, days=30)
            if not hit:
                continue
            for entry in hit.get("hits", []) or []:
                subject = entry.get("actor_handle") or query
                findings.append(
                    ExposureFinding(
                        kind=ExposureKind.DARKWEB_CREDENTIAL,
                        tenant_id=self.tenant_id,
                        subject=f"{query}|{subject}",
                        title=f"Dark-web mention referencing {query}",
                        narrative=(
                            f"Cyble dark-web crawler observed a forum post on "
                            f"{entry.get('forum')} at {entry.get('ts')} "
                            f"referencing {query}:\n\n"
                            f"  {entry.get('snippet', '')}\n\n"
                            f"Confidence: {entry.get('confidence', 'unknown')}. "
                            "Proactive containment proposal: rotate any "
                            "credentials tied to this identifier."
                        ),
                        severity="high",
                        affected_users=[query] if "@" in query else [],
                        affected_hosts=[query] if "." in query and "@" not in query else [],
                        evidence={"darkweb_hit": entry},
                        source_tool="cti.darkweb_search",
                    )
                )

        # cti.brand_intel — typosquats / fake apps / impersonation
        for brand in fingerprint["brands"]:
            hit = await self._safe_call("cti.brand_intel", brand=brand)
            if not hit:
                continue
            for typosquat in hit.get("examples", []) or []:
                findings.append(
                    ExposureFinding(
                        kind=ExposureKind.BRAND_TYPOSQUAT,
                        tenant_id=self.tenant_id,
                        subject=typosquat,
                        title=f"Active typosquat: {typosquat}",
                        narrative=(
                            f"Cyble brand-intel surfaced an active typosquat "
                            f"of {brand}: {typosquat}.\n\n"
                            f"Cyble currently tracks "
                            f"{hit.get('active_typosquats', '?')} active "
                            f"typosquats and "
                            f"{hit.get('phishing_kits_observed', '?')} hosted "
                            "phishing kits for this brand. Proactive "
                            "containment proposal: open a takedown ticket "
                            "and block sender domain at the email gateway."
                        ),
                        severity="medium",
                        affected_hosts=[typosquat],
                        evidence={"brand": brand, "brand_intel": hit},
                        source_tool="cti.brand_intel",
                    )
                )

        # cti.asm_lookup — new attack surface
        for domain in fingerprint["domains"]:
            hit = await self._safe_call("cti.asm_lookup", domain=domain)
            if not hit:
                continue
            for asm in hit.get("high_risk_findings", []) or []:
                severity = asm.get("severity") or "medium"
                findings.append(
                    ExposureFinding(
                        kind=ExposureKind.ASM_FINDING,
                        tenant_id=self.tenant_id,
                        subject=asm.get("asset") or domain,
                        title=f"ASM: {asm.get('asset')} — {asm.get('issue')}",
                        narrative=(
                            "Cyble ASM identified a high-risk exposure on "
                            f"the tenant's external attack surface:\n\n"
                            f"  Asset: {asm.get('asset')}\n"
                            f"  Issue: {asm.get('issue')}\n"
                            f"  Severity: {severity}\n\n"
                            "Proactive containment proposal: open a "
                            "remediation ticket for the asset owner."
                        ),
                        severity=severity,
                        affected_hosts=[asm.get("asset") or ""],
                        evidence={"asm_finding": asm, "asm_summary": hit},
                        source_tool="cti.asm_lookup",
                    )
                )

        # cti.vuln_intel — exploited-in-wild CVEs tied to the tenant
        for cve in fingerprint["cves"]:
            hit = await self._safe_call("cti.vuln_intel", cve=cve)
            if not hit:
                continue
            if not hit.get("exploited_in_wild"):
                continue
            findings.append(
                ExposureFinding(
                    kind=ExposureKind.VULN_INTEL,
                    tenant_id=self.tenant_id,
                    subject=cve,
                    title=f"ITW-exploited vulnerability: {cve}",
                    narrative=(
                        f"Cyble vuln-intel reports {cve} is exploited in the "
                        f"wild (first ITW {hit.get('first_itw')}). Exploit "
                        f"kits: {', '.join(hit.get('exploit_kits', []) or [])}. "
                        f"Ransomware groups using it: "
                        f"{', '.join(hit.get('ransomware_use', []) or [])}. "
                        f"Patch priority: {hit.get('patch_priority')}. "
                        "Proactive containment proposal: open a patch ticket."
                    ),
                    severity="high",
                    evidence={"vuln_intel": hit},
                    source_tool="cti.vuln_intel",
                )
            )

        result.findings_total = len(findings)
        return findings

    # ── Phase 2 + 3: materialise + route ──────────────────────────
    async def _materialise(
        self, finding: ExposureFinding, result: ExposureSweepResult
    ) -> None:
        """Turn a finding into a graph node + (if new) a proactive case."""
        # Did we see this exposure before?
        existing = graph_find_nodes(
            tenant_id=self.tenant_id,
            type=NodeType.EXPOSURE,
            key_prefix=finding.key,
            limit=1,
        )
        is_new = not existing

        # Always re-upsert so last_seen advances — that's what makes
        # the "signal is still present after window N" verification
        # work on a future sweep.
        graph_upsert_node(
            tenant_id=self.tenant_id,
            type=NodeType.EXPOSURE,
            key=finding.key,
            label=finding.title,
            props={
                "kind": finding.kind.value,
                "subject": finding.subject,
                "severity": finding.severity,
                "source": _SOURCE,
                "source_tool": finding.source_tool,
                "evidence": finding.evidence,
                "last_observed_at": _now_iso(),
            },
            tags=["exposure", finding.kind.value],
        )
        result.graph_nodes_upserted += 1

        # Edge: affected asset/identity -> exposure. We use the
        # exposure-side endpoint type that fits best so the graph
        # stays semantically clean.
        for host in finding.affected_hosts:
            if not host:
                continue
            graph_upsert_edge(
                tenant_id=self.tenant_id,
                src=(NodeType.ASSET, host),
                dst=(NodeType.EXPOSURE, finding.key),
                type=EdgeType.EXPOSED_AS,
                props={"observed_via": finding.source_tool, "source": _SOURCE},
            )
            result.graph_edges_upserted += 1
        for user in finding.affected_users:
            if not user:
                continue
            graph_upsert_edge(
                tenant_id=self.tenant_id,
                src=(NodeType.USER, user),
                dst=(NodeType.EXPOSURE, finding.key),
                type=EdgeType.EXPOSED_AS,
                props={"observed_via": finding.source_tool, "source": _SOURCE},
            )
            result.graph_edges_upserted += 1

        if not is_new:
            # Already known + already has a case (or was explicitly
            # closed). Don't churn the SOC's inbox; verification phase
            # already advanced last_seen so persistence-based
            # escalation will fire on the next window crossing.
            return

        # ── new exposure → open proactive case ────────────────────
        case_id = await self._open_proactive_case(finding)
        result.new_findings += 1
        result.cases_opened.append(case_id)

        # ── route deterministic response if we have one ───────────
        if DEFAULT_RESPONSE_TOOL.get(finding.kind):
            await self._route_response(case_id, finding)
            result.responses_routed += 1

    async def _open_proactive_case(self, finding: ExposureFinding) -> int:
        case = Case(
            tenant_id=self.tenant_id,
            title=f"[Exposure] {finding.title}",
            narrative=finding.narrative + f"\n\nexposure_key: {finding.key}",
            status=CaseStatus.NEW,
            severity=_severity(finding.severity),
            affected_users=list(finding.affected_users),
            affected_hosts=list(finding.affected_hosts),
            iocs=[finding.subject] if finding.subject else [],
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        assert case.id is not None

        self._log_trace(
            case_id=case.id,
            step=TraceStep.DECISION,
            summary=f"Opened proactive exposure case for {finding.key}",
            detail={
                "exposure_key": finding.key,
                "kind": finding.kind.value,
                "source_tool": finding.source_tool,
                "subject": finding.subject,
                "severity": finding.severity,
            },
        )
        await publish_case_created(
            tenant_id=self.tenant_id,
            case_id=case.id,
            title=case.title,
            severity=case.severity.value,
            status=case.status.value,
            source=_SOURCE,
        )
        return case.id

    async def _route_response(self, case_id: int, finding: ExposureFinding) -> None:
        """Hand the case off to the Responder via Case.response_actions.

        We deliberately do **not** call the write tool ourselves.
        Responder owns the risk gate + HITL pipeline; the Exposure
        agent's job ends at proposing a concrete action.
        """
        tool_name = DEFAULT_RESPONSE_TOOL[finding.kind]
        if tool_name is None:
            return

        # Per-kind param shaping. Every tool referenced here is on the
        # Responder's allowlist (see app/agents/responder.py), so the
        # Responder can execute (or HITL-queue) the action on its next
        # run without any further wiring.
        if finding.kind is ExposureKind.DARKWEB_CREDENTIAL:
            # Identity to reset: prefer an email-looking subject,
            # otherwise fall back to the raw subject so the Responder
            # at least has *something* concrete to point a human at.
            user = next(
                (u for u in finding.affected_users if "@" in u),
                finding.subject.split("|", 1)[0],
            )
            params: dict[str, Any] = {"user_id": user, "reason": "darkweb_credential_exposure"}
        elif finding.kind is ExposureKind.BRAND_TYPOSQUAT:
            params = {
                "system": "takedown",
                "title": f"Takedown request: {finding.subject}",
                "body": finding.narrative,
                "priority": "high",
            }
        elif finding.kind is ExposureKind.ASM_FINDING:
            params = {
                "system": "asm-remediation",
                "title": f"Remediate exposed asset: {finding.subject}",
                "body": finding.narrative,
                "priority": finding.severity,
            }
        elif finding.kind is ExposureKind.VULN_INTEL:
            params = {
                "system": "patch",
                "title": f"Patch ITW-exploited vuln: {finding.subject}",
                "body": finding.narrative,
                "priority": "P0",
            }
        else:
            params = {}

        case = self.session.get(Case, case_id)
        if case is None:
            return
        actions = list(case.response_actions or [])
        actions.append(
            {
                "tool": tool_name,
                "params": params,
                "source": _SOURCE,
                "exposure_key": finding.key,
                "proposed_at": _now_iso(),
            }
        )
        case.response_actions = actions
        case.status = CaseStatus.RESPONDING
        case.updated_at = datetime.now(timezone.utc)
        self.session.add(case)
        self.session.commit()

        self._log_trace(
            case_id=case_id,
            step=TraceStep.HANDOFF,
            summary=f"Proposed response action {tool_name} for {finding.key}",
            detail={"tool": tool_name, "params": params, "exposure_key": finding.key},
        )

    # ── Phase 4: verification ─────────────────────────────────────
    async def _verify(
        self, current_keys: set[str], result: ExposureSweepResult
    ) -> None:
        """Sweep through open exposure cases and verify / escalate.

        Strategy:
        * Re-extract the ``exposure_key`` from each open Exposure case's
          narrative footer (we wrote it there in
          :meth:`_open_proactive_case`).
        * If the case's exposure_key is *not* in this sweep's findings,
          the CTI signal has cleared → close ``CLOSED_BENIGN``.
        * If the case is older than the configured verification window
          AND the exposure_key is *still* in the current findings → the
          signal has persisted past SLA → escalate.
        """
        window = settings.exposure_verification_window_seconds
        cutoff = datetime.now(timezone.utc).timestamp() - window

        # All open exposure cases for this tenant.
        rows = self.session.exec(
            select(Case)
            .where(Case.tenant_id == self.tenant_id)
            .where(Case.status.in_([
                CaseStatus.NEW,
                CaseStatus.TRIAGING,
                CaseStatus.INVESTIGATING,
                CaseStatus.AWAITING_HITL,
                CaseStatus.RESPONDING,
            ]))
            .where(Case.title.like("[Exposure]%"))
        ).all()

        for case in rows:
            key = _extract_exposure_key(case.narrative)
            if not key:
                continue

            if key not in current_keys:
                # Signal cleared → close benign.
                case.status = CaseStatus.CLOSED_BENIGN
                case.closed_at = datetime.now(timezone.utc)
                case.updated_at = case.closed_at
                self.session.add(case)
                self.session.commit()
                assert case.id is not None
                result.cases_verified_closed.append(case.id)
                self._log_trace(
                    case_id=case.id,
                    step=TraceStep.DECISION,
                    summary=f"Verification: signal cleared for {key}; closing benign",
                    detail={"exposure_key": key},
                )
                continue

            # Signal still present. Escalate only if we're past the
            # verification window — otherwise the case is doing
            # exactly what it should.
            opened_ts = case.created_at.timestamp() if case.created_at else 0
            if opened_ts and opened_ts < cutoff and case.status != CaseStatus.ESCALATED:
                case.status = CaseStatus.ESCALATED
                case.updated_at = datetime.now(timezone.utc)
                self.session.add(case)
                self.session.commit()
                assert case.id is not None
                result.cases_escalated.append(case.id)
                self._log_trace(
                    case_id=case.id,
                    step=TraceStep.DECISION,
                    summary=(
                        f"Verification: signal persisted past "
                        f"{window}s window; escalating {key}"
                    ),
                    detail={
                        "exposure_key": key,
                        "window_seconds": window,
                        "case_age_seconds": int(
                            datetime.now(timezone.utc).timestamp() - opened_ts
                        ),
                    },
                )

    # ── helpers ───────────────────────────────────────────────────
    def _fingerprint(self) -> dict[str, list[str]]:
        """Per-tenant CTI query set.

        Heuristic placeholder: we synthesise a brand + primary domain
        from the tenant_id (e.g. ``demo-tenant`` → ``demo`` brand,
        ``demo.com`` domain) and ship a small fixed CVE list to keep
        the vuln-intel phase exercising. A real implementation reads
        these from a tenant_profile table maintained by the asset
        agent (t2i-asset-cmdb). The contract — return four lists —
        won't change when that arrives, so the rest of the agent
        doesn't have to.
        """
        slug = self.tenant_id.split("-", 1)[0] or "tenant"
        primary = f"{slug}.com"
        return {
            "darkweb_queries": [primary, f"admin@{primary}"],
            "brands": [slug],
            "domains": [primary],
            # CL0P / Akira / known-ITW CVEs — the mock vuln-intel tool
            # always reports exploited_in_wild=True so this exercises
            # the full path during smoke tests.
            "cves": ["CVE-2024-21887"],
        }

    async def _safe_call(self, tool_name: str, /, **params: Any) -> dict[str, Any] | None:
        """Best-effort tool dispatch with a per-call timeout + try/except.

        We deliberately bypass :class:`BaseAgent.call_tool` here — that
        path assumes a case_id, runs the risk gate, etc. Every CTI
        tool is :class:`RiskClass.READ` so there's nothing to gate;
        and we have no case_id yet (the *point* of this phase is to
        decide whether one is warranted).
        """
        td = registry.get(tool_name)
        if td is None:
            logger.warning("exposure: missing tool %s", tool_name)
            return None
        if not registry.is_allowed_for_tenant(tool_name, self.tenant_id):
            logger.info(
                "exposure: tool %s denied for tenant %s; skipping",
                tool_name,
                self.tenant_id,
            )
            return None
        try:
            result = await td.handler(**params)
        except Exception as exc:  # noqa: BLE001 — observability + survive
            logger.exception(
                "exposure: tool %s raised tenant=%s params=%s",
                tool_name,
                self.tenant_id,
                params,
            )
            return None
        if not isinstance(result, dict):
            return None
        return result

    def _log_trace(
        self,
        *,
        case_id: int | None,
        step: TraceStep,
        summary: str,
        detail: dict[str, Any],
    ) -> None:
        # AgentTrace's FK requires case_id; summary-only traces go to
        # the process logger (Loki/CloudWatch picks them up). Same
        # shape as DetectionValidationAgent._log_trace for consistency.
        if case_id is None:
            logger.info("exposure:summary tenant=%s %s", self.tenant_id, summary)
            return
        trace = AgentTrace(
            tenant_id=self.tenant_id,
            case_id=case_id,
            agent=AgentName.EXPOSURE,
            step=step,
            summary=summary,
            detail=detail,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(trace)
        self.session.commit()

    def _log_summary(self, result: ExposureSweepResult) -> None:
        logger.info(
            "exposure:sweep_complete tenant=%s findings=%d new=%d "
            "cases=%d responses_routed=%d verified_closed=%d escalated=%d "
            "graph_nodes=%d graph_edges=%d errors=%d",
            self.tenant_id,
            result.findings_total,
            result.new_findings,
            len(result.cases_opened),
            result.responses_routed,
            len(result.cases_verified_closed),
            len(result.cases_escalated),
            result.graph_nodes_upserted,
            result.graph_edges_upserted,
            len(result.errors),
        )


# ── module-level helpers ─────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity(value: str | None) -> Severity:
    """Coerce free-form CTI severity strings into the Severity enum."""
    v = (value or "medium").lower()
    if v in {"critical", "crit", "p0"}:
        return Severity.CRITICAL
    if v in {"high", "h", "p1"}:
        return Severity.HIGH
    if v in {"medium", "med", "moderate", "m", "p2"}:
        return Severity.MEDIUM
    if v in {"low", "l", "p3"}:
        return Severity.LOW
    if v in {"info", "informational"}:
        return Severity.INFO
    return Severity.MEDIUM


def _extract_exposure_key(narrative: str) -> str | None:
    """Pull the ``exposure_key: ...`` footer back out of a case narrative.

    We stash the key in the narrative (not a dedicated column) to
    avoid a schema migration just for this agent. Same approach the
    BAS agent uses for ``sim_id``.
    """
    if not narrative:
        return None
    marker = "exposure_key:"
    idx = narrative.rfind(marker)
    if idx < 0:
        return None
    return narrative[idx + len(marker):].strip().splitlines()[0].strip()


__all__ = ["ExposureAgent"]
