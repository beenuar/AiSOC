"""Brand Responder Agent — orchestrates the discover→takedown loop.

This is the §3c entry point: a proactive, scheduler-driven agent
that, per tenant, runs the four-step brand-defense pipeline:

1. **Discover** — pull candidate domains via ``cti.brand_intel`` for
   every registered :class:`~app.models.brand.BrandAsset` and score
   them with the deterministic detector. Anything above
   ``brand_min_candidate_score`` becomes (or refreshes) a
   :class:`~app.models.brand.TyposquatCandidate` row.

2. **Score** — handled by the detector. The agent's only job here
   is bucketing candidates by ``brand_auto_takedown_threshold`` to
   decide between "auto-file" and "park for HITL triage".

3. **Evidence** — call :func:`build_evidence_packet` to assemble a
   frozen, auditable filing payload.

4. **Submit** — for each configured default channel
   (``brand_default_channels``), create a
   :class:`~app.models.brand.TakedownRequest` and dispatch it via
   :func:`submit_takedown_request`. Provider acknowledgement /
   failure lands in ``status_history``.

Design choices that mirror :class:`~app.agents.exposure.agent.ExposureAgent`:

- **Not** a :class:`BaseAgent` subclass. The Responder is proactive
  and tenant-scoped, not alert-driven.
- Sweep is best-effort: a single candidate failing must not nuke
  the rest of the sweep. We catch and record per-candidate errors
  in :class:`BrandSweepReport`.
- The Responder NEVER writes outside its three tables and one
  Case. No graph edits, no IOC writes, no firewall calls. The
  takedown is the action — anything else is downstream.

The Responder opens one proactive :class:`~app.models.case.Case`
per auto-filed candidate so the existing case workspace, HITL UI,
and Reporter all surface the takedown without bespoke wiring.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from app.brand_responder.detector import DetectorMatch, detect_typosquats
from app.brand_responder.evidence import build_evidence_packet
from app.brand_responder.submitter import (
    SubmissionResult,
    status_history_entry,
    submit_takedown_request,
)
from app.config import settings
from app.models.brand import (
    BrandAsset,
    CandidateStatus,
    TakedownChannel,
    TakedownRequest,
    TakedownStatus,
    TyposquatCandidate,
)
from app.models.case import Case, CaseStatus, Severity
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_created
from app.tools.registry import registry

logger = logging.getLogger("aisoc.brand_responder")


_SOURCE = "brand-responder"
"""Marker for Case.response_actions[*].source and trace attribution."""


# ── per-sweep report ─────────────────────────────────────────────────
@dataclass
class BrandSweepReport:
    """What one sweep over one tenant produced.

    Returned from :meth:`BrandResponderAgent.sweep` so the
    scheduler (and tests) can assert on what happened without
    re-querying the database. Mirrors
    :class:`~app.agents.exposure.models.ExposureSweepResult`.
    """

    tenant_id: str
    candidates_considered: int = 0
    candidates_recorded: int = 0
    candidates_auto_filed: int = 0
    candidates_parked: int = 0
    takedowns_submitted: int = 0
    takedowns_acknowledged: int = 0
    takedowns_failed: int = 0
    cases_opened: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── agent ────────────────────────────────────────────────────────────
class BrandResponderAgent:
    """One sweep per tenant; scheduler instantiates it per-run."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        if not tenant_id:
            # Same hard requirement as Exposure / BAS: refuse to
            # construct without a tenant so MSSP fan-out cannot
            # cross-contaminate.
            raise ValueError("BrandResponderAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id

    # ── public entry point ────────────────────────────────────────
    async def sweep(self) -> BrandSweepReport:
        report = BrandSweepReport(tenant_id=self.tenant_id)

        assets = self._load_assets()
        if not assets:
            # Nothing registered to defend — exit cleanly. Logging
            # at debug avoids spamming the scheduler for tenants
            # that haven't onboarded brand assets yet.
            logger.debug(
                "brand-responder: no brand assets tenant=%s", self.tenant_id
            )
            return report

        # Phase 1: pull candidates per asset via cti.brand_intel.
        candidates_per_asset = await self._collect_candidates(assets, report)

        # Phase 2: deterministic scoring + dedupe across assets.
        matches: list[DetectorMatch] = []
        for asset, cand_domains in candidates_per_asset:
            report.candidates_considered += len(cand_domains)
            asset_matches = detect_typosquats(
                [asset],
                cand_domains,
                min_score=settings.brand_min_candidate_score,
            )
            matches.extend(asset_matches)

        if not matches:
            self._log_summary(report)
            return report

        asset_by_id = {a.id: a for a in assets if a.id is not None}

        # Phases 3 + 4: persist candidates, then either auto-file
        # takedowns (high-confidence) or park for HITL (medium).
        for match in matches:
            try:
                await self._handle_match(match, asset_by_id, report)
            except Exception as exc:  # noqa: BLE001 - sweep-wide best-effort
                logger.exception(
                    "brand-responder: handle_match failed tenant=%s domain=%s",
                    self.tenant_id,
                    match.candidate_domain,
                )
                report.errors.append(f"{match.candidate_domain}: {exc!s}")

        self._log_summary(report)
        return report

    # ── helpers ───────────────────────────────────────────────────
    def _load_assets(self) -> list[BrandAsset]:
        """Active brand assets for this tenant.

        We honour ``active=False`` so an operator can pause defense
        on a brand surface without deleting its history.
        """
        stmt = select(BrandAsset).where(
            BrandAsset.tenant_id == self.tenant_id,
            BrandAsset.active == True,  # noqa: E712 - SQLAlchemy comparison
        )
        return list(self.session.exec(stmt))

    async def _collect_candidates(
        self,
        assets: list[BrandAsset],
        report: BrandSweepReport,
    ) -> list[tuple[BrandAsset, list[str]]]:
        """Pull candidate domains per asset via ``cti.brand_intel``.

        We call the existing CTI tool registry rather than reaching
        directly into ``app.tools.cti`` so that tenant-specific tool
        allowlists / mocks (used by tests) take effect.

        Returns a list of ``(asset, candidates)`` tuples — list rather
        than dict because SQLModel rows are not hashable.
        """
        out: list[tuple[BrandAsset, list[str]]] = []
        for asset in assets:
            hit = await self._safe_call("cti.brand_intel", brand=asset.name)
            if not hit:
                out.append((asset, []))
                continue
            examples = list(hit.get("examples", []) or [])
            # Also include monitored_terms-derived candidates the
            # operator explicitly asked us to defend (e.g. product
            # names): the detector will score them against the
            # brand label and drop anything irrelevant.
            extras = [
                f"{t.lower()}-{asset.root_domain.split('.', 1)[-1] or 'com'}"
                for t in asset.monitored_terms
            ]
            out.append((asset, [*examples, *extras]))
        return out

    async def _safe_call(self, name: str, /, **kwargs: Any) -> dict[str, Any] | None:
        """Wrapper that swallows tool errors per-tool but logs them.

        Matches the contract used by
        :meth:`app.agents.exposure.agent.ExposureAgent._safe_call`;
        the Brand Responder must continue scoring even if one CTI
        tool blew up.
        """
        td = registry.get(name)
        if td is None:
            logger.warning("brand-responder: missing tool %s", name)
            return None
        if not registry.is_allowed_for_tenant(name, self.tenant_id):
            logger.info(
                "brand-responder: tool %s denied for tenant %s; skipping",
                name,
                self.tenant_id,
            )
            return None
        try:
            result = await td.handler(**kwargs)
        except Exception:  # noqa: BLE001 - best-effort sweep
            logger.exception(
                "brand-responder: tool %s failed tenant=%s",
                name,
                self.tenant_id,
            )
            return None
        if not isinstance(result, dict):
            return None
        return result

    async def _handle_match(
        self,
        match: DetectorMatch,
        asset_by_id: dict[int, BrandAsset],
        report: BrandSweepReport,
    ) -> None:
        """Persist one candidate and, if eligible, auto-file takedowns."""
        asset = asset_by_id.get(match.matched_brand_asset_id)
        if asset is None or asset.id is None:
            # Detector somehow scored against an asset we just
            # didn't load — defensive bail-out, should never happen.
            report.errors.append(
                f"orphan match: brand_asset_id={match.matched_brand_asset_id}"
            )
            return

        candidate = self._upsert_candidate(asset, match)
        report.candidates_recorded += 1

        if match.score < settings.brand_auto_takedown_threshold:
            # Park for HITL. The candidate row + reasons are enough
            # for an analyst to triage; we don't fire actions.
            report.candidates_parked += 1
            return

        # Above threshold → auto-file. Build evidence once, fan out
        # across the configured channels.
        evidence = build_evidence_packet(
            asset=asset,
            candidate=candidate,
            detector_match=match,
        )

        channels = self._resolve_channels()
        if not channels:
            report.errors.append(
                f"{candidate.candidate_domain}: no default channels configured"
            )
            return

        submissions: list[tuple[TakedownRequest, SubmissionResult]] = []
        for channel in channels:
            request = self._create_request(
                candidate=candidate, channel=channel, evidence=evidence
            )
            result = submit_takedown_request(channel=channel, evidence=evidence)
            self._apply_submission(request, result)
            submissions.append((request, result))
            report.takedowns_submitted += 1
            if result.status in (
                TakedownStatus.ACKNOWLEDGED,
                TakedownStatus.ACTIONED,
            ):
                report.takedowns_acknowledged += 1
            elif result.is_failure:
                report.takedowns_failed += 1

        # Flip the candidate to TAKEDOWN_FILED so the UI shows the
        # current state without re-deriving from TakedownRequest rows.
        candidate.status = CandidateStatus.TAKEDOWN_FILED
        candidate.last_seen = datetime.now(timezone.utc)
        self.session.add(candidate)
        self.session.commit()
        self.session.refresh(candidate)

        case_id = await self._open_case(asset, candidate, submissions)
        if case_id is not None:
            report.cases_opened.append(case_id)
            self._record_trace(case_id, candidate, match, submissions)
        report.candidates_auto_filed += 1

    def _upsert_candidate(
        self, asset: BrandAsset, match: DetectorMatch
    ) -> TyposquatCandidate:
        """Insert-or-refresh a candidate row.

        Idempotent against ``(tenant_id, brand_asset_id, candidate_domain)``
        so re-running the sweep doesn't create duplicates — the
        score / reasons / last_seen just refresh.
        """
        stmt = select(TyposquatCandidate).where(
            TyposquatCandidate.tenant_id == self.tenant_id,
            TyposquatCandidate.brand_asset_id == asset.id,
            TyposquatCandidate.candidate_domain == match.candidate_domain,
        )
        existing = self.session.exec(stmt).first()
        now = datetime.now(timezone.utc)

        if existing is None:
            row = TyposquatCandidate(
                tenant_id=self.tenant_id,
                brand_asset_id=asset.id,  # type: ignore[arg-type]
                candidate_domain=match.candidate_domain,
                score=match.score,
                severity=match.severity,
                reasons=list(match.reasons),
                enrichment={"detector": "brand-responder-v1"},
                status=CandidateStatus.NEW,
                first_seen=now,
                last_seen=now,
            )
        else:
            existing.score = max(existing.score, match.score)
            existing.severity = match.severity
            existing.reasons = list(match.reasons)
            existing.last_seen = now
            # If a previously-dismissed candidate now scores
            # critical, surface it again rather than leave it
            # buried as DISMISSED. We don't reopen RESOLVED
            # ones — that's a human's call.
            if (
                existing.status == CandidateStatus.DISMISSED
                and match.severity in {"high", "critical"}
            ):
                existing.status = CandidateStatus.NEW
            row = existing

        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return row

    def _resolve_channels(self) -> list[TakedownChannel]:
        """Map the configured channel strings to enum values.

        Bad strings are skipped with a logged warning so a typo in
        config doesn't crash the sweep.
        """
        out: list[TakedownChannel] = []
        for raw in settings.brand_default_channels:
            try:
                out.append(TakedownChannel(raw))
            except ValueError:
                logger.warning(
                    "brand-responder: unknown channel %r in brand_default_channels",
                    raw,
                )
        return out

    def _create_request(
        self,
        *,
        candidate: TyposquatCandidate,
        channel: TakedownChannel,
        evidence: dict[str, Any],
    ) -> TakedownRequest:
        """Create a PENDING TakedownRequest row.

        Pending becomes SUBMITTED / ACKNOWLEDGED / FAILED inside
        :meth:`_apply_submission` so the row carries the full
        history (pending → built → submitted → ack) instead of
        just the terminal state.
        """
        history = [
            status_history_entry(
                TakedownStatus.PENDING, "request created"
            ),
            status_history_entry(
                TakedownStatus.EVIDENCE_BUILT,
                f"evidence packet {evidence.get('evidence_id', 'unknown')}",
            ),
        ]
        row = TakedownRequest(
            tenant_id=self.tenant_id,
            candidate_id=candidate.id,  # type: ignore[arg-type]
            channel=channel,
            status=TakedownStatus.EVIDENCE_BUILT,
            evidence=dict(evidence),
            status_history=history,
            submitted_by=_SOURCE,
        )
        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return row

    def _apply_submission(
        self, request: TakedownRequest, result: SubmissionResult
    ) -> None:
        """Fold a :class:`SubmissionResult` into the request row."""
        request.status = result.status
        request.recipient = result.recipient
        request.provider_ticket = result.provider_ticket
        history = list(request.status_history or [])
        history.append(
            status_history_entry(
                TakedownStatus.SUBMITTED,
                f"dispatched to {request.channel.value} → {result.recipient}",
            )
        )
        history.append(status_history_entry(result.status, result.note))
        request.status_history = history
        request.updated_at = datetime.now(timezone.utc)
        self.session.add(request)
        self.session.commit()
        self.session.refresh(request)

    async def _open_case(
        self,
        asset: BrandAsset,
        candidate: TyposquatCandidate,
        submissions: list[tuple[TakedownRequest, SubmissionResult]],
    ) -> int | None:
        """Open a proactive case so the takedown is visible everywhere.

        The case enters ``RESPONDING`` immediately because we have
        already filed — the analyst's role is to verify, not to
        approve a future action.
        """
        severity = self._severity_to_case_enum(candidate.severity)
        narrative = (
            f"Brand Responder filed an autonomous takedown against "
            f"{candidate.candidate_domain} (impersonating {asset.name} / "
            f"{asset.root_domain}).\n\n"
            f"Detector score: {candidate.score} ({candidate.severity}). "
            f"Reasons: {', '.join(candidate.reasons) or 'n/a'}.\n\n"
            f"Channels submitted: "
            f"{', '.join(r.channel.value for r, _ in submissions)}."
        )

        response_actions = [
            {
                "source": _SOURCE,
                "kind": "brand_takedown",
                "channel": request.channel.value,
                "status": request.status.value,
                "provider_ticket": request.provider_ticket,
                "recipient": request.recipient,
                "candidate_domain": candidate.candidate_domain,
                "evidence_id": (request.evidence or {}).get("evidence_id"),
            }
            for request, _ in submissions
        ]

        case = Case(
            tenant_id=self.tenant_id,
            title=f"Brand takedown: {candidate.candidate_domain}",
            narrative=narrative,
            severity=severity,
            status=CaseStatus.RESPONDING,
            response_actions=response_actions,
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)

        try:
            await publish_case_created(
                tenant_id=self.tenant_id,
                case_id=case.id,  # type: ignore[arg-type]
                title=case.title,
                severity=case.severity.value
                if hasattr(case.severity, "value")
                else str(case.severity),
                status=case.status.value
                if hasattr(case.status, "value")
                else str(case.status),
                source=_SOURCE,
            )
        except Exception:  # noqa: BLE001 - publishing is best-effort
            logger.exception(
                "brand-responder: publish_case_created failed case=%s",
                case.id,
            )

        return case.id

    def _record_trace(
        self,
        case_id: int,
        candidate: TyposquatCandidate,
        match: DetectorMatch,
        submissions: list[tuple[TakedownRequest, SubmissionResult]],
    ) -> None:
        """Persist an :class:`AgentTrace` row for the case workspace."""
        detail = {
            "candidate_domain": candidate.candidate_domain,
            "score": match.score,
            "severity": match.severity,
            "reasons": list(match.reasons),
            "channels": [r.channel.value for r, _ in submissions],
            "tickets": [
                r.provider_ticket for r, _ in submissions if r.provider_ticket
            ],
            "source": _SOURCE,
        }
        trace = AgentTrace(
            tenant_id=self.tenant_id,
            case_id=case_id,
            agent=AgentName.BRAND_RESPONDER,
            step=TraceStep.HANDOFF,
            summary=(
                f"Filed brand takedown for {candidate.candidate_domain} "
                f"(score {match.score})"
            ),
            detail=detail,
        )
        self.session.add(trace)
        self.session.commit()

    # ── tiny utilities ─────────────────────────────────────────────
    def _severity_to_case_enum(self, severity: str) -> Severity:
        """Map detector severity strings to the Case severity enum.

        The Case model uses :class:`~app.models.case.Severity`; the
        brand pipeline speaks plain strings ("low" / "medium" / ...)
        so a Reporter writing JSON or a CLI dump doesn't have to
        import the enum.
        """
        try:
            return Severity(severity)
        except ValueError:
            return Severity.MEDIUM

    def _log_summary(self, report: BrandSweepReport) -> None:
        logger.info(
            "brand-responder: tenant=%s considered=%d recorded=%d "
            "auto_filed=%d parked=%d submitted=%d ack=%d failed=%d "
            "cases=%d errors=%d",
            report.tenant_id,
            report.candidates_considered,
            report.candidates_recorded,
            report.candidates_auto_filed,
            report.candidates_parked,
            report.takedowns_submitted,
            report.takedowns_acknowledged,
            report.takedowns_failed,
            len(report.cases_opened),
            len(report.errors),
        )


__all__ = ["BrandResponderAgent", "BrandSweepReport"]
