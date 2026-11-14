"""HITL gateway — blocking analyst approval for risky tool calls.

Replaces the prior `demo-auto-approve` stub in BaseAgent.call_tool. The agent
coroutine that invoked a risky tool awaits `gateway.wait_for_decision(...)`,
which:

1. Creates a `HitlRequest` row (state = PENDING) and fans out notifications
   (console event bus + optional Slack/Teams interactive cards).
2. Polls the row until a decision is recorded (APPROVED / DENIED) or the SLA
   timer expires.
3. On SLA expiry, transitions the request to TIMEOUT and writes an escalation
   record. The action is NEVER auto-approved; TIMEOUT is treated as deny by
   the caller.
4. An optional pre-SLA escalation timer (default 5 min before timeout) flips
   `escalated=True` and re-fires notifications to the on-call channel.

Concurrency model
-----------------
- The agent coroutine awaits using short polling (`hitl_poll_interval_ms`)
  rather than a per-request asyncio.Event so multiple processes / workers see
  a single source of truth (the DB row). This matches how a real distributed
  SOC platform would later wire this through Redis pub/sub.
- We use short-lived `Session(engine)` rather than the agent's request-scoped
  session so the background watcher can mutate rows without fighting the
  agent's transaction.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from app.config import settings
from app.db import engine
from app.hitl import notifications
from app.models.case import Case, CaseStatus
from app.models.hitl import HitlChannel, HitlRequest, HitlState
from app.models.tool_call import RiskClass
from app.models.trace import AgentName, AgentTrace, TraceStep

logger = logging.getLogger(__name__)


class HitlTimeoutDenied(Exception):
    """Raised when an SLA expires before an analyst decides. The action is
    explicitly DENIED (never auto-approved)."""

    def __init__(self, request_id: int) -> None:
        super().__init__(f"HITL request {request_id} timed out — denied")
        self.request_id = request_id


class HitlDenied(Exception):
    """Raised when an analyst explicitly denies a request."""

    def __init__(self, request_id: int, reason: str | None) -> None:
        super().__init__(f"HITL request {request_id} denied: {reason or '(no reason)'}")
        self.request_id = request_id
        self.reason = reason


class HitlGateway:
    """Singleton orchestrator for blocking HITL approvals."""

    def __init__(self) -> None:
        self._watcher_task: asyncio.Task[None] | None = None

    # ── lifecycle ────────────────────────────────────────────────────────
    def start_background_tasks(self) -> None:
        """Idempotently start the SLA / escalation watcher."""
        if self._watcher_task and not self._watcher_task.done():
            return
        loop = asyncio.get_event_loop()
        self._watcher_task = loop.create_task(self._watcher_loop())
        logger.info("hitl: timeout/escalation watcher started")

    async def stop_background_tasks(self) -> None:
        if self._watcher_task:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except (asyncio.CancelledError, Exception):
                pass
            self._watcher_task = None

    # ── core API: request → decision ─────────────────────────────────────
    async def request_approval(
        self,
        *,
        case_id: int,
        tenant_id: str,
        agent: AgentName | str,
        tool_name: str,
        integration: str,
        risk_class: RiskClass,
        params: dict[str, Any],
        rationale: str = "",
        blast_radius: dict[str, Any] | None = None,
        trace_id: int | None = None,
        tool_call_id: int | None = None,
    ) -> HitlRequest:
        """Create a PENDING HitlRequest and fan out notifications.

        `tenant_id` is mandatory: HITL rows are tenant-scoped so analysts in
        tenant A can never see (let alone approve) tenant B's pending actions.

        When the caller does not provide an explicit ``blast_radius`` we
        run the dry-run simulator (t4-dry-run) so every approval request
        ships with a deterministic preview: target CMDB record,
        first-hop graph dependents, reversibility, severity hint, and
        the counterfactual "what happens if you skip this?" line. The
        simulator is a *pure* function so it does not block the agent
        loop or trigger any external IO.
        """
        from app.hitl.dry_run import simulate_action  # avoid import cycle

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=settings.hitl_sla_seconds)
        # Always run the dry-run simulator and *merge* the result with
        # any caller-supplied blast_radius dict. We give the simulator
        # output its own ``simulation`` key so the caller's data never
        # gets clobbered by the fields we add.
        merged_blast_radius: dict[str, Any] = dict(blast_radius or {})
        try:
            simulation = simulate_action(
                tool_name=tool_name,
                params=params,
                tenant_id=tenant_id,
            )
            merged_blast_radius.setdefault("simulation", simulation.to_dict())
            # Lift the headline fields up so the HITL UI can render the
            # traffic-light without parsing the nested simulation dict.
            merged_blast_radius.setdefault(
                "severity_hint", simulation.severity_hint
            )
            merged_blast_radius.setdefault(
                "reversibility", simulation.reversibility
            )
            merged_blast_radius.setdefault(
                "collateral_count", simulation.collateral_count
            )
            merged_blast_radius.setdefault(
                "counterfactual", simulation.counterfactual
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "dry-run simulation failed for tool=%s tenant=%s: %s",
                tool_name,
                tenant_id,
                exc,
            )

        req = HitlRequest(
            case_id=case_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            tool_call_id=tool_call_id,
            agent=str(agent),
            tool_name=tool_name,
            integration=integration,
            risk_class=risk_class.value if hasattr(risk_class, "value") else str(risk_class),
            params=params,
            rationale=rationale,
            blast_radius=merged_blast_radius,
            state=HitlState.PENDING,
            created_at=now,
            expires_at=expires_at,
            notifications=[],
        )
        with Session(engine) as s:
            s.add(req)
            s.commit()
            s.refresh(req)

            # Move case to awaiting-HITL so the operator console can highlight it.
            case = s.get(Case, case_id)
            if case and case.status not in (
                CaseStatus.CLOSED_TRUE_POSITIVE,
                CaseStatus.CLOSED_FALSE_POSITIVE,
                CaseStatus.CLOSED_BENIGN,
            ):
                case.status = CaseStatus.AWAITING_HITL
                s.add(case)

            # Record the HITL request in the trace stream.
            s.add(
                AgentTrace(
                    case_id=case_id,
                    tenant_id=tenant_id,
                    agent=str(agent),
                    step=TraceStep.HITL_REQUEST,
                    summary=f"awaiting analyst approval: {tool_name}",
                    detail={
                        "request_id": req.id,
                        "tool_name": tool_name,
                        "integration": integration,
                        "risk_class": req.risk_class,
                        "expires_at": expires_at.isoformat(),
                        "sla_seconds": settings.hitl_sla_seconds,
                    },
                )
            )
            s.commit()
            s.refresh(req)

        # Fan out notifications (best-effort, captured on the row).
        try:
            sent = await notifications.dispatch_request(req)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("hitl: notification dispatch failed: %s", exc)
            sent = []

        if sent:
            with Session(engine) as s:
                fresh = s.get(HitlRequest, req.id)
                if fresh is not None:
                    fresh.notifications = (fresh.notifications or []) + sent
                    s.add(fresh)
                    s.commit()
                    s.refresh(fresh)
                    req = fresh
        return req

    async def wait_for_decision(self, request_id: int) -> HitlRequest:
        """Block the caller until the request is APPROVED / DENIED / TIMEOUT.

        Raises:
            HitlDenied — analyst explicitly denied
            HitlTimeoutDenied — SLA expired before decision (treated as deny)

        Returns the final HitlRequest row on APPROVED.
        """
        poll_s = max(settings.hitl_poll_interval_ms, 50) / 1000.0
        while True:
            with Session(engine) as s:
                req = s.get(HitlRequest, request_id)
                if req is None:
                    raise RuntimeError(f"HITL request {request_id} disappeared")

                if req.state == HitlState.APPROVED:
                    return req
                if req.state == HitlState.DENIED:
                    raise HitlDenied(request_id, req.decision_reason)
                if req.state == HitlState.TIMEOUT:
                    raise HitlTimeoutDenied(request_id)
                if req.state == HitlState.CANCELLED:
                    raise HitlDenied(request_id, "cancelled before decision")

            await asyncio.sleep(poll_s)

    # ── analyst-driven decisions (called by API routes) ──────────────────
    def decide(
        self,
        *,
        request_id: int,
        approve: bool,
        decided_by: str,
        mfa_method: str | None,
        mfa_receipt_hash: str | None,
        channel: HitlChannel,
        reason: str | None = None,
    ) -> HitlRequest:
        """Record a terminal decision. Safe to call only once."""
        with Session(engine) as s:
            req = s.get(HitlRequest, request_id)
            if req is None:
                raise ValueError(f"unknown HITL request {request_id}")
            if req.state != HitlState.PENDING:
                raise ValueError(
                    f"HITL request {request_id} already {req.state.value}"
                )

            req.state = HitlState.APPROVED if approve else HitlState.DENIED
            req.decided_at = datetime.now(timezone.utc)
            req.decided_by = decided_by
            req.decided_by_mfa_method = mfa_method
            req.decided_by_mfa_token = mfa_receipt_hash
            req.decided_channel = channel
            req.decision_reason = reason
            s.add(req)

            # Audit step on the trace stream.
            s.add(
                AgentTrace(
                    case_id=req.case_id,
                    tenant_id=req.tenant_id,
                    agent=req.agent,
                    step=TraceStep.DECISION,
                    summary=(
                        f"HITL {'approved' if approve else 'denied'} "
                        f"by {decided_by} via {channel.value}"
                    ),
                    detail={
                        "request_id": req.id,
                        "tool_name": req.tool_name,
                        "state": req.state.value,
                        "mfa_method": mfa_method,
                        "reason": reason,
                    },
                )
            )
            s.commit()
            s.refresh(req)

        notifications.publish_decision_event(req)
        return req

    def cancel(self, request_id: int, reason: str = "case closed") -> HitlRequest | None:
        """System-cancel a pending request (e.g. case closed)."""
        with Session(engine) as s:
            req = s.get(HitlRequest, request_id)
            if req is None or req.state != HitlState.PENDING:
                return req
            req.state = HitlState.CANCELLED
            req.decided_at = datetime.now(timezone.utc)
            req.decided_by = "system"
            req.decided_channel = HitlChannel.SYSTEM
            req.decision_reason = reason
            s.add(req)
            s.commit()
            s.refresh(req)
        notifications.publish_decision_event(req)
        return req

    # ── timeout / escalation watcher ─────────────────────────────────────
    async def _watcher_loop(self) -> None:
        """Periodically flag escalations and expire stalled requests.

        Runs every ~5s. On expiry we transition PENDING → TIMEOUT — the
        blocked agent coroutine sees that and raises HitlTimeoutDenied.
        """
        try:
            while True:
                try:
                    await self._tick()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("hitl watcher tick failed: %s", exc)
                await asyncio.sleep(5)
        except asyncio.CancelledError:  # pragma: no cover
            return

    async def _tick(self) -> None:
        now = datetime.now(timezone.utc)
        escalation_threshold = timedelta(
            seconds=settings.hitl_escalation_seconds
        )

        with Session(engine) as s:
            pendings: list[HitlRequest] = list(
                s.exec(
                    select(HitlRequest).where(HitlRequest.state == HitlState.PENDING)
                ).all()
            )

            timed_out: list[HitlRequest] = []
            escalated: list[HitlRequest] = []

            for req in pendings:
                # SQLite strips tz; normalize to aware UTC for comparisons.
                expires_at = _as_utc(req.expires_at)
                created_at = _as_utc(req.created_at)

                # Escalate before timeout if we're within the escalation window.
                if (
                    not req.escalated
                    and (expires_at - now) <= escalation_threshold
                    and (now - created_at) >= timedelta(seconds=10)
                ):
                    req.escalated = True
                    req.escalated_at = now
                    req.escalation_target = "on-call"
                    s.add(req)
                    escalated.append(req)

                # Hard timeout — explicit denial path.
                if expires_at <= now:
                    req.state = HitlState.TIMEOUT
                    req.decided_at = now
                    req.decided_by = "system"
                    req.decided_channel = HitlChannel.SYSTEM
                    req.decision_reason = (
                        f"SLA of {settings.hitl_sla_seconds}s expired without "
                        "analyst decision — action denied"
                    )
                    s.add(req)
                    s.add(
                        AgentTrace(
                            case_id=req.case_id,
                            tenant_id=req.tenant_id,
                            agent=req.agent,
                            step=TraceStep.DECISION,
                            summary=f"HITL timed out — denied: {req.tool_name}",
                            detail={
                                "request_id": req.id,
                                "tool_name": req.tool_name,
                                "sla_seconds": settings.hitl_sla_seconds,
                            },
                        )
                    )
                    timed_out.append(req)

            if escalated or timed_out:
                s.commit()
                for req in escalated:
                    s.refresh(req)
                for req in timed_out:
                    s.refresh(req)

        for req in escalated:
            notifications.publish_escalation_event(req)
        for req in timed_out:
            notifications.publish_decision_event(req)


def _as_utc(dt: datetime) -> datetime:
    """SQLite drops tzinfo; treat naive timestamps as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# Process-wide singleton — the agents and API routes share one gateway.
gateway = HitlGateway()
