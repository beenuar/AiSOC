"""Auto-triage every fused alert off the Kafka stream (Phase B1).

The reality audit's core autonomy gap: investigations were manual/API-only —
nothing consumed ``aisoc.alerts.fused`` to actually run the agent, so the
platform's headline claim (an agent that triages *every* alert, like a leading
AI-SOC) was not true out of the box. This worker closes that: it subscribes to
the fused-alert topic and runs auto-triage on each alert.

**Copilot / dry-run is the default.** Triage is *read-only*: the worker
classifies the alert (verdict + calibrated confidence), records the reasoning
to the Investigation Ledger, and stops. It NEVER executes a response action —
proposed actions carry ``requires_approval=True`` and are surfaced for a human
(or a tenant that has explicitly raised its L0-L4 autonomy tier — that wiring
is B2/C3). ``response_dispatched`` is therefore always ``False`` here.

Tier selection is cost- and determinism-aware, in this order (each degrades
safely to the deterministic tier, which needs no LLM key — the air-gapped /
no-key / CI default):

1. cost-governor ``DEDUPLICATED`` → reuse the cached verdict (a flood of
   identical alerts costs one triage, not N);
2. governor ``CIRCUIT_OPEN`` / ``AISOC_DETERMINISTIC`` / no LLM key →
   deterministic heuristic triage (``run_triage``);
3. otherwise → LLM auto-triage (``run_auto_triage``), falling back to
   deterministic triage if the LLM call fails.

Everything is fail-soft: a bad message is logged and skipped; a ledger/DB
outage degrades to "triage still runs, audit write is a no-op"; the Kafka loop
never dies on one poison alert.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from app.agents.auto_triage_agent import run_auto_triage
from app.agents.dispositions import NEEDS_REVIEW
from app.agents.triage_agent import run_triage
from app.core.cost_governor import Decision, get_governor
from app.core.cost_telemetry import CostTracker
from app.graph.runner import default_budget, run_escalation
from app.investigator import ledger as ledger_module
from app.llm.factory import llm_override
from app.models.state import AgentStatus, InvestigationState
from app.routing.model_router import is_deterministic_mode
from app.security.llm_resolver import resolve_llm_config
from app.workers.business_context import BusinessContextApplier

logger = structlog.get_logger()

_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "tryaisoc.com/agents/auto-triage")

# Idempotency key component (issue #571): the deterministic run_id is derived
# from (canonical alert id, workflow version), so a replayed fused message
# reuses the same run_id and cannot duplicate ledger runs/outcomes. Bump this
# when the triage workflow changes in a way that should re-run past alerts.
WORKFLOW_VERSION = "auto-triage-v1"

# Bounded retries before dead-lettering a poison alert (issue #571).
_MAX_ATTEMPTS = int(os.getenv("AISOC_AGENT_MAX_ATTEMPTS", "3"))
_RETRY_BACKOFF_S = float(os.getenv("AISOC_AGENT_RETRY_BACKOFF_S", "0.5"))

_METRICS = {
    "triaged": 0,
    "deduplicated": 0,
    "deterministic": 0,
    "llm": 0,
    "bc_suppressed": 0,
    "bc_mutated": 0,
    "needs_review_fallback": 0,
    "escalated": 0,
    "persist_retries": 0,
    "dead_lettered": 0,
    "errors": 0,
}


def _escalation_enabled() -> bool:
    """Route non-auto-closed alerts through the full investigation graph
    (issue #569). On by default; set ``AISOC_AGENT_ESCALATE_TO_GRAPH=0`` to
    keep triage-only (e.g. in CI / low-resource deployments)."""
    return os.getenv("AISOC_AGENT_ESCALATE_TO_GRAPH", "1").strip().lower() not in {"0", "false", "no", "off"}


def _coerce_uuid(value: Any, *, fallback: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return uuid.uuid5(_NAMESPACE, str(value or fallback))


def _rationale_of(state: InvestigationState) -> str:
    """Human-readable rationale for the verdict, for the ledger + alerts row."""
    if state.confidence_basis:
        return " · ".join(str(b) for b in state.confidence_basis)[:8000]
    if state.findings:
        return " · ".join(str(f) for f in state.findings)[:8000]
    return f"Auto-triage verdict={state.verdict} confidence={state.confidence:.2f}"


def build_state(message: dict[str, Any]) -> InvestigationState | None:
    """Map an ``aisoc.alerts.fused`` message to a seeded InvestigationState."""
    if not isinstance(message, dict):
        return None
    alert = message.get("alert")
    if not isinstance(alert, dict):
        return None
    tenant = _coerce_uuid(message.get("tenant_id") or alert.get("tenant_id"), fallback="default")
    incident = _coerce_uuid(message.get("incident_id") or message.get("id") or alert.get("id"), fallback=str(tenant))
    # Canonical alert row id (issue #568): the fused envelope now carries the
    # durable alerts.id as `alert_row_id`, falling back to the (also canonical)
    # message id. This is what the verdict is persisted against.
    alert_row_id = str(message.get("alert_row_id") or message.get("id") or alert.get("id") or "")
    summary = str(alert.get("title") or "").strip()
    if message.get("narrative"):
        summary = f"{summary} — {message['narrative']}"[:1000] if summary else str(message["narrative"])[:1000]
    raw_alert = {
        "id": alert_row_id,
        "severity": alert.get("severity"),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "hostname": alert.get("hostname"),
        "username": alert.get("username"),
        "file_hash": alert.get("file_hash"),
        "domain": alert.get("domain"),
        "url": alert.get("url"),
        "mitre_techniques": alert.get("mitre_techniques", []),
        "risk_score": alert.get("risk_score", 0.0),
        "raw_event": alert.get("raw_event", {}),
        "confidence": message.get("confidence_score"),
        "fusion_decision": message.get("fusion_decision"),
        # Connector provenance (issue #568) carried through the graph so the
        # investigation (e.g. the Splunk evidence tool, #570) can resolve the
        # originating connector instance.
        "connector_id": alert.get("connector_id"),
        "connector_type": alert.get("connector_type"),
        "source_event_ids": alert.get("source_event_ids", []),
    }
    # Deterministic, replay-stable run id (issue #571) — same alert + workflow
    # version ⇒ same run, so replays are idempotent in the ledger.
    run_id = uuid.uuid5(_NAMESPACE, f"{alert_row_id}:{WORKFLOW_VERSION}") if alert_row_id else uuid.uuid4()
    return InvestigationState(
        run_id=run_id,
        incident_id=incident,
        tenant_id=tenant,
        alert_summary=summary,
        raw_alert=raw_alert,
        status=AgentStatus.PENDING,
    )


class FusedAlertTriageWorker:
    """Consumes ``aisoc.alerts.fused`` and auto-triages each alert (copilot)."""

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "aisoc.alerts.fused",
        group_id: str = "aisoc-agents-triage",
        dlq_topic: str | None = None,
        max_attempts: int = _MAX_ATTEMPTS,
        business_context: BusinessContextApplier | None = None,
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._dlq_topic = dlq_topic or os.getenv("KAFKA_TOPIC_ALERTS_FUSED_DLQ", f"{topic}.dlq")
        self._max_attempts = max(1, max_attempts)
        self._consumer: Any | None = None
        self._producer: Any | None = None  # lazily created for the DLQ
        self._running = False
        # Phase B4 — environment-specific noise reduction applied post-fusion →
        # pre-triage. None = disabled (no rules file / flag off).
        self._business_context = business_context

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer  # noqa: PLC0415 — optional dep, only at runtime

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="latest",
            # At-least-once: commit only after an alert is triaged, so a crash
            # mid-triage re-delivers the alert instead of dropping it.
            enable_auto_commit=False,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        await self._consumer.start()
        self._running = True
        logger.info("auto_triage_worker.started", topic=self._topic, group=self._group_id)
        try:
            async for msg in self._consumer:
                if not self._running:
                    break
                # Commit ONLY after a durable outcome (verdict + ledger written)
                # or after the poison alert is dead-lettered — so a crash between
                # inference and persistence replays the alert instead of losing
                # it, and offsets advance only on durable completion (issue #571).
                await self._process_with_retry(msg.value)
                try:
                    await self._consumer.commit()
                except Exception as commit_exc:  # noqa: BLE001 — reprocess on restart
                    logger.warning("auto_triage_worker.commit_failed", error=str(commit_exc))
        finally:
            await self._consumer.stop()

    async def _process_with_retry(self, message: Any) -> bool:
        """Triage one alert with bounded retries; dead-letter on exhaustion.

        Returns True on durable success, False if the message was dead-lettered.
        Either way the caller commits (a poison alert must not wedge the loop).
        """
        last_error: str = ""
        stage = "triage"
        for attempt in range(1, self._max_attempts + 1):
            try:
                await self.triage(message)
                return True
            except ledger_module.LedgerPersistError as exc:
                stage = "persist"
                last_error = str(exc)
                _METRICS["persist_retries"] += 1
                logger.warning("auto_triage_worker.persist_retry", attempt=attempt, error=last_error)
            except Exception as exc:  # noqa: BLE001 — retry, then dead-letter
                stage = "triage"
                last_error = str(exc)
                logger.warning("auto_triage_worker.triage_retry", attempt=attempt, error=last_error)
            if attempt < self._max_attempts:
                await asyncio.sleep(self._retry_backoff(attempt))
        _METRICS["errors"] += 1
        await self._send_to_dlq(message, attempts=self._max_attempts, stage=stage, error=last_error)
        return False

    def _retry_backoff(self, attempt: int) -> float:
        return _RETRY_BACKOFF_S * attempt

    async def _ensure_producer(self) -> Any | None:
        if self._producer is not None:
            return self._producer
        try:
            from aiokafka import AIOKafkaProducer  # noqa: PLC0415 — optional dep, runtime only

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            await self._producer.start()
            return self._producer
        except Exception as exc:  # noqa: BLE001 — DLQ is best-effort
            logger.error("auto_triage_worker.dlq_producer_failed", error=str(exc))
            self._producer = None
            return None

    async def _send_to_dlq(self, message: Any, *, attempts: int, stage: str, error: str) -> None:
        """Publish a poison alert to the DLQ with alert id, attempts, and stage."""
        alert_id = ""
        if isinstance(message, dict):
            alert = message.get("alert") if isinstance(message.get("alert"), dict) else {}
            alert_id = str(message.get("alert_row_id") or message.get("id") or alert.get("id") or "")
        record = {
            "alert_id": alert_id,
            "attempts": attempts,
            "failure_stage": stage,
            "error": (error or "")[:2000],
            "dead_lettered_at": datetime.now(UTC).isoformat(),
            "original": message if isinstance(message, dict) else {"raw": str(message)[:2000]},
        }
        producer = await self._ensure_producer()
        if producer is None:
            logger.error("auto_triage_worker.dlq_unavailable", alert_id=alert_id, stage=stage)
            return
        try:
            await producer.send(self._dlq_topic, value=record)
            _METRICS["dead_lettered"] += 1
            logger.error("auto_triage_worker.dead_lettered", alert_id=alert_id, stage=stage, attempts=attempts)
        except Exception as exc:  # noqa: BLE001 — never wedge the loop on a DLQ failure
            logger.error("auto_triage_worker.dlq_send_failed", alert_id=alert_id, error=str(exc))

    async def stop(self) -> None:
        self._running = False
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        if self._producer is not None:
            with contextlib.suppress(Exception):
                await self._producer.stop()
            self._producer = None
        logger.info("auto_triage_worker.stopped", metrics=dict(_METRICS))

    async def triage(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Auto-triage one fused alert. Read-only (copilot): never dispatches a
        response. Returns a verdict summary dict, or None if unprocessable."""
        # Phase B4 — apply business-context rules on the post-fusion alert BEFORE
        # any triage work. A suppress rule drops the alert (no triage spend); a
        # severity/route/tag rule mutates the alert the agent reasons over.
        bc_matched: list[str] = []
        if self._business_context is not None and isinstance(message, dict) and isinstance(message.get("alert"), dict):
            bc = self._business_context.apply(message["alert"])
            bc_matched = bc.matched_rule_ids
            if bc.suppressed:
                _METRICS["bc_suppressed"] += 1
                logger.info("auto_triage_worker.bc_suppressed", matched=bc_matched)
                return {
                    "incident_id": str(message.get("incident_id") or message.get("id") or ""),
                    "suppressed": True,
                    "business_context_rules": bc_matched,
                    "response_dispatched": False,
                }
            if bc.changed:
                _METRICS["bc_mutated"] += 1
                message = {**message, "alert": bc.alert}

        state = build_state(message)
        if state is None:
            logger.warning("auto_triage_worker.unprocessable", keys=sorted(message.keys()) if isinstance(message, dict) else None)
            return None

        governor = get_governor()
        fingerprint = governor.evidence_fingerprint(str(state.tenant_id), state.raw_alert)
        decision = governor.check(str(state.tenant_id), fingerprint)

        tier: str
        cost_usd = 0.0
        tokens = 0
        if decision.decision is Decision.DEDUPLICATED and decision.cached_verdict:
            _METRICS["deduplicated"] += 1
            verdict = decision.cached_verdict.get("verdict")
            confidence = float(decision.cached_verdict.get("confidence", 0.0))
            tier = "cached"
        else:
            cfg = await self._resolve_tenant_llm(state.tenant_id)
            use_llm = decision.use_llm and not is_deterministic_mode() and cfg is not None
            # Bind a CostTracker so every LLM call on this path records its
            # token/cost (safe_ainvoke -> record_llm_call) — previously the
            # highest-volume LLM spend was recorded as $0 and invisible.
            async with CostTracker(run_id=str(state.run_id), tenant_id=str(state.tenant_id)) as tracker:
                if use_llm and cfg is not None:
                    # Route the LLM call through the tenant's BYOK key/model so
                    # auto-triage actually honours per-tenant credentials.
                    with llm_override(api_key=cfg.api_key, base_url=cfg.base_url, model=cfg.model):
                        state, tier = await self._llm_triage(state)
                else:
                    state = await run_triage(state)
                    tier = "deterministic"
                    _METRICS["deterministic"] += 1
                cost_usd = tracker.total_cost_usd
                tokens = tracker.total_tokens
            verdict = state.verdict
            confidence = state.confidence
            # Never complete with a null/empty verdict (issue #571): if both the
            # LLM and deterministic paths somehow left it unset, fail safe to
            # needs_review so the alert is escalated to a human, not auto-closed.
            if not verdict:
                verdict = state.verdict = NEEDS_REVIEW
                if state.status is AgentStatus.COMPLETED:
                    state.status = AgentStatus.RUNNING
                _METRICS["needs_review_fallback"] += 1
                state.add_finding("Triage produced no verdict — defaulting to needs_review (escalated).")
            # Close the cost-governor loop: cache the verdict (so an alert flood
            # dedups instead of re-paying) and account the spend (so per-tenant
            # budgets + the circuit breaker actually fire). Best-effort.
            try:
                governor.record_verdict(
                    str(state.tenant_id),
                    fingerprint,
                    {"verdict": verdict, "confidence": confidence},
                    usd=cost_usd,
                    tokens=tokens,
                )
            except Exception as exc:  # noqa: BLE001 — governance accounting is best-effort
                logger.debug("auto_triage_worker.governor_record_failed", error=str(exc))

        _METRICS["triaged"] += 1
        await self._record(state, tier=tier, verdict=verdict, confidence=confidence, tokens=tokens, cost_usd=cost_usd)

        # Issue #569: route escalations (anything NOT auto-closed — TP,
        # low-confidence, needs_review) through the full investigation graph.
        # High-confidence FP/BTP already terminated (status COMPLETED) and
        # skip enrichment. Best-effort: the verdict is already durable, so an
        # enrichment/investigation failure never fails the triage outcome.
        if state.status is not AgentStatus.COMPLETED:
            await self._maybe_escalate(state)

        return {
            "run_id": str(state.run_id),
            "incident_id": str(state.incident_id),
            "tenant_id": str(state.tenant_id),
            "verdict": verdict,
            "confidence": confidence,
            "tier": tier,
            "business_context_rules": bc_matched,
            # Copilot default: triage is read-only, response requires approval.
            "response_dispatched": False,
            "proposed_actions": [{"action_type": a.action_type, "requires_approval": a.requires_approval} for a in state.proposed_actions],
        }

    async def _maybe_escalate(self, state: InvestigationState) -> None:
        """Run the full investigation graph for an escalated alert (issue #569).

        Shares the same graph runner as the manual investigations API. Every
        node is recorded to the ledger under the deterministic run_id, so a
        restart re-runs idempotently. Best-effort + budgeted — a failure or
        timeout leaves the durable verdict intact and the alert escalated.
        """
        if not _escalation_enabled():
            return
        try:
            async with CostTracker(run_id=str(state.run_id), tenant_id=str(state.tenant_id)):
                await run_escalation(state, budget=default_budget(), seq_start=1)
            _METRICS["escalated"] += 1
        except Exception as exc:  # noqa: BLE001 — escalation is best-effort over a durable verdict
            logger.warning("auto_triage_worker.escalation_failed", run_id=str(state.run_id), error=str(exc))

    async def _resolve_tenant_llm(self, tenant_id: uuid.UUID) -> Any:
        """Resolve the tenant's LLM config, or None to force deterministic triage."""
        try:
            cfg = await resolve_llm_config(str(tenant_id))
            return cfg if (cfg.allowed and cfg.api_key) else None
        except Exception as exc:  # noqa: BLE001 — resolver failure => deterministic
            logger.debug("auto_triage_worker.llm_resolve_failed", error=str(exc))
            return None

    async def _llm_triage(self, state: InvestigationState) -> tuple[InvestigationState, str]:
        try:
            state = await run_auto_triage(state)
            _METRICS["llm"] += 1
            return state, "llm"
        except Exception as exc:  # noqa: BLE001 — fall back to deterministic triage
            logger.warning("auto_triage_worker.llm_failed_fallback", error=str(exc))
            state = await run_triage(state)
            _METRICS["deterministic"] += 1
            return state, "deterministic"

    async def _record(
        self,
        state: InvestigationState,
        *,
        tier: str,
        verdict: Any,
        confidence: float,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        """Durably persist the triage outcome (issue #571).

        Writes the verdict/confidence/rationale/recommendations to BOTH the
        ledger and the ``alerts`` row in one transaction. No DB configured =>
        no-op (returns without raising). A real DB error raises
        :class:`LedgerPersistError` so the caller retries / dead-letters — the
        Kafka offset is not committed until this succeeds.
        """
        rationale = _rationale_of(state)
        recommendations = [
            {
                "action_type": a.action_type,
                "description": a.description,
                "risk_level": a.risk_level.value if hasattr(a.risk_level, "value") else str(a.risk_level),
                "requires_approval": a.requires_approval,
                "target": a.target,
            }
            for a in state.proposed_actions
        ]
        await ledger_module.persist_auto_triage(
            run_id=state.run_id,
            alert_id=(state.raw_alert or {}).get("id"),
            tenant_ref=str(state.tenant_id),
            alert_summary=state.alert_summary or "",
            raw_alert=state.raw_alert or {},
            tier=tier,
            verdict=str(verdict) if verdict else NEEDS_REVIEW,
            confidence=float(confidence or 0.0),
            rationale=rationale,
            findings=list(state.findings),
            proposed_actions=recommendations,
            auto_closed=state.status is AgentStatus.COMPLETED,
            iterations=state.iteration_count,
            tokens=tokens,
            cost_usd=cost_usd,
        )

    @staticmethod
    def get_metrics() -> dict[str, int]:
        return dict(_METRICS)


def worker_enabled() -> bool:
    """Off unless a Kafka broker is configured and it's not explicitly disabled."""
    if os.getenv("AISOC_AGENT_KAFKA_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return bool(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip())
