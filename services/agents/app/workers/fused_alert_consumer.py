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

import json
import os
import uuid
from typing import Any

import structlog

from app.agents.auto_triage_agent import run_auto_triage
from app.agents.triage_agent import run_triage
from app.core.cost_governor import Decision, get_governor
from app.investigator import ledger as ledger_module
from app.models.state import AgentStatus, InvestigationState
from app.routing.model_router import is_deterministic_mode
from app.security.llm_resolver import resolve_llm_config

logger = structlog.get_logger()

_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "tryaisoc.com/agents/auto-triage")

_METRICS = {"triaged": 0, "deduplicated": 0, "deterministic": 0, "llm": 0, "errors": 0}


def _coerce_uuid(value: Any, *, fallback: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return uuid.uuid5(_NAMESPACE, str(value or fallback))


def build_state(message: dict[str, Any]) -> InvestigationState | None:
    """Map an ``aisoc.alerts.fused`` message to a seeded InvestigationState."""
    if not isinstance(message, dict):
        return None
    alert = message.get("alert")
    if not isinstance(alert, dict):
        return None
    tenant = _coerce_uuid(message.get("tenant_id") or alert.get("tenant_id"), fallback="default")
    incident = _coerce_uuid(message.get("incident_id") or message.get("id") or alert.get("id"), fallback=str(tenant))
    summary = str(alert.get("title") or "").strip()
    if message.get("narrative"):
        summary = f"{summary} — {message['narrative']}"[:1000] if summary else str(message["narrative"])[:1000]
    raw_alert = {
        "id": str(message.get("id") or alert.get("id") or ""),
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
    }
    return InvestigationState(
        incident_id=incident,
        tenant_id=tenant,
        alert_summary=summary,
        raw_alert=raw_alert,
        status=AgentStatus.PENDING,
    )


class FusedAlertTriageWorker:
    """Consumes ``aisoc.alerts.fused`` and auto-triages each alert (copilot)."""

    def __init__(self, *, bootstrap_servers: str, topic: str = "aisoc.alerts.fused", group_id: str = "aisoc-agents-triage") -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._consumer: Any | None = None
        self._running = False

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer  # noqa: PLC0415 — optional dep, only at runtime

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        await self._consumer.start()
        self._running = True
        logger.info("auto_triage_worker.started", topic=self._topic, group=self._group_id)
        try:
            async for msg in self._consumer:
                if not self._running:
                    break
                try:
                    await self.triage(msg.value)
                except Exception as exc:  # noqa: BLE001 — one poison alert must not kill the loop
                    _METRICS["errors"] += 1
                    logger.error("auto_triage_worker.error", error=str(exc), exc_info=True)
        finally:
            await self._consumer.stop()

    async def stop(self) -> None:
        self._running = False
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        logger.info("auto_triage_worker.stopped", metrics=dict(_METRICS))

    async def triage(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Auto-triage one fused alert. Read-only (copilot): never dispatches a
        response. Returns a verdict summary dict, or None if unprocessable."""
        state = build_state(message)
        if state is None:
            logger.warning("auto_triage_worker.unprocessable", keys=sorted(message.keys()) if isinstance(message, dict) else None)
            return None

        governor = get_governor()
        fingerprint = governor.evidence_fingerprint(str(state.tenant_id), state.raw_alert)
        decision = governor.check(str(state.tenant_id), fingerprint)

        tier: str
        if decision.decision is Decision.DEDUPLICATED and decision.cached_verdict:
            _METRICS["deduplicated"] += 1
            verdict = decision.cached_verdict.get("verdict")
            confidence = float(decision.cached_verdict.get("confidence", 0.0))
            tier = "cached"
        else:
            use_llm = decision.use_llm and not is_deterministic_mode() and await self._llm_available(state.tenant_id)
            if use_llm:
                state, tier = await self._llm_triage(state)
            else:
                state = await run_triage(state)
                tier = "deterministic"
                _METRICS["deterministic"] += 1
            verdict = state.verdict
            confidence = state.confidence

        _METRICS["triaged"] += 1
        await self._record(state, tier=tier, verdict=verdict, confidence=confidence)

        return {
            "run_id": str(state.run_id),
            "incident_id": str(state.incident_id),
            "tenant_id": str(state.tenant_id),
            "verdict": verdict,
            "confidence": confidence,
            "tier": tier,
            # Copilot default: triage is read-only, response requires approval.
            "response_dispatched": False,
            "proposed_actions": [{"action_type": a.action_type, "requires_approval": a.requires_approval} for a in state.proposed_actions],
        }

    async def _llm_available(self, tenant_id: uuid.UUID) -> bool:
        try:
            cfg = await resolve_llm_config(str(tenant_id))
            return bool(cfg.allowed and cfg.api_key)
        except Exception as exc:  # noqa: BLE001 — resolver failure => deterministic
            logger.debug("auto_triage_worker.llm_resolve_failed", error=str(exc))
            return False

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

    async def _record(self, state: InvestigationState, *, tier: str, verdict: Any, confidence: float) -> None:
        """Best-effort ledger write. No DB => no-op (never raises)."""
        try:
            await ledger_module.start_run(
                run_id=state.run_id,
                case_id=str(state.incident_id),
                tenant_ref=str(state.tenant_id),
                alert_summary=state.alert_summary or "",
                raw_alert=state.raw_alert or {},
                model_used=f"kafka:auto_triage:{tier}",
            )
            await ledger_module.complete_run(
                run_id=state.run_id,
                tenant_id=state.tenant_id,
                status="completed",
                error=None,
                iterations=state.iteration_count,
                total_tokens=0,
                total_cost_usd=0.0,
            )
        except Exception as exc:  # noqa: BLE001 — audit is best-effort
            logger.debug("auto_triage_worker.ledger_noop", error=str(exc), verdict=verdict, confidence=confidence)

    @staticmethod
    def get_metrics() -> dict[str, int]:
        return dict(_METRICS)


def worker_enabled() -> bool:
    """Off unless a Kafka broker is configured and it's not explicitly disabled."""
    if os.getenv("AISOC_AGENT_KAFKA_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return bool(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip())
