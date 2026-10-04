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
from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, NEEDS_REVIEW, normalize_disposition
from app.agents.triage_agent import run_triage
from app.confidence.groundedness import score_groundedness
from app.context import dispositions as dispositions_module
from app.context import identity as identity_module
from app.context import knowledge_base
from app.context.tenant_skills import select_skill
from app.core.cost_governor import Decision, get_governor
from app.core.cost_telemetry import CostSummary, CostTracker
from app.core.kafka_security import kafka_client_kwargs
from app.graph.runner import default_budget, run_escalation
from app.investigator import ledger as ledger_module
from app.investigator.bundle_prompt import prefetch_context_bundle_dict
from app.llm.factory import llm_override
from app.memory.outcomes import AI, suppression_refusal
from app.models.state import AgentStatus, InvestigationState
from app.playbook import alert_trigger
from app.routing.model_router import is_deterministic_mode
from app.security.llm_resolver import resolve_llm_config
from app.workers.business_context import BusinessContextApplier
from app.workers.shadow_mode import (
    LiveShadowModePolicy,
    ShadowDecision,
    ShadowModePolicy,
    ShadowModeTriageWriter,
    alert_class_of,
)
from app.workers.triage_persistence import (
    LiveTriageContextReader,
    LiveTriageWriter,
    TriageContextReader,
    TriageWriter,
)

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
    "outcome_written": 0,
    "outcome_suppressed": 0,
    "ungrounded_demoted": 0,
    "persist_retries": 0,
    "dead_lettered": 0,
    "approvals_raised": 0,
    # Two-way SIEM loop. Kept as two counters, not one: "attempted" grows
    # on every dry run too, and an operator who sees attempts climbing
    # while executions stay at zero is looking at the default posture
    # rather than a broken integration.
    "writeback_attempted": 0,
    "writeback_executed": 0,
    # Phase 2.1. Two counters for the same reason as the writeback pair: a
    # shadow run whose decision row never lands measures nothing, and the
    # symptom of that is a scorecard that stays empty rather than an error.
    "shadow_triaged": 0,
    "shadow_decisions_recorded": 0,
    # Phase 6.1. An operator who authored, backtested and activated a skill
    # needs to see that it is reaching alerts; zero here with an active skill
    # is the difference between "my guidance is not helping" and "my guidance
    # was never read".
    "tenant_skill_applied": 0,
    # Phase 6.3. Same reasoning as the skill counter, plus the refusal beside
    # it: a library whose documents keep being withheld is a library somebody
    # needs to look at, and a silent drop would leave the operator wondering
    # why triage never cites the runbook they wrote.
    "runbooks_retrieved": 0,
    "runbooks_refused_for_injection": 0,
    "recent_dispositions_read": 0,
    "identity_context_read": 0,
    "errors": 0,
}


def _escalation_enabled() -> bool:
    """Route non-auto-closed alerts through the full investigation graph
    (issue #569). On by default; set ``AISOC_AGENT_ESCALATE_TO_GRAPH=0`` to
    keep triage-only (e.g. in CI / low-resource deployments)."""
    return os.getenv("AISOC_AGENT_ESCALATE_TO_GRAPH", "1").strip().lower() not in {"0", "false", "no", "off"}


def _truthy(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() not in {"0", "false", "no", "off"}


def _memory_suppression_enabled() -> bool:
    """Auto-suppress a repeat alert that matches a trusted prior benign/FP
    outcome (Wave 1). On by default; disable with AISOC_AGENT_MEMORY_SUPPRESSION=0."""
    return _truthy("AISOC_AGENT_MEMORY_SUPPRESSION")


def _memory_writeback_enabled() -> bool:
    """Write every durable triage outcome back as a per-signature prior (Wave 1)
    so autonomous closures compound. Disable with AISOC_AGENT_MEMORY_WRITEBACK=0."""
    return _truthy("AISOC_AGENT_MEMORY_WRITEBACK")


def _approvals_enabled() -> bool:
    """Queue approval-requiring proposed actions for human sign-off.

    On by default. Queueing an approval executes nothing — the worker stays
    copilot-default — so the risk of leaving it on is a longer approvals
    list, while the cost of leaving it off is the pre-v9.0 behaviour where
    the queue had no producer. Disable with AISOC_AGENT_RAISE_APPROVALS=0.
    """
    return _truthy("AISOC_AGENT_RAISE_APPROVALS")


def _groundedness_gate_enabled() -> bool:
    """Demote a verdict whose reasoning cites indicators the evidence lacks.

    On by default; disable with AISOC_AGENT_GROUNDEDNESS_GATE=0.
    """
    return _truthy("AISOC_AGENT_GROUNDEDNESS_GATE")


def _groundedness_floor() -> float:
    """Minimum grounded fraction for a verdict to be trusted to auto-close."""
    try:
        return float(os.getenv("AISOC_AGENT_GROUNDEDNESS_FLOOR", "0.75"))
    except ValueError:
        return 0.75


def _coerce_uuid(value: Any, *, fallback: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return uuid.uuid5(_NAMESPACE, str(value or fallback))


def _cost_payload(cost: CostSummary, tokens: int) -> dict[str, Any]:
    """The spend a triage summary reports, with the provenance of every figure.

    Added for Phase 1.2: replay has to record measured cost, tokens and the
    model per decision, and the only place that knows them is this worker.
    ``measured_usd`` stays ``None`` when no call reported a cost, because a
    replay report that printed 0.0 there would be claiming a measurement of
    free rather than the absence of one.
    """
    return {
        "measured_usd": cost.measured_usd,
        "measured_calls": cost.measured_calls,
        "estimated_usd": cost.estimated_usd,
        "estimated_calls": cost.estimated_calls,
        "unpriced_calls": cost.unpriced_calls,
        "resolved_models": list(cost.resolved_models),
        "tokens": tokens,
    }


def _opt_text(value: Any) -> str | None:
    """A trimmed string, or ``None`` for absent and empty alike.

    The shadow decision row distinguishes the two: a null rule id means the
    alert carried none, and an empty string would become a segment key named
    after nothing in the per-rule breakdown.
    """
    text = str(value).strip() if value is not None else ""
    return text or None


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
        # Rule identity travels with the alert so the evidence fingerprint can
        # tell two different detections on the same host apart. Without it, a
        # benign prior for one detection would suppress an unrelated one.
        "title": alert.get("title"),
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),
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

    #: Production sinks, declared on the class rather than only assigned in
    #: ``__init__``. Several tests build this worker with ``__new__`` to drive
    #: one method without a broker, and a sink that existed only as an instance
    #: attribute would leave those objects with no persistence at all —
    #: silently, since every write here is fail-soft. A class-level default
    #: makes "the default is production" true however the object was made.
    #: Both implementations are stateless (``__slots__ = ()``), so one shared
    #: instance carries nothing between workers.
    _writer: TriageWriter = LiveTriageWriter()
    _reader: TriageContextReader = LiveTriageContextReader()
    #: Phase 2.1. Not a sink: it decides *which* sink each alert gets. Stated
    #: at class level for the same reason as the two above, so a worker built
    #: with ``__new__`` still resolves a policy rather than raising.
    _shadow_policy: ShadowModePolicy = LiveShadowModePolicy()

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "aisoc.alerts.fused",
        group_id: str = "aisoc-agents-triage",
        dlq_topic: str | None = None,
        max_attempts: int = _MAX_ATTEMPTS,
        business_context: BusinessContextApplier | None = None,
        writer: TriageWriter | None = None,
        context_reader: TriageContextReader | None = None,
        shadow_policy: ShadowModePolicy | None = None,
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        # Phase 1.2 — persistence is injected so replay evaluation can run this
        # exact path writing nothing. The defaults are what the worker did
        # inline before, so a production deployment that passes neither is
        # byte-for-byte the same behaviour.
        self._writer: TriageWriter = writer or LiveTriageWriter()
        self._reader: TriageContextReader = context_reader or LiveTriageContextReader()
        self._shadow_policy: ShadowModePolicy = shadow_policy or LiveShadowModePolicy()
        self._dlq_topic = dlq_topic or os.getenv("KAFKA_TOPIC_ALERTS_FUSED_DLQ", f"{topic}.dlq")
        self._max_attempts = max(1, max_attempts)
        self._consumer: Any | None = None
        self._producer: Any | None = None  # lazily created for the DLQ
        self._running = False
        self._attached = False
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
            **kafka_client_kwargs(),
        )
        await self._consumer.start()
        self._running = True
        self._attached = True
        logger.info("auto_triage_worker.started", topic=self._topic, group=self._group_id)
        try:
            async for msg in self._consumer:
                if not self._running:
                    break
                # Commit ONLY after a durable outcome (verdict + ledger written)
                # or after the poison alert is dead-lettered — so a crash between
                # inference and persistence replays the alert instead of losing
                # it, and offsets advance only on durable completion (issue #571).
                #
                # ``_process_with_retry`` catches and dead-letters rather than
                # raising, which is the reason this loop survives a poison
                # alert. The guard is here as well because that is a property
                # of another method: the loop must not depend on a callee
                # staying total, which is exactly how the ueba consumer came
                # to have no ``except`` on its only handler.
                try:
                    await self._process_with_retry(msg.value)
                except Exception as exc:  # noqa: BLE001 — one alert must not end the subscription
                    _METRICS["errors"] += 1
                    logger.error(
                        "auto_triage_worker.handler_escaped",
                        error=str(exc),
                        error_type=type(exc).__name__,
                        partition=getattr(msg, "partition", None),
                        offset=getattr(msg, "offset", None),
                        exc_info=True,
                    )
                try:
                    await self._consumer.commit()
                except Exception as commit_exc:  # noqa: BLE001 — reprocess on restart
                    logger.warning("auto_triage_worker.commit_failed", error=str(commit_exc))
        finally:
            # Cleared before the teardown await, which can itself raise on a
            # broker that has gone away.
            self._attached = False
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
                **kafka_client_kwargs(),
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

    @property
    def topic(self) -> str:
        """The topic this worker subscribes to (names its readiness probe)."""
        return self._topic

    @property
    def attached(self) -> bool:
        """Whether the consume loop is currently iterating the subscription."""
        return self._attached

    async def stop(self) -> None:
        self._running = False
        self._attached = False
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
            # Per tenant, not one global rule set. The console writes
            # business-context rules per tenant and this worker only ever read
            # a YAML file whose path nothing sets, so authored rules applied to
            # no triage decision.
            bc = await self._business_context.apply_for_tenant(
                message.get("tenant_id") or message["alert"].get("tenant_id"),
                message["alert"],
            )
            bc_matched = bc.matched_rule_ids
            if bc.suppressed:
                _METRICS["bc_suppressed"] += 1
                logger.info("auto_triage_worker.bc_suppressed", matched=bc_matched)
                return {
                    "incident_id": str(message.get("incident_id") or message.get("id") or ""),
                    "suppressed": True,
                    "cost": _cost_payload(CostSummary(), 0),
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

        # Phase 2.1 — which sink this alert's writes go to is a per-alert
        # question, because shadow mode is per tenant *and* per alert class.
        # The constructor sinks stay untouched: `writer` is the tenant's live
        # sink or a shadow wrapper around it, chosen here and passed down
        # explicitly rather than swapped onto `self`, which would leak across
        # concurrently triaged alerts.
        writer = await self._sink_for(state, fingerprint)

        # Wave 1 — forward auto-suppression: if this signature has a trusted
        # prior benign/FP outcome, auto-resolve the repeat WITHOUT re-triage
        # (this is what makes alert volume actually shrink over time). Gated on
        # trust (human prior, or corroborated high-confidence AI prior).
        if _memory_suppression_enabled():
            suppressed = await self._maybe_suppress_from_memory(state, fingerprint, bc_matched, writer=writer)
            if suppressed is not None:
                return suppressed

        decision = governor.check(str(state.tenant_id), fingerprint)

        tier: str
        # None, not 0.0: a cached or deterministic verdict placed no LLM call,
        # and "no call was made" is a different fact from "the call was free".
        cost: CostSummary = CostSummary()
        tokens = 0
        if decision.decision is Decision.DEDUPLICATED and decision.cached_verdict:
            _METRICS["deduplicated"] += 1
            verdict = decision.cached_verdict.get("verdict")
            confidence = float(decision.cached_verdict.get("confidence", 0.0))
            tier = "cached"
        else:
            cfg = await self._resolve_tenant_llm(state.tenant_id)
            use_llm = decision.use_llm and not is_deterministic_mode() and cfg is not None
            if use_llm:
                # What analysts have repeatedly taught this tenant's platform,
                # read once here rather than inside the agent so the round trip
                # is on the worker's timeline and is skipped entirely when no
                # LLM call is going to happen. Never raises; an empty list just
                # means the prompt is what it was before.
                state.organisation_memory = await self._reader.fetch_statements(str(state.tenant_id))
                # Phase 6.1: the tenant's own skill for this shape of alert.
                # Read through the same port for the same reason: it is durable
                # state a verdict depends on, so the replay freeze has to be
                # able to reach it. Selection is per alert and cheap; the fetch
                # behind it is cached.
                await self._attach_tenant_skill(state)
                # Phase 6.3: the tenant's own runbooks for this shape of alert.
                # Same port again, and for a source the freeze holds still by
                # a server-side cutoff rather than by capture, which is why
                # the worker passes a query and never a point in time.
                await self._attach_runbooks(state)
                # Phase 6.3: what this tenant's analysts decided the last few
                # times, and who is behind the account. Both are cutoff-frozen
                # sources like runbooks, so neither takes a point in time from
                # here.
                await self._attach_recent_dispositions(state)
                await self._attach_identity_context(state)
            # Bind a CostTracker so every LLM call on this path records its
            # token/cost (safe_ainvoke -> record_llm_call) — previously the
            # highest-volume LLM spend was recorded as $0 and invisible.
            async with CostTracker(
                run_id=str(state.run_id),
                tenant_id=str(state.tenant_id),
                persist=writer.persists_cost,
            ) as tracker:
                if use_llm and cfg is not None:
                    # Route the LLM call through the tenant's BYOK key/model so
                    # auto-triage actually honours per-tenant credentials.
                    #
                    # Only the fields the *tenant* set are overrides. The
                    # resolver also carries an env baseline, and passing that
                    # through here replaced the `triage` role's gateway alias
                    # with whatever `OPENAI_MODEL` held — `gpt-4-turbo-preview`
                    # in the shipped .env.example, which the gateway 400s. An
                    # env default is not a per-tenant override.
                    # The key needs the same treatment: the env baseline's key
                    # is a *provider* key, and forcing it here would send it to
                    # the gateway as a bearer token, which 401s. Left unset,
                    # make_chat_model resolves the key that pairs with the route
                    # it actually chose.
                    with llm_override(
                        api_key=cfg.api_key if getattr(cfg, "api_key_from_tenant", False) else None,
                        base_url=cfg.base_url if getattr(cfg, "base_url_from_tenant", False) else None,
                        model=cfg.model if getattr(cfg, "model_from_tenant", False) else None,
                    ):
                        state, tier = await self._llm_triage(state)
                else:
                    state = await run_triage(state)
                    tier = "deterministic"
                    _METRICS["deterministic"] += 1
                cost = CostSummary.from_tracker(tracker)
                tokens = tracker.total_tokens
                # From the call that answered, not from the pin. The shadow
                # writer stamps a decision with `state.model_used`, and the
                # field did not exist, so every shadow decision recorded a
                # null model and per-model agreement was empty on every
                # deployment. `resolved_models` is what the tracker observed,
                # so the deterministic path correctly leaves this `None`.
                if cost.resolved_models:
                    state.model_used = ", ".join(sorted({str(m) for m in cost.resolved_models}))

            # Parity 5.1. `find_matching()` had no production caller, so no
            # playbook ever ran from an alert. Three switches must agree
            # before one acts (deployment, tenant, playbook) and anything
            # short of all three runs in **preview**, with its plan and
            # simulated steps attached to the alert.
            #
            # After triage, because a playbook's conditions read the
            # verdict and the confidence, and before them it would be
            # matching on an alert nobody has assessed.
            try:
                playbook_outcome = await alert_trigger.run_for_alert(state)
                if playbook_outcome.matched:
                    state.add_finding(
                        f"Playbooks matched: {', '.join(playbook_outcome.matched)}"
                        + (f" ({len(playbook_outcome.executed)} ran, {len(playbook_outcome.previewed)} previewed)")
                    )
            except Exception as exc:  # noqa: BLE001
                # A playbook failure must not lose the triage result it was
                # attached to.
                logger.warning("auto_triage_worker.playbook_trigger_failed", error=str(exc))

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
                # The budget circuit breaker gets measured spend only. Fed the
                # old alias-priced guess it would eventually trip
                # AISOC_BUDGET_HARD_USD on a local deployment and degrade a
                # working install to deterministic-only over money nobody
                # spent. An unmeasured call contributes no dollars — it still
                # contributes tokens, which is the cap that can be enforced
                # honestly without a price.
                writer.cache_verdict(
                    governor,
                    str(state.tenant_id),
                    fingerprint,
                    {"verdict": verdict, "confidence": confidence},
                    usd=cost.measured_usd or 0.0,
                    tokens=tokens,
                )
            except Exception as exc:  # noqa: BLE001 — governance accounting is best-effort
                logger.debug("auto_triage_worker.governor_record_failed", error=str(exc))

        # Groundedness gate: does the verdict's reasoning cite indicators the
        # evidence actually contained? `score_groundedness` existed as an eval
        # axis with no caller in the service, so a confident verdict citing an
        # IP or hash that appeared nowhere in the alert was persisted, acted on
        # and auto-closed with no signal that it was invented.
        verdict, confidence = self._apply_groundedness_gate(state, verdict, confidence)

        _METRICS["triaged"] += 1
        await self._record(state, tier=tier, verdict=verdict, confidence=confidence, tokens=tokens, cost=cost, writer=writer)

        # Wave 1 — write the durable outcome back as a per-signature prior so
        # autonomous closures compound (a later identical alert can suppress).
        if _memory_writeback_enabled() and verdict:
            with contextlib.suppress(Exception):
                await writer.record_outcome(
                    str(state.tenant_id),
                    fingerprint,
                    disposition=str(verdict),
                    confidence=float(confidence or 0.0),
                    author=AI,
                    alert_id=(state.raw_alert or {}).get("id"),
                    # The guard already ran over this alert's runbook
                    # retrieval; carrying its verdict onto the prior is what
                    # stops a disposition derived from attacker-reachable
                    # text from auto-closing the next one.
                    injection_suspected=bool(getattr(state, "injection_suspected", False)),
                )
                _METRICS["outcome_written"] += 1

        # Issue #569: route escalations (anything NOT auto-closed — TP,
        # low-confidence, needs_review) through the full investigation graph.
        # High-confidence FP/BTP already terminated (status COMPLETED) and
        # skip enrichment. Best-effort: the verdict is already durable, so an
        # enrichment/investigation failure never fails the triage outcome.
        if state.status is not AgentStatus.COMPLETED:
            await self._maybe_escalate(state, writer=writer)

        # Queue every action that needs sign-off so a human can actually give
        # it. Until v9.0 proposed actions were persisted as JSON and stopped
        # there, so "requires_approval" described an approval nobody could
        # grant — the responder app's queue had no producer at all.
        approvals = await self._raise_approvals(state, writer=writer)

        # Close the loop with the SIEM that raised this alert. Runs last and
        # fails soft: the verdict is already durable, and an unreachable
        # Splunk must not re-drive the retry path and dead-letter an alert
        # that was triaged correctly.
        source_writeback = await self._write_back_to_source(state, verdict, confidence, rationale=_rationale_of(state), writer=writer)

        shadow = isinstance(writer, ShadowModeTriageWriter)
        if isinstance(writer, ShadowModeTriageWriter) and writer.recorded:
            _METRICS["shadow_decisions_recorded"] += 1

        return {
            # Phase 2.1. Stated on the summary rather than inferred from the
            # empty writeback and approval lists, because "shadow mode" and
            # "nothing needed doing" produce the same empty lists and lead an
            # operator to opposite conclusions.
            "shadow": shadow,
            "run_id": str(state.run_id),
            "incident_id": str(state.incident_id),
            "tenant_id": str(state.tenant_id),
            "verdict": verdict,
            "confidence": confidence,
            "tier": tier,
            "cost": _cost_payload(cost, tokens),
            "findings": list(state.findings),
            "confidence_basis": list(state.confidence_basis),
            "business_context_rules": bc_matched,
            # Copilot default: triage is read-only, response requires approval.
            "response_dispatched": False,
            "approvals_raised": approvals,
            # None when nothing was attempted. When present, `executed` is the
            # only field that means a vendor was actually written to — a dry
            # run reports the same shape with `executed: False`.
            "source_writeback": source_writeback,
            "proposed_actions": [{"action_type": a.action_type, "requires_approval": a.requires_approval} for a in state.proposed_actions],
        }

    async def _sink_for(self, state: InvestigationState, fingerprint: str) -> TriageWriter:
        """The sink this alert's writes go to: the tenant's live one, or a shadow wrapper.

        Resolved per alert because shadow mode is per tenant *and* per alert
        class, and the class is not known until the alert is in hand. The
        wrapper delegates to whatever sink the worker was constructed with, so
        a replay passing its own sink keeps it and a production worker wraps
        the live one.

        A policy read that fails is treated as shadow by
        :class:`~app.workers.shadow_mode.LiveShadowModePolicy`, which is the
        conservative direction: the cost of being wrong is a few seconds of
        suppressed writeback, against acting on an alert a tenant asked us
        only to observe.
        """
        raw = state.raw_alert or {}
        alert_class = alert_class_of(raw)
        if not await self._shadow_policy.is_shadow(str(state.tenant_id), alert_class):
            return self._writer

        _METRICS["shadow_triaged"] += 1
        return ShadowModeTriageWriter(
            self._writer,
            ShadowDecision(
                tenant_ref=str(state.tenant_id),
                alert_class=alert_class,
                alert_id=raw.get("id"),
                external_id=_opt_text(raw.get("external_id")),
                rule_id=_opt_text(raw.get("rule_id")),
                source=_opt_text(raw.get("connector_type") or raw.get("source")),
                model=_opt_text(getattr(state, "model_used", None)),
                evidence_signature=fingerprint,
            ),
        )

    async def _write_back_to_source(
        self,
        state: InvestigationState,
        verdict: Any,
        confidence: float,
        *,
        rationale: str,
        writer: TriageWriter,
    ) -> dict[str, Any] | None:
        """Ask the API to project this verdict onto the source finding.

        The worker decides nothing about *what* may be written — that policy
        lives in the actions service, so it cannot drift between two copies.
        All that happens here is the call, and the metrics that let an
        operator see whether the loop is closing.
        """
        alert_id = str((state.raw_alert or {}).get("id") or "")
        if not alert_id or not verdict:
            return None
        try:
            report = await writer.write_back_disposition(
                tenant_id=str(state.tenant_id),
                alert_id=alert_id,
                disposition=str(verdict),
                confidence=float(confidence or 0.0),
                rationale=rationale,
            )
        except Exception as exc:  # noqa: BLE001 — a durable verdict outranks its writeback
            logger.warning("auto_triage_worker.source_writeback_failed", alert_id=alert_id, error=str(exc)[:300])
            return None
        if report is None:
            return None
        _METRICS["writeback_attempted"] += 1
        if report.get("executed"):
            _METRICS["writeback_executed"] += 1
        return report

    async def _raise_approvals(self, state: InvestigationState, *, writer: TriageWriter) -> list[str]:
        """Queue each approval-requiring proposed action; return the ids.

        Only actions the agent itself marked ``requires_approval`` are
        queued. The ones it did not are still not executed — the worker is
        copilot-default and dispatches nothing — so this does not widen what
        the agent can do. It makes the subset that was always meant to reach a
        human reach one.
        """
        if not _approvals_enabled():
            return []
        raised: list[str] = []
        for action in state.proposed_actions:
            if not action.requires_approval:
                continue
            risk = action.risk_level.value if hasattr(action.risk_level, "value") else str(action.risk_level)
            approval_id = await writer.raise_approval(
                tenant_ref=str(state.tenant_id),
                run_id=state.run_id,
                alert_id=(state.raw_alert or {}).get("id"),
                title=action.description[:200] or f"Approve {action.action_type}",
                summary=(action.rationale or action.description or "").strip()
                or f"The agent proposes {action.action_type} against {action.target}.",
                risk_level=risk,
                action={
                    "action_type": action.action_type,
                    "target": action.target,
                    "parameters": dict(action.parameters or {}),
                    "risk_level": risk,
                },
            )
            if approval_id is not None:
                raised.append(str(approval_id))
                _METRICS["approvals_raised"] += 1
        return raised

    async def _attach_tenant_skill(self, state: InvestigationState) -> None:
        """Resolve the tenant skill matching this alert and record it on the state.

        Best-effort in exactly one direction: a lookup that fails leaves the
        state without a skill and triage proceeds as it did before. The
        opposite failure, a skill that matched and was not recorded, is the one
        that matters, because the verdict would then carry guidance with no
        provenance. So the selection and the record happen together.
        """
        try:
            rows = await self._reader.fetch_skills(str(state.tenant_id))
        except Exception as exc:  # noqa: BLE001 - guidance is advisory, triage is not
            logger.warning("auto_triage_worker.skill_lookup_failed", error=str(exc)[:200])
            return
        if not rows:
            return

        raw = state.raw_alert or {}
        skill = select_skill(
            rows,
            summary=state.alert_summary or "",
            techniques=list(state.mitre_mappings or []),
            rule_id=str(raw.get("rule_id") or "") or None,
            source=str(raw.get("connector_type") or raw.get("source") or "") or None,
        )
        if skill is None:
            return

        state.tenant_skill = skill.as_provenance()
        guidance = skill.triage_guidance()
        if guidance:
            state.tenant_skill["triage_guidance"] = guidance
        _METRICS["tenant_skill_applied"] += 1

    async def _attach_runbooks(self, state: InvestigationState) -> None:
        """Retrieve the tenant's runbooks for this alert and record them on the state.

        Best-effort in one direction only, the same shape
        :meth:`_attach_tenant_skill` uses: a retrieval that fails leaves the
        state without runbooks and triage proceeds as it did before. The
        failure that matters is the other one, a chunk that reached the prompt
        with nothing recording which document it came from, so the retrieval
        and the citation record happen together.
        """
        query = knowledge_base.query_for(state.alert_summary or "", state.raw_alert)
        if not query:
            return
        try:
            retrieval = await self._reader.retrieve_runbooks(str(state.tenant_id), query=query)
        except Exception as exc:  # noqa: BLE001 - guidance is advisory, triage is not
            logger.warning("auto_triage_worker.runbook_lookup_failed", error=str(exc)[:200])
            return
        if not retrieval.runbooks and not retrieval.dropped_for_injection:
            return

        state.knowledge_base = retrieval.as_state()
        if retrieval.runbooks:
            _METRICS["runbooks_retrieved"] += len(retrieval.runbooks)
        if retrieval.dropped_for_injection:
            _METRICS["runbooks_refused_for_injection"] += retrieval.dropped_for_injection
            # Recorded on the state so it reaches the outcome prior. Without
            # this the flag threaded into `record_outcome` would read a field
            # nobody sets and the whole injection rule would be dead code
            # that looks like a control.
            state.injection_suspected = True

    async def _attach_recent_dispositions(self, state: InvestigationState) -> None:
        """Record what this tenant's analysts decided the last few times.

        Best-effort in one direction, like the two above: a lookup that fails
        leaves the state without decisions and triage proceeds as it did.
        """
        raw = state.raw_alert or {}
        rule_id = str(raw.get("rule_id") or "").strip()
        entities = dispositions_module.entities_for(raw)
        if not rule_id and not entities:
            return
        try:
            found = await self._reader.recent_dispositions(str(state.tenant_id), rule_id=rule_id, entities=entities)
        except Exception as exc:  # noqa: BLE001 - past decisions are advisory, triage is not
            logger.warning("auto_triage_worker.disposition_lookup_failed", error=str(exc)[:200])
            return
        if not found.decisions:
            return
        state.recent_dispositions = found.as_state()
        _METRICS["recent_dispositions_read"] += len(found.decisions)

    async def _attach_identity_context(self, state: InvestigationState) -> None:
        """Record who is behind the accounts this alert names, if anyone knows.

        A tenant with no directory connector gets nothing here and nothing in
        the prompt, which is the correct outcome: an empty block is silence,
        and a block saying the principal is unidentified is a claim.
        """
        accounts = identity_module.accounts_for(state.raw_alert)
        if not accounts:
            return
        try:
            found = await self._reader.fetch_identity_context(str(state.tenant_id), accounts=accounts)
        except Exception as exc:  # noqa: BLE001 - directory context is advisory, triage is not
            logger.warning("auto_triage_worker.identity_lookup_failed", error=str(exc)[:200])
            return
        if not found.identities:
            return
        state.identity_context = found.as_state()
        _METRICS["identity_context_read"] += len(found.identities)

    async def _maybe_suppress_from_memory(
        self,
        state: InvestigationState,
        signature: str,
        bc_matched: list[str],
        *,
        writer: TriageWriter,
    ) -> dict[str, Any] | None:
        """Auto-resolve a repeat alert from a trusted prior outcome (Wave 1).

        Returns a summary dict (and short-circuits triage) when suppressed, else
        None. Best-effort: any lookup failure falls through to normal triage.

        Under a shadow sink this still runs and still reaches a verdict, and
        still resolves nothing: suppression is what production would have done
        with this alert, so it is exactly the decision worth measuring. The
        sink declines the outcome and suppression writes, and the shadow flag
        keeps the alert row open, so the analyst closes it themselves and the
        agreement is real.
        """
        try:
            prior = await self._reader.lookup_prior(str(state.tenant_id), signature)
        except Exception as exc:  # noqa: BLE001 — memory read is advisory
            logger.debug("auto_triage_worker.memory_lookup_failed", error=str(exc))
            return None
        refusal = suppression_refusal(prior)
        if refusal is not None:
            # Logged with the reason. "Suppression declined" alone makes a
            # control that has silently stopped working look identical to one
            # that is working, and these rules decline far more often now
            # than the old corroboration threshold did.
            logger.debug(
                "auto_triage_worker.suppression_declined",
                signature=signature,
                reason=refusal,
            )
            return None

        assert prior is not None  # narrowed by suppression_refusal
        disposition = normalize_disposition(prior.get("disposition"), default=NEEDS_REVIEW)
        confidence = float(prior.get("confidence", 0.9))
        count = int(prior.get("count", 1))
        author = str(prior.get("author", AI))

        state.verdict = disposition
        state.confidence = confidence
        state.status = AgentStatus.COMPLETED
        state.confidence_basis = [f"outcome_memory: prior {disposition} seen {count}x (author={author})"]
        state.add_finding(
            f"Auto-resolved from prior outcome memory: matches a prior {disposition} disposition "
            f"(seen {count}x, author={author}) — repeat suppressed without re-triage."
        )

        _METRICS["outcome_suppressed"] += 1
        _METRICS["triaged"] += 1
        await self._record(state, tier="memory", verdict=disposition, confidence=confidence, writer=writer)
        with contextlib.suppress(Exception):
            await writer.record_outcome(
                str(state.tenant_id),
                signature,
                disposition=disposition,
                confidence=confidence,
                author=author,
                alert_id=(state.raw_alert or {}).get("id"),
            )
        with contextlib.suppress(Exception):
            await writer.record_suppression(
                tenant_ref=str(state.tenant_id),
                signature=signature,
                alert_id=(state.raw_alert or {}).get("id"),
                disposition=disposition,
                prior_author=author,
            )
        logger.info(
            "auto_triage_worker.memory_suppressed",
            run_id=str(state.run_id),
            disposition=disposition,
            prior_count=count,
            author=author,
        )
        return {
            "run_id": str(state.run_id),
            "incident_id": str(state.incident_id),
            "tenant_id": str(state.tenant_id),
            "verdict": disposition,
            "confidence": confidence,
            "tier": "memory",
            # No model call was placed, so every figure here is a zero that was
            # counted rather than a measurement that is missing.
            "cost": _cost_payload(CostSummary(), 0),
            "findings": list(state.findings),
            "confidence_basis": list(state.confidence_basis),
            "suppressed_by_memory": True,
            "business_context_rules": bc_matched,
            "response_dispatched": False,
            "proposed_actions": [],
        }

    async def _maybe_escalate(self, state: InvestigationState, *, writer: TriageWriter) -> None:
        """Run the full investigation graph for an escalated alert (issue #569).

        Shares the same graph runner as the manual investigations API. Every
        node is recorded to the ledger under the deterministic run_id, so a
        restart re-runs idempotently. Best-effort + budgeted — a failure or
        timeout leaves the durable verdict intact and the alert escalated.
        """
        # Two independent switches. The env flag is the operator's; the
        # writer's is the caller's, and a shadow run declines because every
        # graph node records itself to the ledger.
        if not _escalation_enabled() or not writer.escalation_allowed:
            return
        # Pre-fetch the same context an analyst-initiated investigation gets.
        # The manual orchestrator has built a ContextBundle since T2.1; the
        # escalation path never did, so the high-volume automatic route
        # investigated with strictly less context — no graph neighbourhood, no
        # blast radius, no historical verdicts for the same entities — than a
        # human clicking "investigate" on the identical alert.
        state.context_bundle = await prefetch_context_bundle_dict(
            case_id=str(state.incident_id),
            tenant_id=str(state.tenant_id),
            alert_summary=state.alert_summary or "",
            raw_alert=state.raw_alert or {},
        )
        try:
            async with CostTracker(
                run_id=str(state.run_id),
                tenant_id=str(state.tenant_id),
                persist=writer.persists_cost,
            ):
                await run_escalation(state, budget=default_budget(), seq_start=1)
            _METRICS["escalated"] += 1
        except Exception as exc:  # noqa: BLE001 — escalation is best-effort over a durable verdict
            logger.warning("auto_triage_worker.escalation_failed", run_id=str(state.run_id), error=str(exc))

    async def _resolve_tenant_llm(self, tenant_id: uuid.UUID) -> Any:
        """Resolve the tenant's LLM config, or None to force deterministic triage."""
        try:
            cfg = await resolve_llm_config(str(tenant_id))
        except Exception as exc:  # noqa: BLE001 — resolver failure => deterministic
            logger.debug("auto_triage_worker.llm_resolve_failed", error=str(exc))
            return None
        # The resolver's env baseline now resolves the bearer that pairs with
        # the route it chose, so a deployment doing exactly what the compose
        # file sets up — gateway URL and master key, provider key held by the
        # gateway — reports a usable key here instead of "none configured".
        return cfg if (cfg.allowed and cfg.api_key) else None

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

    def _apply_groundedness_gate(
        self,
        state: InvestigationState,
        verdict: Any,
        confidence: float,
    ) -> tuple[Any, float]:
        """Refuse to auto-close on reasoning the evidence does not support.

        `score_groundedness` measures what fraction of the concrete indicators
        an output asserts — IPs, hashes, CVEs, MITRE techniques, domains —
        actually appear in the evidence the agent was given. It shipped as an
        eval axis and had no caller in the service, so a confident verdict
        citing an IP that appeared nowhere in the alert was persisted, acted on
        and auto-closed with nothing recording that it was invented.

        Only auto-closing verdicts are gated. Demoting an escalation because
        its prose mentioned an extra indicator would add review load without
        reducing risk, and a verdict that already routes to a human is not
        making an unsupervised decision.
        """
        if not _groundedness_gate_enabled() or not verdict:
            return verdict, confidence
        if normalize_disposition(str(verdict), default=NEEDS_REVIEW) not in AUTO_CLOSEABLE_DISPOSITIONS:
            return verdict, confidence

        reasoning = " ".join(str(part) for part in [*(state.findings or []), *(state.confidence_basis or [])])
        if not reasoning.strip():
            return verdict, confidence

        try:
            evidence = json.dumps(state.raw_alert or {}, default=str)
            result = score_groundedness(reasoning, f"{evidence}\n{state.alert_summary or ''}")
        except Exception as exc:  # noqa: BLE001 — a scoring failure must not change the verdict
            logger.debug("auto_triage_worker.groundedness_failed", error=str(exc))
            return verdict, confidence

        state.groundedness = result.score
        if result.score >= _groundedness_floor():
            return verdict, confidence

        _METRICS["ungrounded_demoted"] += 1
        logger.warning(
            "auto_triage_worker.ungrounded_verdict_demoted",
            run_id=str(state.run_id),
            original_verdict=str(verdict),
            groundedness=result.score,
            hallucinated=result.hallucinated[:10],
        )
        state.add_finding(
            f"Verdict demoted to needs_review: only {result.score:.0%} of the indicators cited in "
            f"the reasoning appear in the evidence (unsupported: {', '.join(result.hallucinated[:5])})."
        )
        if state.status is AgentStatus.COMPLETED:
            state.status = AgentStatus.RUNNING
        state.verdict = NEEDS_REVIEW
        # Confidence describes the demoted verdict now, not the discarded one.
        return NEEDS_REVIEW, min(float(confidence or 0.0), result.score)

    async def _record(
        self,
        state: InvestigationState,
        *,
        tier: str,
        verdict: Any,
        confidence: float,
        tokens: int = 0,
        cost: CostSummary | None = None,
        writer: TriageWriter,
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
        await writer.persist_auto_triage(
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
            cost_usd=(cost or CostSummary()).measured_usd,
            measured_call_count=(cost or CostSummary()).measured_calls,
            estimated_cost_usd=(cost or CostSummary()).estimated_usd,
            estimated_call_count=(cost or CostSummary()).estimated_calls,
            unpriced_call_count=(cost or CostSummary()).unpriced_calls,
            # Persisted so an ungrounded auto-closure is auditable after the
            # fact and aggregatable on /metrics/funnel, rather than surviving
            # only inside a findings string.
            groundedness=state.groundedness,
            ungrounded=(state.groundedness is not None and state.groundedness < _groundedness_floor()),
        )

    @staticmethod
    def get_metrics() -> dict[str, int]:
        return dict(_METRICS)


def worker_enabled() -> bool:
    """Off unless a Kafka broker is configured and it's not explicitly disabled."""
    if os.getenv("AISOC_AGENT_KAFKA_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return bool(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip())
