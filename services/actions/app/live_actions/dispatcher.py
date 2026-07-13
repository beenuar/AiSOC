"""
Dispatch live-action requests to registered executors.

The dispatcher is the single entry point used by the REST router and by
internal callers (agent loop, playbook engine). It enforces these invariants
so individual executors never have to think about them:

  1. **Unknown (vendor, capability) returns FAILED, not 500.** Callers
     get a structured :class:`LiveActionResult` so the agent loop can
     decide whether to fall back to a different vendor.
  2. **Executor exceptions are caught and converted to FAILED.** A
     buggy plugin must never crash the actions service.
  3. **Structured logs include request_id, vendor, capability, dry_run
     and outcome.** This is what feeds the audit trail and the cost
     dashboard.
  4. **Phase B2 — the autonomy-safety policy governs every real execution.**
     Any request whose capability maps to an :class:`ActionType` runs through
     ``autonomy_safety.decide()`` before the executor is invoked (this closes
     the Phase 9b wiring gap). Copilot is the default: below-tier actions are
     downgraded to a dry-run preview, HIGH/CRITICAL blast queues for a human,
     and tier L0 blocks outright. The gate never *upgrades* a request — an
     explicit ``dry_run=True`` stays a dry-run whatever the tier says.
  5. **Phase B2 — connector-style credentials are translated at the boundary.**
     A request carrying ``auth_config`` (connector schema field names) has it
     resolved into the executor's vendor-prefixed params via
     ``credential_resolver.resolve_params`` — so configured connector
     credentials actually reach the executor instead of falling back to
     simulation mode.
"""

from __future__ import annotations

import os
from uuid import uuid4

import structlog

from app.models.action import ActionRequest, ActionType
from app.services.autonomy_safety import AutonomyDecision, AutonomyMode, decide
from app.services.credential_resolver import resolve_params
from app.services.maturity import MaturityTier

from . import registry
from .models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)

_TIER_ENV = "AISOC_MATURITY_TIER"


def configured_tier() -> MaturityTier:
    """Deployment-wide autonomy tier. Conservative default: L1 (notify).

    Accepts ``L2`` / ``L2_CONTAIN`` / ``2``. Per-tenant tier scoping arrives
    with the autonomy-scoping UI (Phase C3); until then one conservative
    deployment default keeps copilot the out-of-the-box posture.
    """
    raw = os.environ.get(_TIER_ENV, "").strip().upper()
    if not raw:
        return MaturityTier.L1_NOTIFY
    for tier in MaturityTier:
        if raw in {tier.name, tier.name.split("_")[0], str(tier.value)}:
            return tier
    logger.warning("live_action.bad_tier_env", value=raw)
    return MaturityTier.L1_NOTIFY


def _action_type_for(request: LiveActionRequest, executor: object) -> ActionType | None:
    """Map a live capability onto the legacy ActionType vocabulary."""
    legacy = getattr(executor, "_legacy_action_type", None)
    if isinstance(legacy, ActionType):
        return legacy
    try:
        return ActionType(request.capability)
    except ValueError:
        return None


def _govern(request: LiveActionRequest, action_type: ActionType) -> AutonomyDecision:
    action_request = ActionRequest(
        incident_id=request.case_id or uuid4(),
        tenant_id=request.tenant_id or uuid4(),
        action_type=action_type,
        target=request.target,
        parameters=request.params,
        requested_by=request.requested_by,
    )
    return decide(action_request, tier=configured_tier())


def _not_executed(request: LiveActionRequest, status: LiveActionStatus, decision: AutonomyDecision) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=request.capability,
        vendor_id=request.vendor_id,
        summary=f"{request.capability} on {request.target or 'target'}: {status.value} by autonomy policy — {decision.reason}",
        details={
            "autonomy_mode": decision.mode.value,
            "blast_radius": decision.blast_radius.value,
            "tier": decision.tier.name,
            "rollback": decision.rollback.value,
            "reason": decision.reason,
        },
    )


async def dispatch(request: LiveActionRequest) -> LiveActionResult:
    """Run ``request`` through the registered executor and return a result.

    This function never raises for expected failure modes (unknown
    vendor, executor returning an error, executor raising). It always
    returns a :class:`LiveActionResult` so REST handlers and the agent
    loop have a single, predictable contract.
    """
    log = logger.bind(
        request_id=str(request.request_id),
        vendor_id=request.vendor_id,
        capability=request.capability,
        dry_run=request.dry_run,
    )

    # Phase B2 — translate connector-style credentials into executor params.
    if request.auth_config:
        resolved = resolve_params(request.vendor_id, request.auth_config, extra=request.params)
        request = request.model_copy(update={"params": resolved, "auth_config": None})

    executor = registry.get_executor(request.vendor_id, request.capability)
    if executor is None:
        log.warning("live_action.unknown")
        available = registry.list_vendors_for_capability(request.capability)
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.FAILED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"No executor registered for {request.vendor_id}/{request.capability}",
            error="executor_not_found",
            details={"available_vendors_for_capability": available},
        )

    # Phase B2 — autonomy-safety gate (Phase 9a decide(), wired = Phase 9b).
    # An explicit dry_run request is already the safest mode — no downgrade
    # possible — so governance applies to would-be real executions only.
    decision: AutonomyDecision | None = None
    action_type = _action_type_for(request, executor)
    if action_type is not None and not request.dry_run:
        decision = _govern(request, action_type)
        log = log.bind(autonomy_mode=decision.mode.value, blast=decision.blast_radius.value)
        if decision.mode is AutonomyMode.BLOCKED:
            log.warning("live_action.blocked_by_policy", reason=decision.reason)
            return _not_executed(request, LiveActionStatus.BLOCKED, decision)
        if decision.mode is AutonomyMode.QUEUED_APPROVAL:
            log.info("live_action.queued_for_approval", reason=decision.reason)
            return _not_executed(request, LiveActionStatus.PENDING_APPROVAL, decision)
        if decision.mode is AutonomyMode.DRY_RUN:
            log.info("live_action.downgraded_to_dry_run", reason=decision.reason)
            request = request.model_copy(update={"dry_run": True})

    log = log.bind(executor=type(executor).__name__)
    log.info("live_action.dispatch")

    try:
        result = await executor.execute(request)
    except Exception as exc:  # noqa: BLE001 — last line of defence
        log.exception("live_action.executor_crashed")
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.FAILED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"Executor {type(executor).__name__} raised an exception",
            error=f"{type(exc).__name__}: {exc}",
        )

    # Defence in depth: an executor MAY return a result that doesn't
    # echo the request's vendor/capability/request_id correctly. Patch
    # them so downstream consumers (audit log, UI) can always trust
    # these fields.
    if result.request_id != request.request_id:
        log.warning("live_action.request_id_mismatch", returned=str(result.request_id))
        result = result.model_copy(update={"request_id": request.request_id})
    if result.vendor_id != request.vendor_id:
        result = result.model_copy(update={"vendor_id": request.vendor_id})
    if result.capability != request.capability:
        result = result.model_copy(update={"capability": request.capability})

    # Surface the governance verdict on the result for the audit trail.
    if decision is not None:
        details = dict(result.details)
        details.setdefault("autonomy_mode", decision.mode.value)
        details.setdefault("blast_radius", decision.blast_radius.value)
        details.setdefault("autonomy_reason", decision.reason)
        result = result.model_copy(update={"details": details})

    log.info(
        "live_action.completed",
        status=result.status.value,
        has_error=bool(result.error),
    )
    return result
