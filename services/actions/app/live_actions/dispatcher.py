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
from typing import Any
from uuid import uuid4

import structlog

from app.models.action import ActionRequest, ActionType
from app.services.autonomy_safety import (
    ACTION_BLAST_RADIUS,
    AutonomyDecision,
    AutonomyMode,
    BlastRadius,
    decide,
    rollback_capability,
)
from app.services.credential_resolver import resolve_params
from app.services.maturity import MaturityTier
from app.services.tenant_policy import TenantPolicy, resolve_tenant_policy
from app.services.verification import PostActionVerifier, VerificationOutcome

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


async def _govern(request: LiveActionRequest, action_type: ActionType) -> AutonomyDecision:
    """Resolve the autonomy verdict from the *tenant's* policy.

    This used to be `decide(action_request, tier=configured_tier())`: one
    deployment-wide environment variable for every tenant, with the
    `whitelisted` flag left at its default of False so the L4 break-glass path
    for HIGH-blast-radius actions was unreachable. A tenant who selected L2 in
    the console got whatever the operator had exported.

    Now the tier, the per-action overrides and the whitelist all come from the
    tenant's stored policy, falling back to the environment only when there is
    no database to read.
    """
    action_request = ActionRequest(
        incident_id=request.case_id or uuid4(),
        tenant_id=request.tenant_id or uuid4(),
        action_type=action_type,
        target=request.target,
        parameters=request.params,
        requested_by=request.requested_by,
    )
    policy = await resolve_tenant_policy(request.tenant_id)

    # A tenant override is a deliberate, explicit instruction for one action
    # type, so it outranks the tier ladder in both directions.
    override = policy.action_overrides.get(action_type.value, {}) or {}
    if override.get("block"):
        return _override_decision(
            action_type,
            policy,
            AutonomyMode.BLOCKED,
            f"action type '{action_type.value}' is blocked by tenant policy",
        )
    if override.get("force_auto"):
        return _override_decision(
            action_type,
            policy,
            AutonomyMode.AUTO,
            f"action type '{action_type.value}' is force-auto by tenant policy",
        )

    return decide(
        action_request,
        tier=policy.tier,
        whitelisted=policy.is_whitelisted(action_type.value, request.target),
    )


def _override_decision(
    action_type: ActionType,
    policy: TenantPolicy,
    mode: AutonomyMode,
    reason: str,
) -> AutonomyDecision:
    """Build a decision for an explicit per-action tenant override."""
    blast = ACTION_BLAST_RADIUS.get(action_type, BlastRadius.HIGH)
    return AutonomyDecision(
        mode=mode,
        blast_radius=blast,
        tier=policy.tier,
        rollback=rollback_capability(action_type),
        # A force-auto override still earns verification at MEDIUM blast and
        # above: choosing to skip the approval queue is not the same as
        # choosing to skip the proof that the action took effect.
        requires_verification=(mode is AutonomyMode.AUTO and blast is not BlastRadius.MINIMAL),
        reason=f"{reason} (source: {policy.source})",
    )


async def _verify_effect(
    request: LiveActionRequest,
    result: LiveActionResult,
    action_type: ActionType,
    log: Any,
) -> LiveActionResult:
    """Re-query the vendor and record whether the action actually took effect.

    Three outcomes, all recorded honestly on ``result.details``:

    * ``verified``   — a confirming query ran and the effect is present.
    * ``failed``     — a confirming query ran and the effect is absent. The
      action reported success and did not take, which is a genuine alarm, so
      the result status is downgraded to FAILED rather than left COMPLETED.
    * ``unverified`` — no probe exists for this action/vendor, or credentials
      were absent. Reported as-is; never upgraded to a confirmation.

    A verifier crash can never fail the action itself — the action already
    happened, and losing the record of it would be worse than not verifying.
    """
    verifier = PostActionVerifier()
    try:
        # `request.params` already carries the resolved vendor credentials by
        # this point: auth_config was translated and cleared before dispatch.
        outcome = await verifier.verify(action_type, request.target or "", dict(request.params))
    except Exception as exc:  # noqa: BLE001 — verification must not mask a completed action
        log.warning("live_action.verification_crashed", error=str(exc))
        details = dict(result.details)
        details["verification"] = "unverified"
        details["verification_reason"] = f"verifier raised {type(exc).__name__}"
        return result.model_copy(update={"details": details})

    details = dict(result.details)
    details["verification"] = outcome.outcome.value
    details["verification_reason"] = outcome.reason
    log.info(
        "live_action.verified",
        verification=outcome.outcome.value,
        reason=outcome.reason,
    )

    if outcome.outcome is VerificationOutcome.FAILED:
        # The vendor accepted the call and the effect is not there. Saying
        # SUCCEEDED here is how a SOC ends up believing a host is contained
        # when it is not.
        return result.model_copy(
            update={
                "status": LiveActionStatus.FAILED,
                "details": details,
                "error": result.error or f"action reported success but verification failed: {outcome.reason}",
                "summary": f"{result.summary} — VERIFICATION FAILED: {outcome.reason}",
            }
        )

    return result.model_copy(update={"details": details})


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
        decision = await _govern(request, action_type)
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

    # ── Post-action verification ──────────────────────────────────────────
    #
    # The policy layer has always computed `requires_verification` for any
    # auto-executed action at MEDIUM blast or above, and this dispatcher then
    # discarded it: the field was never read, and PostActionVerifier had no
    # caller anywhere outside its own test. So the product could show that a
    # containment call was accepted, and never that containment took effect —
    # which is the single capability the market treats as the dividing line
    # between recommending and responding.
    #
    # Verification runs only for a real execution that actually succeeded. A
    # dry run and a SIMULATED result have nothing to verify, and a failed
    # execution is already an honest negative.
    if (
        decision is not None
        and decision.requires_verification
        and not request.dry_run
        and result.status is LiveActionStatus.SUCCEEDED
        and action_type is not None
    ):
        result = await _verify_effect(request, result, action_type, log)

    log.info(
        "live_action.completed",
        status=result.status.value,
        has_error=bool(result.error),
    )
    return result
