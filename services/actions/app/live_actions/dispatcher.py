"""
Dispatch live-action requests to registered executors.

The dispatcher is the single entry point used by the REST router and by
internal callers (agent loop, playbook engine). It enforces these invariants
so individual executors never have to think about them:

  0. **The kill switch is checked before anything else.** Global or per
     tenant, engaged or unreadable, every request returns BLOCKED without
     an executor being looked up. Parity 2.2 documented this and never
     built it: the switch stopped automatic closure and this dispatcher
     carried on isolating hosts.
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

import asyncio
import os
import socket
from dataclasses import replace
from typing import Any
from uuid import uuid4

import structlog

from app.models.action import ActionRequest, ActionType
from app.security.ssrf_guard import SSRFError, validate_outbound_url
from app.services.approval_matrix import evaluate_contract
from app.services.asset_lookup import asset_criticality_for_target
from app.services.autonomy_safety import (
    _BLAST_ORDER,
    ACTION_BLAST_RADIUS,
    AutonomyDecision,
    AutonomyMode,
    BlastRadius,
    RollbackCapability,
    decide,
    rollback_capability,
)
from app.services.credential_resolver import ProtectedParameterOverride, resolve_params
from app.services.kill_switch import KillSwitchState, kill_switch_state
from app.services.maturity import _AUTO_ALLOWED_AT_TIER, MaturityTier
from app.services.response_schedule_store import resolve_response_schedule
from app.services.tenant_policy import TenantPolicy, resolve_tenant_policy
from app.services.verification import PostActionVerifier, VerificationOutcome

from . import registry
from .approval_rules import EARNED_TIER_CEILING_LABEL, TIER_ORDER, ResponseSchedule, tier_from_env_value
from .capability_contracts import CAPABILITY_CONTRACTS
from .contract import ActionImpact, ApprovalRequirement, Reversal
from .models import LiveActionRequest, LiveActionResult, LiveActionStatus

#: The highest tier an earned grant may lift a tenant to. L3 permits MINIMAL,
#: LOW and MEDIUM blast radius and stops there, so no track record on triage
#: agreement can make a HIGH-blast containment unattended. `force_auto`, which
#: is a human writing down a decision about one verb rather than an inference
#: from agreement, still goes to L4.
#:
#: Read from `approval_rules` rather than written here, because the console
#: has to apply the same ceiling when it tells an operator which verbs run
#: unattended, and it reaches that module through the vendored copy.
EARNED_TIER_CEILING = MaturityTier(TIER_ORDER.index(EARNED_TIER_CEILING_LABEL))

logger = structlog.get_logger(__name__)

_TIER_ENV = "AISOC_MATURITY_TIER"


def configured_tier() -> MaturityTier:
    """Deployment-wide autonomy tier. Conservative default: L1 (notify).

    Accepts ``L2`` / ``L2_CONTAIN`` / ``2``. Per-tenant tier scoping arrives
    with the autonomy-scoping UI (Phase C3); until then one conservative
    deployment default keeps copilot the out-of-the-box posture.

    The parsing itself lives in ``approval_rules`` because the console has to
    name the tier in force on its autonomy page, and a second reader of the
    same variable answering differently is how that page came to announce a
    posture the dispatcher does not implement.
    """
    raw = os.environ.get(_TIER_ENV, "")
    tier, recognised = tier_from_env_value(raw)
    if not recognised:
        logger.warning("live_action.bad_tier_env", value=raw.strip().upper())
    return MaturityTier(TIER_ORDER.index(tier))


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
    # What is this action about to touch? Resolved once per dispatch from the
    # tenant's own inventory; None (no CMDB, no match, outage) grades exactly
    # as before. Tighten-only by construction in evaluate_contract.
    target_criticality = await asset_criticality_for_target(request.tenant_id, request.target)
    # Wave-2 Phase 6.3. The tenant's declared time gates: a change freeze, an
    # out-of-hours condition, a nobody-on-call condition. Raise-only by
    # construction (see `apply_schedule`), and `None` for the overwhelming
    # majority of tenants, who have declared no schedule. Resolved here
    # because this is the door that has a database — the same reasoning as
    # `asset_criticality` directly above.
    schedule = await resolve_response_schedule(request.tenant_id)

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
        # The override lifts the *tier ceiling* — that is what it is for — so
        # the contract is graded as though the tenant were at L4. It does not
        # lift the contract's own floors: a verb declared `analyst` or
        # `mandatory_human`, or one whose impact is never autonomous, stays
        # gated. `ActionContract.approval` says the tenant's autonomy policy
        # "can raise this but never lower it", and before the contract was
        # consulted on this path an override could lower it silently.
        return _apply_capability_contract(
            request,
            _override_decision(
                action_type,
                policy,
                AutonomyMode.AUTO,
                f"action type '{action_type.value}' is force-auto by tenant policy",
            ),
            tier_label="L4",
            asset_criticality=target_criticality,
            schedule=schedule,
        )

    # Gap-closure Phase 2.3. A tenant that has run this verb's alert classes in
    # shadow and agreed with its own analysts often enough, over a large enough
    # sample with enough of it malicious, holds an earned grant. The grant
    # raises the *tier ceiling* exactly as `force_auto` does, and for the same
    # reason: it is the ceiling that is being argued about, not the contract.
    #
    # It stops at L3, where `force_auto` goes to L4. `force_auto` is a human
    # writing down a decision about one verb; a grant is an inference from
    # agreement on triage verdicts. That is evidence about the agent's
    # judgement, and it is not evidence that a HIGH-blast containment was the
    # right call. L3 permits MINIMAL, LOW and MEDIUM blast and stops there, so
    # no track record can make `isolate_host` unattended.
    #
    # `_apply_capability_contract` still runs on top, so a verb declared
    # `analyst` or `mandatory_human` stays gated however good the numbers are:
    # the contract's floors may be raised and never lowered.
    earned = policy.earned_autonomy_for(action_type.value)
    effective_tier = policy.tier
    if earned and policy.tier < EARNED_TIER_CEILING:
        effective_tier = EARNED_TIER_CEILING

    decision = decide(
        action_request,
        tier=effective_tier,
        whitelisted=policy.is_whitelisted(action_type.value, request.target),
    )
    if effective_tier is not policy.tier:
        # Say which grant did it, and whether it was earned or overruled into
        # existence. An incident review quotes this sentence, and "autonomous
        # on a measured track record" and "autonomous because somebody
        # overruled the gate" are the same action and different findings.
        earned_phrase = "an operator override of the promotion gate" if earned == "operator_override" else "a measured track record"
        decision = replace(
            decision,
            reason=(
                f"{decision.reason}; tier ceiling raised from {policy.tier.name} to "
                f"{effective_tier.name} for '{action_type.value}' under {earned_phrase}"
            ),
        )

    return _apply_capability_contract(
        request,
        decision,
        tier_label=_tier_label(effective_tier),
        asset_criticality=target_criticality,
        schedule=schedule,
    )


def _tier_label(tier: object) -> str:
    """Map a ``MaturityTier`` onto the ``L0``..``L4`` labels the matrix uses."""
    name = getattr(tier, "name", None)
    if isinstance(name, str) and name.startswith("L"):
        return name.split("_")[0]
    return "L1"


#: Blast radius implied by a capability's declared impact, for the verbs that
#: have a contract and no ``ActionType``. ``ACTION_BLAST_RADIUS`` is keyed on
#: ``ActionType``, so those verbs resolved to nothing and skipped governance
#: altogether — ``revoke_session`` is MODERATE-impact identity disruption and
#: was executing with no tier check, no blast check and no contract applied.
#: The mapping is the conservative reading of the same two ladders.
_IMPACT_BLAST: dict[ActionImpact, BlastRadius] = {
    ActionImpact.READ_ONLY: BlastRadius.MINIMAL,
    ActionImpact.LOW: BlastRadius.LOW,
    ActionImpact.MODERATE: BlastRadius.MEDIUM,
    ActionImpact.HIGH: BlastRadius.HIGH,
    ActionImpact.SEVERE: BlastRadius.CRITICAL,
    ActionImpact.IRREVERSIBLE: BlastRadius.CRITICAL,
}


async def _govern_by_contract_alone(request: LiveActionRequest) -> AutonomyDecision:
    """Baseline verdict for a capability with a contract and no ``ActionType``.

    Built from the tenant's tier and the contract's own impact so that
    :func:`_apply_capability_contract` has something to raise. Without this a
    contracted verb outside the legacy enum reached its executor with no
    governance at all, which is the worst of both vocabularies: declared
    dangerous and dispatched unchecked.
    """
    contract = CAPABILITY_CONTRACTS[request.capability]
    blast = _IMPACT_BLAST[contract.impact]
    policy = await resolve_tenant_policy(request.tenant_id)
    allowed = _AUTO_ALLOWED_AT_TIER.get(policy.tier, set())
    mode = AutonomyMode.AUTO if blast in allowed else AutonomyMode.QUEUED_APPROVAL
    baseline = AutonomyDecision(
        mode=mode,
        blast_radius=blast,
        tier=policy.tier,
        rollback=(RollbackCapability.REVERSIBLE if contract.reversal is Reversal.PLATFORM else RollbackCapability.UNSUPPORTED),
        requires_verification=(mode is AutonomyMode.AUTO and _BLAST_ORDER[blast] >= _BLAST_ORDER[BlastRadius.MEDIUM]),
        reason=(
            f"capability '{request.capability}' has no legacy ActionType; graded from its "
            f"contract ({contract.impact.value} impact) under tier {policy.tier.name}"
        ),
    )
    return _apply_capability_contract(
        request,
        baseline,
        tier_label=_tier_label(policy.tier),
        asset_criticality=await asset_criticality_for_target(request.tenant_id, request.target),
        schedule=await resolve_response_schedule(request.tenant_id),
    )


def _apply_capability_contract(
    request: LiveActionRequest,
    decision: AutonomyDecision,
    *,
    tier_label: str,
    asset_criticality: str | None = None,
    schedule: ResponseSchedule | None = None,
) -> AutonomyDecision:
    """Raise the autonomy verdict to whatever the capability contract demands.

    ``decide()`` answers one question — is this verb's *blast radius* inside
    the tenant's tier. The capability contract answers the other two, and this
    dispatcher never asked them: what the verb does to an estate when the
    finding is wrong (``impact``), and whether the reason is good enough
    (``confidence``). ``approval_matrix.evaluate`` combines them and has been
    wired into ``POST /actions`` since the approval gate was fixed; the
    registry-driven path next to it still decided on blast radius alone, so
    the same verb was graded differently depending on which door it came
    through.

    Composition rule is the matrix's own: each input may raise a requirement
    and none may lower it. This function therefore never turns a QUEUED or
    BLOCKED verdict into an AUTO one — it can only move in the safe direction,
    which is why switching it on cannot make anything execute that did not
    before.

    A capability with no contract is left to blast radius and recorded at
    debug, not guessed at. ``scripts/check_action_contract.py`` fails the
    build when a registered executor has none, so this is a real absence
    rather than a silent default.
    """
    contract = CAPABILITY_CONTRACTS.get(request.capability)
    if contract is None:
        logger.debug(
            "live_action.no_capability_contract",
            capability=request.capability,
            note="blast radius decides alone; impact is unknown for this verb",
        )
        return decision

    # The whole grading, in one shared call. This used to short-circuit
    # READ_ONLY + AUTOMATIC before reaching the matrix, because the matrix's
    # tier ceiling was `None` at L1 and put a pure read in the analyst queue.
    # The legacy door had no such bypass, so `search_siem` executed here and
    # queued there. The ceiling is fixed at its source now, so the bypass is
    # gone and both doors read the same answer out of the same function.
    verdict = evaluate_contract(
        contract=contract,
        confidence=request.confidence,
        tier=tier_label,
        asset_criticality=asset_criticality,
        schedule=schedule,
    )

    if verdict.is_blocked:
        return replace(
            decision,
            mode=AutonomyMode.BLOCKED,
            reason=verdict.reason,
            requires_verification=False,
        )

    if verdict.requirement == ApprovalRequirement.AUTOMATIC:
        # The matrix is content. Whatever blast radius decided stands.
        return decision

    if decision.mode is AutonomyMode.AUTO:
        # The only direction this function moves: an action the tier would
        # have auto-executed, held because impact and confidence say so.
        # Verification goes with it — nothing ran, so there is no effect to
        # read back.
        return replace(
            decision,
            mode=AutonomyMode.QUEUED_APPROVAL,
            reason=verdict.reason,
            requires_verification=False,
        )

    if decision.mode is AutonomyMode.QUEUED_APPROVAL:
        # Already gated. Keep the matrix's reason, which names impact and
        # confidence — more use to an approver than "blast radius exceeded".
        return replace(decision, reason=verdict.reason)

    return decision


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


def _stopped_by_kill_switch(request: LiveActionRequest, state: KillSwitchState) -> LiveActionResult:
    """A visible refusal that names the switch, and is not a failure.

    Three things this is deliberately not. Not SUCCEEDED, obviously. Not
    FAILED, because FAILED invites a retry and the next attempt is refused
    for the same reason — an agent loop would spend a freeze retrying. And
    not silent: ``blocked_by`` is a machine-readable field so a console or a
    playbook report can say *which* control stopped this, rather than
    leaving an operator to guess between the switch and the tier ladder.

    ``executed`` is the platform's single word for "a vendor was touched",
    and nothing here touched one: the executor is not looked up, let alone
    called, before this returns.
    """
    detail = (
        "kill-switch state unreadable, refusing to dispatch" if state.unreadable else f"kill switch engaged ({state.scope}): {state.reason}"
    )
    return LiveActionResult(
        request_id=request.request_id,
        status=LiveActionStatus.BLOCKED,
        capability=request.capability,
        vendor_id=request.vendor_id,
        summary=f"{request.capability} on {request.target or 'target'}: not dispatched — {detail}",
        details={
            "blocked_by": "kill_switch_unreadable" if state.unreadable else "kill_switch",
            "kill_switch_scope": state.scope,
            "kill_switch_reason": state.reason,
            "vendor_contacted": False,
        },
    )


def _ungovernable_reason(request: LiveActionRequest, action_type: ActionType | None) -> str | None:
    """Why this request cannot be graded, or ``None`` if it can.

    Checked before any executor runs and only for would-be real executions --
    an explicit dry run is already the safest mode and changes nothing, so
    refusing one would stop an operator previewing a verb they are about to
    be told they may not run.
    """
    if request.tenant_id is None:
        return (
            "the request names no tenant, so neither the tenant's autonomy tier nor its kill "
            "switch can be resolved; set tenant_id on the dispatch"
        )
    if action_type is None and request.capability not in CAPABILITY_CONTRACTS:
        return (
            f"capability '{request.capability}' has neither a legacy ActionType nor an entry in "
            "CAPABILITY_CONTRACTS, so its impact, reversibility and approval requirement are "
            "undeclared; add a contract in capability_contracts.py"
        )
    return None


def _refusal(reason: str) -> AutonomyDecision:
    """A blocked verdict for a request governance could not grade.

    CRITICAL blast radius and the lowest tier deliberately: the fields are
    read by callers deciding how loudly to report, and an ungraded request is
    not a low-risk one -- it is one whose risk nobody measured.
    """
    return AutonomyDecision(
        mode=AutonomyMode.BLOCKED,
        blast_radius=BlastRadius.CRITICAL,
        tier=MaturityTier.L0_OBSERVE,
        rollback=RollbackCapability.UNSUPPORTED,
        requires_verification=False,
        reason=reason,
    )


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


def _first_blocked_destination(params: dict[str, Any]) -> tuple[str, str] | None:
    """``(param_name, reason)`` for the first caller-named address we refuse.

    Matches on the *value's* shape, not the key's name: a connection URL
    arrives as ``base_url``, ``cs_base_url``, ``snow_instance_url``,
    ``webhook_url`` and half a dozen other spellings, and a key-name list
    would have to be kept level with every one of them. The same reasoning,
    and the same carve-out, as ``_refuse_internal_destinations`` in the API.

    A hostname that simply fails to resolve is **allowed through**. The vendor
    client's own connection error says more than a guard's would, and refusing
    on a failed lookup would put every dispatch behind a working DNS server —
    turning a transient resolver fault into a refusal to contain a host.

    Blocking ``getaddrinfo`` is why the caller runs this in a thread.
    """
    for key, value in (params or {}).items():
        candidates = value if isinstance(value, list) else [value]
        for item in candidates:
            if not isinstance(item, str) or not item.startswith(("http://", "https://")):
                continue
            try:
                validate_outbound_url(item)
            except SSRFError as exc:
                if isinstance(exc.__cause__, socket.gaierror):
                    continue
                return key, str(exc)
    return None


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

    # ── The kill switch, before anything else ────────────────────────────
    #
    # First, and separately from the autonomy policy, because it is what
    # somebody reaches for at 3am and it must not depend on tier rows,
    # contracts or a registered executor being correct. Every other refusal
    # in this function is a judgement about one action; this one is an
    # operator saying stop.
    #
    # Dry runs are stopped too, which is a decision rather than an
    # oversight. A preview is only credentials-free if the strip list in
    # `builtins` matches what each client factory reads, and
    # `executors/siem.py` records what happened when it did not: "a 'dry
    # run' calls the customer's production SIEM. That is exactly what
    # happened." During a declared freeze that is not a risk worth carrying
    # for the convenience of a preview, and an operator who pressed the stop
    # button did not mean "stop, except for previews".
    switch = await kill_switch_state(str(request.tenant_id) if request.tenant_id else None)
    if switch.engaged:
        log.warning(
            "live_action.blocked_by_kill_switch",
            scope=switch.scope,
            unreadable=switch.unreadable,
            reason=switch.reason,
        )
        return _stopped_by_kill_switch(request, switch)

    # ── Where the caller may point this service ──────────────────────────
    #
    # Two separate controls, because the reported defect had two halves
    # (GHSA-78jg-x2ch-638f) and closing either alone leaves the other open.
    #
    # First: a destination the caller named at all. The vendors with no entry
    # in VENDOR_CREDENTIAL_MAP — osctrl, fleetdm, aisoc_direct — take their
    # whole connection from `params`, so the protected-key rule below has
    # nothing to compare against and the caller is the only source. That is a
    # request this container makes to an address a user chose, with the reply
    # reflected into the dispatch report, which is the shape the connectors
    # service already adopted the platform guard for (GHSA-cq4g-g6wp-4m2w).
    #
    # Matched on the value's shape rather than the key's name, like the API's
    # `_refuse_internal_destinations`, because `base_url` is one of a dozen
    # spellings. A host that merely fails to resolve passes: the vendor
    # client's own connection error is the better diagnostic, and refusing
    # here would make every dispatch depend on DNS.
    refused_destination = await asyncio.to_thread(_first_blocked_destination, request.params)
    if refused_destination is not None:
        key, reason = refused_destination
        log.warning("live_action.blocked_destination", param=key, reason=reason)
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.FAILED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"'{request.capability}' was refused before any request left this service.",
            error=f"{key}: destination refused: {reason}",
        )

    # Second: Phase B2 translation of connector-style credentials into
    # executor params. `request.params` may choose *what* an action does and
    # never *where* it goes or *whose* credential it spends, so a key naming a
    # stored connection or credential field is refused here rather than
    # overriding one. Refused, not dropped: dropping would send the call to
    # the vendor's default endpoint and report success.
    if request.auth_config:
        try:
            resolved = resolve_params(request.vendor_id, request.auth_config, extra=request.params)
        except ProtectedParameterOverride as exc:
            log.warning("live_action.protected_param_override", detail=str(exc))
            return LiveActionResult(
                request_id=request.request_id,
                status=LiveActionStatus.FAILED,
                capability=request.capability,
                vendor_id=request.vendor_id,
                summary=f"'{request.capability}' was refused before any credential was used.",
                error=str(exc),
            )
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
    if not request.dry_run:
        # Two ways a real execution used to escape governance entirely, and
        # both are the same shape: the gate was opt-in, and whatever fell
        # outside the vocabulary it knew ran unchecked (GHSA-fm3f-p5jv-6hcg).
        #
        # F07 -- no tenant. `resolve_tenant_policy(None)` returns the
        # deployment's `AISOC_MATURITY_TIER`, and `kill_switch_state(None)`
        # matches only the global row, so a tenantless request is graded by an
        # environment variable and no tenant's stop button can reach it.
        # `_govern` even papered over it with `tenant_id=request.tenant_id or
        # uuid4()`, inventing a tenant to build the ActionRequest with.
        #
        # F81 -- no contract and no ActionType. 22 of the 95 known
        # capabilities are in that gap. None of the 167 registered executors
        # is, today, so this was latent rather than exploitable -- but the
        # gate was opt-in by vocabulary and a test
        # (`test_unmapped_capability_is_not_governed`) pinned the fail-open as
        # intended behaviour, which is how it would have stayed true for the
        # first write capability added without a contract.
        #
        # Both now refuse. "Unverifiable means not autonomous" is this
        # service's own stated rule for verification probes; a verdict nobody
        # can compute is not a verdict that permits.
        ungovernable = _ungovernable_reason(request, action_type)
        if ungovernable is not None:
            log.warning("live_action.refused_ungovernable", reason=ungovernable)
            return _not_executed(request, LiveActionStatus.BLOCKED, _refusal(ungovernable))

        decision = await (_govern(request, action_type) if action_type is not None else _govern_by_contract_alone(request))
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
    if decision is not None and decision.requires_verification and not request.dry_run and result.status is LiveActionStatus.SUCCEEDED:
        if action_type is not None:
            result = await _verify_effect(request, result, action_type, log)
        else:
            # Probes are keyed on ActionType, so a contracted verb outside the
            # legacy enum has none. Say so rather than leaving the field blank:
            # an absent `verification` key and a verified one are indis-
            # tinguishable to a reader, and the honest answer here is that
            # nothing checked.
            details = dict(result.details)
            details["verification"] = "unverified"
            details["verification_reason"] = f"no probe is registered for '{request.capability}'; it has no ActionType to key one on"
            result = result.model_copy(update={"details": details})

    log.info(
        "live_action.completed",
        status=result.status.value,
        has_error=bool(result.error),
    )
    return result
