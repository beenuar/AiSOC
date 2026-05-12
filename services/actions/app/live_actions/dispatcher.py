"""
Dispatch live-action requests to registered executors.

The dispatcher is the single entry point used by the REST router and by
internal callers (agent loop, playbook engine). It enforces three
invariants that individual executors should not have to think about:

  1. **Unknown (vendor, capability) returns FAILED, not 500.** Callers
     get a structured :class:`LiveActionResult` so the agent loop can
     decide whether to fall back to a different vendor.
  2. **Executor exceptions are caught and converted to FAILED.** A
     buggy plugin must never crash the actions service.
  3. **Structured logs include request_id, vendor, capability, dry_run
     and outcome.** This is what feeds the audit trail and the cost
     dashboard.
"""

from __future__ import annotations

import structlog

from . import registry
from .models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)


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

    log.info(
        "live_action.completed",
        status=result.status.value,
        has_error=bool(result.error),
    )
    return result
