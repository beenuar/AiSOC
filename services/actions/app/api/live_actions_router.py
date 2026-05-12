"""
REST API for the generic live-action interface (Stage 2 #8).

Three endpoints:

  ``GET  /api/v1/live-actions``
      Discovery. Returns every registered ``(vendor_id, capability)``
      pair plus its descriptor so the agent loop, the playbook editor,
      and the frontend can build action menus without hard-coding the
      vendor list.

  ``POST /api/v1/live-actions/dispatch``
      Synchronous dispatch. Looks up the executor for
      ``(vendor_id, capability)`` and runs it. ``dry_run=true`` strips
      credentials and the executor falls through to its simulation
      branch — see ``app.live_actions.builtins`` for the contract.

  ``POST /api/v1/live-actions/dry-run``
      Convenience wrapper that forces ``dry_run=true`` so frontends
      can render a "preview what this would do" button without having
      to know about the dry_run field. Internally identical to
      ``/dispatch``.

The router never raises HTTPException for executor-level failures —
those return ``LiveActionResult`` with ``status=failed`` so callers
have a uniform contract. ``HTTPException`` is reserved for genuinely
malformed requests (which Pydantic catches first anyway).
"""

from __future__ import annotations

from typing import Literal

import structlog
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.live_actions import (
    LiveActionDescriptor,
    LiveActionRequest,
    LiveActionResult,
    dispatch,
    list_capabilities_for_vendor,
    list_descriptors,
    list_vendors_for_capability,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/live-actions", tags=["live-actions"])


class LiveActionDiscoveryResponse(BaseModel):
    """Shape returned by ``GET /live-actions``.

    ``executors`` is the canonical list. ``vendors`` and ``capabilities``
    are derived sort-uniqued projections — they're cheap to compute and
    save the frontend from re-deriving them on every render.
    """

    executors: list[LiveActionDescriptor]
    vendors: list[str] = Field(
        ...,
        description="All vendor IDs that have at least one registered executor.",
    )
    capabilities: list[str] = Field(
        ...,
        description="All capability verbs that have at least one registered executor.",
    )


@router.get(
    "",
    response_model=LiveActionDiscoveryResponse,
    summary="List every registered live action",
)
async def discover_live_actions(
    vendor_id: str | None = None,
    capability: str | None = None,
) -> LiveActionDiscoveryResponse:
    """Return all registered live actions, optionally filtered.

    Filtering is server-side so the agent planner can ask "what can
    isolate a host?" with one round-trip instead of pulling the full
    list and filtering in the prompt. Both filters are exact-match —
    capability and vendor_id are short strings drawn from a known
    vocabulary, so substring search would just hide typos.
    """
    descriptors = list_descriptors()
    if vendor_id:
        descriptors = [d for d in descriptors if d.vendor_id == vendor_id]
    if capability:
        descriptors = [d for d in descriptors if d.capability == capability]

    vendors = sorted({d.vendor_id for d in descriptors})
    capabilities = sorted({d.capability for d in descriptors})

    return LiveActionDiscoveryResponse(
        executors=descriptors,
        vendors=vendors,
        capabilities=capabilities,
    )


@router.get(
    "/by-capability/{capability}",
    response_model=list[str],
    summary="List vendors that implement a given capability",
)
async def vendors_for_capability(capability: str) -> list[str]:
    """Return the vendor IDs that can perform ``capability``.

    Smaller payload than the full discovery response — used by the
    agent planner to answer "which vendors can isolate a host right now?".
    Returns ``[]`` (empty list, not 404) when no vendor implements the
    capability so callers don't have to special-case "missing" vs
    "everything's missing".
    """
    return list_vendors_for_capability(capability)


@router.get(
    "/by-vendor/{vendor_id}",
    response_model=list[str],
    summary="List capabilities supported by a given vendor",
)
async def capabilities_for_vendor(vendor_id: str) -> list[str]:
    """Return the capability verbs implemented by ``vendor_id``."""
    return list_capabilities_for_vendor(vendor_id)


class LiveActionDispatchResponse(BaseModel):
    """Wrapper around :class:`LiveActionResult` for REST callers.

    We wrap rather than returning the result directly so the response
    has a stable top-level shape — useful for adding cross-cutting
    fields (``trace_id``, ``cost_usd``, ...) later without breaking
    existing clients.
    """

    result: LiveActionResult
    mode: Literal["live", "dry_run"]


@router.post(
    "/dispatch",
    response_model=LiveActionDispatchResponse,
    summary="Dispatch a live action to its registered executor",
)
async def dispatch_live_action(request: LiveActionRequest) -> LiveActionDispatchResponse:
    """Run a live action synchronously.

    The executor is responsible for honouring ``request.dry_run``.
    Builtin adapters (see ``app.live_actions.builtins``) enforce dry-run
    by stripping credential keys before delegating to the legacy
    executor, which then falls through to its simulation branch.

    Errors:
      Network glitches, vendor outages, or buggy executors all surface
      as ``LiveActionResult`` with ``status=failed`` and a populated
      ``error`` field. This endpoint never returns 5xx for executor
      failures — the agent loop relies on a uniform success-shape so
      it can decide whether to retry, fall back to a different vendor,
      or escalate to a human.
    """
    result = await dispatch(request)
    return LiveActionDispatchResponse(
        result=result,
        mode="dry_run" if request.dry_run else "live",
    )


@router.post(
    "/dry-run",
    response_model=LiveActionDispatchResponse,
    summary="Dispatch a live action in dry-run mode (forces dry_run=true)",
)
async def dry_run_live_action(request: LiveActionRequest) -> LiveActionDispatchResponse:
    """Identical to ``/dispatch`` but forces ``dry_run=true``.

    Exists so the frontend can wire a "Preview" button to a single
    URL instead of having to mutate the request body. Also forms a
    cleaner audit trail: every call to ``/dry-run`` is *guaranteed*
    not to hit a real vendor, regardless of what the client sent.
    """
    safe_request = request.model_copy(update={"dry_run": True})
    result = await dispatch(safe_request)
    return LiveActionDispatchResponse(result=result, mode="dry_run")
