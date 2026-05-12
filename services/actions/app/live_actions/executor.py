"""
Abstract base class for live-action executors.

A :class:`LiveActionExecutor` is a single ``(vendor_id, capability)``
implementation. Compared to the in-tree :class:`app.executors.base.BaseExecutor`,
it has three deliberate differences:

1. The executor declares its ``vendor_id`` and ``capability`` as class
   attributes so the registry can index it without a second registration
   call. This keeps plugin code one-step:
   ``register_executor(MyExecutor())`` instead of having to repeat the
   key.
2. ``execute()`` accepts a :class:`LiveActionRequest` and returns a
   :class:`LiveActionResult` — both new types decoupled from
   ``ActionType``. Plugin authors don't have to add a member to an enum
   they don't own.
3. Rollback is intentionally omitted from this layer. The classic
   approval/rollback workflow lives in ``services/actions/app/api/router.py``
   and operates on the legacy ``ActionRequest``/``ActionResult`` pair.
   The live-action surface is a pure execution primitive; if a future
   workstream needs reversible live actions we'll add an optional
   ``rollback()`` hook then, rather than forcing every plugin author to
   stub it out today.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import LiveActionRequest, LiveActionResult


class LiveActionExecutor(ABC):
    """Single-vendor, single-capability action executor."""

    #: Connector / vendor ID this executor talks to (e.g. ``"crowdstrike"``).
    vendor_id: str = ""

    #: Capability verb this executor implements. Must be a valid value of
    #: :class:`app.connectors_capabilities.Capability` (mirrored from
    #: ``services/connectors``) — the registry validates this on
    #: registration so typos are caught at import time, not at dispatch.
    capability: str = ""

    #: Whether this executor needs vendor credentials to run for real. The
    #: registry surfaces this in the discovery payload so the frontend can
    #: render a "credentials missing — will simulate" badge.
    requires_credentials: bool = True

    #: One-line human-readable description shown in the discovery API.
    description: str = ""

    @abstractmethod
    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        """Run the action. Implementations must honour ``request.dry_run``.

        Implementations MUST NOT raise on expected vendor errors — return
        a :class:`LiveActionResult` with ``status=FAILED`` and a populated
        ``error`` field instead. The dispatcher only catches unexpected
        exceptions (programmer errors, network blow-ups) and converts them
        to a generic FAILED result so the agent loop never crashes on a
        single bad action.
        """
