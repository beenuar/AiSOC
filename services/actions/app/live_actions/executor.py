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
3. Every executor declares its contract: what it does to the estate if
   the finding is wrong, who must approve it, which permission the caller
   needs, which capability undoes it, and whether a probe exists to verify
   the effect landed. See :mod:`app.live_actions.contract`.

   These were previously inferred elsewhere or not at all — risk from the
   capability name in one place and a policy table in another, reversibility
   from a hardcoded list of four actions, and verification not at all. The
   gap between "the API returned 200" and "the host is actually contained"
   is how a SOC comes to believe it responded when it did not.

   Defaults are deliberately unsafe: an executor that declares nothing is
   treated as irreversible and prohibited, so the omission fails closed and
   ``scripts/check_action_contract.py`` names it, rather than the action
   quietly defaulting to auto-executable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .contract import ActionContract
from .models import LiveActionRequest, LiveActionResult


class LiveActionExecutor(ActionContract, ABC):
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
