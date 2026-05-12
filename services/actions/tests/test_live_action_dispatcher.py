"""
Behavioural tests for :func:`app.live_actions.dispatch`.

The dispatcher is the single place where REST handlers, the agent loop,
and internal callers funnel through. Three properties matter most:

  1. **Unknown ``(vendor, capability)`` returns a structured FAILED
     result, never an exception.** The agent loop relies on this to
     branch into "try a different vendor" without try/except.
  2. **Executor exceptions are caught and translated.** A buggy plugin
     must not crash the actions service.
  3. **The dispatcher *patches* result fields that drift from the
     request.** A misbehaving executor that returns the wrong
     ``request_id`` would otherwise corrupt the audit trail.

Tests use small, hand-rolled stub executors instead of the legacy
adapters so failures point at the dispatcher itself rather than at
some unrelated coupling. We use ``asyncio.run`` to stay consistent
with the rest of the actions test suite (no pytest-asyncio decorator).
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from app.live_actions import (
    LiveActionExecutor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
    dispatch,
    register_executor,
    reset_for_tests,
)

# --- Test doubles ---------------------------------------------------------


class _OkExecutor(LiveActionExecutor):
    """Returns SUCCEEDED with a deterministic summary."""

    vendor_id = "stubvendor"
    capability = "isolate_host"
    description = "succeeds"
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"isolated {request.target}",
            details={"echo_target": request.target, "dry_run": request.dry_run},
        )


class _SimulatingExecutor(LiveActionExecutor):
    """Returns SIMULATED when ``dry_run`` is set, else SUCCEEDED.

    Mirrors the contract that real adapters honour: ``dry_run`` MUST
    short-circuit to a simulation path so the dispatcher can be safely
    exposed via the ``/dry-run`` endpoint.
    """

    vendor_id = "simvendor"
    capability = "block_ip"
    description = "simulates when asked"
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        status = LiveActionStatus.SIMULATED if request.dry_run else LiveActionStatus.SUCCEEDED
        return LiveActionResult(
            request_id=request.request_id,
            status=status,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=("simulated" if request.dry_run else "blocked") + f" {request.target}",
        )


class _CrashingExecutor(LiveActionExecutor):
    """Raises an unexpected exception to exercise the dispatcher's safety net."""

    vendor_id = "crashvendor"
    capability = "kill_process"
    description = "always crashes"
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        raise RuntimeError("boom -- vendor SDK threw")


class _LyingExecutor(LiveActionExecutor):
    """Returns a result with mismatched request_id / vendor / capability.

    Real executors should never do this, but a buggy plugin could. The
    dispatcher patches the fields back so audit logs stay consistent.
    """

    vendor_id = "lyingvendor"
    capability = "disable_user"
    description = "returns wrong identifiers"
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=uuid4(),  # NOT request.request_id
            status=LiveActionStatus.SUCCEEDED,
            capability="something_else",
            vendor_id="wrong_vendor",
            summary="ok",
        )


# --- Fixture --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Wipe registry before *and* after every test so cross-test state
    can't leak -- important because the registry is a module-level dict.
    """
    reset_for_tests()
    yield
    reset_for_tests()


# --- Tests ----------------------------------------------------------------


def test_dispatch_routes_to_registered_executor():
    register_executor(_OkExecutor())
    request = LiveActionRequest(capability="isolate_host", vendor_id="stubvendor", target="srv-12")

    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.SUCCEEDED
    assert result.summary == "isolated srv-12"
    assert result.details["echo_target"] == "srv-12"
    assert result.request_id == request.request_id


def test_dispatch_unknown_pair_returns_failed_not_exception():
    """The agent loop relies on a uniform shape for "no executor"."""
    register_executor(_OkExecutor())  # different vendor

    result = asyncio.run(dispatch(LiveActionRequest(capability="isolate_host", vendor_id="missing_vendor")))

    assert result.status == LiveActionStatus.FAILED
    assert result.error == "executor_not_found"
    # Hint payload should help the planner pick an alternative vendor.
    assert "stubvendor" in result.details["available_vendors_for_capability"]


def test_dispatch_unknown_pair_lists_no_alternatives_when_none_exist():
    result = asyncio.run(dispatch(LiveActionRequest(capability="never_registered_verb", vendor_id="ghost")))

    assert result.status == LiveActionStatus.FAILED
    assert result.details["available_vendors_for_capability"] == []


def test_dispatch_dry_run_propagates_to_executor():
    register_executor(_SimulatingExecutor())

    result = asyncio.run(
        dispatch(
            LiveActionRequest(
                capability="block_ip",
                vendor_id="simvendor",
                target="1.2.3.4",
                dry_run=True,
            )
        )
    )

    assert result.status == LiveActionStatus.SIMULATED
    assert "simulated" in result.summary


def test_dispatch_crashing_executor_is_caught():
    """A buggy plugin must not crash the actions service."""
    register_executor(_CrashingExecutor())

    result = asyncio.run(dispatch(LiveActionRequest(capability="kill_process", vendor_id="crashvendor")))

    assert result.status == LiveActionStatus.FAILED
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "boom" in result.error


def test_dispatch_patches_mismatched_request_id():
    """Defence in depth: if an executor returns the wrong request_id we
    patch it so the audit trail remains correlatable."""
    register_executor(_LyingExecutor())
    request = LiveActionRequest(capability="disable_user", vendor_id="lyingvendor")

    result = asyncio.run(dispatch(request))

    assert result.request_id == request.request_id
    assert result.vendor_id == request.vendor_id
    assert result.capability == request.capability
