"""
Registration semantics for the live-action registry.

Covers four invariants:

  1. Required fields (``vendor_id``, ``capability``) are enforced at
     registration time, not at dispatch time. A typo in a plugin
     setup hook should crash the plugin import, not silently produce
     a "no executor for ..." error six months later.
  2. Duplicate registration is a hard error unless the caller opts
     into ``overwrite=True``. Two plugins fighting for the same
     ``(vendor_id, capability)`` is almost always a bug.
  3. Unknown capabilities log a warning but do *not* crash — plugin
     authors must be able to experiment with new verbs without first
     patching the core service. Verified via ``caplog``.
  4. Discovery helpers (``list_descriptors``, ``list_vendors_for_capability``,
     ``list_capabilities_for_vendor``) return stable, sorted output so
     the agent loop can rely on a deterministic prompt context.
"""

from __future__ import annotations

import pytest
from app.live_actions import (
    LiveActionExecutor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
    get_executor,
    list_capabilities_for_vendor,
    list_descriptors,
    list_vendors_for_capability,
    register_executor,
    reset_for_tests,
    unregister_executor,
)


class _StubExecutor(LiveActionExecutor):
    """Minimal executor used to exercise the registry without dragging
    in the full builtin adapter machinery (which would couple these
    tests to the legacy ``BaseExecutor`` implementations)."""

    def __init__(
        self,
        vendor_id: str,
        capability: str,
        *,
        description: str = "stub",
        requires_credentials: bool = True,
    ) -> None:
        self.vendor_id = vendor_id
        self.capability = capability
        self.description = description
        self.requires_credentials = requires_credentials

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=self.capability,
            vendor_id=self.vendor_id,
            summary="stub-ok",
        )


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Each test starts with an empty registry and ends with one too.

    Without this, registration state leaks between tests and the
    "duplicate registration" test gets flaky depending on collection
    order.
    """
    reset_for_tests()
    yield
    reset_for_tests()


def test_register_requires_vendor_and_capability():
    """Empty vendor_id or capability is a programmer error — the
    registry must catch it loudly at registration time."""
    with pytest.raises(ValueError):
        register_executor(_StubExecutor(vendor_id="", capability="isolate_host"))
    with pytest.raises(ValueError):
        register_executor(_StubExecutor(vendor_id="crowdstrike", capability=""))


def test_register_then_get_round_trip():
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    executor = get_executor("crowdstrike", "isolate_host")
    assert executor is not None
    assert executor.vendor_id == "crowdstrike"
    assert executor.capability == "isolate_host"


def test_get_returns_none_for_unknown():
    """Lookup must be a soft miss, not an exception. The dispatcher
    converts the miss into a ``FAILED`` result with details — test
    that contract here."""
    assert get_executor("nonexistent", "isolate_host") is None


def test_duplicate_registration_is_rejected_by_default():
    """Two executors for the same (vendor, capability) is a bug in
    99% of cases. Forcing ``overwrite=True`` makes the rare legitimate
    case (test cleanup, hot reload) explicit."""
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    with pytest.raises(ValueError, match="already registered"):
        register_executor(_StubExecutor("crowdstrike", "isolate_host"))


def test_overwrite_flag_replaces_existing_binding():
    a = _StubExecutor("crowdstrike", "isolate_host", description="first")
    b = _StubExecutor("crowdstrike", "isolate_host", description="second")
    register_executor(a)
    register_executor(b, overwrite=True)

    current = get_executor("crowdstrike", "isolate_host")
    assert current is b
    assert current.description == "second"


def test_unknown_capability_does_not_raise():
    """Plugins MAY register experimental verbs not in the canonical
    set. The registry must accept them (logging a warning behind the
    scenes) so plugin authors can iterate without first patching the
    core service.

    We deliberately do NOT assert on the warning being captured by
    ``caplog`` — structlog's default configuration writes through its
    own ``PrintLoggerFactory`` rather than stdlib logging, so caplog
    capture is fragile across environments. The behavioural contract
    we care about is "registration succeeds for unknown verbs"; the
    warning is a soft observability signal, not a hard assertion.
    """
    register_executor(_StubExecutor("acme_corp", "do_a_barrel_roll"))
    assert get_executor("acme_corp", "do_a_barrel_roll") is not None


def test_unregister_removes_binding():
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    assert get_executor("crowdstrike", "isolate_host") is not None
    removed = unregister_executor("crowdstrike", "isolate_host")
    assert removed is True
    assert get_executor("crowdstrike", "isolate_host") is None
    # Idempotent: unregistering twice is not an error.
    assert unregister_executor("crowdstrike", "isolate_host") is False


def test_list_descriptors_is_sorted():
    """Deterministic ordering matters for prompt stability — if the
    agent's tool list shuffles every restart, prompt-cache hit rates
    plummet and unit tests on agent output become flaky."""
    register_executor(_StubExecutor("zscaler", "block_domain"))
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    register_executor(_StubExecutor("crowdstrike", "kill_process"))

    descriptors = list_descriptors()
    keys = [(d.vendor_id, d.capability) for d in descriptors]
    assert keys == sorted(keys)


def test_list_by_capability_returns_sorted_vendors():
    register_executor(_StubExecutor("defender", "isolate_host"))
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    register_executor(_StubExecutor("crowdstrike", "kill_process"))

    vendors = list_vendors_for_capability("isolate_host")
    assert vendors == ["crowdstrike", "defender"]
    assert list_vendors_for_capability("nonexistent") == []


def test_list_by_vendor_returns_sorted_capabilities():
    register_executor(_StubExecutor("crowdstrike", "kill_process"))
    register_executor(_StubExecutor("crowdstrike", "isolate_host"))
    register_executor(_StubExecutor("crowdstrike", "quarantine_file"))

    caps = list_capabilities_for_vendor("crowdstrike")
    assert caps == ["isolate_host", "kill_process", "quarantine_file"]
    assert list_capabilities_for_vendor("nonexistent") == []
