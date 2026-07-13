"""
Tests for the builtin adapter layer (Stage 2 #8).

These tests verify two things that matter for plugin authors and for
the agent loop:

1. **Builtin registration is complete and stable.** ``register_builtin_executors``
   produces the canonical set of (vendor_id, capability) pairs that the
   agent can plan against today. Drift here means the planner gets stale.

2. **The legacy adapter shim correctly translates calls.** The legacy
   executors fall back to a "Simulation mode" branch when credentials
   are absent. The adapter layer must surface that as
   ``LiveActionStatus.SIMULATED`` (not SUCCEEDED) so the UI can show
   the correct badge and the audit log marks the action as not having
   touched the real vendor.

We intentionally exercise the live adapters end-to-end — no mocks for
the legacy ``BaseExecutor``. The legacy executors are deterministic in
simulation mode (they don't make network calls), so this is fast and
catches contract drift between the two layers.
"""

from __future__ import annotations

import asyncio

import pytest
from app.live_actions import (
    LiveActionRequest,
    LiveActionStatus,
    dispatch,
    list_descriptors,
    register_builtin_executors,
    reset_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    reset_for_tests()
    yield
    reset_for_tests()


def test_register_builtin_executors_returns_full_count() -> None:
    """The registered count is the contract surface for the startup log.

    If a maintainer adds or removes an adapter from ``_BUILTIN_ADAPTERS``,
    this assertion forces them to update the expectation here too — a
    cheap reminder to update docs / discovery snapshots.
    """
    count = register_builtin_executors()
    # 19 original + 10 Phase B2 vendors (SentinelOne/Entra/GWS/PAN-OS/FortiGate/
    # Cloudflare/Jira/ServiceNow/PagerDuty/Slack).
    assert count == 29


def test_builtin_executors_cover_canonical_vendor_capability_pairs() -> None:
    """The canonical pairs the agent plans against today.

    This is the discovery surface the UI shows on first load and what
    the planner narrows from. Encoding it explicitly prevents silent
    regressions (e.g. accidentally dropping ``okta/disable_user``).
    """
    register_builtin_executors()
    descriptors = list_descriptors()
    pairs = {(d.vendor_id, d.capability) for d in descriptors}

    expected = {
        # Endpoint
        ("crowdstrike", "isolate_host"),
        ("defender", "isolate_host"),
        ("crowdstrike", "quarantine_file"),
        ("crowdstrike", "kill_process"),
        ("crowdstrike", "run_script"),
        ("defender", "run_av_scan"),
        # Identity
        ("okta", "disable_user"),
        ("okta", "reset_password"),
        ("okta", "suspend_session"),
        ("okta", "force_mfa"),
        # Network
        ("aws_security_groups", "block_ip"),
        ("aws_security_groups", "allow_ip"),
        ("generic", "block_domain"),
        # SIEM
        ("splunk", "search_siem"),
        ("elastic", "search_siem"),
        ("splunk", "create_notable_event"),
        ("splunk", "sync_detection_rule"),
        ("elastic", "update_watcher"),
        ("defender", "block_ioc"),
        # Phase B2 — previously-unregistered vendors
        ("sentinelone", "isolate_host"),
        ("azure_entra", "disable_user"),
        ("google_workspace", "disable_user"),
        ("panos", "block_ip"),
        ("fortigate", "block_ip"),
        ("cloudflare", "block_ip"),
        ("jira", "create_ticket"),
        ("servicenow", "create_ticket"),
        ("pagerduty", "create_ticket"),
        ("slack", "notify"),
    }
    assert pairs == expected


def test_builtin_descriptors_marked_as_builtin_source() -> None:
    """Source metadata distinguishes adapters from plugin-registered executors."""
    register_builtin_executors()
    descriptors = list_descriptors()
    sources = {d.source for d in descriptors}
    assert sources == {"builtin"}


def test_builtin_descriptor_has_human_description() -> None:
    """Descriptions feed the agent's tool catalogue and the UI tooltips."""
    register_builtin_executors()
    descriptors = list_descriptors()
    for descriptor in descriptors:
        assert descriptor.description, f"Adapter {descriptor.vendor_id}/{descriptor.capability} has no description"


def test_register_builtin_executors_is_idempotent_with_overwrite() -> None:
    """Calling twice with ``overwrite=True`` should not raise.

    Tests that share the registry (autouse fixture) rely on this being
    safe so they can call ``register_builtin_executors(overwrite=True)``
    in setup without first asserting clean state.
    """
    register_builtin_executors()
    # Second call without overwrite would raise — confirm overwrite works.
    count = register_builtin_executors(overwrite=True)
    assert count == 29


def test_register_builtin_twice_without_overwrite_raises() -> None:
    """Without overwrite, double-registration is a hard error.

    This protects against two callers (e.g. a misbehaving plugin's
    ``setup()`` plus the bootstrap hook) both registering ``crowdstrike/
    isolate_host`` and silently shadowing each other.
    """
    register_builtin_executors()
    with pytest.raises(ValueError, match="already registered"):
        register_builtin_executors(overwrite=False)


def test_builtin_dispatch_without_credentials_returns_simulated() -> None:
    """The simulation branch in the legacy executor must surface as SIMULATED.

    No credentials in ``params`` means the legacy executor falls into
    its simulation branch and emits ``note="Simulation mode..."``. The
    adapter detects that note and translates the status. Without this
    contract the UI would show "succeeded" for a call that never left
    the process — which would be misleading and dangerous.
    """
    register_builtin_executors()
    request = LiveActionRequest(
        capability="isolate_host",
        vendor_id="crowdstrike",
        target="host-77",
        # No cs_client_id / cs_client_secret => simulation branch.
    )
    result = asyncio.run(dispatch(request))

    assert result.status == LiveActionStatus.SIMULATED
    assert result.vendor_id == "crowdstrike"
    assert result.capability == "isolate_host"
    # The summary should reflect the simulated nature so the audit log
    # is unambiguous when humans review it.
    assert "imulat" in result.summary.lower()


def test_builtin_dispatch_with_dry_run_strips_credentials_and_simulates() -> None:
    """``dry_run=True`` must force simulation even when credentials are present.

    The ``_LegacyExecutorAdapter.execute`` strips credential keys
    before calling the legacy executor when dry_run is set. This
    guarantees a "Preview" button can never accidentally fire a live
    action just because credentials happened to be in scope.
    """
    register_builtin_executors()
    request = LiveActionRequest(
        capability="isolate_host",
        vendor_id="crowdstrike",
        target="host-77",
        params={
            "cs_client_id": "fake-id",
            "cs_client_secret": "fake-secret",
            "cs_base_url": "https://api.crowdstrike.com",
        },
        dry_run=True,
    )
    result = asyncio.run(dispatch(request))

    # Credentials were stripped before reaching the legacy executor, so
    # it falls into the simulation branch and the adapter detects that
    # via the ``note`` field.
    assert result.status == LiveActionStatus.SIMULATED


def test_builtin_dispatch_for_block_domain_simulates_without_credentials() -> None:
    """``generic/block_domain`` declares ``requires_credentials=False`` but
    its legacy executor still uses the simulation branch (DNS-block is
    a placeholder pending Route53/Umbrella integration). Verify that
    contract holds end-to-end so docs and discovery don't lie.
    """
    register_builtin_executors()
    request = LiveActionRequest(
        capability="block_domain",
        vendor_id="generic",
        target="evil.example.com",
    )
    result = asyncio.run(dispatch(request))
    # Legacy ``BlockDomainExecutor`` emits ``Simulation mode`` notes
    # because there's no real DNS-block integration yet.
    assert result.status == LiveActionStatus.SIMULATED
    assert result.vendor_id == "generic"


def test_plugin_registered_executor_appears_in_descriptors() -> None:
    """Plugin-registered executors show ``source="plugin"`` in discovery.

    This is the contract the marketplace UI relies on: builtins get a
    "shipped with AiSOC" badge, plugin executors get a "from <plugin>"
    badge. If this assertion ever flips, the badge logic also needs
    auditing.
    """
    from app.live_actions import (
        LiveActionExecutor,
        LiveActionResult,
        register_executor,
    )

    class _MyPluginIsolate(LiveActionExecutor):
        vendor_id = "myplugin"
        capability = "isolate_host"
        description = "Plugin-defined isolate-host."
        requires_credentials = False

        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            return LiveActionResult(
                request_id=request.request_id,
                status=LiveActionStatus.SUCCEEDED,
                capability=self.capability,
                vendor_id=self.vendor_id,
                summary=f"plugin-isolated {request.target}",
            )

    register_builtin_executors()
    register_executor(_MyPluginIsolate(), source="plugin")

    descriptors = list_descriptors()
    plugin_descriptors = [d for d in descriptors if d.source == "plugin"]
    assert len(plugin_descriptors) == 1
    assert plugin_descriptors[0].vendor_id == "myplugin"

    # And a real dispatch should hit the plugin code, not any builtin.
    result = asyncio.run(
        dispatch(
            LiveActionRequest(
                capability="isolate_host",
                vendor_id="myplugin",
                target="host-99",
            )
        )
    )
    assert result.status == LiveActionStatus.SUCCEEDED
    assert "plugin-isolated host-99" in result.summary
