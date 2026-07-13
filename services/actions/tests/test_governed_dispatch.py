"""Phase B2 — autonomy-governed dispatch tests.

Proves the Phase 9a `decide()` policy actually governs the live-action path
(the Phase 9b wiring gap): at the default tier a HIGH-blast action queues for
approval instead of executing, below-tier actions are downgraded to dry-run,
L0 blocks outright, explicit dry-run requests are honored unchanged, and
connector-style `auth_config` is translated to executor params at dispatch.
"""

from __future__ import annotations

import asyncio

import pytest
from app.live_actions import registry
from app.live_actions.dispatcher import configured_tier, dispatch
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.services.maturity import MaturityTier


class _RecordingExecutor(LiveActionExecutor):
    """Echoes back what it received so tests can inspect params/dry_run."""

    vendor_id = "govtest"
    capability = "isolate_host"
    description = "test"
    requires_credentials = False

    def __init__(self) -> None:
        self.last_request: LiveActionRequest | None = None

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        self.last_request = request
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SIMULATED if request.dry_run else LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="ok",
            details={"params_seen": dict(request.params)},
        )


class _NotifyExecutor(_RecordingExecutor):
    vendor_id = "govtest"
    capability = "notify_slack"


@pytest.fixture()
def recording_executor():
    registry.reset_for_tests()
    ex = _RecordingExecutor()
    registry.register_executor(ex, source="test")
    yield ex
    registry.reset_for_tests()


@pytest.fixture()
def notify_executor():
    registry.reset_for_tests()
    ex = _NotifyExecutor()
    registry.register_executor(ex, source="test")
    yield ex
    registry.reset_for_tests()


def _run(request: LiveActionRequest) -> LiveActionResult:
    return asyncio.run(dispatch(request))


# ── tier resolution ───────────────────────────────────────────────────────────


def test_default_tier_is_l1_notify(monkeypatch):
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    assert configured_tier() == MaturityTier.L1_NOTIFY


def test_tier_env_accepts_name_short_and_number(monkeypatch):
    for raw, expected in [("L3_REMEDIATE", MaturityTier.L3_REMEDIATE), ("L2", MaturityTier.L2_CONTAIN), ("4", MaturityTier.L4_AUTOMATE)]:
        monkeypatch.setenv("AISOC_MATURITY_TIER", raw)
        assert configured_tier() == expected


# ── governance outcomes ──────────────────────────────────────────────────────


def test_high_blast_action_downgrades_to_dry_run_at_default_tier(monkeypatch, recording_executor):
    """Copilot default: a HIGH-blast action above the tier allowance becomes a
    dry-run PREVIEW — never a silent real execution."""
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    monkeypatch.delenv("AISOC_ACTIONS_DEFAULT_DRY_RUN", raising=False)
    result = _run(LiveActionRequest(capability="isolate_host", vendor_id="govtest", target="srv-1"))
    assert result.status == LiveActionStatus.SIMULATED
    assert recording_executor.last_request is not None
    assert recording_executor.last_request.dry_run is True  # downgraded
    assert result.details["autonomy_mode"] == "dry_run"


def test_high_blast_action_queues_when_dry_run_disabled(monkeypatch, recording_executor):
    """With dry-run disabled, an above-tier action queues for a human instead
    of executing — the executor is never invoked."""
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    monkeypatch.setenv("AISOC_ACTIONS_DEFAULT_DRY_RUN", "0")
    result = _run(LiveActionRequest(capability="isolate_host", vendor_id="govtest", target="srv-1"))
    assert result.status == LiveActionStatus.PENDING_APPROVAL
    assert recording_executor.last_request is None  # executor NEVER invoked
    assert result.details["autonomy_mode"] == "queued_approval"


def test_high_blast_queues_even_at_l4_without_whitelist(monkeypatch, recording_executor):
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L4_AUTOMATE")
    monkeypatch.delenv("AISOC_ALLOW_HIGH_BLAST_AUTO", raising=False)
    result = _run(LiveActionRequest(capability="isolate_host", vendor_id="govtest", target="srv-1"))
    assert result.status == LiveActionStatus.PENDING_APPROVAL
    assert recording_executor.last_request is None


def test_l0_blocks_outright(monkeypatch, recording_executor):
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L0_OBSERVE")
    result = _run(LiveActionRequest(capability="isolate_host", vendor_id="govtest", target="srv-1"))
    assert result.status == LiveActionStatus.BLOCKED
    assert recording_executor.last_request is None


def test_low_blast_action_executes_at_permitted_tier(monkeypatch, notify_executor):
    # notify_slack is LOW blast — permitted to auto-execute at L1.
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    result = _run(LiveActionRequest(capability="notify_slack", vendor_id="govtest", target="#soc"))
    assert result.status == LiveActionStatus.SUCCEEDED
    assert notify_executor.last_request is not None
    assert notify_executor.last_request.dry_run is False


def test_explicit_dry_run_is_honoured_not_governed(monkeypatch, recording_executor):
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L0_OBSERVE")  # would block a real run
    result = _run(LiveActionRequest(capability="isolate_host", vendor_id="govtest", target="srv-1", dry_run=True))
    # An explicit dry-run is already the safest mode; it executes as a preview.
    assert result.status == LiveActionStatus.SIMULATED
    assert recording_executor.last_request is not None
    assert recording_executor.last_request.dry_run is True


def test_unmapped_capability_is_not_governed(monkeypatch):
    registry.reset_for_tests()
    ex = _RecordingExecutor()
    ex.capability = "echo_probe"  # no ActionType mapping
    registry.register_executor(ex, source="test")
    try:
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L0_OBSERVE")
        result = _run(LiveActionRequest(capability="echo_probe", vendor_id="govtest", target="x"))
        assert result.status == LiveActionStatus.SUCCEEDED
    finally:
        registry.reset_for_tests()


# ── credential translation at the boundary ──────────────────────────────────


def test_auth_config_is_translated_to_executor_params(monkeypatch, notify_executor):
    monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
    # Vendor 'govtest' has no map -> only already-prefixed keys pass through;
    # use okta-style via a registered okta capability instead.
    registry.reset_for_tests()
    ex = _NotifyExecutor()
    ex.vendor_id = "okta"
    ex.capability = "notify_slack"
    registry.register_executor(ex, source="test")
    try:
        result = _run(
            LiveActionRequest(
                capability="notify_slack",
                vendor_id="okta",
                target="user@corp.com",
                auth_config={"domain": "https://org.okta.com", "api_token": "tok"},
                params={"note": "hi"},
            )
        )
        assert result.status == LiveActionStatus.SUCCEEDED
        seen = ex.last_request.params
        assert seen["okta_domain"] == "https://org.okta.com"
        assert seen["okta_api_token"] == "tok"
        assert seen["note"] == "hi"
        assert ex.last_request.auth_config is None  # consumed at the boundary
    finally:
        registry.reset_for_tests()


# ── new vendor adapters are registered ───────────────────────────────────────


def test_phase_b2_vendors_are_registered():
    from app.live_actions.builtins import register_builtin_executors

    registry.reset_for_tests()
    try:
        register_builtin_executors(overwrite=True)
        for vendor, capability in [
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
        ]:
            assert registry.get_executor(vendor, capability) is not None, f"{vendor}/{capability} not registered"
    finally:
        registry.reset_for_tests()
