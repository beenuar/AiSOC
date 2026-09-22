"""Read-only vendor verbs: safe by construction, honest when they fail.

Twenty-nine executors could change the estate and exactly one could ask it a
question. With no way to read a vendor, an investigation can only reach the
lake — so anything the lake did not ingest is invisible, and the pivot chain
has nowhere to pivot to.

The tests below are mostly about the distinction these must preserve: a read
that *failed* is not a read that found *nothing*. An investigation
concluding a host is clean because the API was down is worse than one that
says it could not check.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from app.live_actions import investigation_reads as module
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement, Reversal
from app.live_actions.investigation_reads import (
    CrowdStrikeGetDetections,
    CrowdStrikeGetHost,
    CrowdStrikeUnisolateHost,
    DefenderGetHost,
    OktaGetUserActivity,
)
from app.live_actions.models import LiveActionRequest, LiveActionStatus

READ_VERBS = ("get_host", "get_detections", "get_user_activity")


def _request(target: str = "WS-042", **params) -> LiveActionRequest:
    return LiveActionRequest(
        vendor_id="crowdstrike",
        capability="get_host",
        target=target,
        params=params,
        dry_run=False,
    )


class TestContracts:
    @pytest.mark.parametrize("capability", READ_VERBS)
    def test_a_read_changes_nothing_and_needs_no_approval(self, capability: str) -> None:
        """Gating a read behind an analyst is how an agent learns to
        conclude without looking."""
        contract = CAPABILITY_CONTRACTS[capability]
        assert contract.impact is ActionImpact.READ_ONLY
        assert contract.approval is ApprovalRequirement.AUTOMATIC
        assert contract.reversal is Reversal.NOT_APPLICABLE

    @pytest.mark.parametrize("capability", READ_VERBS)
    def test_a_read_does_not_require_the_containment_permission(self, capability: str) -> None:
        """Bundling them means anyone who can look can also isolate."""
        assert CAPABILITY_CONTRACTS[capability].required_permission == "actions:investigate"
        assert CAPABILITY_CONTRACTS[capability].required_permission != "actions:contain"


class TestCrowdStrikeGetHost:
    @pytest.mark.asyncio
    async def test_returns_a_projected_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value="dev-1")
        client.get_device = AsyncMock(return_value={"device_id": "dev-1", "hostname": "WS-042", "containment_status": "normal"})
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeGetHost().execute(_request())
        assert result.status is LiveActionStatus.SUCCEEDED
        assert result.details["found"] is True
        assert result.details["hostname"] == "WS-042"

    @pytest.mark.asyncio
    async def test_a_host_that_does_not_exist_is_a_result_not_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A renamed or decommissioned host is not an outage."""
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value=None)
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeGetHost().execute(_request())
        assert result.status is LiveActionStatus.SUCCEEDED
        assert result.details["found"] is False

    @pytest.mark.asyncio
    async def test_a_failed_read_is_a_failure_not_an_empty_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The distinction this whole module turns on."""
        client = AsyncMock()
        client.get_device_id = AsyncMock(side_effect=RuntimeError("503 from Falcon"))
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeGetHost().execute(_request())
        assert result.status is LiveActionStatus.FAILED
        assert "503" in (result.error or "")

    @pytest.mark.asyncio
    async def test_missing_credentials_says_so_rather_than_reporting_nothing_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "_cs_client", lambda p: None)
        result = await CrowdStrikeGetHost().execute(_request())
        assert result.status is LiveActionStatus.FAILED
        assert "not a statement about the target" in (result.error or "")

    @pytest.mark.asyncio
    async def test_dry_run_does_not_call_the_vendor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        monkeypatch.setattr(module, "_cs_client", lambda p: client)
        request = _request()
        request.dry_run = True

        result = await CrowdStrikeGetHost().execute(request)
        assert result.status is LiveActionStatus.SIMULATED
        client.get_device_id.assert_not_called()


class TestCrowdStrikeGetDetections:
    @pytest.mark.asyncio
    async def test_returns_detections_with_a_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value="dev-1")
        client.get_detections = AsyncMock(return_value=[{"detection_id": "d1", "severity": "High"}])
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeGetDetections().execute(_request())
        assert result.details["count"] == 1

    @pytest.mark.asyncio
    async def test_no_detections_is_an_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value="dev-1")
        client.get_detections = AsyncMock(return_value=[])
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeGetDetections().execute(_request())
        assert result.status is LiveActionStatus.SUCCEEDED
        assert result.details["count"] == 0


class TestDefenderGetHost:
    @pytest.mark.asyncio
    async def test_projects_the_machine_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.find_machine = AsyncMock(return_value={"id": "m-1", "computerDnsName": "WS-042", "riskScore": "High"})
        monkeypatch.setattr(module, "_mde_client", lambda p: client)

        result = await DefenderGetHost().execute(_request())
        assert result.details["device_id"] == "m-1"
        assert result.details["risk_score"] == "High"


class TestOktaGetUserActivity:
    @pytest.mark.asyncio
    async def test_reports_whether_signin_is_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value="SUSPENDED")
        monkeypatch.setattr(module, "_okta_client", lambda p: client)

        result = await OktaGetUserActivity().execute(_request("j.doe"))
        assert result.details["sign_in_blocked"] is True

    @pytest.mark.asyncio
    async def test_an_unreadable_account_fails_rather_than_looking_fine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ "We could not read this account" and "this account is fine" are
        different, and only one should let an investigation move on."""
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value=None)
        monkeypatch.setattr(module, "_okta_client", lambda p: client)

        result = await OktaGetUserActivity().execute(_request("j.doe"))
        assert result.status is LiveActionStatus.FAILED


class TestUnisolateHost:
    """The rollback for the most disruptive action had no executor at all —
    the contract declared a route back and dispatch answered
    executor_not_found."""

    @pytest.mark.asyncio
    async def test_lifts_containment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value="dev-1")
        client.lift_containment = AsyncMock(return_value={"resources": [{"id": "dev-1"}]})
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeUnisolateHost().execute(_request())
        assert result.status is LiveActionStatus.SUCCEEDED
        client.lift_containment.assert_awaited_once_with("dev-1")

    @pytest.mark.asyncio
    async def test_an_unresolvable_host_fails_rather_than_reporting_release(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reporting success would leave the host contained with the
        incident closed, which is how a containment becomes permanent."""
        client = AsyncMock()
        client.get_device_id = AsyncMock(return_value=None)
        monkeypatch.setattr(module, "_cs_client", lambda p: client)

        result = await CrowdStrikeUnisolateHost().execute(_request())
        assert result.status is LiveActionStatus.FAILED
        assert "not lifted" in (result.error or "")

    def test_isolate_now_has_a_reachable_reverse(self) -> None:
        from app.live_actions import builtins

        implemented = {cls.capability for cls in builtins._BUILTIN_ADAPTERS}  # noqa: SLF001
        reverse = CAPABILITY_CONTRACTS["isolate_host"].reverse_capability
        assert reverse in implemented, f"isolate_host declares {reverse} as its reverse and nothing implements it"
