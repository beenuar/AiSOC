"""Vendor capabilities the clients implemented and the registry could not reach.

Seventeen vendors were wired and most exposed exactly one verb, so the
registry looked like breadth and behaved like a single button per product.
Not because the integrations were shallow: `SentinelOneClient` implements
seven operations and one was reachable; `AzureEntraClient` implements six
and one was reachable. The work existed and nothing connected it.

The tests below are structural on purpose. Asserting that seventeen
executors each forward to the right client method is low-value repetition;
asserting that **every executor calls a method its client actually has** is
the property that would have caught the whole class of defect, and it is
the one that breaks when a client is refactored.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock

import pytest
from app.live_actions import vendor_breadth
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.live_actions.vendor_breadth import (
    VENDOR_BREADTH_EXECUTORS,
    CloudflareAllowIP,
    EntraEnableUser,
    SentinelOneUnisolateHost,
)

#: executor -> (factory name in vendor_breadth, client method it must call)
EXPECTED_CALLS = {
    "SentinelOneUnisolateHost": ("_s1_client", "lift_containment"),
    "SentinelOneKillProcess": ("_s1_client", "kill_process"),
    "SentinelOneQuarantineFile": ("_s1_client", "quarantine_file"),
    "SentinelOneRunAVScan": ("_s1_client", "run_av_scan"),
    "SentinelOneRunScript": ("_s1_client", "run_script"),
    "EntraEnableUser": ("_entra_client", "enable_user"),
    "EntraRevokeSession": ("_entra_client", "revoke_sessions"),
    "EntraResetPassword": ("_entra_client", "reset_password"),
    "EntraForceMFA": ("_entra_client", "require_mfa"),
    "GoogleWorkspaceEnableUser": ("_gws_client", "unsuspend_user"),
    "GoogleWorkspaceRevokeSession": ("_gws_client", "revoke_sessions"),
    "GoogleWorkspaceResetPassword": ("_gws_client", "reset_password"),
    "CloudflareAllowIP": ("_cloudflare_client", "unblock_ip_zone"),
    "CloudflareBlockDomain": ("_cloudflare_client", "sinkhole_domain"),
    "CloudflareAllowDomain": ("_cloudflare_client", "unsinkhole_domain"),
    "PanOsAllowIP": ("_panos_client", "unblock_ip"),
    "FortiGateAllowIP": ("_fortigate_client", "unblock_ip"),
}

REAL_CLIENTS = {
    "_s1_client": "app.clients.sentinelone_client.SentinelOneClient",
    "_entra_client": "app.clients.azure_entra_client.AzureEntraClient",
    "_gws_client": "app.clients.google_workspace_client.GoogleWorkspaceClient",
    "_cloudflare_client": "app.clients.cloudflare_client.CloudflareClient",
    "_panos_client": "app.clients.panos_client.PanOsClient",
    "_fortigate_client": "app.clients.fortigate_client.FortiGateClient",
}


def _import(path: str):
    module_path, _, name = path.rpartition(".")
    module = __import__(module_path, fromlist=[name])
    return getattr(module, name)


def _request(capability: str, vendor: str, **params) -> LiveActionRequest:
    return LiveActionRequest(vendor_id=vendor, capability=capability, target="TARGET", params=params)


class TestEveryExecutorIsBacked:
    def test_every_executor_is_covered_by_this_test(self) -> None:
        """A new executor added without a row here is untested breadth,
        which is how a registry fills with things nobody exercised."""
        names = {cls.__name__ for cls in VENDOR_BREADTH_EXECUTORS}
        assert names == set(EXPECTED_CALLS)

    @pytest.mark.parametrize(("executor_name", "expected"), sorted(EXPECTED_CALLS.items()))
    def test_the_client_method_exists(self, executor_name: str, expected: tuple[str, str]) -> None:
        """The property that would have caught the whole class of defect.

        Simulation mode never constructs the client, so an executor calling
        a method that does not exist works in every test and raises the
        first time a credential is present. Checked against the real class,
        not a mock.
        """
        factory_name, method = expected
        client_cls = _import(REAL_CLIENTS[factory_name])
        assert hasattr(client_cls, method), f"{executor_name} calls {method}() which {client_cls.__name__} does not have"
        assert inspect.iscoroutinefunction(getattr(client_cls, method)), f"{client_cls.__name__}.{method} is not awaitable"

    @pytest.mark.parametrize("executor_cls", VENDOR_BREADTH_EXECUTORS, ids=lambda c: c.__name__)
    def test_every_capability_has_a_contract(self, executor_cls: type) -> None:
        assert executor_cls.capability in CAPABILITY_CONTRACTS


class TestSharedBehaviour:
    """Three properties every executor inherits from the shared body. Tested
    on representatives rather than all seventeen: the body is shared, so
    seventeen copies of the same assertion tests the parametrize decorator."""

    @pytest.mark.asyncio
    async def test_dry_run_does_not_reach_the_vendor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        monkeypatch.setattr(vendor_breadth, "_s1_client", lambda p: client)
        request = _request("unisolate_host", "sentinelone")
        request.dry_run = True

        result = await SentinelOneUnisolateHost().execute(request)
        assert result.status is LiveActionStatus.SIMULATED
        client.lift_containment.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_credentials_says_so_rather_than_failing_vaguely(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ "We could not reach the vendor" and "the vendor refused" send an
        operator to different places."""
        monkeypatch.setattr(vendor_breadth, "_entra_client", lambda p: None)
        result = await EntraEnableUser().execute(_request("enable_user", "azure_entra"))
        assert result.status is LiveActionStatus.FAILED
        assert "not a statement about the target" in (result.error or "")

    @pytest.mark.asyncio
    async def test_a_vendor_exception_becomes_failed_not_an_escape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An exception escaping an executor wedges the agent loop."""
        client = AsyncMock()
        client.lift_containment = AsyncMock(side_effect=RuntimeError("503"))
        monkeypatch.setattr(vendor_breadth, "_s1_client", lambda p: client)

        result = await SentinelOneUnisolateHost().execute(_request("unisolate_host", "sentinelone"))
        assert result.status is LiveActionStatus.FAILED
        assert "503" in (result.error or "")

    @pytest.mark.asyncio
    async def test_success_carries_the_vendor_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.lift_containment = AsyncMock(return_value={"ok": True})
        monkeypatch.setattr(vendor_breadth, "_s1_client", lambda p: client)

        result = await SentinelOneUnisolateHost().execute(_request("unisolate_host", "sentinelone"))
        assert result.status is LiveActionStatus.SUCCEEDED
        assert result.details["vendor_response"] == {"ok": True}

    @pytest.mark.asyncio
    async def test_vendor_specific_params_are_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cloudflare's unblock needs a rule and zone id, not just the IP.
        Dropping them would produce a call that succeeds against the wrong
        zone or fails obscurely."""
        client = AsyncMock()
        client.unblock_ip_zone = AsyncMock(return_value={})
        monkeypatch.setattr(vendor_breadth, "_cloudflare_client", lambda p: client)

        await CloudflareAllowIP().execute(_request("allow_ip", "cloudflare", rule_id="r1", cf_zone_id="z1"))
        client.unblock_ip_zone.assert_awaited_once_with("r1", "z1")


class TestReversesAreNowReachable:
    """Several of these are the reverse actions the contract already
    promised and nothing implemented."""

    @pytest.mark.parametrize(
        ("forward", "reverse"),
        [
            ("disable_user", "enable_user"),
            ("isolate_host", "unisolate_host"),
            ("block_ip", "allow_ip"),
            ("block_domain", "allow_domain"),
        ],
    )
    def test_a_declared_reverse_has_an_implementation(self, forward: str, reverse: str) -> None:
        from app.live_actions import builtins

        implemented = {c.capability for c in builtins._BUILTIN_ADAPTERS}  # noqa: SLF001
        declared = CAPABILITY_CONTRACTS[forward].reverse_capability
        assert declared == reverse
        assert reverse in implemented, (
            f"{forward} declares {reverse} as its reverse and nothing implements it, so the rollback path resolves to nothing"
        )
