"""A declared verification probe must exist, and must not certify falsely.

The contract marked nine capabilities `has_verification_probe=True` while
three probes were registered. Nothing compared the two, so the declaration
was a claim rather than a fact — and it is precisely the claim the contract
exists to make trustworthy: "this action is checked against the vendor rather
than assumed from an accepted request".

The tests below are mostly about the indeterminate case. A probe that cannot
reach the vendor must say "I do not know", never "yes". Returning True on a
failed lookup is how an uncontained host gets certified as contained, and it
is a one-character mistake.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement
from app.models.action import ActionType
from app.services import verification as module
from app.services.verification import (
    _DEFAULT_PROBES,
    _probe_allow_ip,
    _probe_disable_user,
    _probe_enable_user,
)

PARAMS: dict[str, Any] = {"okta_domain": "https://x.okta.com", "okta_api_token": "t"}


class TestDeclarationsMatchReality:
    def test_every_declared_probe_is_registered(self) -> None:
        """The gap that shipped: nine declared, three implemented."""
        registered = {a.value for a in _DEFAULT_PROBES}
        known = {a.value for a in ActionType}
        for capability, contract in CAPABILITY_CONTRACTS.items():
            if not contract.has_verification_probe:
                continue
            assert capability in known, f"{capability} declares a probe but has no ActionType, so the verifier can never be reached for it"
            assert capability in registered, f"{capability} declares has_verification_probe=True with no probe registered"

    def test_an_absent_probe_at_containment_impact_is_explained(self) -> None:
        """An omission and a deliberate decision look identical afterwards."""
        for capability, contract in CAPABILITY_CONTRACTS.items():
            if contract.has_verification_probe:
                continue
            if contract.impact not in (ActionImpact.HIGH, ActionImpact.SEVERE):
                continue
            assert contract.verification_gap.strip(), f"{capability} is {contract.impact.value} impact with no probe and no stated reason"

    def test_unverifiable_actions_are_not_automatic(self) -> None:
        """Unverifiable means not autonomous, whatever the confidence."""
        for capability, contract in CAPABILITY_CONTRACTS.items():
            if contract.approval != ApprovalRequirement.AUTOMATIC:
                continue
            if contract.impact in (ActionImpact.READ_ONLY, ActionImpact.LOW):
                # A created ticket returns its own id; the response is the
                # confirmation.
                continue
            assert contract.has_verification_probe, (
                f"{capability} is automatic at {contract.impact.value} impact with nothing checking the effect"
            )


class TestDisableUserProbe:
    @pytest.mark.parametrize("status", ["SUSPENDED", "DEPROVISIONED", "LOCKED_OUT"])
    @pytest.mark.asyncio
    async def test_blocked_states_verify(self, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value=status)
        monkeypatch.setattr(module, "_okta_client", lambda p: client)
        assert await _probe_disable_user("j.doe", PARAMS) is True

    @pytest.mark.parametrize("status", ["ACTIVE", "PROVISIONED", "RECOVERY"])
    @pytest.mark.asyncio
    async def test_states_that_still_permit_signin_fail(self, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
        """RECOVERY is the trap: it sounds remedial and still allows sign-in."""
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value=status)
        monkeypatch.setattr(module, "_okta_client", lambda p: client)
        assert await _probe_disable_user("j.doe", PARAMS) is False

    @pytest.mark.asyncio
    async def test_unreadable_status_is_indeterminate_not_verified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The one-character mistake that certifies an active account."""
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value=None)
        monkeypatch.setattr(module, "_okta_client", lambda p: client)
        assert await _probe_disable_user("j.doe", PARAMS) is None

    @pytest.mark.asyncio
    async def test_no_credentials_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "_okta_client", lambda p: None)
        monkeypatch.setattr(module, "_entra_client", lambda p: None)
        assert await _probe_disable_user("j.doe", {}) is None

    @pytest.mark.asyncio
    async def test_falls_through_to_entra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entra = AsyncMock()
        entra.get_user_enabled = AsyncMock(return_value=False)
        monkeypatch.setattr(module, "_okta_client", lambda p: None)
        monkeypatch.setattr(module, "_entra_client", lambda p: entra)
        assert await _probe_disable_user("j.doe@x.com", {}) is True

    @pytest.mark.asyncio
    async def test_entra_enabled_account_fails_verification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entra = AsyncMock()
        entra.get_user_enabled = AsyncMock(return_value=True)
        monkeypatch.setattr(module, "_okta_client", lambda p: None)
        monkeypatch.setattr(module, "_entra_client", lambda p: entra)
        assert await _probe_disable_user("j.doe@x.com", {}) is False


class TestReverseProbes:
    """A rollback that silently fails leaves someone locked out after the
    incident closes, and nobody is watching for that."""

    @pytest.mark.asyncio
    async def test_enable_user_inverts_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value="ACTIVE")
        monkeypatch.setattr(module, "_okta_client", lambda p: client)
        assert await _probe_enable_user("j.doe", PARAMS) is True

        client.get_user_status = AsyncMock(return_value="SUSPENDED")
        assert await _probe_enable_user("j.doe", PARAMS) is False

    @pytest.mark.asyncio
    async def test_enable_user_indeterminate_stays_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Inverting None must not produce True."""
        client = AsyncMock()
        client.get_user_status = AsyncMock(return_value=None)
        monkeypatch.setattr(module, "_okta_client", lambda p: client)
        assert await _probe_enable_user("j.doe", PARAMS) is None

    @pytest.mark.asyncio
    async def test_allow_ip_confirms_removal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import app.executors.network as network

        monkeypatch.setattr(network, "read_back_blocked_ip", AsyncMock(return_value=False))
        assert await _probe_allow_ip("203.0.113.9", {}) is True

        monkeypatch.setattr(network, "read_back_blocked_ip", AsyncMock(return_value=True))
        assert await _probe_allow_ip("203.0.113.9", {}) is False

    @pytest.mark.asyncio
    async def test_allow_ip_indeterminate_stays_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import app.executors.network as network

        monkeypatch.setattr(network, "read_back_blocked_ip", AsyncMock(return_value=None))
        assert await _probe_allow_ip("203.0.113.9", {}) is None


class TestVerifierBehaviour:
    @pytest.mark.asyncio
    async def test_a_raising_probe_is_unverified_not_verified(self) -> None:
        """A probe error must never become a confirmation."""
        from app.services.verification import PostActionVerifier, VerificationOutcome

        async def boom(target: str, params: dict[str, Any]) -> bool | None:
            raise RuntimeError("vendor unreachable")

        verifier = PostActionVerifier()
        verifier.register(ActionType.DISABLE_USER, boom)
        result = await verifier.verify(ActionType.DISABLE_USER, "j.doe", {})
        assert result.outcome is VerificationOutcome.UNVERIFIED

    @pytest.mark.asyncio
    async def test_an_unknown_action_is_unverified_not_verified(self) -> None:
        from app.services.verification import PostActionVerifier, VerificationOutcome

        verifier = PostActionVerifier()
        verifier.probes.clear()
        result = await verifier.verify(ActionType.DISABLE_USER, "j.doe", {})
        assert result.outcome is VerificationOutcome.UNVERIFIED
