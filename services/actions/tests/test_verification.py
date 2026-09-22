"""Phase B3 — post-action verification tests.

Proves the verifier re-queries the vendor and returns VERIFIED only when a real
probe confirms the effect, FAILED when the effect is absent, and UNVERIFIED
(honest) when no probe exists, no credentials are present, or the probe errors.
"""

from __future__ import annotations

import pytest
from app.models.action import ActionType
from app.services import verification
from app.services.verification import PostActionVerifier, VerificationOutcome

pytestmark = pytest.mark.asyncio


CREDS = {"cs_client_id": "x", "cs_client_secret": "y"}


def _stub_cs(monkeypatch, *, device_id="dev-1", status="contained"):
    """Stub the EDR client with a resolvable device and a containment state."""

    class _CS:
        async def get_device_id(self, hostname):  # noqa: ANN001
            return device_id

        async def get_containment_status(self, dev):  # noqa: ANN001
            return status

    monkeypatch.setattr(verification, "_cs_client", lambda params: _CS())


async def test_verified_only_when_the_host_is_actually_contained(monkeypatch):
    _stub_cs(monkeypatch, status="contained")
    res = await PostActionVerifier().verify(ActionType.ISOLATE_HOST, "WIN-DC01", CREDS)
    assert res.outcome == VerificationOutcome.VERIFIED


async def test_resolvable_host_that_is_not_contained_is_a_failure(monkeypatch):
    """The regression this probe exists to catch.

    The probe used to return ``bool(device_id)`` — true for every host in the
    fleet, contained or not — so a host that was never contained was reported
    VERIFIED. Hostname resolution is not containment.
    """
    _stub_cs(monkeypatch, status="normal")
    res = await PostActionVerifier().verify(ActionType.ISOLATE_HOST, "WIN-DC01", CREDS)
    assert res.outcome == VerificationOutcome.FAILED


async def test_containment_pending_is_not_verified(monkeypatch):
    """Accepted-but-not-in-force is exactly what this must not certify."""
    _stub_cs(monkeypatch, status="containment_pending")
    res = await PostActionVerifier().verify(ActionType.ISOLATE_HOST, "WIN-DC01", CREDS)
    assert res.outcome == VerificationOutcome.FAILED


async def test_missing_host_is_indeterminate_not_failed(monkeypatch):
    """A renamed or decommissioned host is not proof containment did not take."""
    _stub_cs(monkeypatch, device_id=None)
    res = await PostActionVerifier().verify(ActionType.ISOLATE_HOST, "ghost-host", CREDS)
    assert res.outcome == VerificationOutcome.UNVERIFIED


async def test_unreadable_status_is_indeterminate(monkeypatch):
    _stub_cs(monkeypatch, status=None)
    res = await PostActionVerifier().verify(ActionType.ISOLATE_HOST, "WIN-DC01", CREDS)
    assert res.outcome == VerificationOutcome.UNVERIFIED


async def test_unverified_without_credentials(monkeypatch):
    monkeypatch.setattr(verification, "_cs_client", lambda params: None)
    v = PostActionVerifier()
    res = await v.verify(ActionType.ISOLATE_HOST, "WIN-DC01", {})
    assert res.outcome == VerificationOutcome.UNVERIFIED


async def test_unverified_for_action_without_probe():
    v = PostActionVerifier()
    res = await v.verify(ActionType.QUARANTINE_FILE, "x", {})
    assert res.outcome == VerificationOutcome.UNVERIFIED
    assert "no read-back verifier" in res.reason


async def test_probe_error_is_unverified_never_false_verified(monkeypatch):
    class _CS:
        async def get_device_id(self, hostname):  # noqa: ANN001
            raise RuntimeError("boom")

    monkeypatch.setattr(verification, "_cs_client", lambda params: _CS())
    v = PostActionVerifier()
    res = await v.verify(ActionType.ISOLATE_HOST, "h", {"cs_client_id": "x", "cs_client_secret": "y"})
    assert res.outcome == VerificationOutcome.UNVERIFIED


async def test_custom_probe_registration():
    v = PostActionVerifier()

    async def _always_present(target, params):  # noqa: ANN001
        return True

    v.register(ActionType.BLOCK_IP, _always_present)
    res = await v.verify(ActionType.BLOCK_IP, "1.2.3.4", {})
    assert res.outcome == VerificationOutcome.VERIFIED
