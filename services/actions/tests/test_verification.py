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


async def test_verified_when_probe_confirms(monkeypatch):
    class _CS:
        async def get_device_id(self, hostname):  # noqa: ANN001
            return "dev-1"

    monkeypatch.setattr(verification, "_cs_client", lambda params: _CS())
    v = PostActionVerifier()
    res = await v.verify(ActionType.ISOLATE_HOST, "WIN-DC01", {"cs_client_id": "x", "cs_client_secret": "y"})
    assert res.outcome == VerificationOutcome.VERIFIED


async def test_failed_when_effect_absent(monkeypatch):
    class _CS:
        async def get_device_id(self, hostname):  # noqa: ANN001
            return None

    monkeypatch.setattr(verification, "_cs_client", lambda params: _CS())
    v = PostActionVerifier()
    res = await v.verify(ActionType.ISOLATE_HOST, "ghost-host", {"cs_client_id": "x", "cs_client_secret": "y"})
    assert res.outcome == VerificationOutcome.FAILED


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
