"""Phase B3 — honest reverse-action tests.

Proves reverse calls actually hit the vendor client when credentials are
present, degrade to an honest *simulated* result (not a fake success) when
they're absent, report failures instead of hiding them, and that the
autonomy layer's REVERSIBLE_ACTIONS set never claims a reverse the rollback
module can't perform.
"""

from __future__ import annotations

import pytest
from app.models.action import ActionType
from app.services import rollback
from app.services.rollback import REVERSIBLE_ACTIONS, reverse_action

pytestmark = pytest.mark.asyncio


class _FakeCS:
    def __init__(self) -> None:
        self.lifted: list[str] = []

    async def get_device_id(self, hostname):  # noqa: ANN001
        return "dev-123"

    async def lift_containment(self, device_id):  # noqa: ANN001
        self.lifted.append(device_id)
        return {"ok": True}


class _FakeAws:
    def __init__(self) -> None:
        self.unblocked: list[str] = []

    async def unblock_ip(self, ip, **kw):  # noqa: ANN001, ANN003
        self.unblocked.append(ip)
        return {"ok": True}


class _FakeOkta:
    def __init__(self) -> None:
        self.enabled: list[str] = []

    async def enable_user(self, login):  # noqa: ANN001
        self.enabled.append(login)
        return {"ok": True}

    async def unsuspend_user(self, login):  # noqa: ANN001
        self.enabled.append(login)
        return {"ok": True}


# ── real reverse calls ───────────────────────────────────────────────────────


async def test_isolate_reverse_calls_crowdstrike_when_credentialed(monkeypatch):
    fake = _FakeCS()
    monkeypatch.setattr(rollback, "_cs_client", lambda params: fake)
    monkeypatch.setattr(rollback, "_mde_client", lambda params: None)
    monkeypatch.setattr(rollback, "_s1_client", lambda params: None)
    res = await reverse_action(ActionType.ISOLATE_HOST, "WIN-DC01", {"cs_client_id": "x", "cs_client_secret": "y"})
    assert res.reversed_ is True
    assert res.simulated is False
    assert res.vendor == "crowdstrike"
    assert fake.lifted == ["dev-123"]


async def test_block_ip_reverse_calls_aws(monkeypatch):
    fake = _FakeAws()
    monkeypatch.setattr(rollback, "_aws_client", lambda params: fake)
    monkeypatch.setattr(rollback, "_panos_client", lambda params: None)
    monkeypatch.setattr(rollback, "_fortigate_client", lambda params: None)
    monkeypatch.setattr(rollback, "_cloudflare_client", lambda params: None)
    res = await reverse_action(ActionType.BLOCK_IP, "1.2.3.4", {"aws_security_group_id": "sg-1"})
    assert res.reversed_ is True
    assert fake.unblocked == ["1.2.3.4"]


async def test_disable_user_reverse_calls_okta(monkeypatch):
    fake = _FakeOkta()
    monkeypatch.setattr(rollback, "_okta_client", lambda params: fake)
    monkeypatch.setattr(rollback, "_entra_client", lambda params: None)
    monkeypatch.setattr(rollback, "_gws_client", lambda params: None)
    res = await reverse_action(ActionType.DISABLE_USER, "user@corp.com", {"okta_domain": "d", "okta_api_token": "t"})
    assert res.reversed_ is True
    assert fake.enabled == ["user@corp.com"]


# ── honest degradation ───────────────────────────────────────────────────────


async def test_no_credentials_is_simulated_not_fake_success(monkeypatch):
    for name in ("_cs_client", "_mde_client", "_s1_client"):
        monkeypatch.setattr(rollback, name, lambda params: None)
    res = await reverse_action(ActionType.ISOLATE_HOST, "WIN-DC01", {})
    assert res.reversed_ is False
    assert res.simulated is True
    assert res.ok is True  # simulation is a safe outcome
    assert "simulated" in res.reason


async def test_unsupported_action_is_reported_honestly():
    res = await reverse_action(ActionType.QUARANTINE_FILE, "x", {})
    assert res.supported is False
    assert res.reversed_ is False
    assert res.simulated is False
    assert res.ok is False


async def test_reverse_failure_is_reported_not_hidden(monkeypatch):
    class _Boom:
        async def get_device_id(self, hostname):  # noqa: ANN001
            raise RuntimeError("api down")

    monkeypatch.setattr(rollback, "_cs_client", lambda params: _Boom())
    monkeypatch.setattr(rollback, "_mde_client", lambda params: None)
    monkeypatch.setattr(rollback, "_s1_client", lambda params: None)
    res = await reverse_action(ActionType.ISOLATE_HOST, "h", {"cs_client_id": "x", "cs_client_secret": "y"})
    assert res.reversed_ is False
    assert res.simulated is False
    assert res.ok is False
    assert "failed" in res.reason


# ── the reversible-set gate ──────────────────────────────────────────────────


async def test_autonomy_reversible_set_matches_rollback_source_of_truth():
    from app.services.autonomy_safety import REVERSIBLE_ACTIONS as AUTONOMY_SET

    assert AUTONOMY_SET == REVERSIBLE_ACTIONS


async def test_every_reversible_action_has_a_real_reverser():
    # No action may be declared reversible without an actual reverse path.
    for action_type in REVERSIBLE_ACTIONS:
        assert action_type in rollback._REVERSERS, action_type
