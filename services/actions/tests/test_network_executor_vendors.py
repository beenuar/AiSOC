"""
Phase 3.2 — integration tests for the executor → vendor dispatch
logic in :mod:`app.executors.network`.

These tests stub the client factories so we focus on the vendor
selection rules (which credentials trigger which path, in which
order) without re-asserting wire shape — the wire shape is locked
down by :file:`test_network_firewall_clients.py`.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors.network import AllowIPExecutor, BlockDomainExecutor, BlockIPExecutor
from app.models.action import ActionRequest, ActionStatus, ActionType


def _block_ip_request(**params: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.BLOCK_IP,
        target="1.2.3.4",
        parameters=dict(params),
    )


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    async def block_ip(self, **kwargs: object) -> dict:
        self.calls.append(("block_ip", (), kwargs))
        return {"success": True, "action": "block_ip", **kwargs}

    async def unblock_ip(self, **kwargs: object) -> dict:
        self.calls.append(("unblock_ip", (), kwargs))
        return {"success": True, "action": "unblock_ip", **kwargs}

    async def block_ip_zone(self, **kwargs: object) -> dict:
        self.calls.append(("block_ip_zone", (), kwargs))
        return {"success": True, "action": "block_ip", "rule_id": "rule-1"}

    async def sinkhole_domain(self, **kwargs: object) -> dict:
        self.calls.append(("sinkhole_domain", (), kwargs))
        return {"success": True, "action": "block_domain", **kwargs}


# ────────────────────────────────────────────────────────────────────
# BlockIP — vendor priority
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_ip_prefers_panos_when_panos_creds_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """PAN-OS must fire when its three required params are present
    and the higher-priority AWS path doesn't have an SG."""
    from app.executors import network

    fake_panos = _FakeClient()
    monkeypatch.setattr(network, "_aws_client", lambda p: None)
    monkeypatch.setattr(network, "_panos_client", lambda p: fake_panos)
    monkeypatch.setattr(network, "_fortigate_client", lambda p: None)
    monkeypatch.setattr(network, "_cloudflare_client", lambda p: None)

    req = _block_ip_request(panos_host="fw.example.com", panos_api_key="K", panos_tag="aisoc-blocked")
    result = await BlockIPExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "panos"
    assert fake_panos.calls[0][2]["tag"] == "aisoc-blocked"


@pytest.mark.asyncio
async def test_block_ip_falls_through_to_fortigate(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.executors import network

    fake_fgt = _FakeClient()
    monkeypatch.setattr(network, "_aws_client", lambda p: None)
    monkeypatch.setattr(network, "_panos_client", lambda p: None)
    monkeypatch.setattr(network, "_fortigate_client", lambda p: fake_fgt)
    monkeypatch.setattr(network, "_cloudflare_client", lambda p: None)

    req = _block_ip_request(fgt_address_group="blocked")
    result = await BlockIPExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "fortigate"
    assert fake_fgt.calls[0][2]["group"] == "blocked"


@pytest.mark.asyncio
async def test_block_ip_uses_cloudflare_when_zone_id_present(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.executors import network

    fake_cf = _FakeClient()
    monkeypatch.setattr(network, "_aws_client", lambda p: None)
    monkeypatch.setattr(network, "_panos_client", lambda p: None)
    monkeypatch.setattr(network, "_fortigate_client", lambda p: None)
    monkeypatch.setattr(network, "_cloudflare_client", lambda p: fake_cf)

    req = _block_ip_request(cf_zone_id="Z1")
    result = await BlockIPExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "cloudflare"
    assert result.rollback_data["rule_id"] == "rule-1"


@pytest.mark.asyncio
async def test_block_ip_simulation_when_no_credentials_lists_all_vendors() -> None:
    req = _block_ip_request()
    result = await BlockIPExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    note = result.output["note"]
    for vendor_prefix in ("aws_", "panos_", "fgt_", "cf_"):
        assert vendor_prefix in note


# ────────────────────────────────────────────────────────────────────
# AllowIP — vendor priority for unblock
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_allow_ip_dispatches_to_panos_unblock(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.executors import network

    fake_panos = _FakeClient()
    monkeypatch.setattr(network, "_aws_client", lambda p: None)
    monkeypatch.setattr(network, "_panos_client", lambda p: fake_panos)
    monkeypatch.setattr(network, "_fortigate_client", lambda p: None)
    monkeypatch.setattr(network, "_cloudflare_client", lambda p: None)

    req = ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.ALLOW_IP,
        target="1.2.3.4",
        parameters={"panos_host": "x", "panos_api_key": "y", "panos_tag": "t"},
    )
    result = await AllowIPExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert fake_panos.calls[0][0] == "unblock_ip"
    assert result.rollback_data["vendor"] == "panos"


# ────────────────────────────────────────────────────────────────────
# BlockDomain — Cloudflare gateway sinkhole
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_domain_uses_cloudflare_gateway_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.executors import network

    fake_cf = _FakeClient()
    monkeypatch.setattr(network, "_cloudflare_client", lambda p: fake_cf)

    req = ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.BLOCK_DOMAIN,
        target="evil.example",
        parameters={"cf_api_token": "T", "cf_account_id": "A1", "cf_block_list_id": "L1"},
    )
    result = await BlockDomainExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "cloudflare_gateway"
    assert fake_cf.calls[0][0] == "sinkhole_domain"
    assert fake_cf.calls[0][2]["domain"] == "evil.example"


@pytest.mark.asyncio
async def test_block_domain_simulation_when_no_credentials() -> None:
    req = ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.BLOCK_DOMAIN,
        target="evil.example",
        parameters={},
    )
    result = await BlockDomainExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert "cf_api_token" in result.output["note"]
