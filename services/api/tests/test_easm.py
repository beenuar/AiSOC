"""Tests for Tier 3.6 — EASM discovery and drift detection.

Validates:
  1. Discovery connectors parse Shodan / Censys API responses correctly.
  2. Active port scanner returns DiscoveredAsset instances.
  3. Drift detection identifies new_asset, new_port, gone_port events.
  4. The run_discovery orchestrator honours feature flags.

All tests run with mocked HTTP and socket calls — no live APIs required.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.easm import ExternalAsset, ExternalAssetDrift, ExternalAssetType
from app.services.easm_discovery import (
    DiscoveredAsset,
    _shodan_search,
    _censys_search,
    _active_scan,
    run_discovery,
)
from app.services.easm_drift import (
    _detect_port_drift,
    _merge_metadata,
    detect_drift,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TENANT_ID = uuid.uuid4()


def _fake_shodan_response() -> dict[str, Any]:
    return {
        "matches": [
            {
                "ip_str": "1.2.3.4",
                "port": 443,
                "org": "AcmeCorp",
                "asn": "AS12345",
                "os": "Linux",
                "hostnames": ["www.acme.com", "api.acme.com"],
            },
            {
                "ip_str": "5.6.7.8",
                "port": 22,
                "org": "AcmeCorp",
                "asn": "AS12345",
                "os": None,
                "hostnames": [],
            },
        ]
    }


def _fake_censys_response() -> dict[str, Any]:
    return {
        "result": {
            "hits": [
                {
                    "ip": "10.0.0.1",
                    "services": [
                        {"port": 80},
                        {"port": 443},
                    ],
                    "autonomous_system": {"asn": 99999, "name": "TestASN"},
                    "dns": {"names": ["mail.acme.com"]},
                },
            ]
        }
    }


# ---------------------------------------------------------------------------
# Discovery: Shodan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shodan_search_parses_matches():
    mock_resp = MagicMock()
    mock_resp.json.return_value = _fake_shodan_response()
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.easm_discovery.httpx.AsyncClient", return_value=mock_client):
        assets = await _shodan_search("org:AcmeCorp", "fake-key")

    ips = [a for a in assets if a.asset_type == ExternalAssetType.IP]
    subs = [a for a in assets if a.asset_type == ExternalAssetType.SUBDOMAIN]

    assert len(ips) == 2
    assert ips[0].value == "1.2.3.4"
    assert ips[0].metadata["source"] == "shodan"
    assert ips[0].metadata["ports"] == [443]

    assert len(subs) == 2
    assert {s.value for s in subs} == {"www.acme.com", "api.acme.com"}


@pytest.mark.asyncio
async def test_shodan_search_handles_error():
    import httpx

    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.ConnectError("connection refused")
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.easm_discovery.httpx.AsyncClient", return_value=mock_client):
        assets = await _shodan_search("org:AcmeCorp", "fake-key")

    assert assets == []


# ---------------------------------------------------------------------------
# Discovery: Censys
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_censys_search_parses_hits():
    mock_resp = MagicMock()
    mock_resp.json.return_value = _fake_censys_response()
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.easm_discovery.httpx.AsyncClient", return_value=mock_client):
        assets = await _censys_search("acme.com", "id", "secret")

    ips = [a for a in assets if a.asset_type == ExternalAssetType.IP]
    subs = [a for a in assets if a.asset_type == ExternalAssetType.SUBDOMAIN]

    assert len(ips) == 1
    assert ips[0].value == "10.0.0.1"
    assert 80 in ips[0].metadata["ports"]
    assert 443 in ips[0].metadata["ports"]

    assert len(subs) == 1
    assert subs[0].value == "mail.acme.com"


# ---------------------------------------------------------------------------
# Discovery: Active scan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_active_scan_open_ports():
    async def mock_probe(host, port, timeout=3.0):
        return port in (80, 443)

    with patch("app.services.easm_discovery._probe_port", side_effect=mock_probe):
        assets = await _active_scan(["192.168.1.1"], [22, 80, 443])

    assert len(assets) == 1
    assert assets[0].value == "192.168.1.1"
    assert assets[0].metadata["ports"] == [80, 443]
    assert assets[0].metadata["source"] == "active_scan"


@pytest.mark.asyncio
async def test_active_scan_no_open_ports():
    async def mock_probe(host, port, timeout=3.0):
        return False

    with patch("app.services.easm_discovery._probe_port", side_effect=mock_probe):
        assets = await _active_scan(["10.0.0.1"], [22, 80])

    assert assets == []


# ---------------------------------------------------------------------------
# Discovery: run_discovery orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_discovery_uses_configured_connectors():
    fake_settings = MagicMock()
    fake_settings.AISOC_EASM_SHODAN_API_KEY = "sk-test"
    fake_settings.AISOC_EASM_CENSYS_API_ID = ""
    fake_settings.AISOC_EASM_CENSYS_API_SECRET = ""
    fake_settings.AISOC_EASM_ACTIVE_SCAN_ENABLED = False
    fake_settings.AISOC_EASM_SCAN_PORTS = [80]

    shodan_asset = DiscoveredAsset(
        asset_type=ExternalAssetType.IP,
        value="1.2.3.4",
        metadata={"source": "shodan"},
    )

    with (
        patch("app.services.easm_discovery.get_settings", return_value=fake_settings),
        patch("app.services.easm_discovery._shodan_search", return_value=[shodan_asset]) as mock_shodan,
        patch("app.services.easm_discovery._censys_search") as mock_censys,
        patch("app.services.easm_discovery._active_scan") as mock_active,
    ):
        results = await run_discovery("org:Acme")

    mock_shodan.assert_awaited_once()
    mock_censys.assert_not_awaited()
    mock_active.assert_not_awaited()
    assert len(results) == 1
    assert results[0].value == "1.2.3.4"


@pytest.mark.asyncio
async def test_run_discovery_runs_active_when_enabled():
    fake_settings = MagicMock()
    fake_settings.AISOC_EASM_SHODAN_API_KEY = ""
    fake_settings.AISOC_EASM_CENSYS_API_ID = ""
    fake_settings.AISOC_EASM_CENSYS_API_SECRET = ""
    fake_settings.AISOC_EASM_ACTIVE_SCAN_ENABLED = True
    fake_settings.AISOC_EASM_SCAN_PORTS = [22, 80]

    active_asset = DiscoveredAsset(
        asset_type=ExternalAssetType.IP,
        value="10.0.0.1",
        metadata={"source": "active_scan", "ports": [22]},
    )

    with (
        patch("app.services.easm_discovery.get_settings", return_value=fake_settings),
        patch("app.services.easm_discovery._active_scan", return_value=[active_asset]) as mock_active,
    ):
        results = await run_discovery("org:Acme", ip_targets=["10.0.0.1"])

    mock_active.assert_awaited_once()
    assert len(results) == 1


# ---------------------------------------------------------------------------
# Drift: metadata merge
# ---------------------------------------------------------------------------

def test_merge_metadata_combines_ports():
    old = {"source": "shodan", "ports": [22, 80]}
    new = {"source": "censys", "ports": [80, 443]}
    merged = _merge_metadata(old, new)
    assert merged["ports"] == [22, 80, 443]
    assert merged["source"] == "censys"


def test_merge_metadata_no_ports():
    old = {"source": "shodan", "org": "Acme"}
    new = {"source": "censys", "asn": "AS123"}
    merged = _merge_metadata(old, new)
    assert "ports" not in merged or merged["ports"] == []
    assert merged["org"] == "Acme"
    assert merged["asn"] == "AS123"


# ---------------------------------------------------------------------------
# Drift: port drift detection
# ---------------------------------------------------------------------------

def test_detect_port_drift_new_ports():
    old = {"ports": [22, 80]}
    new = {"ports": [22, 80, 443, 8080]}
    drifts = _detect_port_drift(old, new)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == "new_port"
    assert set(drifts[0]["details"]["ports"]) == {443, 8080}


def test_detect_port_drift_gone_ports():
    old = {"ports": [22, 80, 443]}
    new = {"ports": [443]}
    drifts = _detect_port_drift(old, new)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == "gone_port"
    assert set(drifts[0]["details"]["ports"]) == {22, 80}


def test_detect_port_drift_both_directions():
    old = {"ports": [22, 80]}
    new = {"ports": [80, 443]}
    drifts = _detect_port_drift(old, new)
    types = {d["drift_type"] for d in drifts}
    assert types == {"new_port", "gone_port"}


def test_detect_port_drift_no_change():
    old = {"ports": [22, 80]}
    new = {"ports": [22, 80]}
    drifts = _detect_port_drift(old, new)
    assert drifts == []


# ---------------------------------------------------------------------------
# Drift: detect_drift integration (mock DB)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_drift_new_asset():
    """A brand-new asset should produce a 'new_asset' drift record."""
    db = AsyncMock()
    db.add = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    db.execute.return_value = execute_result
    db.flush = AsyncMock()

    discovered = [
        DiscoveredAsset(
            asset_type=ExternalAssetType.IP,
            value="9.9.9.9",
            metadata={"source": "shodan", "ports": [443]},
        ),
    ]

    records = await detect_drift(db, TENANT_ID, discovered)
    assert len(records) == 1
    assert records[0].drift_type == "new_asset"
    assert records[0].details["value"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_detect_drift_existing_asset_port_change():
    """An existing asset with new ports should produce new_port drift."""
    existing_asset = MagicMock(spec=ExternalAsset)
    existing_asset.id = uuid.uuid4()
    existing_asset.metadata_json = {"source": "shodan", "ports": [22]}
    existing_asset.last_seen = datetime(2025, 1, 1, tzinfo=timezone.utc)

    db = AsyncMock()

    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = existing_asset
        return result

    db.execute = mock_execute
    db.flush = AsyncMock()
    db.add = MagicMock()

    discovered = [
        DiscoveredAsset(
            asset_type=ExternalAssetType.IP,
            value="1.2.3.4",
            metadata={"source": "shodan", "ports": [22, 443]},
        ),
    ]

    records = await detect_drift(db, TENANT_ID, discovered)
    new_port_drifts = [r for r in records if r.drift_type == "new_port"]
    assert len(new_port_drifts) == 1
    assert 443 in new_port_drifts[0].details["ports"]
