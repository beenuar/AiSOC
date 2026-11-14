"""Tests for the Oracle Cloud Infrastructure (OCI) audit connector (T4.15).

Brings the wave-2 ``oci`` connector to wave-1 test parity: schema +
registry wiring, the eventName->severity collapse (high-risk Delete*,
medium Create/Update/ChangeCompartment, failed-call floor to low), the
cloudevents-style ``data`` unwrapping, the ``opc-next-page`` header
pagination, and ``test_connection``. The OCI request signer is absent in
tests (the SDK isn't installed); respx intercepts before signing matters.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.oci import OCIConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "oci" / "sample_event.json"
_BASE = "https://audit.us-ashburn-1.oraclecloud.com"
_PATH = "/20190901/auditEvents"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def _connector() -> OCIConnector:
    return OCIConnector(
        tenancy_ocid="ocid1.tenancy.oc1..aaa",
        user_ocid="ocid1.user.oc1..bbb",
        compartment_ocid="ocid1.compartment.oc1..ccc",
        fingerprint="aa:bb:cc:dd",
        private_key_pem="-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n",
        region="us-ashburn-1",
    )


def test_schema_valid():
    schema = OCIConnector.schema()
    assert schema.connector_id == "oci"
    assert schema.category == "cloud"
    names = {f.name for f in schema.fields}
    assert {"tenancy_ocid", "user_ocid", "compartment_ocid", "fingerprint", "private_key_pem", "region"} <= names
    assert Capability.PULL_AUDIT in OCIConnector.capabilities()


def test_registry_contains_oci():
    assert "oci" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["oci"] is OCIConnector


def test_normalize_delete_user_to_high(fixture):
    out = _connector().normalize(fixture[0])
    assert out["severity"] == "high"
    assert out["external_id"] == "oci-delete-user"
    assert out["actor"] == "admin"
    assert out["src_ip"] == "203.0.113.7"


def test_normalize_create_user_to_medium(fixture):
    assert _connector().normalize(fixture[1])["severity"] == "medium"


def test_normalize_list_buckets_to_info(fixture):
    assert _connector().normalize(fixture[2])["severity"] == "info"


def test_normalize_failed_call_floors_to_low(fixture):
    """A non-risky read that returned >=400 surfaces as low, not info."""
    assert _connector().normalize(fixture[3])["severity"] == "low"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_opc_next_page(fixture, monkeypatch):
    monkeypatch.setattr("app.connectors.oci._PER_PAGE", 2)
    c = _connector()
    route = respx.get(f"{_BASE}{_PATH}")
    route.side_effect = [
        httpx.Response(200, json=fixture[:2], headers={"opc-next-page": "cur1"}),
        httpx.Response(200, json=fixture[2:3]),  # short, no header → stop
    ]
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == 3
    assert all(e["source"] == "oci" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = _connector()
    respx.get(f"{_BASE}{_PATH}").respond(200, json=[])
    res = await c.test_connection()
    assert res["success"] is True
    assert res["region"] == "us-ashburn-1"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = _connector()
    respx.get(f"{_BASE}{_PATH}").respond(401, json={"message": "NotAuthenticated"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "401" in res["error"]
