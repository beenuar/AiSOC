"""
Unit tests for the osctrl + FleetDM osquery-fleet connectors.

These tests follow the same pattern as ``test_saas_connectors.py``:

  1. Schema sanity — the wizard form has the fields the docs promise and
     the secret-typed fields are masked.
  2. ``normalize()`` produces the canonical AiSOC alert shape and applies
     the table-driven severity ladder.
  3. HTTP routing through ``respx`` exercises the real ``httpx`` paths
     and proves we hit the documented osctrl / Fleet endpoints.

We intentionally do not test against a live osctrl or Fleet instance
here — those are integration tests that live with the docker-compose
harness in PR4.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.base import Capability
from app.connectors.fleetdm import FleetDMConnector
from app.connectors.osctrl import OsctrlConnector

OSCTRL_BASE = "https://osctrl.test.local"
OSCTRL_TOKEN = "osctrl-fake-admin-token"
OSCTRL_ENV = "prod"

FLEET_BASE = "https://fleet.test.local"
FLEET_TOKEN = "fleet-fake-token"


# ===========================================================================
# osctrl
# ===========================================================================


def test_osctrl_schema_has_required_fields():
    schema = OsctrlConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"base_url", "api_token", "environment", "verify_tls"} <= names
    assert schema.category == "edr"
    token = next(f for f in schema.fields if f.name == "api_token")
    assert token.type == "secret"


def test_osctrl_capabilities_include_query_and_pivot():
    caps = set(OsctrlConnector.capabilities())
    # PR1 only declares the read + query verbs. The kinetic verbs that
    # PR3 layers on (live-query response action) are not declared here
    # because the action is dispatched via the action client, not the
    # connector itself.
    assert Capability.PULL_LOGS in caps
    assert Capability.QUERY_LOGS in caps
    assert Capability.QUERY_PROCESSES in caps
    assert Capability.PIVOT_HOST in caps


def test_osctrl_normalize_high_severity_for_persistence_table():
    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    raw = {
        "query": {
            "name": "list-startup-items",
            "uuid": "q-1",
            "query": "select * from startup_items where username='root'",
        },
        "row": {
            "uuid": "host-uuid-1",
            "hostname": "macbook-01.corp",
            "name": "evil.app",
            "path": "/Library/StartupItems/evil",
        },
        "environment": OSCTRL_ENV,
    }
    normalized = connector.normalize(raw)
    assert normalized["source"] == "osctrl"
    assert normalized["category"] == "endpoint"
    assert normalized["severity"] == "high"
    assert normalized["hostname"] == "macbook-01.corp"
    assert normalized["host"] == "macbook-01.corp"
    assert normalized["osquery_table"] == "startup_items"
    assert normalized["raw_event"]["path"] == "/Library/StartupItems/evil"
    # Flattened osquery columns must be reachable at the top level so
    # detection rules can match on them via match_when (the matcher
    # only reads top-level fields).
    assert normalized["path"] == "/Library/StartupItems/evil"
    assert normalized["name"] == "evil.app"
    assert normalized["query_name"] == "list-startup-items"
    # event_type is the stable handle detection authors use to scope
    # rules to osquery row events (vs. EndpointSecurity 'exec' events).
    assert normalized["event_type"] == "osquery_query_row"


def test_osctrl_normalize_inventory_table_is_info():
    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    raw = {
        "query": {
            "name": "uptime",
            "uuid": "q-2",
            "query": "select * from uptime",
        },
        "row": {"hostname": "linux-edge-01", "days": 12},
    }
    normalized = connector.normalize(raw)
    assert normalized["severity"] == "info"
    assert normalized["osquery_table"] == "uptime"


def test_osctrl_normalize_unknown_table_defaults_medium():
    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    raw = {
        "query": {
            "name": "custom-thing",
            "uuid": "q-3",
            "query": "select * from totally_made_up_table",
        },
        "row": {"hostname": "h1"},
    }
    assert connector.normalize(raw)["severity"] == "medium"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_osctrl_test_connection_ok(respx_mock):
    respx_mock.get(f"{OSCTRL_BASE}/api/v1/nodes").mock(return_value=httpx.Response(200, json={"nodes": []}))
    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    result = await connector.test_connection()
    assert result["success"] is True


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_osctrl_test_connection_auth_failure(respx_mock):
    respx_mock.get(f"{OSCTRL_BASE}/api/v1/nodes").mock(return_value=httpx.Response(401))
    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "auth" in result["error"].lower()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_osctrl_fetch_alerts_pulls_query_results(respx_mock):
    queries_payload = [
        {
            "name": "running-processes",
            "uuid": "q-aa",
            "query": "select pid, name from processes",
            "created_at": "2099-01-01T00:00:00Z",  # always within window
        },
        {
            "name": "stale-q",
            "uuid": "q-bb",
            "query": "select * from system_info",
            "created_at": "1970-01-01T00:00:00Z",  # ancient — should skip
        },
    ]
    results_payload = {
        "results": [
            {"hostname": "h1", "pid": "100", "name": "ssh"},
            {"hostname": "h2", "pid": "200", "name": "bash"},
        ]
    }

    respx_mock.get(f"{OSCTRL_BASE}/api/v1/queries/{OSCTRL_ENV}/list").mock(return_value=httpx.Response(200, json=queries_payload))
    respx_mock.get(f"{OSCTRL_BASE}/api/v1/queries/{OSCTRL_ENV}/results/running-processes").mock(
        return_value=httpx.Response(200, json=results_payload)
    )

    connector = OsctrlConnector(OSCTRL_BASE, OSCTRL_TOKEN, OSCTRL_ENV)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 2
    assert {e["hostname"] for e in events} == {"h1", "h2"}
    # All rows must inherit the query's source + table
    assert all(e["osquery_table"] == "processes" for e in events)
    assert all(e["source"] == "osctrl" for e in events)


# ===========================================================================
# FleetDM
# ===========================================================================


def test_fleetdm_schema_has_required_fields():
    schema = FleetDMConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"base_url", "api_token", "team_id", "verify_tls"} <= names
    assert schema.category == "edr"
    token = next(f for f in schema.fields if f.name == "api_token")
    assert token.type == "secret"


def test_fleetdm_capabilities_match_osctrl():
    caps = set(FleetDMConnector.capabilities())
    assert Capability.PULL_LOGS in caps
    assert Capability.QUERY_LOGS in caps
    assert Capability.QUERY_PROCESSES in caps
    assert Capability.PIVOT_HOST in caps


def test_fleetdm_normalize_host_status_missing_is_medium():
    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    raw = {
        "kind": "host",
        "host": {
            "id": 17,
            "hostname": "ws-finance-04",
            "platform": "darwin",
            "os_version": "macOS 14.5",
            "status": "missing",
        },
    }
    norm = connector.normalize(raw)
    assert norm["source"] == "fleetdm"
    assert norm["severity"] == "medium"
    assert norm["hostname"] == "ws-finance-04"
    assert norm["external_id"] == "17"
    assert "missing" in norm["title"].lower()


def test_fleetdm_normalize_host_status_online_is_info():
    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    raw = {
        "kind": "host",
        "host": {"id": 1, "hostname": "h1", "status": "online"},
    }
    assert connector.normalize(raw)["severity"] == "info"


def test_fleetdm_normalize_query_row_uses_table_severity():
    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    raw = {
        "kind": "query_row",
        "query": {
            "id": 5,
            "name": "scheduled-tasks",
            "query": "select * from scheduled_tasks where state='Ready'",
        },
        "row": {
            "host_id": 22,
            "host_hostname": "win-jumphost",
            "name": "evil-task",
        },
    }
    norm = connector.normalize(raw)
    assert norm["severity"] == "high"
    assert norm["osquery_table"] == "scheduled_tasks"
    assert norm["hostname"] == "win-jumphost"
    # Flattened osquery columns reachable at the top level
    assert norm["name"] == "evil-task"
    assert norm["host_id"] == 22
    assert norm["event_type"] == "osquery_query_row"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fleetdm_test_connection_ok(respx_mock):
    respx_mock.get(f"{FLEET_BASE}/api/v1/fleet/me").mock(return_value=httpx.Response(200, json={"user": {"id": 1}}))
    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    res = await connector.test_connection()
    assert res["success"] is True


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fleetdm_test_connection_unauthorised(respx_mock):
    respx_mock.get(f"{FLEET_BASE}/api/v1/fleet/me").mock(return_value=httpx.Response(403))
    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    res = await connector.test_connection()
    assert res["success"] is False


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_fleetdm_fetch_alerts_returns_hosts_and_query_rows(respx_mock):
    respx_mock.get(f"{FLEET_BASE}/api/v1/fleet/hosts").mock(
        return_value=httpx.Response(
            200,
            json={
                "hosts": [
                    {
                        "id": 7,
                        "hostname": "ws-finance-04",
                        "platform": "darwin",
                        "os_version": "macOS 14.5",
                        "status": "missing",
                    }
                ]
            },
        )
    )
    respx_mock.get(f"{FLEET_BASE}/api/v1/fleet/queries").mock(
        return_value=httpx.Response(
            200,
            json={
                "queries": [
                    {
                        "id": 3,
                        "name": "running-procs",
                        "query": "select pid, name from processes",
                    }
                ]
            },
        )
    )
    respx_mock.get(f"{FLEET_BASE}/api/v1/fleet/queries/3/report").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "host_id": 7,
                        "host_hostname": "ws-finance-04",
                        "pid": "1234",
                        "name": "suspicious",
                    }
                ]
            },
        )
    )

    connector = FleetDMConnector(FLEET_BASE, FLEET_TOKEN)
    events = await connector.fetch_alerts(since_seconds=999_999_999)
    # one host event + one query-row event
    assert len(events) == 2
    kinds = {e["raw"].get("kind") for e in events}
    assert kinds == {"host", "query_row"}


# ===========================================================================
# Registry sanity
# ===========================================================================


def test_both_connectors_register_under_expected_ids():
    from app.connectors import CONNECTOR_REGISTRY

    assert CONNECTOR_REGISTRY["osctrl"] is OsctrlConnector
    assert CONNECTOR_REGISTRY["fleetdm"] is FleetDMConnector
