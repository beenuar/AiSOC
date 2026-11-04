"""CrowdStrike's investigation read must use the Alerts API, not `/detects`.

Issue #1695 reported the *connector* 404ing on
`/detects/queries/detects/v1`, decommissioned on 2025-09-30. The same two
endpoints are called a second time in this service, by
`CrowdStrikeRTRClient.get_detections`, and that copy fails worse than the
connector does.

`get_detections` logs a warning and returns `[]` on a non-200, so
`CrowdStrikeGetDetections` never sees an exception: it reports `SUCCEEDED`
with `count: 0`, and an investigation reads "no detections on this host" —
the strongest exonerating evidence there is — from a call that 404s on every
deployment. Its own docstring names that hazard. `test_..._phase4.py` already
pins the opposite behaviour for SentinelOne and Defender; CrowdStrike was the
vendor without the pin.

Every payload here is **synthetic**, shaped to the Alerts API response schema
as published in CrowdStrike's own `falconpy` endpoint table (`PostCombinedAlertsV1`)
and corroborated against Elastic's CrowdStrike alert field mapping. No call in
this file reaches a real vendor, and no live CrowdStrike call was made to
produce it.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

import httpx
import pytest
import respx
from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.live_actions.investigation_reads import CrowdStrikeGetDetections
from app.live_actions.models import LiveActionRequest, LiveActionStatus

CS = "https://api.eu-1.crowdstrike.com"
ALERTS = f"{CS}/alerts/combined/alerts/v1"
TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
CREDS = {"cs_client_id": "id", "cs_client_secret": "secret", "cs_base_url": CS}


def _request(target: str, params: Mapping[str, Any]) -> LiveActionRequest:
    return LiveActionRequest(
        request_id=uuid.uuid4(),
        capability="get_detections",
        vendor_id="crowdstrike",
        target=target,
        params=dict(params),
        dry_run=False,
        tenant_id=TENANT,
    )


def _token() -> None:
    respx.post(f"{CS}/oauth2/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))


def _device() -> None:
    respx.get(f"{CS}/devices/queries/devices/v1").mock(return_value=httpx.Response(200, json={"resources": ["aid-1"]}))


def _alert() -> dict[str, Any]:
    """One alert as `POST /alerts/combined/alerts/v1` returns it.

    Note where the fields sit: `tactic`, `technique`, `filename` and `sha256`
    are on the alert itself. On the decommissioned Detects payload they lived
    under `behaviors[0]`, which is why reading them from there returns None
    against a real Alerts response.
    """
    return {
        "composite_id": "abc:ind:1",
        "severity": 95,
        "severity_name": "Critical",
        "display_name": "Credential dumping",
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003.001",
        "filename": "procdump64.exe",
        "sha256": "d" * 64,
        "status": "new",
        "product": "epp",
        "created_timestamp": "2026-11-04T15:00:00Z",
        "device": {"device_id": "aid-1", "hostname": "WKSTN-01"},
    }


class TestEndpoint:
    @pytest.mark.asyncio
    @respx.mock
    async def test_get_detections_uses_the_alerts_api_not_decommissioned_detects(self):
        _token()
        alerts = respx.post(ALERTS).mock(return_value=httpx.Response(200, json={"resources": [_alert()]}))
        detects = respx.route(path__startswith="/detects/").mock(return_value=httpx.Response(404))

        rows = await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1")

        assert alerts.called, "get_detections must query the Alerts API"
        assert not detects.called, "the Detects API was decommissioned on 2025-09-30"
        assert len(rows) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_query_scopes_to_the_device_and_sorts_on_an_alerts_field(self):
        # `last_behavior` is a Detects field and does not exist on an Alert, so
        # the old sort would be rejected even once the path was corrected.
        _token()
        route = respx.post(ALERTS).mock(return_value=httpx.Response(200, json={"resources": []}))

        await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1", limit=5)

        body = route.calls.last.request.content.decode()
        assert "device.device_id:'aid-1'" in body
        assert "last_behavior" not in body
        assert "created_timestamp" in body


class TestFieldMapping:
    @pytest.mark.asyncio
    @respx.mock
    async def test_alert_level_fields_are_read_from_the_alert(self):
        _token()
        respx.post(ALERTS).mock(return_value=httpx.Response(200, json={"resources": [_alert()]}))

        row = (await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1"))[0]

        assert row["detection_id"] == "abc:ind:1"
        assert row["severity"] == "Critical"
        assert row["tactic"] == "Credential Access"
        assert row["technique"] == "OS Credential Dumping"
        assert row["filename"] == "procdump64.exe"
        assert row["sha256"] == "d" * 64
        assert row["status"] == "new"


def _decommissioned_detects() -> None:
    """What `/detects/*` answers today: 404, as issue #1695 recorded.

    Mocked explicitly rather than left unmocked. An unmocked route makes respx
    raise, and a `pytest.raises` around that passes against the broken tree —
    the test would be green for respx's reason instead of the product's.
    """
    respx.route(path__startswith="/detects/").mock(return_value=httpx.Response(404, text="Not Found"))


class TestFailureIsNotAbsence:
    @pytest.mark.asyncio
    @respx.mock
    async def test_a_failed_read_raises_rather_than_returning_no_detections(self):
        _token()
        _decommissioned_detects()
        respx.post(ALERTS).mock(return_value=httpx.Response(500, text="boom"))

        with pytest.raises(Exception):  # noqa: B017 — the type is the fix's choice; the raise is the contract
            await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1")

    @pytest.mark.asyncio
    @respx.mock
    async def test_executor_reports_failed_and_publishes_no_count(self):
        _token()
        _device()
        _decommissioned_detects()
        respx.post(ALERTS).mock(return_value=httpx.Response(500, text="boom"))

        result = await CrowdStrikeGetDetections().execute(_request("WKSTN-01", CREDS))

        assert result.status is LiveActionStatus.FAILED
        # A `count: 0` here would be read as "the EDR has nothing on this
        # host", which is the strongest possible exonerating evidence and
        # would be false. Same contract as SentinelOne and Defender.
        assert "count" not in result.details
        assert "detections" not in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_missing_alerts_scope_names_the_permission(self):
        # An API client carrying only the RTR scopes authenticates fine and is
        # refused here, which is indistinguishable from "no detections" unless
        # the refusal is surfaced with the scope that is missing.
        _token()
        respx.post(ALERTS).mock(return_value=httpx.Response(403, json={"errors": [{"message": "access denied"}]}))

        with pytest.raises(Exception, match="Alerts: Read"):
            await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1")

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_empty_alerts_page_is_still_no_detections(self):
        # The positive control for the above: a successful read with nothing
        # in it must stay an empty list, or the fix would make every clean
        # host look like an outage.
        _token()
        respx.post(ALERTS).mock(return_value=httpx.Response(200, json={"resources": []}))

        assert await CrowdStrikeRTRClient("id", "secret", CS).get_detections("aid-1") == []
