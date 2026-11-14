"""Depth plan 4.1 — Entra and Activity logs off an Event Hub's Capture output.

Two fixtures carry the vendor shapes: ``list_paths.json`` is a Data Lake
Gen2 ``List Paths`` response as the service returns it, and
``capture_block.avro`` is a binary Avro container holding two Event Hubs
Capture events whose bodies are Azure Monitor diagnostic batches (a failed
high-risk sign-in, a role assignment, and a denied VM delete).

What that fixture is, stated plainly: it was **synthesised from the Avro
specification and Microsoft's documented Capture schema**, not recorded from
a live Event Hub, because no Azure subscription is available to this
repository. It is committed as bytes and the expectations below are written
independently of the decoder, so the decoder is graded against a fixed
artefact rather than against itself — but a decoder and a fixture that share
an author share a misreading of the specification, and only a capture from a
real hub closes that. Recorded in `DEPTH_PROGRESS.md` as an open
verification gap rather than left for a reader to discover.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from app.connectors.azure_event_hubs import AzureEventHubsConnector, _identity_name, _location, _record_severity

FIXTURES = Path(__file__).parent / "fixtures" / "azure_event_hubs"
_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ACCOUNT = "contosologs"
_CONTAINER = "insights-logs"
_DFS_ROOT = f"https://{_ACCOUNT}.dfs.core.windows.net/{_CONTAINER}"
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
_CAPTURE_PATH = "contoso-ns/aisoc-hub/0/2026/10/08/11/25/00.avro"


def _connector(**kwargs: Any) -> AzureEventHubsConnector:
    defaults: dict[str, Any] = {
        "tenant_id": _TENANT,
        "client_id": "11111111-2222-3333-4444-555555555555",
        "client_secret": "s3cr3t",
        "storage_account": _ACCOUNT,
        "container": _CONTAINER,
    }
    defaults.update(kwargs)
    return AzureEventHubsConnector(**defaults)


def _mock_token() -> None:
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "eyJ.test", "expires_in": 3599}))


def _mock_listing() -> Any:
    payload = json.loads((FIXTURES / "list_paths.json").read_text(encoding="utf-8"))
    return respx.get(_DFS_ROOT).mock(return_value=httpx.Response(200, json=payload))


def _mock_capture() -> Any:
    blob = (FIXTURES / "capture_block.avro").read_bytes()
    return respx.get(f"{_DFS_ROOT}/{_CAPTURE_PATH}").mock(return_value=httpx.Response(200, content=blob))


class TestSeverity:
    def test_a_successful_sign_in_keeps_its_level(self) -> None:
        assert _record_severity({"category": "SignInLogs", "level": "Informational", "resultType": "0"}) == "info"

    def test_a_failed_sign_in_is_raised_above_the_level(self) -> None:
        """A sign-in log is mostly successes; the failures are the half worth
        looking at, and Azure files many of them at Informational."""
        assert _record_severity({"category": "SignInLogs", "level": "Informational", "resultType": "50126"}) == "medium"

    def test_entras_own_high_risk_verdict_becomes_critical(self) -> None:
        record = {"category": "SignInLogs", "level": "Error", "resultType": "0", "properties": {"riskLevelDuringSignIn": "high"}}
        assert _record_severity(record) == "critical"

    def test_a_successful_role_assignment_outranks_a_failed_one(self) -> None:
        """Adding a member to a role is the privilege-escalation primitive.
        The success is the finding; the failure is an attempt."""
        granted = {"category": "AuditLogs", "operationName": "Add member to role", "properties": {"result": "success"}}
        refused = {"category": "AuditLogs", "operationName": "Add member to role", "properties": {"result": "failure"}}
        assert _record_severity(granted) == "high"
        assert _record_severity(refused) == "medium"

    def test_azures_critical_level_is_not_collapsed_into_high(self) -> None:
        assert _record_severity({"category": "Administrative", "level": "Critical", "resultType": "Success"}) == "critical"

    def test_a_failed_activity_log_operation_is_at_least_medium(self) -> None:
        assert _record_severity({"category": "Administrative", "level": "Informational", "resultType": "Failed"}) == "medium"


class TestIdentityAndLocation:
    def test_the_three_shapes_azure_uses_for_a_principal(self) -> None:
        """A single `.get("identity")` returns a dict for the Activity log and
        renders as `{'claims': ...}` in the console."""
        assert _identity_name({"properties": {"userPrincipalName": "alice@example.com"}}) == "alice@example.com"
        initiated = {"properties": {"initiatedBy": {"user": {"userPrincipalName": "mallory@example.com"}}}}
        assert _identity_name(initiated) == "mallory@example.com"
        claims = {"identity": {"claims": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "contractor@example.com"}}}
        assert _identity_name(claims) == "contractor@example.com"

    def test_an_unattributable_record_says_so_rather_than_inventing(self) -> None:
        assert _identity_name({"category": "Administrative"}) is None

    def test_location_reads_both_the_nested_object_and_the_flat_string(self) -> None:
        assert _location({"properties": {"location": {"city": "London", "countryOrRegion": "GB"}}}) == "GB"
        assert _location({"location": "westeurope"}) == "westeurope"


class TestAPoll:
    @pytest.mark.asyncio
    @respx.mock
    async def test_capture_files_become_normalized_records(self) -> None:
        _mock_token()
        _mock_listing()
        _mock_capture()

        alerts = await _connector().fetch_alerts()

        assert [a["log_category"] for a in alerts] == ["SignInLogs", "AuditLogs", "Administrative"]
        assert [a["category"] for a in alerts] == ["identity", "identity", "cloud"]
        assert alerts[0]["user_name"] == "alice@example.com"
        assert alerts[0]["src_ip"] == "198.51.100.24"
        assert alerts[0]["severity"] == "critical"
        assert alerts[1]["user_name"] == "mallory@example.com"
        assert alerts[2]["user_name"] == "contractor@example.com"
        assert alerts[2]["result_type"] == "Failed"

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_batch_inside_one_event_is_unpacked(self) -> None:
        """Azure Monitor batches several records into one event body. A reader
        that treats the body as a single record silently keeps the first."""
        _mock_token()
        _mock_listing()
        _mock_capture()

        assert len(await _connector().fetch_alerts()) == 3

    @pytest.mark.asyncio
    @respx.mock
    async def test_zero_length_capture_files_are_not_opened(self) -> None:
        """Capture writes an empty file for every window the hub was idle in.
        Opening them costs a round trip each and yields nothing."""
        _mock_token()
        _mock_listing()
        reads = _mock_capture()

        await _connector().fetch_alerts()

        assert reads.call_count == 1, "only the one file with a non-zero contentLength is read"

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_unreadable_capture_file_does_not_strand_the_poll(self) -> None:
        _mock_token()
        _mock_listing()
        respx.get(f"{_DFS_ROOT}/{_CAPTURE_PATH}").mock(return_value=httpx.Response(200, content=b"not avro at all"))

        assert await _connector().fetch_alerts() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_re_read_file_is_suppressed_by_the_cursor(self) -> None:
        """Capture files are never deleted — the storage account is the
        customer's — so every poll sees the same files and the cursor is the
        only thing that stops every record arriving again."""
        _mock_token()
        _mock_listing()
        _mock_capture()
        first = _connector()
        assert len(await first.fetch_alerts()) == 3
        cursor = first.get_checkpoint()
        assert cursor is not None

        resumed = _connector()
        resumed.set_checkpoint(cursor)
        assert await resumed.fetch_alerts() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_prefix_narrows_the_listing(self) -> None:
        _mock_token()
        listing = _mock_listing()
        _mock_capture()

        await _connector(prefix="contoso-ns/aisoc-hub").fetch_alerts()

        assert listing.calls.last.request.url.params["directory"] == "contoso-ns/aisoc-hub"


class TestBackpressure:
    def test_the_budget_is_declared_and_says_where_the_remainder_goes(self) -> None:
        budget = AzureEventHubsConnector.collection_budget
        assert budget is not None
        assert budget.max_batches_per_poll > 0
        assert budget.max_events_per_poll > 0
        assert "next poll" in budget.backlog_stays_on_the_queue

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_listing_asks_for_no_more_files_than_the_budget(self) -> None:
        """A first poll against a month of captured sign-in logs would
        otherwise list and read all of it."""
        from app.connectors import base as base_mod

        _mock_token()
        listing = _mock_listing()
        _mock_capture()
        connector = _connector()
        connector.collection_budget = base_mod.CollectionBudget(  # type: ignore[misc]
            max_batches_per_poll=3,
            max_events_per_poll=10,
            backlog_stays_on_the_queue="test bound; the rest is left for the next poll",
        )

        await connector.fetch_alerts()

        assert int(listing.calls.last.request.url.params["maxResults"]) == 3


class TestTestConnection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_an_empty_container_names_the_likely_cause(self) -> None:
        """A credential that works, a container that exists, and no events
        ever. "Capture was never switched on" is invisible otherwise."""
        _mock_token()
        respx.get(_DFS_ROOT).mock(return_value=httpx.Response(200, json={"paths": []}))

        result = await _connector().test_connection()

        assert result["success"] is True
        assert "Enable Capture" in result["warning"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_rejected_credential_is_reported_rather_than_raised(self) -> None:
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))

        result = await _connector().test_connection()

        assert result["success"] is False
        assert "401" in result["error"]
