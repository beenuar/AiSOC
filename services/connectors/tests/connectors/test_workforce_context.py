"""HR and device context has to reach triage, not just exist.

Depth plan wave 2, item 1.3.

Three things are asserted here and each one has failed in this repository
before, in this order of severity:

1. **The connector is registered.** A class in the tree that is not in
   `_CONNECTOR_CLASSES` is invisible to the catalogue, the wizard and the
   scheduler.
2. **The scheduler actually syncs it.** The defining defect of this tree is
   a mechanism with no caller. An HR connector whose `fetch_workforce` is
   called by nothing is indistinguishable from no connector at all, and the
   plan says so explicitly: the import must run on the schedule, not only on
   the manual route.
3. **The vendor shapes are real.** Every read is replayed against a
   recorded, vendor-shaped payload through a mock transport, following
   `test_live_vendor_smoke.py`. The field names come from each vendor's
   current public reference, cited in the connector module.

The mock payloads are synthetic and labelled as such. They carry the field
names and the response envelope the vendor documents, and nothing else.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.connectors import _CONNECTOR_CLASSES  # noqa: E402
from app.connectors.bamboohr import BambooHRConnector  # noqa: E402
from app.connectors.microsoft_intune import MicrosoftIntuneConnector  # noqa: E402
from app.connectors.rippling import RipplingConnector  # noqa: E402
from app.workforce import WorkforceRecord  # noqa: E402

WORKFORCE_CONNECTOR_IDS = {"bamboohr", "rippling", "microsoft_intune"}


def _registered() -> set[str]:
    return {cls.connector_id for cls in _CONNECTOR_CLASSES}


class TestRegistration:
    def test_every_workforce_connector_is_in_the_registry(self) -> None:
        missing = WORKFORCE_CONNECTOR_IDS - _registered()
        assert not missing, f"not in _CONNECTOR_CLASSES, so invisible to the catalogue and the scheduler: {sorted(missing)}"

    def test_secrets_are_declared_secret(self) -> None:
        """A credential field typed `string` renders in the clear and is
        stored unencrypted, because the vault keys off the declared type."""
        expected_secret = {
            "bamboohr": {"api_key"},
            "rippling": {"api_token"},
            "microsoft_intune": {"client_secret"},
        }
        for cls in (BambooHRConnector, RipplingConnector, MicrosoftIntuneConnector):
            declared = {f.name for f in cls.schema().fields if f.type == "secret"}
            assert declared == expected_secret[cls.connector_id], cls.connector_id

    def test_each_declares_the_workforce_capability(self) -> None:
        from app.connectors.base import Capability

        for cls in (BambooHRConnector, RipplingConnector, MicrosoftIntuneConnector):
            assert Capability.PULL_WORKFORCE in cls.capabilities(), cls.connector_id


class TestSchedulerRunsTheImport:
    """The wiring half. `import_context` had exactly one production caller
    before this work -- a manual POST route -- so a tenant's HR data was only
    ever as current as the last time somebody uploaded a file."""

    def test_the_scheduler_calls_a_workforce_sync_on_every_poll(self) -> None:
        import inspect

        from app.scheduler import ConnectorScheduler

        source = inspect.getsource(ConnectorScheduler._poll_one)
        assert "_sync_workforce_context" in source, (
            "the poll path does not sync workforce context, so an HR connector would be "
            "registered, configured, polled and silently ignored"
        )

    @pytest.mark.asyncio
    async def test_a_connector_without_the_method_is_skipped_quietly(self) -> None:
        """An EDR connector must not be asked for an employee roster."""
        from app.scheduler import ConnectorScheduler

        scheduler = ConnectorScheduler.__new__(ConnectorScheduler)
        scheduler._engine = None
        # No `fetch_workforce` attribute at all: the sync returns without
        # touching the engine, which is None here precisely so that a sync
        # that tried would raise rather than pass.
        await ConnectorScheduler._sync_workforce_context(scheduler, object(), object())


def _transport(handler):  # noqa: ANN001, ANN202
    return httpx.MockTransport(handler)


class TestBambooHRVendorShape:
    """Recorded against `GET /api/v1/employees/{id}` with an explicit field
    list, documented at documentation.bamboohr.com.

    The directory endpoint is deliberately NOT used: its own reference says
    it "never includes ... employment status and history, in any
    configuration" and excludes former employees entirely -- which is
    precisely the population this feature exists to see.
    """

    @pytest.mark.asyncio
    async def test_it_reads_the_fields_1_3_names_and_nothing_else(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            if request.url.path.endswith("/employees/directory"):
                return httpx.Response(
                    200,
                    json={
                        "fields": [{"id": "displayName"}, {"id": "workEmail"}],
                        "employees": [{"id": "431", "displayName": "Ada Byron", "workEmail": "ada@example.com"}],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "id": "431",
                    "displayName": "Ada Byron",
                    "workEmail": "ada@example.com",
                    "department": "Platform Engineering",
                    "jobTitle": "Staff Engineer",
                    "supervisorEid": "12",
                    "hireDate": "2021-03-01",
                    "terminationDate": "2026-11-14",
                    "status": "Active",
                    "employmentHistoryStatus": "Full-Time",
                },
            )

        connector = BambooHRConnector(subdomain="acme", api_key="k", transport=_transport(handler))
        records = await connector.fetch_workforce()

        assert len(records) == 1
        record = records[0]
        assert isinstance(record, WorkforceRecord)
        assert record.external_id == "431"
        assert record.email == "ada@example.com"
        assert record.department == "Platform Engineering"
        assert record.manager_external_id == "12"
        assert record.start_date == "2021-03-01"
        assert record.end_date == "2026-11-14"
        assert record.worker_type == "employee"
        # The request must ask for the fields, not hope for them: a reader
        # that does not name a column cannot recover it with an adapter.
        assert "terminationDate" in seen["url"]
        assert "hireDate" in seen["url"]

    @pytest.mark.asyncio
    async def test_a_contractor_is_reported_as_one(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/employees/directory"):
                return httpx.Response(200, json={"fields": [], "employees": [{"id": "7"}]})
            return httpx.Response(
                200,
                json={"id": "7", "employmentHistoryStatus": "Contractor", "status": "Active"},
            )

        connector = BambooHRConnector(subdomain="acme", api_key="k", transport=_transport(handler))
        assert (await connector.fetch_workforce())[0].worker_type == "contractor"


class TestRipplingVendorShape:
    """Recorded against `GET https://rest.ripplingapis.com/workers/`, OAuth
    scope `workers.read`, documented at developer.rippling.com."""

    @pytest.mark.asyncio
    async def test_it_maps_the_documented_status_vocabulary(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": "w_1",
                            "work_email": "grace@example.com",
                            "status": "TERMINATED",
                            "start_date": "2019-06-03",
                            "end_date": "2026-10-30",
                            "manager_id": "w_0",
                            "department": {"id": "d_1", "name": "Security"},
                            "employment_type": {"type": "CONTRACTOR"},
                            "title": "Principal Analyst",
                        }
                    ],
                    "next_link": None,
                },
            )

        connector = RipplingConnector(api_token="t", transport=_transport(handler))
        record = (await connector.fetch_workforce())[0]
        assert record.external_id == "w_1"
        assert record.status == "terminated"
        assert record.end_date == "2026-10-30"
        assert record.manager_external_id == "w_0"
        assert record.department == "Security"
        assert record.worker_type == "contractor"

    @pytest.mark.asyncio
    async def test_an_unknown_status_is_unknown_and_not_guessed(self) -> None:
        """A vocabulary the vendor adds later must not be read as `active`.
        Deciding somebody still works here on a value we do not recognise is
        the wrong direction to be wrong in."""

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"results": [{"id": "w_2", "status": "ON_LEAVE_EXTENDED"}], "next_link": None},
            )

        connector = RipplingConnector(api_token="t", transport=_transport(handler))
        assert (await connector.fetch_workforce())[0].status == "unknown"


class TestIntuneVendorShape:
    """Recorded against `GET /deviceManagement/managedDevices` on Microsoft
    Graph v1.0, permission `DeviceManagementManagedDevices.Read.All`."""

    @pytest.mark.asyncio
    async def test_it_reads_the_device_fields_1_3_names(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/token"):
                return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "705c034c-034c-705c-4c03-5c704c035c70",
                            "deviceName": "LAPTOP-ADA",
                            "userPrincipalName": "ada@example.com",
                            "complianceState": "noncompliant",
                            "operatingSystem": "Windows",
                            "osVersion": "10.0.26100.2033",
                            "isEncrypted": False,
                            "partnerReportedThreatState": "activated",
                            "managedDeviceOwnerType": "company",
                            "serialNumber": "S-1",
                            "lastSyncDateTime": "2026-10-31T23:00:00Z",
                        }
                    ]
                },
            )

        connector = MicrosoftIntuneConnector(
            tenant_id="t", client_id="c", client_secret="s", transport=_transport(handler)
        )
        device = (await connector.fetch_devices())[0]
        assert device.external_id == "705c034c-034c-705c-4c03-5c704c035c70"
        assert device.hostname == "LAPTOP-ADA"
        assert device.owner_email == "ada@example.com"
        assert device.compliance_state == "noncompliant"
        assert device.os_version == "10.0.26100.2033"
        assert device.encrypted is False
        assert device.edr_agent_health == "activated"

    @pytest.mark.asyncio
    async def test_an_unreported_compliance_state_is_unknown(self) -> None:
        """Graph's own enumeration has `unknown`, and a device Intune has
        not evaluated must not read as compliant."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/token"):
                return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
            return httpx.Response(200, json={"value": [{"id": "d1", "complianceState": "unknown"}]})

        connector = MicrosoftIntuneConnector(
            tenant_id="t", client_id="c", client_secret="s", transport=_transport(handler)
        )
        device = (await connector.fetch_devices())[0]
        assert device.compliance_state == "unknown"
        # Encryption nobody reported is None, not False: "not encrypted" is
        # a finding and "not reported" is not.
        assert device.encrypted is None
