"""Governance and honesty of the disposition writeback.

Three things this has to get right, and one it must never do.

Right: the feature is on but does not execute by default; a dry run is
dispatched as a dry run and recorded as one; a refusal, a simulation and a
transport failure all record ``executed=False``.

Never: report an unexecuted writeback as executed. Every branch below asserts
on ``executed`` rather than on the HTTP status, because at the HTTP layer a
dry run and a live call are both 200.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.services import siem_writeback
from app.services.alert_source_link import AlertSourceLink

TENANT = uuid.uuid4()
ALERT = uuid.uuid4()


def _link(vendor: str = "splunk", external_id: str = "NOTABLE-42") -> AlertSourceLink:
    return AlertSourceLink(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        alert_id=ALERT,
        vendor=vendor,
        external_id=external_id,
        connector_instance_id=None,
    )


def _db() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=SimpleNamespace(fetchone=lambda: None, fetchall=lambda: []))
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _dispatch_response(*, status: str = "succeeded", written: bool = True, action: str = "close") -> dict:
    return {
        "result": {
            "status": status,
            "summary": "s",
            "details": {"written": written, "writeback_action": action, "reason": "because"},
        },
        "mode": "live",
    }


# ── Governance defaults ────────────────────────────────────────────────────


def test_enabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_ENABLED", raising=False)
    assert siem_writeback.writeback_enabled() is True


def test_execute_is_off_by_default(monkeypatch) -> None:
    """The flag that decides whether a customer's SIEM is touched."""
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_EXECUTE", raising=False)
    assert siem_writeback.writeback_executes() is False


def test_case_closure_is_off_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_CLOSE_CASE", raising=False)
    assert siem_writeback.ticket_projection_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE"])
def test_execute_opt_in_spellings(monkeypatch, value: str) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", value)
    assert siem_writeback.writeback_executes() is True


@pytest.mark.parametrize("value", ["0", "false", "off", "", "no", "maybe"])
def test_anything_not_an_explicit_yes_stays_a_dry_run(monkeypatch, value: str) -> None:
    """An unrecognised value must not be read as consent."""
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", value)
    assert siem_writeback.writeback_executes() is False


# ── The default path writes nothing ────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_posture_dispatches_a_dry_run(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_EXECUTE", raising=False)
    dispatch = AsyncMock(return_value=_dispatch_response())

    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="false_positive")

    assert dispatch.await_args.kwargs["dry_run"] is True
    assert report.mode == "dry_run"
    assert report.executed_count == 0
    assert report.as_dict()["executed"] is False
    assert report.outcomes[0].status == "dry_run"
    # An operator reading the detail must not have to infer this.
    assert report.outcomes[0].detail.startswith("DRY RUN")


@pytest.mark.asyncio
async def test_a_dry_run_is_never_reported_as_executed_even_when_the_vendor_says_written(monkeypatch) -> None:
    """The load-bearing case: a confused executor cannot promote a dry run."""
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_EXECUTE", raising=False)
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(
            siem_writeback.actions_client,
            "dispatch_live_action",
            AsyncMock(return_value=_dispatch_response(written=True)),
        ),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")
    assert report.executed_count == 0


@pytest.mark.asyncio
async def test_disabled_flag_attempts_nothing(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_ENABLED", "0")
    dispatch = AsyncMock()
    with patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="false_positive")
    dispatch.assert_not_awaited()
    assert report.mode == "disabled"
    assert report.as_dict()["executed"] is False


# ── Execution, and the states that are not execution ───────────────────────


@pytest.mark.asyncio
async def test_execute_flag_dispatches_live_and_records_executed(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    recorded = AsyncMock()
    dispatch = AsyncMock(return_value=_dispatch_response())

    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
        patch.object(siem_writeback, "record_writeback", recorded),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="false_positive")

    assert dispatch.await_args.kwargs["dry_run"] is False
    assert report.mode == "live"
    assert report.executed_count == 1
    assert recorded.await_args.kwargs["executed"] is True


@pytest.mark.asyncio
async def test_a_refusal_is_recorded_as_not_executed(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    recorded = AsyncMock()
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(
            siem_writeback.actions_client,
            "dispatch_live_action",
            AsyncMock(return_value=_dispatch_response(written=False, action="refuse")),
        ),
        patch.object(siem_writeback, "record_writeback", recorded),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="true_positive")
    assert report.outcomes[0].status == "refused"
    assert report.executed_count == 0
    assert recorded.await_args.kwargs["executed"] is False


@pytest.mark.asyncio
async def test_a_credential_less_simulation_is_not_an_execution(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(
            siem_writeback.actions_client,
            "dispatch_live_action",
            AsyncMock(return_value=_dispatch_response(status="simulated", written=False)),
        ),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")
    assert report.outcomes[0].status == "simulated"
    assert report.executed_count == 0


@pytest.mark.asyncio
async def test_actions_service_outage_fails_soft(monkeypatch) -> None:
    """A writeback failure must never surface as an exception to triage."""
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(
            siem_writeback.actions_client,
            "dispatch_live_action",
            AsyncMock(side_effect=siem_writeback.actions_client.ActionsServiceError("down")),
        ),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")
    assert report.outcomes[0].status == "failed"
    assert report.executed_count == 0


# ── Routing and scope ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_disposition_costs_no_round_trip() -> None:
    dispatch = AsyncMock()
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link()])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="resolved")
    dispatch.assert_not_awaited()
    assert report.outcomes == []


@pytest.mark.asyncio
async def test_a_vendor_with_no_writeback_arm_is_skipped_not_dispatched(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    dispatch = AsyncMock()
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link(vendor="pagerduty")])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")
    dispatch.assert_not_awaited()
    assert report.outcomes[0].status == "skipped"
    assert report.executed_count == 0


@pytest.mark.asyncio
async def test_the_vendor_is_pinned_so_credential_order_cannot_choose(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    dispatch = AsyncMock(return_value=_dispatch_response())
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[_link(vendor="qradar")])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
        patch.object(siem_writeback, "record_writeback", AsyncMock()),
    ):
        await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")

    kwargs = dispatch.await_args.kwargs
    assert kwargs["vendor_id"] == "qradar"
    assert kwargs["params"]["alert_vendor"] == "qradar"
    assert kwargs["target"] == "NOTABLE-42"
    assert kwargs["capability"] == "update_alert_disposition"


@pytest.mark.asyncio
async def test_no_source_link_means_no_dispatch() -> None:
    dispatch = AsyncMock()
    with (
        patch.object(siem_writeback, "links_for_alert", AsyncMock(return_value=[])),
        patch.object(siem_writeback.actions_client, "dispatch_live_action", dispatch),
    ):
        report = await siem_writeback.write_back_disposition(_db(), tenant_id=TENANT, alert_id=ALERT, disposition="benign")
    dispatch.assert_not_awaited()
    assert report.outcomes == []
