"""
Phase 3.3 — executor-level tests for the alert ack + suppress
verbs.

We pin :func:`_ack_vendor`'s priority order (explicit ``alert_vendor``
→ Splunk → Elastic → Defender → simulation) by stubbing the
relevant client factories. The vendor selection has more shape
than the EDR/network ones because we have a single executor that
chooses between three vendors instead of a fall-through chain.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors import siem
from app.executors.siem import AckAlertExecutor, SuppressAlertExecutor
from app.models.action import ActionRequest, ActionStatus, ActionType


def _req(action_type: ActionType, **params: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target="alert-123",
        parameters=dict(params),
    )


class _FakeSplunk:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def acknowledge_notable_event(self, **kwargs: object) -> dict:
        self.calls.append(("ack", kwargs))
        return {"success": True}

    async def suppress_notable_event(self, **kwargs: object) -> dict:
        self.calls.append(("suppress", kwargs))
        return {"success": True}


class _FakeElastic:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def acknowledge_alert(self, **kwargs: object) -> dict:
        self.calls.append(("ack", kwargs))
        return {"success": True}

    async def close_alert(self, **kwargs: object) -> dict:
        self.calls.append(("close", kwargs))
        return {"success": True}


@pytest.mark.asyncio
async def test_ack_alert_prefers_splunk_when_both_credentials_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """Priority order: when both Splunk and Elastic credentials are
    supplied, we fire Splunk (lower index in the priority list)."""
    fake_splunk = _FakeSplunk()
    fake_elastic = _FakeElastic()
    monkeypatch.setattr(siem, "_splunk_client", lambda p: fake_splunk)
    monkeypatch.setattr(siem, "_elastic_client", lambda p: fake_elastic)

    req = _req(ActionType.ACK_ALERT)
    result = await AckAlertExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "splunk"
    assert len(fake_splunk.calls) == 1
    assert len(fake_elastic.calls) == 0


@pytest.mark.asyncio
async def test_ack_alert_explicit_alert_vendor_pins_elastic(monkeypatch: pytest.MonkeyPatch) -> None:
    """``alert_vendor: elastic`` overrides the default priority."""
    fake_splunk = _FakeSplunk()
    fake_elastic = _FakeElastic()
    monkeypatch.setattr(siem, "_splunk_client", lambda p: fake_splunk)
    monkeypatch.setattr(siem, "_elastic_client", lambda p: fake_elastic)

    req = _req(ActionType.ACK_ALERT, alert_vendor="elastic")
    result = await AckAlertExecutor().execute(req)

    assert result.rollback_data["vendor"] == "elastic"
    assert len(fake_elastic.calls) == 1
    assert len(fake_splunk.calls) == 0


@pytest.mark.asyncio
async def test_suppress_alert_falls_back_to_simulation_when_no_credentials() -> None:
    req = _req(ActionType.SUPPRESS_ALERT)
    result = await SuppressAlertExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED  # simulation success
    assert "Simulation mode" in result.output["note"]


@pytest.mark.asyncio
async def test_suppress_alert_dispatches_to_elastic_close(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_elastic = _FakeElastic()
    monkeypatch.setattr(siem, "_splunk_client", lambda p: None)
    monkeypatch.setattr(siem, "_elastic_client", lambda p: fake_elastic)

    req = _req(ActionType.SUPPRESS_ALERT)
    result = await SuppressAlertExecutor().execute(req)

    assert result.rollback_data["vendor"] == "elastic"
    assert fake_elastic.calls[0][0] == "close"


@pytest.mark.asyncio
async def test_ack_alert_dispatches_to_defender_when_only_mde_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """When neither Splunk nor Elastic credentials are present but
    MDE's tenant/client/secret triple are, the executor reaches for
    Defender."""
    monkeypatch.setattr(siem, "_splunk_client", lambda p: None)
    monkeypatch.setattr(siem, "_elastic_client", lambda p: None)

    fake_mde_calls: list[tuple[str, dict]] = []

    class _FakeDefender:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def acknowledge_alert(self, **kwargs: object) -> dict:
            fake_mde_calls.append(("ack", kwargs))
            return {"success": True}

    # The executor imports DefenderClient inside the function (to
    # avoid a hard import-time dep when MDE is unused) so we have
    # to patch the import path that the executor actually reads.
    import app.clients.defender_client as defender_module

    monkeypatch.setattr(defender_module, "DefenderClient", _FakeDefender)

    req = _req(
        ActionType.ACK_ALERT,
        mde_tenant_id="t",
        mde_client_id="c",
        mde_client_secret="s",
    )
    result = await AckAlertExecutor().execute(req)

    assert result.rollback_data["vendor"] == "defender"
    assert len(fake_mde_calls) == 1
