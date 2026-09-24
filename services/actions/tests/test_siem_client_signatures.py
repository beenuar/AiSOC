"""SIEM executors must call their clients with the signatures the clients have.

Simulation mode never constructs the client, so a wrong keyword argument is
invisible in every test that does not supply credentials — and then raises
``TypeError`` on the first live call, in a customer's environment, on the one
code path nobody exercised.

Two instances shipped: ``SearchSIEMExecutor`` passed ``max_results=`` to a
client taking ``max_count`` (fixed in #570), and ``CreateNotableEventExecutor``
passed ``title=`` / ``description=`` / ``fields=`` to a client taking
``rule_name`` / ``event_data``.

``create_autospec`` is the point. A hand-written fake with ``**kwargs``
accepts anything and so proves nothing; an autospec'd mock enforces the real
signature and fails exactly as the live client would.
"""

from __future__ import annotations

from unittest.mock import create_autospec
from uuid import uuid4

import pytest
from app.clients.elastic_client import ElasticClient
from app.clients.qradar_client import QRadarClient
from app.clients.sentinel_client import SentinelClient
from app.clients.splunk_client import SplunkClient
from app.executors import siem
from app.executors.siem import (
    CreateNotableEventExecutor,
    SearchSIEMExecutor,
    UpdateAlertDispositionExecutor,
)
from app.models.action import ActionRequest, ActionStatus, ActionType


def _autospec(cls):
    """An async-aware autospec whose methods reject wrong keyword arguments."""
    return create_autospec(cls, spec_set=True, instance=True)


def _request(action_type: ActionType, **parameters) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target=parameters.pop("target", "FINDING-1"),
        parameters=parameters,
        rationale="signature conformance test",
    )


@pytest.mark.asyncio
async def test_create_notable_event_matches_the_client_signature(monkeypatch) -> None:
    """Fails on the pre-fix executor: `title=` is not a parameter of the client."""
    client = _autospec(SplunkClient)
    client.create_notable_event.return_value = {"success": True}
    monkeypatch.setattr(siem, "_splunk_client", lambda params: client)

    result = await CreateNotableEventExecutor().execute(
        _request(
            ActionType.CREATE_NOTABLE_EVENT,
            event_title="Credential stuffing on svc-01",
            severity="high",
            description="120 failed logins in 4 minutes",
            fields={"src_ip": "198.51.100.7"},
        )
    )

    assert result.status is ActionStatus.COMPLETED, result.error
    kwargs = client.create_notable_event.call_args.kwargs
    assert kwargs["rule_name"] == "Credential stuffing on svc-01"
    assert kwargs["event_data"]["description"] == "120 failed logins in 4 minutes"
    assert kwargs["event_data"]["src_ip"] == "198.51.100.7"


@pytest.mark.asyncio
async def test_search_siem_matches_the_client_signature(monkeypatch) -> None:
    client = _autospec(SplunkClient)
    client.run_search.return_value = [{"_raw": "evt"}]
    monkeypatch.setattr(siem, "_splunk_client", lambda params: client)

    result = await SearchSIEMExecutor().execute(_request(ActionType.SEARCH_SIEM, query="index=main", max_results=25))

    assert result.status is ActionStatus.COMPLETED, result.error
    assert client.run_search.call_args.kwargs["max_count"] == 25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("vendor", "factory_attr", "client_cls", "method", "disposition"),
    [
        ("splunk", "_splunk_client", SplunkClient, "suppress_notable_event", "false_positive"),
        ("splunk", "_splunk_client", SplunkClient, "acknowledge_notable_event", "true_positive"),
        ("elastic", "_elastic_client", ElasticClient, "close_alert", "benign"),
        ("elastic", "_elastic_client", ElasticClient, "acknowledge_alert", "true_positive"),
        ("sentinel", "_sentinel_client", SentinelClient, "close_incident", "false_positive"),
        ("sentinel", "_sentinel_client", SentinelClient, "escalate_incident", "true_positive"),
        ("qradar", "_qradar_client", QRadarClient, "close_offense", "false_positive"),
        ("qradar", "_qradar_client", QRadarClient, "escalate_offense", "true_positive"),
    ],
)
async def test_disposition_writeback_matches_every_client_signature(
    monkeypatch,
    vendor: str,
    factory_attr: str,
    client_cls: type,
    method: str,
    disposition: str,
) -> None:
    """Every writeback arm, autospec'd, for both the close and escalate paths.

    Without this, a rename in any of four clients would surface as a
    ``TypeError`` only in a live customer environment — the same defect class
    that shipped twice already on this exact module.
    """
    client = _autospec(client_cls)
    getattr(client, method).return_value = {"success": True}
    for attr in ("_splunk_client", "_elastic_client", "_sentinel_client", "_qradar_client"):
        monkeypatch.setattr(siem, attr, (lambda params: client) if attr == factory_attr else (lambda params: None))

    result = await UpdateAlertDispositionExecutor().execute(
        _request(
            ActionType.UPDATE_ALERT_DISPOSITION,
            target="FINDING-77",
            disposition=disposition,
            confidence=0.93,
            rationale="Matches a known scanner fingerprint.",
            alert_vendor=vendor,
            qradar_closing_reason_id=3,
        )
    )

    assert result.status is ActionStatus.COMPLETED, result.error
    assert result.output["written"] is True
    getattr(client, method).assert_called_once()
