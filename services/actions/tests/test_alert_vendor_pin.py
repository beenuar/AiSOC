"""An ``alert_vendor`` pin must be checked against the credentials.

``_ack_vendor`` used to return the pinned vendor unconditionally:

    explicit = (params.get("alert_vendor") or "").strip().lower()
    if explicit in {"splunk", "elastic", "defender", "mde"}:
        return "defender" if explicit == "mde" else explicit

Two consequences, both reached in normal operation. A dry run works by
stripping credentials, so the pin survived the strip and the executor
resolved "splunk" with no client — then hit ``assert splunk is not None``,
crashing an action that was supposed to be a harmless preview. And a pin
naming a vendor the tenant has never configured reported a vendor arm that
could not possibly have run.

The fix also has to be conservative in the other direction: a pin that cannot
be honoured must NOT silently fall through to whichever other SIEM happens to
have credentials. "Write this verdict to Splunk" turning into "write it to
Elastic" puts a disposition on a finding in a system nobody asked about.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors import siem
from app.models.action import ActionRequest, ActionStatus, ActionType

SPLUNK = {"splunk_url": "https://splunk.example.invalid:8089", "splunk_token": "unit-test-placeholder"}
ELASTIC = {
    "elastic_url": "https://es.example.invalid:9243",
    "elastic_api_key": "unit-test-placeholder",
    "kibana_url": "https://kibana.example.invalid:5601",
}


def test_pin_without_credentials_does_not_resolve_a_vendor() -> None:
    assert siem._ack_vendor({"alert_vendor": "splunk"}) is None


def test_pin_with_credentials_resolves() -> None:
    assert siem._ack_vendor({**SPLUNK, "alert_vendor": "splunk"}) == "splunk"


def test_an_unhonourable_pin_never_falls_through_to_another_vendor() -> None:
    """Splunk pinned, only Elastic configured: refuse rather than redirect."""
    assert siem._ack_vendor({**ELASTIC, "alert_vendor": "splunk"}) is None


def test_unknown_pin_is_refused() -> None:
    assert siem._ack_vendor({**SPLUNK, "alert_vendor": "not_a_siem"}) is None


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("mde", "defender"),
        ("microsoft_sentinel", "sentinel"),
        ("ibm_qradar", "qradar"),
        ("splunk_enterprise", "splunk"),
        ("elasticsearch", "elastic"),
    ],
)
def test_connector_ids_alias_onto_vendor_ids(alias: str, expected: str) -> None:
    """A connector id is what a tenant actually has; it must still be checked."""
    assert siem._ack_vendor({"alert_vendor": alias}) is None, "alias without credentials must not resolve"
    credentials = {
        "defender": {
            "mde_tenant_id": "t",
            "mde_client_id": "c",
            "mde_client_secret": "unit-test-placeholder",
        },
        "sentinel": {
            "sentinel_tenant_id": "t",
            "sentinel_client_id": "c",
            "sentinel_client_secret": "unit-test-placeholder",
            "sentinel_subscription_id": "s",
            "sentinel_resource_group": "rg",
            "sentinel_workspace_name": "ws",
        },
        "qradar": {"qradar_url": "https://qradar.example.invalid", "qradar_token": "unit-test-placeholder"},
        "splunk": SPLUNK,
        "elastic": ELASTIC,
    }[expected]
    assert siem._ack_vendor({**credentials, "alert_vendor": alias}) == expected


def test_no_pin_falls_back_to_credential_order() -> None:
    assert siem._ack_vendor(ELASTIC) == "elastic"
    assert siem._ack_vendor({**SPLUNK, **ELASTIC}) == "splunk"
    assert siem._ack_vendor({}) is None


@pytest.mark.asyncio
async def test_ack_with_an_unhonourable_pin_simulates_instead_of_crashing() -> None:
    """The regression in full: previously an AssertionError, now a simulation."""
    result = await siem.AckAlertExecutor().execute(
        ActionRequest(
            incident_id=uuid4(),
            tenant_id=uuid4(),
            action_type=ActionType.ACK_ALERT,
            target="NOTABLE-9",
            parameters={"alert_vendor": "splunk"},
        )
    )
    assert result.status is ActionStatus.COMPLETED
    assert result.output["note"].startswith("Simulation mode")
