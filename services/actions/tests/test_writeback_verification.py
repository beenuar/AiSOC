"""The disposition writeback is checked against the vendor, not against a 202.

The writeback shipped declaring no verification probe, which was the honest
choice at the time — a declared probe that does not run is the defect the
contract gate exists to catch. But the standing rule is that an unverifiable
action is not an autonomous one, and this one is automatic, so it needed a real
read-back rather than a lower tier.

What makes a probe real is that it can return False. An earlier isolation probe
returned ``bool(device_id)`` — true of every host in the fleet, contained or
not — and would have certified an uncontained host. Each vendor arm below is
therefore driven through both the state it should reach and a state it should
not, and the arms that cannot tell the two apart answer UNVERIFIED rather than
inventing a confirmation.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from app.clients.qradar_client import QRadarClient
from app.clients.splunk_client import SplunkClient
from app.models.action import ActionType
from app.services import verification
from app.services.verification import PostActionVerifier, VerificationOutcome

SPLUNK_CREDS = {
    "splunk_url": "https://splunk.example.invalid:8089",
    "splunk_token": "unit-test-placeholder",
}
QRADAR_CREDS = {
    "qradar_url": "https://qradar.example.invalid",
    "qradar_token": "unit-test-placeholder",
}
ELASTIC_CREDS = {
    "elastic_url": "https://es.example.invalid:9243",
    "kibana_url": "https://kibana.example.invalid:5601",
    "elastic_api_key": "unit-test-placeholder",
}


class _FakeSplunk:
    """Returns whatever ``incident_review`` state the test wants read back."""

    def __init__(self, state: dict[str, Any] | None) -> None:
        self._state = state
        self.calls: list[str] = []

    async def get_notable_event_state(self, event_id: str) -> dict[str, Any] | None:
        self.calls.append(event_id)
        return self._state


class _FakeQRadar:
    def __init__(self, offense: dict[str, Any]) -> None:
        self._offense = offense
        self.calls: list[str] = []

    async def get_offense(self, offense_id: str) -> dict[str, Any]:
        self.calls.append(offense_id)
        return self._offense


def _use_splunk(monkeypatch: pytest.MonkeyPatch, state: dict[str, Any] | None) -> _FakeSplunk:
    client = _FakeSplunk(state)
    monkeypatch.setattr(verification, "_splunk_client", lambda params: client)
    return client


def _use_qradar(monkeypatch: pytest.MonkeyPatch, offense: dict[str, Any]) -> _FakeQRadar:
    client = _FakeQRadar(offense)
    monkeypatch.setattr(verification, "_qradar_client", lambda params: client)
    return client


async def _verify(action: ActionType, target: str, params: dict[str, Any]) -> VerificationOutcome:
    result = await PostActionVerifier().verify(action, target, params)
    return result.outcome


# ── Splunk ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_splunk_close_is_verified_when_the_notable_is_actually_closed(monkeypatch) -> None:
    client = _use_splunk(monkeypatch, {"status": "5", "owner": "aisoc"})

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-7f3a",
        {**SPLUNK_CREDS, "disposition": "false_positive"},
    )

    assert outcome is VerificationOutcome.VERIFIED
    assert client.calls == ["NOTABLE-7f3a"], "the probe must actually re-query the vendor"


@pytest.mark.asyncio
async def test_splunk_close_fails_when_the_notable_is_still_open(monkeypatch) -> None:
    """The property that makes this a probe: it can say the effect is absent.

    A writeback the vendor rejected, or silently dropped, leaves the notable in
    the analyst queue while AiSOC reports it handled. That disagreement is what
    a responder needs told.
    """
    _use_splunk(monkeypatch, {"status": "1", "owner": "aisoc"})

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-7f3a",
        {**SPLUNK_CREDS, "disposition": "benign"},
    )

    assert outcome is VerificationOutcome.FAILED


@pytest.mark.asyncio
async def test_splunk_escalation_checks_the_owner_as_well_as_the_status(monkeypatch) -> None:
    """Status alone is weak here: a notable an analyst already picked up reads
    as in-progress whether or not AiSOC's write landed. The owner is what makes
    the two distinguishable."""
    _use_splunk(monkeypatch, {"status": "1", "owner": "aisoc"})
    assert (
        await _verify(
            ActionType.UPDATE_ALERT_DISPOSITION,
            "NOTABLE-1",
            {**SPLUNK_CREDS, "disposition": "true_positive"},
        )
        is VerificationOutcome.VERIFIED
    )

    _use_splunk(monkeypatch, {"status": "1", "owner": "someone-else"})
    assert (
        await _verify(
            ActionType.UPDATE_ALERT_DISPOSITION,
            "NOTABLE-1",
            {**SPLUNK_CREDS, "disposition": "true_positive"},
        )
        is VerificationOutcome.FAILED
    )


@pytest.mark.asyncio
async def test_no_incident_review_entry_is_unverified_not_failed(monkeypatch) -> None:
    """Splunk ES absent, or no review row yet, is "cannot tell" — not "did not
    happen". Conflating them turns a deployment fact into a false alarm."""
    _use_splunk(monkeypatch, None)

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-1",
        {**SPLUNK_CREDS, "disposition": "false_positive"},
    )

    assert outcome is VerificationOutcome.UNVERIFIED


# ── QRadar ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    [("CLOSED", VerificationOutcome.VERIFIED), ("OPEN", VerificationOutcome.FAILED)],
)
async def test_qradar_close_reads_the_offense_status_back(monkeypatch, status: str, expected) -> None:
    _use_qradar(monkeypatch, {"id": 42, "status": status})
    monkeypatch.setattr(verification, "_splunk_client", lambda params: None)

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "42",
        {**QRADAR_CREDS, "disposition": "false_positive", "qradar_closing_reason_id": 3},
    )

    assert outcome is expected


@pytest.mark.asyncio
async def test_qradar_escalation_is_unverified_rather_than_trivially_true(monkeypatch) -> None:
    """The ``bool(device_id)`` trap, avoided explicitly.

    A QRadar escalation annotates the offense and leaves it OPEN — which is
    also the state it was in beforehand. Reporting VERIFIED because the offense
    is still OPEN would certify a write that never happened, so this answers
    indeterminate instead.
    """
    _use_qradar(monkeypatch, {"id": 42, "status": "OPEN"})
    monkeypatch.setattr(verification, "_splunk_client", lambda params: None)

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "42",
        {**QRADAR_CREDS, "disposition": "true_positive"},
    )

    assert outcome is VerificationOutcome.UNVERIFIED


# ── Arms with no read-back, and the refusal path ──────────────────────────


@pytest.mark.asyncio
async def test_vendors_without_a_read_back_report_unverified() -> None:
    """Elastic, Sentinel and Defender expose no read of a finding's state.

    Saying so is the point. The alternative — treating "no probe for this
    vendor" as success — is what makes a verification field worthless.
    """
    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "SIGNAL-1",
        {**ELASTIC_CREDS, "disposition": "false_positive"},
    )

    assert outcome is VerificationOutcome.UNVERIFIED


@pytest.mark.asyncio
async def test_a_refused_writeback_is_unverified_not_verified(monkeypatch) -> None:
    """``needs_review`` writes nothing, so there is no effect to confirm.

    VERIFIED here would read as "the verdict reached the finding", which is the
    opposite of what happened.
    """
    client = _use_splunk(monkeypatch, {"status": "5", "owner": "aisoc"})

    outcome = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-1",
        {**SPLUNK_CREDS, "disposition": "needs_review"},
    )

    assert outcome is VerificationOutcome.UNVERIFIED
    assert client.calls == [], "a refusal wrote nothing, so the probe must not claim to confirm it"


@pytest.mark.asyncio
async def test_the_probe_derives_the_expected_state_from_the_disposition(monkeypatch) -> None:
    """One notable, one state read back, two verdicts, opposite answers.

    The expectation is re-derived through the same ``plan_writeback`` the
    executor used rather than passed in beside the disposition: a probe told
    separately what to expect can be told wrong.
    """
    _use_splunk(monkeypatch, {"status": "5", "owner": "aisoc"})

    closed = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-1",
        {**SPLUNK_CREDS, "disposition": "false_positive"},
    )
    escalated = await _verify(
        ActionType.UPDATE_ALERT_DISPOSITION,
        "NOTABLE-1",
        {**SPLUNK_CREDS, "disposition": "true_positive"},
    )

    assert closed is VerificationOutcome.VERIFIED
    assert escalated is VerificationOutcome.FAILED


# ── The two newly-reachable verbs get the same read-back ──────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "status", "expected"),
    [
        (ActionType.ACK_ALERT, "1", VerificationOutcome.VERIFIED),
        (ActionType.ACK_ALERT, "0", VerificationOutcome.FAILED),
        (ActionType.SUPPRESS_ALERT, "5", VerificationOutcome.VERIFIED),
        (ActionType.SUPPRESS_ALERT, "1", VerificationOutcome.FAILED),
    ],
)
async def test_ack_and_suppress_are_verified_against_the_same_store(monkeypatch, action: ActionType, status: str, expected) -> None:
    _use_splunk(monkeypatch, {"status": status, "owner": "aisoc"})

    assert await _verify(action, "NOTABLE-1", dict(SPLUNK_CREDS)) is expected


def test_every_probe_the_contract_claims_is_registered() -> None:
    """Mirrors the gate, at unit-test speed: a declared probe that is not
    registered is a claim rather than a fact, and this is the specific claim
    the contract exists to make trustworthy."""
    from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS

    registered = {a.value for a in verification._DEFAULT_PROBES}  # noqa: SLF001
    for capability in ("update_alert_disposition", "ack_alert", "suppress_alert"):
        assert CAPABILITY_CONTRACTS[capability].has_verification_probe is True
        assert capability in registered


@pytest.mark.asyncio
async def test_the_probe_clients_expose_the_methods_the_probe_calls() -> None:
    """Autospec'd signature check for the read-back half.

    Simulation never constructs a client, so a renamed read-back would raise
    only on a live call — the same defect that shipped twice on the forward
    path (``max_results`` vs ``max_count``, ``title`` vs ``event_data``).
    """
    from unittest.mock import create_autospec

    splunk = create_autospec(SplunkClient, spec_set=True, instance=True)
    qradar = create_autospec(QRadarClient, spec_set=True, instance=True)

    # spec_set raises AttributeError for a method the real class lacks, and
    # autospec rejects a keyword the real signature does not take.
    splunk.get_notable_event_state.return_value = {"status": "5", "owner": "aisoc"}
    qradar.get_offense.return_value = {"id": 42, "status": "CLOSED"}
    assert await splunk.get_notable_event_state(event_id="NOTABLE-1") == {"status": "5", "owner": "aisoc"}
    assert await qradar.get_offense(offense_id="42") == {"id": 42, "status": "CLOSED"}


@pytest.mark.asyncio
@respx.mock
async def test_splunk_read_back_parses_the_incident_review_collection() -> None:
    """The real client against the real request shape, not a fake.

    ``/services/notable_update`` records every lifecycle change in the
    ``incident_review`` KV store collection keyed by ``rule_id`` — the same
    value it is sent as ``ruleUIDs`` — so this reads the effect of the write
    rather than the acceptance of the request.
    """
    route = respx.get(
        "https://splunk.example.invalid:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/storage/collections/data/incident_review"
    ).mock(return_value=httpx.Response(200, json=[{"rule_id": "NOTABLE-1", "status": "5", "owner": "aisoc"}]))

    client = SplunkClient(host="https://splunk.example.invalid:8089", token="unit-test-placeholder")
    state = await client.get_notable_event_state("NOTABLE-1")

    assert state == {"status": "5", "owner": "aisoc"}
    assert json.loads(route.calls.last.request.url.params["query"]) == {"rule_id": "NOTABLE-1"}


@pytest.mark.asyncio
@respx.mock
async def test_splunk_read_back_is_none_without_enterprise_security() -> None:
    """A deployment without ES has no incident review store. That is a fact
    about the deployment, not an error, and certainly not a confirmation."""
    respx.get(url__regex=r".*incident_review.*").mock(return_value=httpx.Response(404))

    client = SplunkClient(host="https://splunk.example.invalid:8089", token="unit-test-placeholder")

    assert await client.get_notable_event_state("NOTABLE-1") is None


@pytest.mark.asyncio
@respx.mock
async def test_splunk_read_back_is_none_when_the_notable_has_no_review_row() -> None:
    respx.get(url__regex=r".*incident_review.*").mock(return_value=httpx.Response(200, json=[]))

    client = SplunkClient(host="https://splunk.example.invalid:8089", token="unit-test-placeholder")

    assert await client.get_notable_event_state("NOTABLE-1") is None
