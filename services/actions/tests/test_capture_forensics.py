"""Evidence acquisition: the verb the agent recommended and nothing could run.

``capture_forensics`` was an ``ActionType`` with no executor anywhere, and
``services/agents/app/agents/investigation_agent.py`` proposes it by name
whenever an investigation reaches the C2 or exfiltration stage, with
``requires_approval=True``. So the product raised an approval for evidence
acquisition on the most serious class of incident and answered "No executor
found for action type" when somebody approved it — a control that is reachable
from a recommendation and dead on approval.

Three claims are tested here, in the order they matter:

1. the verb resolves — through the legacy route *and* through governed
   dispatch, which are different failures with different error messages;
2. it does not lie about being finished. MDE queues a machine action and
   replies immediately; the package appears minutes later or never. The
   executor reports ``RUNNING`` / ``AWAITING_COMPLETION`` rather than success,
   because an analyst who reads "done" stops looking for the evidence;
3. the probe reads the package back rather than the vendor's own optimism —
   ``Succeeded`` with nothing to download is a failure, not a success.
"""

from __future__ import annotations

from unittest.mock import create_autospec
from uuid import uuid4

import httpx
import pytest
import respx
from app.clients.defender_client import DefenderClient
from app.executors import endpoint
from app.executors.endpoint import INVESTIGATION_PACKAGE_ACTION, CaptureForensicsExecutor
from app.live_actions import builtins, registry
from app.live_actions.capabilities import KNOWN_CAPABILITIES
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.models.action import ActionRequest, ActionStatus, ActionType
from app.services import verification
from app.services.executor_registry import EXECUTOR_REGISTRY
from app.services.verification import PostActionVerifier, VerificationOutcome

MDE_CREDENTIALS = {
    "mde_tenant_id": "00000000-0000-0000-0000-000000000001",
    "mde_client_id": "00000000-0000-0000-0000-000000000002",
    "mde_client_secret": "unit-test-placeholder",
}


@pytest.fixture(autouse=True)
def _registered() -> None:
    registry.reset_for_tests()
    builtins.register_builtin_executors(overwrite=True)


def _request(**parameters) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.CAPTURE_FORENSICS,
        target=parameters.pop("target", "WS-4471"),
        parameters=parameters,
        rationale="Exfiltration/C2 stage detected — preserve evidence",
    )


# ── 1. The verb resolves ───────────────────────────────────────────────────


def test_capture_forensics_has_an_executor() -> None:
    """The legacy route. Without this it answers 'No executor found'."""
    assert ActionType.CAPTURE_FORENSICS in EXECUTOR_REGISTRY


def test_capture_forensics_resolves_through_governed_dispatch() -> None:
    """The governed route, which has the contract and approval matrix on it.

    A legacy executor with no adapter is reachable only through the ActionType
    REST endpoint, which has none of those in front of it.
    """
    assert registry.get_executor("defender", "capture_forensics") is not None


def test_capture_forensics_is_in_the_vocabulary_and_has_a_contract() -> None:
    assert "capture_forensics" in KNOWN_CAPABILITIES
    contract = CAPABILITY_CONTRACTS["capture_forensics"]
    # Analyst-gated, not automatic: the verb has no bound on what it collects
    # or from whom, which is the same reasoning that separated suppress_alert
    # from update_alert_disposition at an identical impact tier.
    assert contract.impact is ActionImpact.LOW
    assert contract.approval is ApprovalRequirement.ANALYST
    assert contract.has_verification_probe is True
    assert ActionType.CAPTURE_FORENSICS in verification._DEFAULT_PROBES


# ── 2. It does not claim to have finished ──────────────────────────────────


@pytest.mark.asyncio
async def test_defender_arm_reports_running_not_completed(monkeypatch) -> None:
    """Collection is asynchronous, so 'completed' would be the 200-is-proof lie.

    Autospec'd, per the rule that simulation mode never constructs the client:
    a wrong keyword here is invisible until a live call raises ``TypeError``
    in a customer's tenant.
    """
    client = create_autospec(DefenderClient, spec_set=True, instance=True)
    client.collect_investigation_package.return_value = {
        "success": True,
        "action": "collect_investigation_package",
        "machine_id": "mde-1",
        "hostname": "WS-4471",
        "mde_action_id": "act-9",
        "status": "Pending",
    }
    monkeypatch.setattr(endpoint, "_mde_client", lambda params: client)

    result = await CaptureForensicsExecutor().execute(_request(**MDE_CREDENTIALS))

    assert result.status is ActionStatus.RUNNING, "a queued acquisition is not a completed one"
    assert result.output["executed"] is True
    assert result.output["package_ready"] is False
    assert result.output["mde_action_id"] == "act-9"
    client.collect_investigation_package.assert_called_once()
    assert client.collect_investigation_package.call_args.args[0] == "WS-4471"


@pytest.mark.asyncio
async def test_governed_dispatch_surfaces_awaiting_completion(monkeypatch) -> None:
    """The adapter-level claim, and the reason a new status had to exist.

    ``_to_live_status`` used to fold everything that was not FAILED or a
    simulation into SUCCEEDED, so an acquisition that had not happened yet
    would have been reported as a completed action.
    """
    client = create_autospec(DefenderClient, spec_set=True, instance=True)
    client.collect_investigation_package.return_value = {
        "hostname": "WS-4471",
        "mde_action_id": "act-9",
        "status": "Pending",
    }
    monkeypatch.setattr(endpoint, "_mde_client", lambda params: client)

    executor = registry.get_executor("defender", "capture_forensics")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="capture_forensics",
            vendor_id="defender",
            target="WS-4471",
            params=dict(MDE_CREDENTIALS),
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.AWAITING_COMPLETION
    assert "not yet available" in result.summary
    assert "act-9" in result.summary, "the machine action id is what a later verification pass reads"


@pytest.mark.asyncio
async def test_no_credentials_simulates_rather_than_claiming_an_acquisition() -> None:
    result = await CaptureForensicsExecutor().execute(_request())

    assert result.output["executed"] is False
    assert result.output["package_ready"] is False
    assert str(result.output["note"]).startswith("Simulation mode")


@pytest.mark.asyncio
async def test_dry_run_never_builds_a_defender_client(monkeypatch) -> None:
    """A preview must not reach the vendor, whatever credentials are supplied."""

    real = endpoint._mde_client

    def _tripwire(params):
        if real(params) is not None:
            raise AssertionError("a dry run built a live Defender client")
        return None

    monkeypatch.setattr(endpoint, "_mde_client", _tripwire)

    executor = registry.get_executor("defender", "capture_forensics")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="capture_forensics",
            vendor_id="defender",
            target="WS-4471",
            params=dict(MDE_CREDENTIALS),
            dry_run=True,
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.SIMULATED


@pytest.mark.asyncio
async def test_a_defender_failure_is_reported_as_failed(monkeypatch) -> None:
    client = create_autospec(DefenderClient, spec_set=True, instance=True)
    client.collect_investigation_package.side_effect = httpx.HTTPError("403 Forbidden")
    monkeypatch.setattr(endpoint, "_mde_client", lambda params: client)

    result = await CaptureForensicsExecutor().execute(_request(**MDE_CREDENTIALS))

    assert result.status is ActionStatus.FAILED
    assert "403" in (result.error or "")


# ── 3. The probe reads the package back ────────────────────────────────────


def _probe_client(status: str, *, package_uri: str | None) -> DefenderClient:
    client = create_autospec(DefenderClient, spec_set=True, instance=True)
    client.find_machine.return_value = {"id": "mde-1"}
    client.list_machine_actions.return_value = [{"id": "act-9", "creationDateTimeUtc": "2026-09-23T10:00:00Z"}]
    client.get_machine_action.return_value = {"id": "act-9", "status": status}
    client.get_investigation_package_uri.return_value = package_uri
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "package_uri", "expected"),
    [
        # The only combination that means evidence exists and can be fetched.
        ("Succeeded", "https://mde.example.invalid/pkg.zip", VerificationOutcome.VERIFIED),
        # Claims to have finished with nothing to download. Reading the status
        # alone would certify this, which is why the probe asks for the artefact.
        ("Succeeded", None, VerificationOutcome.FAILED),
        # Genuine alarms: the responder believes they hold evidence and do not.
        ("Failed", None, VerificationOutcome.FAILED),
        ("TimeOut", None, VerificationOutcome.FAILED),
        ("Cancelled", None, VerificationOutcome.FAILED),
        # Not finished is not the same fact as not happening.
        ("Pending", None, VerificationOutcome.UNVERIFIED),
        ("InProgress", None, VerificationOutcome.UNVERIFIED),
    ],
)
async def test_the_probe_distinguishes_collected_from_failed_from_still_running(
    monkeypatch,
    status: str,
    package_uri: str | None,
    expected: VerificationOutcome,
) -> None:
    monkeypatch.setattr(verification, "_mde_client", lambda params: _probe_client(status, package_uri=package_uri))

    result = await PostActionVerifier().verify(ActionType.CAPTURE_FORENSICS, "WS-4471", dict(MDE_CREDENTIALS))

    assert result.outcome is expected


@pytest.mark.asyncio
async def test_the_probe_prefers_an_explicit_action_id(monkeypatch) -> None:
    """Given the id the executor returned, the probe reads exactly that action.

    Without one it falls back to the newest collection against the machine,
    which is this one unless somebody started a second on the same host in the
    same window. A caller who needs certainty passes the id.
    """
    client = _probe_client("Succeeded", package_uri="https://mde.example.invalid/pkg.zip")
    monkeypatch.setattr(verification, "_mde_client", lambda params: client)

    result = await PostActionVerifier().verify(
        ActionType.CAPTURE_FORENSICS,
        "WS-4471",
        {**MDE_CREDENTIALS, "mde_action_id": "act-explicit"},
    )

    assert result.outcome is VerificationOutcome.VERIFIED
    client.find_machine.assert_not_called()
    client.list_machine_actions.assert_not_called()
    client.get_machine_action.assert_called_once_with("act-explicit")


@pytest.mark.asyncio
async def test_the_probe_reports_unverified_without_credentials() -> None:
    """Honest over confident: "we cannot check" is not "it failed"."""
    result = await PostActionVerifier().verify(ActionType.CAPTURE_FORENSICS, "WS-4471", {})

    assert result.outcome is VerificationOutcome.UNVERIFIED


# ── Wire shape ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_collect_investigation_package_hits_the_mde_endpoint() -> None:
    captured: dict[str, object] = {}

    respx.post("https://login.microsoftonline.com/tid/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.get("https://api.securitycenter.microsoft.com/api/machines").mock(
        return_value=httpx.Response(200, json={"value": [{"id": "mde-1", "computerDnsName": "WS-4471"}]})
    )

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(201, json={"id": "act-9", "type": INVESTIGATION_PACKAGE_ACTION, "status": "Pending"})

    respx.post("https://api.securitycenter.microsoft.com/api/machines/mde-1/collectInvestigationPackage").mock(side_effect=respond)

    client = DefenderClient(tenant_id="tid", client_id="cid", client_secret="unit-test-placeholder")
    result = await client.collect_investigation_package("WS-4471", comment="C2 stage")

    assert result["mde_action_id"] == "act-9"
    assert result["status"] == "Pending"
    assert "C2 stage" in str(captured["body"])


@pytest.mark.asyncio
@respx.mock
async def test_package_uri_is_read_from_the_value_field() -> None:
    respx.post("https://login.microsoftonline.com/tid/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.get("https://api.securitycenter.microsoft.com/api/machineactions/act-9/getPackageUri").mock(
        return_value=httpx.Response(200, json={"value": "https://mde.example.invalid/pkg.zip"})
    )

    client = DefenderClient(tenant_id="tid", client_id="cid", client_secret="unit-test-placeholder")
    assert await client.get_investigation_package_uri("act-9") == "https://mde.example.invalid/pkg.zip"


@pytest.mark.asyncio
@respx.mock
async def test_package_uri_is_none_while_the_collection_is_still_running() -> None:
    """MDE only issues a URI once the package exists; 404 is not an error here."""
    respx.post("https://login.microsoftonline.com/tid/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.get("https://api.securitycenter.microsoft.com/api/machineactions/act-9/getPackageUri").mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFound"}})
    )

    client = DefenderClient(tenant_id="tid", client_id="cid", client_secret="unit-test-placeholder")
    assert await client.get_investigation_package_uri("act-9") is None


@pytest.mark.asyncio
@respx.mock
async def test_machine_actions_are_sorted_newest_first() -> None:
    """Sorted here, not with ``$orderby``.

    The ordering is the part the verifier depends on: a server-side sort that
    silently is not applied would hand back the oldest acquisition as if it
    were the one we just started.
    """
    respx.post("https://login.microsoftonline.com/tid/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.get("https://api.securitycenter.microsoft.com/api/machineactions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {"id": "old", "creationDateTimeUtc": "2026-09-01T00:00:00Z"},
                    {"id": "new", "creationDateTimeUtc": "2026-09-23T00:00:00Z"},
                ]
            },
        )
    )

    client = DefenderClient(tenant_id="tid", client_id="cid", client_secret="unit-test-placeholder")
    actions = await client.list_machine_actions("mde-1", INVESTIGATION_PACKAGE_ACTION)

    assert [a["id"] for a in actions] == ["new", "old"]
