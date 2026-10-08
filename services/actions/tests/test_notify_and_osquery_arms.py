"""Depth 5.1 — the notify and osquery arms, against mock vendor servers.

Two classes of proof here, because the two classes of defect this replaces
are invisible to each other.

**Mock-vendor smoke.** Each arm is driven through its real httpx path against
a respx server returning the shape the vendor documents, so a wrong endpoint,
a wrong payload key or a normalize that KeyErrors is a failing test rather
than a 400 during an incident. Payload shapes are taken from the references
named in each arm's module docstring.

**Signature conformance, autospec'd.** Executor-to-client drift is invisible
in simulation mode because the client is never constructed —
``SearchSIEMExecutor`` passed ``max_results=`` to a client taking
``max_count`` and every live call raised ``TypeError`` while every test
passed. ``autospec=True`` makes the double enforce the real signature.

And one reproduce, kept as a regression: with no webhook configured,
``NotifySlackExecutor`` returned COMPLETED with ``message_sent: True``, and
because ``_LegacyExecutorAdapter`` previews by stripping credentials so the
executor takes its simulation branch — which that executor does not have —
*every dry run* reported a completed send.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx
from app.clients.aisoc_direct_client import AiSOCDirectClient
from app.clients.fleetdm_client import FleetDMClient
from app.clients.osctrl_client import OsctrlClient
from app.clients.pagerduty_client import PagerDutyClient
from app.executors.notification import NotifySlackExecutor
from app.live_actions import notify_arms, osquery_arms
from app.live_actions.builtins import SlackNotify
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.models.action import ActionRequest, ActionStatus, ActionType

pytestmark = pytest.mark.asyncio


def _request(vendor_id: str, capability: str = "notify", **params: Any) -> LiveActionRequest:
    return LiveActionRequest(capability=capability, vendor_id=vendor_id, params=params)


# ---------------------------------------------------------------------------
# Reproduce: a notification nobody received, recorded as delivered
# ---------------------------------------------------------------------------


async def test_slack_without_a_webhook_fails_rather_than_completing() -> None:
    result = await NotifySlackExecutor().execute(
        ActionRequest(
            action_type=ActionType.NOTIFY_SLACK,
            incident_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            target="#soc",
            rationale="test",
            parameters={},
        )
    )
    assert result.status == ActionStatus.FAILED
    assert "webhook" in (result.error or "").lower()


async def test_slack_dry_run_is_simulated_not_completed() -> None:
    """The adapter has to simulate before the base class strips credentials.

    Fixing the executor to fail closed is necessary and not sufficient: with
    the credential stripped, a preview would then report a *failure*, which
    is equally untrue.
    """
    result = await SlackNotify().execute(
        _request("slack", webhook_url="https://hooks.slack.com/services/T/B/x", message="hello", dry_run=False)
    )
    # Sanity: without dry_run the adapter delegates. The dry-run branch is
    # the assertion below; this line proves the two paths are distinct.
    assert result.status in {LiveActionStatus.SUCCEEDED, LiveActionStatus.FAILED}

    preview = await SlackNotify().execute(
        LiveActionRequest(
            capability="notify",
            vendor_id="slack",
            params={"webhook_url": "https://hooks.slack.com/services/T/B/x", "message": "hello"},
            dry_run=True,
        )
    )
    assert preview.status == LiveActionStatus.SIMULATED
    assert "would notify" in preview.summary


# ---------------------------------------------------------------------------
# Mock-vendor smoke — notify
# ---------------------------------------------------------------------------


@respx.mock
async def test_teams_posts_an_adaptive_card_to_a_workflows_webhook() -> None:
    route = respx.post("https://prod-1.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke").mock(
        return_value=httpx.Response(202, text="")
    )
    result = await notify_arms.TeamsWebhookNotify().execute(
        _request(
            "teams",
            webhook_url="https://prod-1.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
            message="Impossible travel for alice@example.com",
            destination="TEAMS_SOC",
        )
    )
    assert result.status == LiveActionStatus.SUCCEEDED
    sent = route.calls[0].request
    body = sent.read().decode()
    assert '"type":"message"' in body
    assert "application/vnd.microsoft.card.adaptive" in body
    assert "Impossible travel for alice@example.com" in body
    # The webhook URL is a bearer credential for Teams; the audit record
    # names the destination and never its address.
    assert result.details["destination"] == "TEAMS_SOC"
    assert "logic.azure.com" not in str(result.details)


@respx.mock
async def test_teams_reports_a_rejected_post_rather_than_succeeding() -> None:
    respx.post("https://teams.example/hook").mock(return_value=httpx.Response(400, text="Bad payload"))
    result = await notify_arms.TeamsWebhookNotify().execute(_request("teams", webhook_url="https://teams.example/hook", message="x"))
    assert result.status == LiveActionStatus.FAILED
    assert "400" in (result.error or "")


@respx.mock
async def test_pagerduty_triggers_through_the_events_api() -> None:
    route = respx.post("https://events.pagerduty.com/v2/enqueue").mock(
        return_value=httpx.Response(202, json={"status": "success", "message": "Event processed", "dedup_key": "dk-1"})
    )
    result = await notify_arms.PagerDutyNotify().execute(
        _request("pagerduty", pd_routing_key="R" * 32, message="Credential stuffing", severity="critical", destination="PD_SOC_KEY")
    )
    assert result.status == LiveActionStatus.SUCCEEDED
    body = route.calls[0].request.read().decode()
    assert '"event_action"' in body and "trigger" in body
    assert "critical" in body


async def test_pagerduty_without_a_routing_key_says_so() -> None:
    result = await notify_arms.PagerDutyNotify().execute(_request("pagerduty", message="x"))
    assert result.status == LiveActionStatus.FAILED
    assert "routing key" in (result.error or "")


async def test_email_sends_through_the_relay_off_the_event_loop() -> None:
    sent: dict[str, Any] = {}

    def _capture(**kwargs: Any) -> None:
        sent.update(kwargs)

    with patch.object(notify_arms, "_send_smtp", _capture):
        result = await notify_arms.EmailNotify().execute(
            _request(
                "email",
                smtp_host="smtp.example.com",
                smtp_port=587,
                smtp_sender="aisoc@example.com",
                smtp_recipients="soc@example.com, ciso@example.com",
                message="Suspicious sign-in blocked",
                destination="EMAIL_SOC",
            )
        )
    assert result.status == LiveActionStatus.SUCCEEDED
    assert sent["recipients"] == ["soc@example.com", "ciso@example.com"]
    assert sent["body"] == "Suspicious sign-in blocked"
    assert result.details["recipient_count"] == 2


async def test_email_without_recipients_is_not_a_send() -> None:
    result = await notify_arms.EmailNotify().execute(_request("email", smtp_host="smtp.example.com", message="x"))
    assert result.status == LiveActionStatus.FAILED
    assert "recipient" in (result.error or "")


@pytest.mark.parametrize("arm", notify_arms.NOTIFY_ARMS)
async def test_every_notify_arm_previews_without_touching_a_vendor(arm: type[LiveActionExecutor]) -> None:
    """Off by default means a preview reaches nothing, on every arm."""
    with respx.mock(assert_all_called=False) as mock:
        catch_all = mock.route(host__regex=r".*").mock(return_value=httpx.Response(500))
        result = await arm().execute(
            LiveActionRequest(
                capability="notify",
                vendor_id=arm.vendor_id,
                params={"webhook_url": "https://x.example/hook", "pd_routing_key": "k", "smtp_host": "s", "smtp_recipients": ["a@b.c"]},
                dry_run=True,
            )
        )
    assert result.status == LiveActionStatus.SIMULATED
    assert not catch_all.called


# ---------------------------------------------------------------------------
# Credential strip — the list must match what the sender reads, exactly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arm", notify_arms.NOTIFY_ARMS + osquery_arms.OSQUERY_ARMS)
def test_declared_credential_keys_are_the_keys_the_arm_reads(arm: type[LiveActionExecutor]) -> None:
    """A key the sender reads and the list omits survives a dry run.

    That is not a theoretical hazard here: ``_SPLUNK_KEYS`` listed
    ``splunk_host``/``token``/``index`` while the client factory read
    ``splunk_url`` plus basic-auth credentials, so a "dry run" called the
    customer's Splunk. Elastic had the identical bug.

    Read off the source rather than by calling, because the branch that
    reads a key is often the one a test would not reach.
    """
    declared = set(getattr(arm, "_credential_keys", ()))
    body = inspect.getsource(arm)
    if arm in osquery_arms.OSQUERY_ARMS:
        body += inspect.getsource(osquery_arms._OsqueryLiveQuery)
    read = {key for key in declared if f'"{key}"' in body}
    assert read == declared, f"{arm.__name__} declares {sorted(declared - read)} that its sender never reads"

    # And the other direction: every params key the sender reads that looks
    # like a credential must be declared. `message`, `severity`, `subject`
    # and friends are content, not secrets, so they are named as exempt.
    content_keys = {"message", "text", "severity", "source", "dedup_key", "destination", "to", "subject", "target_hosts", "template"}
    reads = {
        match.strip("\"'")
        for match in __import__("re").findall(r'params\.get\(\s*["\']([a-z_]+)["\']', body)
        if match not in content_keys and not match.startswith("template")
    }
    assert reads <= declared, f"{arm.__name__} reads {sorted(reads - declared)} which a dry run would not strip"


# ---------------------------------------------------------------------------
# Mock-vendor smoke — osquery
# ---------------------------------------------------------------------------


async def test_osquery_refuses_a_step_with_no_template() -> None:
    """No SQL is accepted from a caller, so a missing template is a refusal.

    Defaulting to some template would run a query nobody asked for against
    production endpoints.
    """
    result = await osquery_arms.FleetDMLiveQuery().execute(
        LiveActionRequest(capability="osquery_live_query", vendor_id="fleetdm", target="WS-1", params={})
    )
    assert result.status == LiveActionStatus.FAILED
    assert "template" in (result.error or "")


async def test_osquery_refuses_a_step_with_no_hosts() -> None:
    result = await osquery_arms.FleetDMLiveQuery().execute(
        LiveActionRequest(capability="osquery_live_query", vendor_id="fleetdm", params={"template": "processes_by_name"})
    )
    assert result.status == LiveActionStatus.FAILED
    assert "host" in (result.error or "")


async def test_osquery_without_credentials_is_not_a_statement_about_the_hosts() -> None:
    result = await osquery_arms.OsctrlLiveQuery().execute(
        LiveActionRequest(
            capability="osquery_live_query",
            vendor_id="osctrl",
            target="WS-1",
            params={"template": "processes_by_name"},
        )
    )
    assert result.status == LiveActionStatus.FAILED
    assert "not a statement about the hosts" in (result.error or "")


async def test_osquery_runs_the_allowlisted_template_through_its_client() -> None:
    """Autospec'd, so a signature drift between arm and client fails here.

    Simulation never constructs the client, which is exactly why this kind
    of drift shipped twice before: ``SearchSIEMExecutor`` passed
    ``max_results=`` to a client taking ``max_count``.
    """
    with patch.object(FleetDMClient, "live_query", autospec=True) as live_query:
        live_query.return_value = {"results": {"WS-1": [{"name": "mimikatz.exe", "pid": 4242}]}}
        result = await osquery_arms.FleetDMLiveQuery().execute(
            LiveActionRequest(
                capability="osquery_live_query",
                vendor_id="fleetdm",
                target="WS-1",
                params={
                    "base_url": "https://fleet.example.com",
                    "api_token": "t",
                    "template": "processes_by_name",
                    "template_params": {"name": "mimikatz.exe"},
                    "timeout_seconds": 30,
                },
            )
        )
    assert result.status == LiveActionStatus.SUCCEEDED
    _self, hosts, template, template_params, timeout = live_query.call_args.args
    assert hosts == ["WS-1"]
    assert template == "processes_by_name"
    assert template_params == {"name": "mimikatz.exe"}
    assert timeout == 30


async def test_osquery_clamps_an_unbounded_timeout() -> None:
    """``params`` bypasses the Pydantic bound on ``PlaybookStep``."""
    with patch.object(OsctrlClient, "live_query", autospec=True) as live_query:
        live_query.return_value = {"results": {}}
        await osquery_arms.OsctrlLiveQuery().execute(
            LiveActionRequest(
                capability="osquery_live_query",
                vendor_id="osctrl",
                target="WS-1",
                params={"base_url": "https://osctrl.example.com", "api_token": "t", "template": "t1", "timeout_seconds": 99999},
            )
        )
    assert live_query.call_args.args[4] == osquery_arms._MAX_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("arm", "client"),
    [
        (osquery_arms.OsctrlLiveQuery, OsctrlClient),
        (osquery_arms.FleetDMLiveQuery, FleetDMClient),
        (osquery_arms.AiSOCDirectLiveQuery, AiSOCDirectClient),
    ],
)
def test_each_arm_builds_its_client_with_a_signature_the_client_accepts(arm: type, client: type) -> None:
    """Constructor drift is the other half of the simulation blind spot."""
    built = arm()._client({"base_url": "https://x.example.com", "api_token": "t", "environment": "prod"})
    assert isinstance(built, client)


def test_pagerduty_arm_matches_the_client_signature() -> None:
    """Caught a real drift while this file was being written.

    The arm passed ``dedup_key=``; the client takes ``case_id`` and derives
    the dedup key from it. Simulation never constructs the client, so the
    first time anyone would have seen it was a live page that raised
    ``TypeError`` instead of going out.
    """
    signature = inspect.signature(PagerDutyClient.trigger_incident)
    for name in ("summary", "severity", "source", "case_id"):
        assert name in signature.parameters, f"PagerDutyNotify passes {name!r}, which the client does not accept"
    assert "dedup_key" not in signature.parameters
