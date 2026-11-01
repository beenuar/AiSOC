"""Depth 6.3 / wave-2 7.1 — AI provider coverage beyond OpenAI and Anthropic.

The gap this file reproduces
----------------------------
``LlmUsageConnector`` accepted exactly two providers. Every other place an
enterprise's AI activity is audited — Gemini in Workspace, Copilot in M365,
Copilot in GitHub, and the consent grants that hand an AI application a whole
mailbox — had no reader at all, so the AI estate's provider-audit discovery
source could only ever see two vendors.

Each test below drives the connector's **real** HTTP path against a mock
server returning a payload shaped like the vendor's own documented response,
following ``test_live_vendor_smoke.py``. Endpoint, query parameters and event
names are taken from the vendor references named in the connector's module
docstring; nothing here is invented.

The negative half matters as much as the positive one: a provider's audit
feed carries far more routine traffic than AI traffic, and a reader that
promotes everything it is handed is a noise generator. ``test_*_filters_*``
asserts the discriminator, not just the parse.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.llm_usage import LlmUsageConnector

pytestmark = pytest.mark.asyncio

_LADDER = {"info", "low", "medium", "high", "critical"}


def _assert_shape(events: list[dict], provider: str) -> None:
    assert events, f"{provider}: fetch_alerts returned nothing from the mock server"
    for e in events:
        assert e.get("source") == "llm_usage"
        assert e.get("severity") in _LADDER, f"{provider}: bad severity {e.get('severity')!r}"
        # The canonical envelope. Emitting `raw` instead of `raw_event` is
        # what once sent 26 connectors through the borrowed Splunk profile.
        assert isinstance(e.get("raw_event"), dict)
        # The dotted top-level event_type is what every llm-* rule clauses on.
        assert str(e.get("event_type", "")).startswith(f"{provider}.")


# --------------------------------------------------------------------------
# Gemini in Workspace apps
# Admin SDK Reports API, applicationName `gemini_in_workspace_apps`.
# --------------------------------------------------------------------------

_GEMINI_ACTIVITY = {
    "items": [
        {
            "id": {"time": "2026-10-30T09:15:00.000Z", "uniqueQualifier": "-1234", "applicationName": "gemini_in_workspace_apps"},
            "actor": {"email": "alice@example.com", "profileId": "1001"},
            "events": [
                {
                    "type": "ai_usage_event",
                    "name": "feature_utilization",
                    "parameters": [
                        {"name": "app_name", "value": "docs"},
                        {"name": "feature_source", "value": "gemini_side_panel"},
                    ],
                }
            ],
        }
    ]
}


@respx.mock
async def test_gemini_reads_workspace_reports_api():
    route = respx.get(
        url__regex=r"https://admin\.googleapis\.com/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps.*"
    ).mock(return_value=httpx.Response(200, json=_GEMINI_ACTIVITY))

    c = LlmUsageConnector(provider="google_gemini", api_key="ya29.access-token")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(3600)

    _assert_shape(events, "google_gemini")
    assert route.called
    assert events[0]["event_type"] == "google_gemini.ai_usage_event.feature_utilization"
    assert events[0]["actor"] == "alice@example.com"


# --------------------------------------------------------------------------
# Copilot in GitHub
# GET /orgs/{org}/audit-log, phrase filter on the copilot action namespace.
# --------------------------------------------------------------------------

_GH_AUDIT = [
    {
        "action": "copilot.swe_agent_mcp_config_updated",
        "actor": "octocat",
        "org": "acme",
        "created_at": 1761800000000,
        "_document_id": "abc123",
    },
    {
        "action": "copilot.content_exclusion_changed",
        "actor": "octocat",
        "org": "acme",
        "created_at": 1761800100000,
        "_document_id": "def456",
    },
]


@respx.mock
async def test_github_copilot_reads_org_audit_log():
    route = respx.get(url__regex=r"https://api\.github\.com/orgs/acme/audit-log.*").mock(return_value=httpx.Response(200, json=_GH_AUDIT))

    c = LlmUsageConnector(provider="github_copilot", api_key="ghp_x", organization="acme")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(3600)

    _assert_shape(events, "github_copilot")
    assert route.called
    # The audit-log API filters server-side; asking for everything and
    # discarding client-side would pull an org's entire audit stream.
    # Read the decoded parameter rather than the raw URL: httpx
    # percent-encodes the colon, so a substring check on the URL asserts the
    # encoding rather than the filter.
    phrase = dict(httpx.URL(str(route.calls[-1].request.url)).params)["phrase"]
    assert phrase.startswith("action:copilot")
    assert events[0]["event_type"] == "github_copilot.copilot.swe_agent_mcp_config_updated"


# --------------------------------------------------------------------------
# Copilot in M365
# Office 365 Management Activity API; RecordType 261 CopilotInteraction and
# 284 AIAppInteraction are the two AI record types in the published schema.
# --------------------------------------------------------------------------

_M365_BLOBS = [{"contentUri": "https://manage.office.com/api/v1.0/t/activity/feed/audit/blob-1"}]
_M365_CONTENT = [
    {
        "Id": "ev-1",
        "RecordType": 261,
        "Operation": "CopilotInteraction",
        "CreationTime": "2026-10-30T09:15:00",
        "UserId": "bob@example.com",
        "Workload": "Copilot",
        "CopilotEventData": {"AppHost": "Word", "AccessedResources": [{"Type": "File", "SensitivityLabelId": "s-1"}]},
    },
    {
        # Not an AI record: the same feed carries the whole general audit.
        "Id": "ev-2",
        "RecordType": 20,
        "Operation": "PageViewed",
        "CreationTime": "2026-10-30T09:16:00",
        "UserId": "bob@example.com",
    },
]


@respx.mock
async def test_m365_copilot_reads_management_activity_api_and_filters_non_ai_records():
    respx.get(url__regex=r"https://manage\.office\.com/api/v1\.0/[^/]+/activity/feed/subscriptions/content.*").mock(
        return_value=httpx.Response(200, json=_M365_BLOBS)
    )
    respx.get("https://manage.office.com/api/v1.0/t/activity/feed/audit/blob-1").mock(return_value=httpx.Response(200, json=_M365_CONTENT))

    c = LlmUsageConnector(provider="microsoft_copilot", api_key="bearer-token", tenant="t")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(3600)
    _assert_shape(events, "microsoft_copilot")
    # Exactly the AI record survives. A reader that forwarded `PageViewed`
    # would turn the AI feed into the general audit feed.
    assert len(events) == 1
    assert events[0]["event_type"] == "microsoft_copilot.CopilotInteraction"


# --------------------------------------------------------------------------
# Entra consent grants to AI applications
# Microsoft Graph auditLogs/directoryAudits.
# --------------------------------------------------------------------------

_ENTRA_AUDITS = {
    "value": [
        {
            "id": "a-1",
            "activityDisplayName": "Consent to application",
            "activityDateTime": "2026-10-30T09:15:00Z",
            "initiatedBy": {"user": {"userPrincipalName": "carol@example.com"}},
            "targetResources": [
                {
                    "displayName": "Acme AI Notetaker",
                    "id": "app-1",
                    "modifiedProperties": [
                        {
                            "displayName": "ConsentAction.Permissions",
                            "newValue": "Scope: Mail.Read Files.ReadWrite.All",
                        }
                    ],
                }
            ],
        },
        {
            # A directory audit that is not a consent grant.
            "id": "a-2",
            "activityDisplayName": "Add user",
            "activityDateTime": "2026-10-30T09:16:00Z",
            "initiatedBy": {"user": {"userPrincipalName": "carol@example.com"}},
            "targetResources": [{"displayName": "dave", "id": "u-9"}],
        },
    ]
}


@respx.mock
async def test_entra_consent_reads_directory_audits_and_extracts_scopes():
    route = respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/auditLogs/directoryAudits.*").mock(
        return_value=httpx.Response(200, json=_ENTRA_AUDITS)
    )

    c = LlmUsageConnector(provider="entra_consent", api_key="bearer-token")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(3600)

    _assert_shape(events, "entra_consent")
    assert route.called
    assert len(events) == 1, "only the consent grant is an OAuth-grant observation"
    # The scopes are the whole point: `Mail.Read` is in BROAD_OAUTH_SCOPES
    # and is what makes the AI estate score this grant as broad.
    assert events[0]["raw_event"]["scopes"] == ["Files.ReadWrite.All", "Mail.Read"]
    assert events[0]["event_type"] == "entra_consent.consent_to_application"


# --------------------------------------------------------------------------
# Guard rails on the selector itself.
# --------------------------------------------------------------------------


async def test_unknown_provider_is_refused_by_name():
    with pytest.raises(ValueError, match="unknown provider"):
        LlmUsageConnector(provider="not_a_provider", api_key="k")


async def test_github_copilot_requires_an_organization():
    """A missing scope-narrowing field must fail at construction.

    The audit-log endpoint is org-scoped; without one there is no URL to
    call, and the honest failure is a refusal rather than a 404 at poll time
    that an operator reads as a credential problem.
    """
    with pytest.raises(ValueError, match="organization"):
        LlmUsageConnector(provider="github_copilot", api_key="ghp_x")


async def test_every_declared_provider_is_reachable_from_the_schema():
    """The select options and the accepted providers cannot drift.

    A provider offered in the console wizard that the constructor rejects is
    a connector a tenant can save and never poll.
    """
    options = {o["value"] for f in LlmUsageConnector.schema().fields if f.name == "provider" for o in (f.options or [])}
    assert options == set(LlmUsageConnector.PROVIDERS)
