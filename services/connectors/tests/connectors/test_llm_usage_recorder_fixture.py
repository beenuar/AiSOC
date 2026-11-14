"""Keep the fusion recorder's fixtures equal to this connector's real output.

`services/fusion` cannot import `services/connectors` — both package their
application as `app`, so importing one in a process shadows the other. The
AI-asset recorder nonetheless has to be tested against what the connector
*really* emits rather than against a shape a fusion test invented, because
inventing the shape is how a recorder came to read `finding.evidence.scopes`,
a path no connector produces.

So the connector's output is committed as a fixture under
`services/fusion/tests/fixtures/llm_usage/` and this test regenerates it and
compares. Two directions, like the vendored narrative and the detection
ruleset: fusion asserts it can read the fixture, this asserts the fixture is
still what the connector produces. Either half alone would rot.

Run with `AISOC_REGENERATE_FIXTURES=1` to rewrite them after a deliberate
change to `normalize()`.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest
from app.connectors.llm_usage import LlmUsageConnector

FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "fusion" / "tests" / "fixtures" / "llm_usage"

GH = {"provider": "github_copilot", "api_key": "ghp_x", "organization": "acme"}
ENTRA = {"provider": "entra_consent", "api_key": "k"}
M365 = {"provider": "microsoft_copilot", "api_key": "k", "tenant": "t"}


def _consent(record_id: str, scope: str) -> dict:
    """One Entra consent record differing only in the granted scope."""
    return {
        "id": record_id,
        "activityDisplayName": "Consent to application",
        "activityDateTime": "2026-10-30T09:15:00Z",
        "initiatedBy": {"user": {"userPrincipalName": "carol@example.com"}},
        "targetResources": [
            {
                "displayName": "Acme AI Notetaker",
                "id": "app-1",
                "modifiedProperties": [{"displayName": "ConsentAction.Permissions", "newValue": f"Scope: {scope}"}],
            }
        ],
    }


def _copilot(record_id: str, resources: int) -> dict:
    """One Copilot interaction differing only in how many resources it read."""
    return {
        "Id": record_id,
        "RecordType": 261,
        "Operation": "CopilotInteraction",
        "CreationTime": "2026-10-30T09:15:00",
        "UserId": "bob@example.com",
        "Workload": "Copilot",
        "CopilotEventData": {
            "AppHost": "Word",
            "AccessedResources": [{"Type": "File", "Id": f"f{i}"} for i in range(resources)],
        },
    }


#: Vendor-shaped source records. Every field is one the vendor's published
#: reference shows; see the connector module docstring for the URLs.
CASES: dict[str, tuple[dict, dict]] = {
    "entra_consent_grant.json": (
        {"provider": "entra_consent", "api_key": "k"},
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
    ),
    # The negative twin: identical in every field but the granted scope,
    # which is the one that decides whether this grant is broad.
    "entra_consent_grant_narrow.json": (
        {"provider": "entra_consent", "api_key": "k"},
        {
            "id": "a-2",
            "activityDisplayName": "Consent to application",
            "activityDateTime": "2026-10-30T09:15:00Z",
            "initiatedBy": {"user": {"userPrincipalName": "carol@example.com"}},
            "targetResources": [
                {
                    "displayName": "Acme AI Notetaker",
                    "id": "app-1",
                    "modifiedProperties": [{"displayName": "ConsentAction.Permissions", "newValue": "Scope: User.Read"}],
                }
            ],
        },
    ),
    # ---- 7.4 rule-pack replay fixtures -----------------------------------
    # Each pair differs in exactly ONE decisive field: the audit action, the
    # granted scope, the resource count. Anything else differing would make
    # a passing negative prove nothing about the clause under test.
    "rule_content_exclusion_changed.json": (
        GH,
        {
            "action": "copilot.content_exclusion_changed",
            "actor": "octocat",
            "org": "acme",
            "created_at": 1761800000000,
            "_document_id": "ce-1",
        },
    ),
    "rule_content_exclusion_changed_negative.json": (
        GH,
        # The decisive field, and only it: a different Copilot action.
        {"action": "copilot.cfb_seat_added", "actor": "octocat", "org": "acme", "created_at": 1761800000000, "_document_id": "ce-2"},
    ),
    "rule_agent_mcp_config_changed.json": (
        GH,
        {
            "action": "copilot.swe_agent_mcp_config_updated",
            "actor": "octocat",
            "org": "acme",
            "created_at": 1761800000000,
            "_document_id": "mc-1",
        },
    ),
    "rule_agent_mcp_config_changed_negative.json": (
        GH,
        # A sibling agent setting that is not the server list.
        {
            "action": "copilot.swe_agent_repo_enabled",
            "actor": "octocat",
            "org": "acme",
            "created_at": 1761800000000,
            "_document_id": "mc-2",
        },
    ),
    "rule_ai_app_write_scope.json": (ENTRA, _consent("ws-1", "Mail.ReadWrite")),
    # Read where the twin is write. Same application, same actor, same
    # event: only the scope decides.
    "rule_ai_app_write_scope_negative.json": (ENTRA, _consent("ws-2", "Mail.Read")),
    "rule_copilot_bulk_access.json": (M365, _copilot("bulk-1", 40)),
    # One below the threshold of 25, so the clause and not the shape is
    # what the negative exercises.
    "rule_copilot_bulk_access_negative.json": (M365, _copilot("bulk-2", 24)),
}


def _render(kwargs: dict, record: dict) -> dict:
    out = LlmUsageConnector(**kwargs).normalize(record)
    assert out is not None, "normalize discarded a record the fixture needs"
    return out


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_matches_the_connector_output(name: str):
    kwargs, record = CASES[name]
    rendered = _render(kwargs, record)
    path = FIXTURES / name

    if os.environ.get("AISOC_REGENERATE_FIXTURES") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")

    assert path.exists(), f"{path} is missing — regenerate with AISOC_REGENERATE_FIXTURES=1"
    committed = json.loads(path.read_text())
    assert committed == rendered, (
        f"{name} no longer matches LlmUsageConnector.normalize(). The fusion "
        "recorder reads this file; regenerate it and re-run the fusion suite "
        "rather than editing it by hand."
    )
