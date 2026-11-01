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
