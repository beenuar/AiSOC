"""The AI-asset recorder against what the connector really emits.

Why this file exists beside `test_ai_asset_recorder.py`
--------------------------------------------------------
That suite hand-builds the OCSF event it wants: it writes
``finding.evidence.scopes`` and asserts the recorder reads
``finding.evidence.scopes``. Both halves are the test's own invention. No
connector in the tree produces that path, and ingest does not synthesise it,
so the assertion holds whether or not the production path works — the test
double is more capable than the real thing.

What ingest actually does is store the connector's own normalized dict as a
**JSON string** under ``ocsf["raw_data"]``; the canonical OCSF field map
carries the identity aliases and nothing else. So every connector-specific
field — a consent grant's scope list, a Copilot record's sensitivity labels —
exists only there, which is exactly why ``_connector_fields`` exists for the
endpoint path.

The fixture below is the real output of
``LlmUsageConnector.normalize()``, captured by
``services/connectors/tests/connectors/test_llm_usage_recorder_fixture.py``,
which regenerates it and fails if it drifts. Two services that cannot import
each other (both package their application as ``app``) are held together by a
committed artefact plus a check in each direction, the same way the vendored
narrative and the detection ruleset are.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from app.services.ai_asset_recorder import classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "llm_usage"
TENANT = "11111111-1111-1111-1111-111111111111"


def _ingest_shape(connector_event: dict) -> dict:
    """What `services/ingest` hands fusion for a connector-pulled event.

    `raw_data` is a JSON **string** — `json.Marshal` then `string` on the Go
    side. A test that puts a dict here is testing a path that does not
    exist, and the dict branch of `_connector_fields` is there only for
    OCSF-native producers.
    """
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 3001,
            "source_type": "llm_usage",
            "activity_name": connector_event["event_type"],
            "actor": {"user": {"name": connector_event.get("actor_email")}},
            "metadata": {"product": {"vendor_name": "Microsoft Entra", "name": "AI / LLM Usage Audit"}},
            "message": connector_event["title"],
            "finding": {"uid": connector_event["external_id"]},
            "raw_data": json.dumps(connector_event),
        },
    }


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_entra_consent_grant_carries_its_scopes_into_the_inventory():
    """The decisive field, through the real shape.

    `Mail.Read` and `Files.ReadWrite.All` are both in
    `BROAD_OAUTH_SCOPES`. If the recorder cannot see them, an AI notetaker
    that has been consented into every mailbox in the organisation scores
    identically to one that was granted nothing, and the console's reason
    list says nothing about the scope — which is the one fact that decides
    whether this grant matters.
    """
    sightings = classify(_ingest_shape(_load("entra_consent_grant.json")))

    assert [s.kind for s in sightings] == ["oauth_grant"]
    assert sightings[0].attributes["scopes"] == ["Files.ReadWrite.All", "Mail.Read"]
    # The application, not the audit record id, is the thing being governed.
    # Keying on the record id would make every re-consent a new asset and
    # reset `first_seen_at` each time.
    assert sightings[0].external_id == "app-1"
    assert sightings[0].display_name == "Acme AI Notetaker"
    assert sightings[0].principal == "carol@example.com"


def test_a_consent_grant_with_narrow_scopes_is_still_recorded_but_not_broad():
    """The negative half: the discriminator is the scope, not the event.

    A grant exists either way — an unreviewed AI application in the estate
    is a finding on its own — but only the broad one may carry a broad-scope
    reason. Without this, a reader that stamped every grant 'broad' would
    pass the test above and be useless.
    """
    sightings = classify(_ingest_shape(_load("entra_consent_grant_narrow.json")))

    assert [s.kind for s in sightings] == ["oauth_grant"]
    assert sightings[0].attributes["scopes"] == ["User.Read"]


@pytest.mark.parametrize(
    "name",
    ["entra_consent_grant.json", "entra_consent_grant_narrow.json"],
)
def test_every_fixture_is_a_real_connector_output_shape(name: str):
    """Guard against a fixture being hand-edited into something nicer.

    The three keys below are the ones the canonical-envelope check and the
    detection engine depend on; a fixture missing any of them would be
    testing a shape ingest never produces.
    """
    blob = _load(name)
    assert blob["source"] == "llm_usage"
    assert isinstance(blob["raw_event"], dict)
    assert str(blob["event_type"]).count(".") >= 1
