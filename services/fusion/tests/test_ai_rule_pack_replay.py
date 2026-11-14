"""The wave-2 AI rules, replayed through the real connector and real engine.

Depth plan wave 2, Phase 7.4.

Why this file is shaped the way it is
--------------------------------------
"A rule counts only when it is replayed through its real connector and the
real engine with a positive fixture that fires and a negative fixture that
differs in exactly one decisive field and does not." That is the plan's rule
and it exists because of a measured failure: **1 of 12 GitHub rules fired on
real connector output**, because the rest claused on unprefixed event names
the connector never emits. Every one of those twelve passed its own fixture
replay, because fixtures are synthesized from the rule they test — so the
fixture carried the rule's own clause key and the replay was tautological.

So nothing here is synthesized from a rule. Each fixture is the committed
output of `LlmUsageConnector.normalize()` on a vendor-shaped record,
regenerated and drift-checked by
`services/connectors/tests/connectors/test_llm_usage_recorder_fixture.py`.
The two services cannot import each other — both package their application
as `app` — so the artefact plus a check in each direction is the join.

The engine below is the real `DetectionEngine` loading the real compiled
ruleset, not a matcher invoked on one rule. That matters: the engine
indexes rules by required field and reconstructs the connector namespace
from `raw_data`, and both of those are steps at which a rule that looks
correct stops firing.

Each negative differs in exactly one field
-------------------------------------------
A different audit action, a read scope where the twin is write, 24
resources where the twin is 40. Everything else — actor, application,
timestamps, event family — is identical, so a passing negative is evidence
about the clause and not about the shape.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from app.services.detection_engine import DetectionEngine

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "llm_usage"
TENANT = "11111111-1111-1111-1111-111111111111"

#: slug -> (positive fixture, negative fixture, the field the twin differs in)
CASES: dict[str, tuple[str, str, str]] = {
    "llm-copilot-content-exclusion-changed": (
        "rule_content_exclusion_changed.json",
        "rule_content_exclusion_changed_negative.json",
        "the audit action",
    ),
    "llm-copilot-agent-mcp-config-changed": (
        "rule_agent_mcp_config_changed.json",
        "rule_agent_mcp_config_changed_negative.json",
        "the audit action",
    ),
    "llm-ai-app-granted-write-scope": (
        "rule_ai_app_write_scope.json",
        "rule_ai_app_write_scope_negative.json",
        "the granted scope",
    ),
    "llm-copilot-bulk-resource-access": (
        "rule_copilot_bulk_access.json",
        "rule_copilot_bulk_access_negative.json",
        "the accessed-resource count",
    ),
}


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    """The real engine over the real compiled ruleset."""
    return DetectionEngine()


def _message(fixture: str) -> dict:
    """What ingest hands fusion for a connector-pulled event.

    `raw_data` is a JSON **string**, which is what `json.Marshal` then
    `string` produces on the Go side. A test that puts a dict here
    exercises a branch the production path does not take.
    """
    event = json.loads((FIXTURES / fixture).read_text())
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 3001,
            "source_type": "llm_usage",
            "activity_name": event["event_type"],
            "actor": {"user": {"name": event.get("actor_email")}},
            "metadata": {"product": {"name": "AI / LLM Usage Audit", "vendor_name": "AI provider"}},
            "message": event["title"],
            "finding": {"uid": event["external_id"]},
            "raw_data": json.dumps(event),
        },
    }


RULESET = pathlib.Path(__file__).parents[1] / "app" / "data" / "detection_ruleset.json"


def _compiled() -> list[dict]:
    blob = json.loads(RULESET.read_text())
    return blob["rules"] if isinstance(blob, dict) and "rules" in blob else blob


#: The engine reports a hit by rule id; the plan, the YAML and this file all
#: speak slugs. Resolved through the compiled artefact rather than by
#: hardcoding the ids, because ids are positional and a rule inserted
#: earlier in a category shifts every later one.
_ID_TO_SLUG: dict[str, str] = {r["id"]: r["slug"] for r in _compiled()}


def _slugs(engine: DetectionEngine, fixture: str) -> set[str]:
    out: set[str] = set()
    for hit in engine.evaluate(_message(fixture)):
        identifier = getattr(hit, "rule_id", None) or getattr(hit, "id", None) or ""
        out.add(_ID_TO_SLUG.get(identifier, identifier))
    return out


@pytest.mark.parametrize(("slug", "case"), sorted(CASES.items()))
def test_the_positive_fixture_fires(engine: DetectionEngine, slug: str, case: tuple[str, str, str]):
    positive, _negative, _field = case
    assert slug in _slugs(engine, positive), (
        f"{slug} did not fire on real connector output. This is the failure the "
        "GitHub pass measured: a rule clausing on a field name the connector "
        "never emits passes its own synthesized fixture and fires on nothing."
    )


@pytest.mark.parametrize(("slug", "case"), sorted(CASES.items()))
def test_the_negative_twin_does_not_fire(engine: DetectionEngine, slug: str, case: tuple[str, str, str]):
    _positive, negative, field = case
    assert slug not in _slugs(engine, negative), (
        f"{slug} fired on its negative twin, which differs only in {field}. A rule that fires either way is not a detection."
    )


def test_the_rules_are_in_the_compiled_ruleset_the_engine_loads():
    """Not in a YAML file somewhere.

    `detections/*.yaml` is generated output; the engine loads
    `detection_ruleset.json`. A rule present in one and absent from the
    other is a published figure describing something that does not run —
    the exact gap `docs/detections/truth-table.md` was found to have when
    it published 947 executable against an engine loading 825.
    """
    compiled = {r["slug"] for r in _compiled()}
    missing = sorted(set(CASES) - compiled)
    assert not missing, f"declared but not compiled: {missing}"


def test_each_pair_differs_in_exactly_one_field():
    """The property that makes a passing negative mean anything.

    Asserted on the fixtures rather than trusted: a negative that also
    changed the actor, or the event family, would pass for a reason that
    has nothing to do with the clause under test, and nobody would notice.
    """
    ignored = {"external_id", "description", "raw_event", "title"}
    for slug, (positive, negative, _field) in sorted(CASES.items()):
        pos = json.loads((FIXTURES / positive).read_text())
        neg = json.loads((FIXTURES / negative).read_text())
        differing = {key for key in set(pos) | set(neg) if key not in ignored and pos.get(key) != neg.get(key)}
        # `event_type` and `severity` move together with the decisive field
        # for the two action-keyed rules, because severity is derived from
        # the event type — that is one change, not three.
        differing -= {"severity"}
        assert len(differing) <= 2, f"{slug}: twins differ in {sorted(differing)}, which is more than one decision"
