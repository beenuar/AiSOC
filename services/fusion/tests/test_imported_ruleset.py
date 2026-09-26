"""The imported ruleset must add rules without disturbing the native ones.

The compiled Sigma corpus roughly trebles what the engine loads. Two things
have to hold for that to be a safe change rather than a large one:

* every native rule keeps the verdict it had, on every committed fixture;
* nothing in the imported tier reuses a native rule id, because the id is a
  join key — it lands on alert rows, suppression priors and customer-written
  exceptions, so a collision would make one rule's history read as another's.

The first is checked by replay rather than by inspection: a change to the
shared field namespace does not show up in a diff of the rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.services.detection_engine import (
    _IMPORTED_RULESET_PATH,
    _RULESET_PATH,
    DetectionEngine,
    DetectionHit,
    _attribution,
)

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "detections" / "fixtures"


def _rules(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["rules"] if path.exists() else []


@pytest.fixture(scope="module")
def native() -> list[dict]:
    return _rules(_RULESET_PATH)


@pytest.fixture(scope="module")
def imported() -> list[dict]:
    return _rules(_IMPORTED_RULESET_PATH)


def _fired(engine: DetectionEngine, event: dict) -> set[str]:
    message = {"ocsf_event": {"raw_data": json.dumps(event, default=str)}}
    return {hit.rule_id for hit in engine.evaluate(message)}


def test_engine_loads_both_rulesets(native, imported):
    assert imported, "the compiled Sigma ruleset is missing — run scripts/compile_sigma_ruleset.py"
    assert DetectionEngine().rule_count == len(native) + len(imported)


def test_no_rule_id_collision_between_tiers(native, imported):
    overlap = {r["id"] for r in native} & {r["id"] for r in imported}
    assert not overlap, f"imported rules reuse native rule ids: {sorted(overlap)[:5]}"


def test_imported_rules_do_not_change_any_native_verdict(native, imported):
    """Replay every committed fixture with and without the imported tier."""
    before = DetectionEngine(rules=native)
    after = DetectionEngine(rules=native + imported)
    native_ids = {r["id"] for r in native}

    drift: list[str] = []
    replayed = 0
    for kind in ("positive", "negative"):
        for path in sorted((FIXTURES / kind).glob("*.json")):
            event = json.loads(path.read_text(encoding="utf-8"))
            if _fired(before, event) != _fired(after, event) & native_ids:
                drift.append(f"{kind}/{path.name}")
            replayed += 1

    assert replayed > 0, "no fixtures were replayed, so this proved nothing"
    assert not drift, f"{len(drift)} fixtures changed which native rules fire: {drift[:5]}"


def test_every_imported_rule_carries_attribution(imported):
    """DRL-1.1 requires attribution to survive redistribution and reach matches."""
    missing = [r["id"] for r in imported if not _attribution(r)]
    assert not missing, f"{len(missing)} imported rules would alert with no upstream credit: {missing[:5]}"


def test_attribution_is_empty_for_a_native_rule(native):
    """Native rules are AiSOC's own, so they must not claim an upstream."""
    assert native, "the native ruleset is missing"
    assert _attribution(native[0]) == ""


def test_alert_description_carries_the_attribution(imported):
    """The credit has to reach the alert, not just the rule file.

    DRL-1.1 asks for two different things, and only one of them is about
    redistribution: messages produced by a match must themselves identify the
    author. An alert is such a message.
    """
    rule = imported[0]
    hit = DetectionHit(
        rule_id=rule["id"],
        name=rule["name"],
        severity=rule["severity"],
        category=rule["category"],
        mitre=[],
        attribution=_attribution(rule),
    )
    alert = DetectionEngine(rules=[rule]).build_alert({"tenant_id": "00000000-0000-0000-0000-000000000001"}, hit)
    assert alert is not None
    assert "SigmaHQ/sigma" in alert.description
    assert "DRL-1.1" in alert.description
