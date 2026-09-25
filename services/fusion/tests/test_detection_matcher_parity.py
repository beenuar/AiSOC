"""Phase A2 — vendored matcher parity gate.

`app/services/detection_matcher.py` is a vendored copy of the canonical matcher
in `scripts/generate_detections.py` (services can't import repo-root scripts at
runtime). This test imports BOTH and asserts identical verdicts over every
committed detection fixture + the exported ruleset's positive/negative specs,
so the copy can never silently diverge from the source of truth.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from app.services.detection_matcher import matches as vendored_matches

_REPO = Path(__file__).resolve().parents[3]


def _load_canonical():
    path = _REPO / "scripts" / "generate_detections.py"
    if not path.exists():
        pytest.skip("repo-root scripts/generate_detections.py not present")
    spec = importlib.util.spec_from_file_location("aisoc_gen_detections_canonical", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fixture_pairs() -> list[tuple[dict, dict]]:
    """Return (match_when, event) pairs from the exported ruleset is not
    possible (no fixtures there); instead read the committed fixtures dir."""
    fixtures_dir = _REPO / "detections" / "fixtures"
    ruleset = _REPO / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
    rules = {r["slug"]: r["match_when"] for r in json.loads(ruleset.read_text())["rules"]}
    pairs: list[tuple[dict, dict]] = []
    for kind in ("positive", "negative"):
        d = fixtures_dir / kind
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            mw = rules.get(f.stem)
            if mw is None:
                continue
            try:
                event = json.loads(f.read_text())
            except ValueError:
                continue
            pairs.append((mw, event))
    return pairs


def test_vendored_matcher_matches_canonical_over_all_fixtures():
    canonical = _load_canonical()
    pairs = _fixture_pairs()
    assert pairs, "no fixture/rule pairs found to compare"
    disagreements = []
    for mw, event in pairs:
        if vendored_matches(mw, event) != canonical.matches(mw, event):
            disagreements.append((mw, event))
    assert not disagreements, f"vendored matcher diverged from canonical on {len(disagreements)} pairs"


def test_positive_fixtures_fire_and_negatives_do_not():
    """Sanity: the vendored matcher upholds the fixture contract directly.

    Events go through the same derived-field enrichment
    ``DetectionEngine.evaluate`` applies. Replaying a fixture against the
    bare matcher tests a pipeline production does not run — and a rule
    matching on a derived field would fail here while working live, which
    trains people to weaken the gate.
    """
    from app.services.derived_fields import enrich, requested_derived_fields

    fixtures_dir = _REPO / "detections" / "fixtures"
    ruleset = _REPO / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
    all_rules = json.loads(ruleset.read_text())["rules"]
    rules = {r["slug"]: r["match_when"] for r in all_rules}
    wanted = requested_derived_fields(all_rules)

    checked = 0
    for f in sorted((fixtures_dir / "positive").glob("*.json")):
        mw = rules.get(f.stem)
        if mw is None:
            continue
        event = enrich(json.loads(f.read_text()), wanted)
        assert vendored_matches(mw, event), f"positive fixture did not fire: {f.stem}"
        checked += 1
    assert checked > 100, f"expected to check many positive fixtures, only {checked}"

    negatives = 0
    for f in sorted((fixtures_dir / "negative").glob("*.json")):
        mw = rules.get(f.stem)
        if mw is None:
            continue
        event = enrich(json.loads(f.read_text()), wanted)
        assert not vendored_matches(mw, event), f"negative fixture fired: {f.stem}"
        negatives += 1
    assert negatives > 100, f"expected to check many negative fixtures, only {negatives}"


def test_vendored_derived_fields_match_canonical():
    """The derived-field helpers are vendored the same way `matches()` is.

    Two copies that can drift silently are worse than one copy plus a gate,
    and this is the gate. Without it the engine could compute a field the
    validator does not, so a rule would pass CI and never fire — or fire in
    CI and never in production.
    """
    from app.services import derived_fields as vendored

    canonical = _load_canonical()
    cases = [
        ({"actor": "alice", "target": "alice"}, {"actor_eq_target"}),
        ({"actor": "Alice", "target": "alice "}, {"actor_eq_target"}),
        ({"actor": "alice"}, {"actor_eq_target"}),
        ({"actor_uid": 1000, "owner_uid": 0}, {"actor_uid_neq_owner_uid"}),
        ({"event_time": "2026-09-22T14:00:00"}, set()),
        ({"event_time": "2026-09-26T14:00:00"}, set()),
        ({"event_time": "not a date"}, set()),
        ({"user_name": "x"}, {"a_eq_b"}),
    ]
    for event, wanted in cases:
        assert vendored.enrich(dict(event), set(wanted)) == canonical.enrich(dict(event), set(wanted)), (
            f"vendored and canonical enrich disagree on {event}"
        )


def test_vendored_requested_fields_match_canonical():
    from app.services import derived_fields as vendored

    canonical = _load_canonical()
    rules = [
        {"match_when": {"actor_eq_target": False, "event_name": "CreateAccessKey"}},
        {"match_when": {"any_of": [{"is_business_hours": False}, {"x": 1}]}},
        {"match_when": {"actor_uid_neq_owner_uid": True, "syscall": "openat"}},
    ]
    assert vendored.requested_derived_fields(rules) == canonical.requested_derived_fields(rules)
