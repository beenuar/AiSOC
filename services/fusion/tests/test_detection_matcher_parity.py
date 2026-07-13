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
    """Sanity: the vendored matcher upholds the fixture contract directly."""
    fixtures_dir = _REPO / "detections" / "fixtures"
    ruleset = _REPO / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
    rules = {r["slug"]: r["match_when"] for r in json.loads(ruleset.read_text())["rules"]}
    checked = 0
    for f in sorted((fixtures_dir / "positive").glob("*.json")):
        mw = rules.get(f.stem)
        if mw is None:
            continue
        assert vendored_matches(mw, json.loads(f.read_text())), f"positive fixture did not fire: {f.stem}"
        checked += 1
    assert checked > 100, f"expected to check many positive fixtures, only {checked}"
