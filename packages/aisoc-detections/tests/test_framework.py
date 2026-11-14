"""Tests for the Python detection framework + the bundled example detections."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisoc_detections import (
    Detection,
    DetectionError,
    evaluate,
    load_detection,
    load_detections,
    run_fixtures,
    run_suite,
)

_ROOT = Path(__file__).resolve().parent.parent
_DETECTIONS = _ROOT / "detections"


def test_bundled_detections_all_pass_their_fixtures():
    report = run_suite(_DETECTIONS)
    assert report.detections >= 2
    assert report.cases >= 4
    assert report.passed, [f"{f.detection_id}:{f.case_name}" for f in report.failures]


def test_load_detections_validates_metadata():
    detections = load_detections(_DETECTIONS)
    ids = {d.id for d in detections}
    assert "py-okta-mfa-fatigue" in ids
    okta = next(d for d in detections if d.id == "py-okta-mfa-fatigue")
    assert okta.severity == "high"
    assert "T1621" in okta.mitre
    # dynamic title + dedup overrides are wired
    event = {"eventType": "user.mfa.attempt", "outcome": "challenge", "attempts": 6, "user": "ceo@corp.com"}
    assert "ceo@corp.com" in okta.title_for(event)
    assert okta.dedup_for(event)


def test_evaluate_is_fail_closed(tmp_path):
    boom = tmp_path / "boom.py"
    boom.write_text(
        "ID='py-boom'\nSEVERITY='low'\n"
        "def rule(event):\n    raise RuntimeError('kaboom')\n"
        "TESTS=[{'name':'p','event':{},'expect':True},{'name':'n','event':{},'expect':False}]\n"
    )
    det = load_detection(boom)
    # A raising rule never fires (and never crashes the batch).
    assert evaluate(det, {}) is False


def test_missing_rule_raises(tmp_path):
    bad = tmp_path / "norule.py"
    bad.write_text("ID='x'\nSEVERITY='low'\n")
    with pytest.raises(DetectionError):
        load_detection(bad)


def test_bad_severity_raises(tmp_path):
    bad = tmp_path / "badsev.py"
    bad.write_text("ID='x'\nSEVERITY='spicy'\ndef rule(e):\n    return True\n")
    with pytest.raises(DetectionError):
        load_detection(bad)


def test_detection_without_positive_and_negative_case_fails():
    det = Detection(
        id="py-onlypos",
        title="t",
        severity="low",
        description="",
        mitre=[],
        rule=lambda e: True,
        tests=[{"name": "p", "event": {}, "expect": True}],  # no negative case
    )
    failures = run_fixtures(det)
    assert failures  # flagged: needs a negative case too


def test_detection_with_no_tests_fails():
    det = Detection(id="py-notests", title="t", severity="low", description="", mitre=[], rule=lambda e: True, tests=[])
    failures = run_fixtures(det)
    assert failures
