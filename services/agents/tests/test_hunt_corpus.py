"""
Hunt Corpus Eval Gate (Wave 2 — w2-hac)
=======================================

Grades every YAML hunt under ``hunts/`` against the dedicated synthetic
hunt telemetry corpus at ``services/agents/tests/eval_data/synthetic_hunt_telemetry.jsonl``.

Each hunt declares two expectations in its YAML:

  * ``expected.positive_incident_id`` — the hunt MUST fire on these events,
    with a per-event match score at or above ``expected.min_match_score``.
  * ``expected.negative_incident_id`` — the hunt MUST NOT fire on these
    events. (False positives here block CI.)

This is the same eval-harness pattern used by detections in
``test_synthetic_telemetry.py`` and the alert-reduction / MITRE suites in
``apps/docs/docs/benchmark.md`` — every claim of new hunt coverage has to
extend the corpus and pass the gate.

Run:
    pytest services/agents/tests/test_hunt_corpus.py -v
"""

from __future__ import annotations

import json
import unittest
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.hunt.engine import HuntEngine
from app.hunt.loader import HuntCorpus, HuntDefinition

_TESTS_DIR = Path(__file__).parent
_HUNT_TELEMETRY_PATH = _TESTS_DIR / "eval_data" / "synthetic_hunt_telemetry.jsonl"

# CI gates (used by both this module's unittest classes and the unified runner
# in scripts/run_evals.py). The hunt corpus is small and hand-authored, so we
# require perfect coverage on declared positives and zero false positives on
# declared negatives. Tighten these only with a corresponding corpus expansion.
_POSITIVE_FLOOR = 1.0
_NEGATIVE_CEILING = 0.0


def _load_hunt_corpus() -> list[HuntDefinition]:
    """Load the YAML hunt corpus from ``hunts/`` (repo root)."""
    corpus = HuntCorpus()
    corpus.reload()
    hunts = corpus.list()
    if not hunts:
        raise FileNotFoundError(
            f"No hunt YAMLs found under {corpus.directory}. Add at least one hunt to `hunts/` before the gate can grade them."
        )
    return hunts


def _load_hunt_telemetry() -> list[dict[str, Any]]:
    if not _HUNT_TELEMETRY_PATH.exists():
        raise FileNotFoundError(f"Missing {_HUNT_TELEMETRY_PATH}. Add positive and negative scenarios for each hunt before merging.")
    events: list[dict[str, Any]] = []
    with _HUNT_TELEMETRY_PATH.open() as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{_HUNT_TELEMETRY_PATH.name}:{line_no} is not valid JSON: {exc}") from exc
    return events


def _events_for_incident(events: list[dict[str, Any]], incident_id: str) -> list[dict[str, Any]]:
    return [e for e in events if e.get("incident_id") == incident_id]


class TestHuntTelemetrySchema(unittest.TestCase):
    """The hunt telemetry corpus has its own minimal schema rules."""

    def setUp(self) -> None:
        self.events = _load_hunt_telemetry()

    def test_every_event_has_envelope_fields(self) -> None:
        """Every event needs at minimum an incident_id and a source."""
        for idx, event in enumerate(self.events):
            self.assertIn("incident_id", event, f"event #{idx} missing incident_id")
            self.assertIn("source", event, f"event #{idx} missing source")
            self.assertTrue(
                str(event["incident_id"]).startswith("INC-HUNT-"),
                f"event #{idx} has non-hunt incident_id {event['incident_id']!r}; "
                "hunt scenarios must use INC-HUNT-* ids to keep them isolated "
                "from the detection telemetry suite.",
            )


class TestHuntCorpusEval(unittest.TestCase):
    """Grade every hunt against its declared positive + negative scenarios."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.hunts = _load_hunt_corpus()
        cls.events = _load_hunt_telemetry()
        cls.engine = HuntEngine()

    def test_every_hunt_has_eval_scenarios(self) -> None:
        """A hunt without positive/negative scenarios cannot be graded."""
        for hunt in self.hunts:
            with self.subTest(hunt=hunt.id):
                self.assertTrue(
                    hunt.expected.positive_incident_id,
                    f"hunt {hunt.id} is missing expected.positive_incident_id; every hunt YAML must declare a positive synthetic scenario.",
                )

    def test_positive_scenarios_fire(self) -> None:
        """Hunt MUST fire on its declared positive incident."""
        misses: list[str] = []
        for hunt in self.hunts:
            pos_id = hunt.expected.positive_incident_id
            if not pos_id:
                continue
            pos_events = _events_for_incident(self.events, pos_id)
            with self.subTest(hunt=hunt.id, scenario=pos_id):
                self.assertTrue(
                    pos_events,
                    f"hunt {hunt.id} declares positive_incident_id={pos_id} but no matching events exist in {_HUNT_TELEMETRY_PATH.name}.",
                )
                result = self.engine.run(hunt, pos_events)
                threshold = hunt.expected.min_match_score
                if not result.findings or result.match_score < threshold:
                    misses.append(
                        f"  - {hunt.id}: scanned {result.events_scanned} events from "
                        f"{pos_id}, got {len(result.findings)} findings, "
                        f"best score {result.match_score:.2f} < {threshold:.2f}"
                    )
        if misses:
            self.fail("Positive-scenario miss — these hunts did not fire on their declared synthetic incident:\n" + "\n".join(misses))

    def test_negative_scenarios_do_not_fire(self) -> None:
        """Hunt MUST NOT fire on its declared negative incident (false positive guard)."""
        false_positives: list[str] = []
        for hunt in self.hunts:
            neg_id = hunt.expected.negative_incident_id
            if not neg_id:
                continue
            neg_events = _events_for_incident(self.events, neg_id)
            with self.subTest(hunt=hunt.id, scenario=neg_id):
                self.assertTrue(
                    neg_events,
                    f"hunt {hunt.id} declares negative_incident_id={neg_id} but no matching events exist in {_HUNT_TELEMETRY_PATH.name}.",
                )
                result = self.engine.run(hunt, neg_events)
                if result.findings:
                    false_positives.append(
                        f"  - {hunt.id}: fired {len(result.findings)} time(s) "
                        f"on negative scenario {neg_id} (best score "
                        f"{result.match_score:.2f})"
                    )
        if false_positives:
            self.fail("False-positive regression — these hunts fired on their declared negative scenario:\n" + "\n".join(false_positives))

    def test_every_hunt_telemetry_event_is_owned(self) -> None:
        """Every INC-HUNT-* event must be referenced by at least one hunt YAML.

        Catches drift in the other direction: telemetry left behind after a
        hunt is renamed or deleted.
        """
        owned: dict[str, set[str]] = defaultdict(set)
        for hunt in self.hunts:
            if hunt.expected.positive_incident_id:
                owned[hunt.expected.positive_incident_id].add(hunt.id)
            if hunt.expected.negative_incident_id:
                owned[hunt.expected.negative_incident_id].add(hunt.id)

        orphans = sorted({e["incident_id"] for e in self.events if e["incident_id"] not in owned})
        self.assertFalse(
            orphans,
            "These hunt-telemetry incident_ids are not referenced by any hunt "
            f"YAML under hunts/: {orphans}. Either add a hunt that owns them "
            f"or remove the events from {_HUNT_TELEMETRY_PATH.name}.",
        )


@dataclass
class HuntCorpusEvalResult:
    """Aggregated grading result over the hunt corpus.

    Surfaces the same shape as the other suite result objects so the
    unified runner (`scripts/run_evals.py`) can format it consistently.
    """

    hunts_total: int
    positives_expected: int
    positives_caught: int
    negatives_expected: int
    false_positives: int
    orphan_incident_ids: list[str] = field(default_factory=list)
    misses: list[dict[str, Any]] = field(default_factory=list)
    false_positive_details: list[dict[str, Any]] = field(default_factory=list)

    @property
    def positive_rate(self) -> float:
        if self.positives_expected == 0:
            return 0.0
        return self.positives_caught / self.positives_expected

    @property
    def false_positive_rate(self) -> float:
        if self.negatives_expected == 0:
            return 0.0
        return self.false_positives / self.negatives_expected


def evaluate_hunt_corpus() -> HuntCorpusEvalResult:
    """Grade the hunt corpus against the synthetic hunt telemetry.

    Mirrors the unittest gates above but returns a structured result so
    `scripts/run_evals.py` can surface hunt coverage as a CI suite without
    needing to re-run pytest.
    """
    hunts = _load_hunt_corpus()
    events = _load_hunt_telemetry()
    engine = HuntEngine()

    misses: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    positives_expected = 0
    positives_caught = 0
    negatives_expected = 0
    false_positive_count = 0
    owned: set[str] = set()

    for hunt in hunts:
        pos_id = hunt.expected.positive_incident_id
        if pos_id:
            owned.add(pos_id)
            positives_expected += 1
            pos_events = _events_for_incident(events, pos_id)
            if not pos_events:
                misses.append(
                    {
                        "hunt_id": hunt.id,
                        "scenario": pos_id,
                        "reason": "no_matching_events",
                    }
                )
            else:
                result = engine.run(hunt, pos_events)
                threshold = hunt.expected.min_match_score
                if result.findings and result.match_score >= threshold:
                    positives_caught += 1
                else:
                    misses.append(
                        {
                            "hunt_id": hunt.id,
                            "scenario": pos_id,
                            "events_scanned": result.events_scanned,
                            "findings": len(result.findings),
                            "match_score": round(result.match_score, 4),
                            "threshold": threshold,
                        }
                    )

        neg_id = hunt.expected.negative_incident_id
        if neg_id:
            owned.add(neg_id)
            negatives_expected += 1
            neg_events = _events_for_incident(events, neg_id)
            if neg_events:
                result = engine.run(hunt, neg_events)
                if result.findings:
                    false_positive_count += 1
                    false_positives.append(
                        {
                            "hunt_id": hunt.id,
                            "scenario": neg_id,
                            "findings": len(result.findings),
                            "match_score": round(result.match_score, 4),
                        }
                    )

    orphans = sorted({e["incident_id"] for e in events if e["incident_id"] not in owned})

    return HuntCorpusEvalResult(
        hunts_total=len(hunts),
        positives_expected=positives_expected,
        positives_caught=positives_caught,
        negatives_expected=negatives_expected,
        false_positives=false_positive_count,
        orphan_incident_ids=orphans,
        misses=misses,
        false_positive_details=false_positives,
    )


if __name__ == "__main__":
    unittest.main()
