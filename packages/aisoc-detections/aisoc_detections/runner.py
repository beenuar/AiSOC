"""Fixture test harness + CLI for Python detections.

Every detection must ship inline ``TESTS`` (positive + negative cases). The
harness runs each case through the real ``rule`` and fails the detection if it
misses a positive (blind) or fires on a negative (noisy) — the same
non-circular guarantee the YAML corpus gets from its fixture replay.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from .base import Detection, evaluate, load_detections


@dataclass(frozen=True)
class FixtureFailure:
    detection_id: str
    case_name: str
    expected: bool
    actual: bool


@dataclass
class TestReport:
    detections: int = 0
    cases: int = 0
    failures: list[FixtureFailure] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def run_fixtures(detection: Detection) -> list[FixtureFailure]:
    """Run one detection's inline TESTS; return the failures (empty == pass)."""
    failures: list[FixtureFailure] = []
    if not detection.tests:
        # A detection with no tests can't be trusted — treat as a failure.
        failures.append(FixtureFailure(detection.id, "<no TESTS declared>", True, False))
        return failures
    has_pos = any(bool(c.get("expect")) for c in detection.tests)
    has_neg = any(not bool(c.get("expect")) for c in detection.tests)
    if not (has_pos and has_neg):
        failures.append(FixtureFailure(detection.id, "<needs >=1 positive AND >=1 negative case>", True, False))
    for case in detection.tests:
        expected = bool(case.get("expect"))
        actual = evaluate(detection, dict(case.get("event") or {}))
        if actual != expected:
            failures.append(FixtureFailure(detection.id, str(case.get("name", "unnamed")), expected, actual))
    return failures


def run_suite(directory: str | Path) -> TestReport:
    """Load every detection in ``directory`` and run its fixtures."""
    report = TestReport()
    for detection in load_detections(directory):
        report.detections += 1
        report.cases += len(detection.tests)
        report.failures.extend(run_fixtures(detection))
    return report


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m aisoc_detections.runner <dir>`` (aka ``aisoc-detections test``)."""
    argv = argv if argv is not None else sys.argv[1:]
    directory = argv[0] if argv else str(Path(__file__).resolve().parent.parent / "detections")
    report = run_suite(directory)
    for fail in report.failures:
        print(f"FAIL {fail.detection_id}: {fail.case_name} (expected {fail.expected}, got {fail.actual})", file=sys.stderr)
    status = "OK" if report.passed else "FAILED"
    print(f"{status}: {report.detections} detections, {report.cases} cases, {len(report.failures)} failures")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
