"""Closed-loop campaign execution + scoring.

Each campaign step emits real telemetry (in production, into the Kafka spine so
the defense side — detections + verdict engine + agents — responds normally),
then a detection oracle reports whether the technique was caught. The runner
scores detected/missed per technique and produces a report the scoreboard and
the Detection-as-Code auto-filer consume.

Telemetry emission and detection lookup are pluggable (a `Protocol` each) so the
loop is deterministic and offline-testable (`InMemoryEmitter` + `CannedOracle`)
while the live path uses Kafka + the alert store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.adversary.planner import Campaign, CampaignStep
from app.adversary.scope_guard import Asset, LabScope, assert_in_scope


class TelemetryEmitter(Protocol):
    """Emit the telemetry a step would generate. Returns an opaque event ref."""

    def emit(self, step: CampaignStep) -> dict:
        """Return an opaque event ref for the telemetry this step generates."""


class DetectionOracle(Protocol):
    """Report whether a technique was detected by the live defense."""

    def was_detected(self, technique_id: str, event: dict) -> tuple[bool, float | None, str | None]:
        """Report (detected, confidence, detector) for a technique against an event."""


class InMemoryEmitter:
    """Records emitted events instead of producing to Kafka (tests / canned run)."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, step: CampaignStep) -> dict:
        event = {
            "technique_id": step.technique_id,
            "stage": step.stage,
            "target": step.target,
            "source": "self-play",
        }
        self.events.append(event)
        return event


class CannedOracle:
    """Deterministic oracle: detects techniques in ``detected_ids``, misses the rest."""

    def __init__(self, detected_ids: set[str], latency_s: float = 12.0) -> None:
        self.detected_ids = detected_ids
        self.latency_s = latency_s

    def was_detected(self, technique_id: str, event: dict) -> tuple[bool, float | None, str | None]:
        if technique_id in self.detected_ids:
            return True, self.latency_s, f"alert-{technique_id}"
        return False, None, None


@dataclass(frozen=True)
class StepResult:
    order: int
    stage: str
    technique_id: str
    technique_name: str
    detected: bool
    latency_s: float | None
    alert_id: str | None


@dataclass
class CampaignReport:
    name: str
    results: list[StepResult] = field(default_factory=list)

    @property
    def techniques_attempted(self) -> list[str]:
        return [r.technique_id for r in self.results]

    @property
    def detected(self) -> list[StepResult]:
        return [r for r in self.results if r.detected]

    @property
    def missed(self) -> list[StepResult]:
        return [r for r in self.results if not r.detected]

    @property
    def detection_rate(self) -> float:
        return round(len(self.detected) / len(self.results), 4) if self.results else 0.0

    @property
    def mean_time_to_verdict_s(self) -> float | None:
        lat = [r.latency_s for r in self.detected if r.latency_s is not None]
        return round(sum(lat) / len(lat), 2) if lat else None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "techniques_attempted": len(self.results),
            "techniques_detected": len(self.detected),
            "detection_rate": self.detection_rate,
            "mean_time_to_verdict_s": self.mean_time_to_verdict_s,
            "missed_techniques": [r.technique_id for r in self.missed],
            "steps": [
                {
                    "order": r.order,
                    "stage": r.stage,
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "detected": r.detected,
                    "latency_s": r.latency_s,
                }
                for r in self.results
            ],
        }


def run_campaign(
    campaign: Campaign,
    emitter: TelemetryEmitter,
    oracle: DetectionOracle,
    scope: LabScope | None = None,
) -> CampaignReport:
    """Execute a campaign step-by-step. Re-asserts lab scope before any emission."""
    # Backstop safety check at execution time — never trust that planning was safe.
    assert_in_scope(list(campaign.targets) or [Asset.of("__none__")], scope)

    report = CampaignReport(name=campaign.name)
    for step in campaign.steps:
        event = emitter.emit(step)
        detected, latency, alert_id = oracle.was_detected(step.technique_id, event)
        report.results.append(
            StepResult(
                order=step.order,
                stage=step.stage,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                detected=detected,
                latency_s=latency,
                alert_id=alert_id,
            )
        )
    return report
