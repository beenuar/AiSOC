"""Self-play scoreboard — turn the repo's own defense improvement into a series.

Aggregates one or more campaign reports into the weekly scoreboard published on
the benchmark page: techniques attempted / detected, detection rate, mean time
to verdict, and new detections filed. Every row carries an explicit ``synthetic``
flag so a canned-campaign row can never be mistaken for a measured live run
(same synthetic-vs-real honesty rule as the rest of the eval harness).
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.adversary.campaign import CampaignReport


def build_scoreboard_row(
    report: CampaignReport,
    *,
    new_detections_filed: int,
    synthetic: bool,
    version: str = "unreleased",
) -> dict:
    return {
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "version": version,
        "campaign": report.name,
        "techniques_attempted": len(report.results),
        "techniques_detected": len(report.detected),
        "detection_rate": report.detection_rate,
        "mean_time_to_verdict_s": report.mean_time_to_verdict_s,
        "new_detections_filed": new_detections_filed,
        # Honesty flag: True for the canned demo campaign; the nightly live
        # campaign against the seeded range sets this False.
        "synthetic": synthetic,
    }


def merge_scoreboard(existing: list[dict], row: dict, keep: int = 52) -> list[dict]:
    """Prepend the newest row, keeping at most ``keep`` weeks."""
    return [row, *existing][:keep]
