"""Auto-file Detection-as-Code proposals for every self-play miss.

For each technique the campaign executed but the defense missed, we generate a
Sigma-rule scaffold and file it as a Detection-as-Code proposal (status
``proposed``) so it flows through the existing eval-gated DAC review — CI rejects
any candidate that fails its own positive/negative fixtures, so self-play can
only *propose*, never silently merge.

Filing is pluggable: ``InMemoryFiler`` for tests / the canned demo,
``HttpDacFiler`` posts to the API's ``POST /api/v1/detection-proposals``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.adversary.campaign import CampaignReport, StepResult


@dataclass(frozen=True)
class DacProposalDraft:
    name: str
    description: str
    rule_language: str
    rule_body: str
    category: str
    severity: str
    confidence: int
    mitre_techniques: list[str]
    tags: list[str]


def build_gap_proposal(miss: StepResult) -> DacProposalDraft:
    """Build a Sigma scaffold proposal for a missed technique."""
    tid = miss.technique_id
    rule_body = (
        f"title: Self-play gap — {miss.technique_name} ({tid})\n"
        "status: experimental\n"
        f"description: Auto-proposed by the self-play purple team after {tid} "
        f"({miss.stage}) executed without detection. Refine the selection before promoting.\n"
        f"tags:\n  - attack.{tid.lower()}\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    # TODO: encode the observable for this technique\n"
        f"    CommandLine|contains: '{miss.technique_name.split()[0].lower()}'\n"
        "  condition: selection\n"
        "falsepositives:\n  - Legitimate administrative activity\n"
        "level: medium\n"
    )
    return DacProposalDraft(
        name=f"[self-play] Detect {tid} — {miss.technique_name}",
        description=f"Coverage gap surfaced by self-play campaign at the {miss.stage} stage.",
        rule_language="sigma",
        rule_body=rule_body,
        category="purple-team-gap",
        severity="medium",
        confidence=40,  # low — it's a scaffold pending eval + human review
        mitre_techniques=[tid],
        tags=["self-play", "coverage-gap", f"stage:{miss.stage}"],
    )


class DacFiler(Protocol):
    """Files a detection-as-code proposal draft; returns an opaque proposal ref."""

    def file(self, draft: DacProposalDraft) -> str:
        """File the proposal draft and return an opaque reference to it."""


class InMemoryFiler:
    """Collects proposals instead of POSTing (tests / canned demo)."""

    def __init__(self) -> None:
        self.filed: list[DacProposalDraft] = []

    def file(self, draft: DacProposalDraft) -> str:
        self.filed.append(draft)
        return f"in-memory-{len(self.filed)}"


def auto_file_gaps(report: CampaignReport, filer: DacFiler) -> list[str]:
    """File one DAC proposal per missed technique. Returns the proposal ids."""
    ids: list[str] = []
    for miss in report.missed:
        ids.append(filer.file(build_gap_proposal(miss)))
    return ids
