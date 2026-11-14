"""Adversary campaign planner.

Composes an ordered, multi-stage attack chain (initial-access → execution →
persistence → privilege-escalation → exfiltration) from the available Atomic Red
Team / Caldera inventory, parameterized by the tenant's environment — it only
plans techniques whose platform actually exists among the (lab-scoped) targets.

The composition is deterministic (pick the highest-priority inventory technique
per stage that matches an available platform). An LLM can re-order or enrich the
plan, but it can never widen scope: the planner selects only lab targets, and
:func:`~app.adversary.scope_guard.assert_in_scope` hard-fails at run time
regardless of what any model proposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.adversary.scope_guard import Asset, LabScope, ScopeViolation, assert_in_scope, filter_lab_targets

# The kill-chain stages we compose, in order.
STAGES: tuple[str, ...] = (
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "exfiltration",
)


@dataclass(frozen=True)
class InventoryTechnique:
    """A technique available to the adversary from ART / Caldera."""

    technique_id: str
    technique_name: str
    stage: str
    platforms: frozenset[str]  # e.g. {"windows", "linux"}
    priority: int = 50  # higher = preferred when multiple match


@dataclass(frozen=True)
class CampaignStep:
    order: int
    stage: str
    technique_id: str
    technique_name: str
    target: str


@dataclass(frozen=True)
class Campaign:
    name: str
    steps: tuple[CampaignStep, ...]
    targets: tuple[Asset, ...] = field(default_factory=tuple)

    @property
    def techniques(self) -> list[str]:
        return [s.technique_id for s in self.steps]


def _platforms_present(targets: list[Asset]) -> set[str]:
    """Infer available platforms from asset tags (e.g. a 'windows' tag)."""
    known = {"windows", "linux", "macos", "aws", "azure", "gcp", "kubernetes", "office365"}
    present: set[str] = set()
    for t in targets:
        present |= {tag for tag in t.tags if tag in known}
    # If the lab doesn't declare platforms, assume a generic linux/windows range.
    return present or {"windows", "linux"}


def plan_campaign(
    name: str,
    inventory: list[InventoryTechnique],
    candidate_targets: list[Asset],
    scope: LabScope | None = None,
) -> Campaign:
    """Compose a lab-scoped campaign. Raises ``ScopeViolation`` if no lab target."""
    scope = scope or LabScope()
    targets = filter_lab_targets(candidate_targets, scope)
    # Backstop: hard-fail before we build a plan against anything unsafe.
    assert_in_scope(targets, scope)

    platforms = _platforms_present(targets)
    primary = targets[0].asset_id

    steps: list[CampaignStep] = []
    order = 1
    for stage in STAGES:
        candidates = [t for t in inventory if t.stage == stage and (t.platforms & platforms or not t.platforms)]
        if not candidates:
            continue  # attack only what the environment can actually run
        chosen = max(candidates, key=lambda t: t.priority)
        steps.append(
            CampaignStep(
                order=order,
                stage=stage,
                technique_id=chosen.technique_id,
                technique_name=chosen.technique_name,
                target=primary,
            )
        )
        order += 1

    if not steps:
        raise ScopeViolation("no inventory technique matches the lab environment's platforms")
    return Campaign(name=name, steps=tuple(steps), targets=tuple(targets))
