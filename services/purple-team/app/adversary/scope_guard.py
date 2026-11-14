"""Hard lab-scope guard for the self-play adversary.

The single most important safety property of a SOC that attacks itself: it must
**never** run an attack step against a production asset. This is enforced in
code — a hard failure that raises before any step executes — not as a prompt
instruction the planner could be argued out of.

Every target asset must carry at least one allowlisted lab tag AND carry no
forbidden production tag. Any violation raises :class:`ScopeViolation` and the
campaign aborts. There is deliberately no "force" flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ScopeViolation(Exception):
    """Raised when a campaign would touch a non-lab / production asset."""


@dataclass(frozen=True)
class Asset:
    """A candidate target. ``tags`` are environment labels (from the graph)."""

    asset_id: str
    tags: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def of(cls, asset_id: str, *tags: str) -> Asset:
        return cls(asset_id=asset_id, tags=frozenset(t.strip().lower() for t in tags))


@dataclass(frozen=True)
class LabScope:
    """Allowlist / denylist of asset tags that define the safe blast radius."""

    allowed_tags: frozenset[str] = frozenset({"lab", "sandbox", "purple-team", "range", "test"})
    forbidden_tags: frozenset[str] = frozenset({"production", "prod", "live", "crown-jewel", "crown_jewels", "pci", "phi", "customer-data"})

    def is_in_scope(self, asset: Asset) -> bool:
        tags = {t.lower() for t in asset.tags}
        if tags & self.forbidden_tags:
            return False
        return bool(tags & self.allowed_tags)


def assert_in_scope(targets: list[Asset], scope: LabScope | None = None) -> None:
    """Hard-fail if *any* target is out of the lab scope. No bypass, by design.

    Raises :class:`ScopeViolation` on: an empty target set (nothing safe to
    attack), a target carrying a forbidden production tag, or a target lacking
    any allowlisted lab tag.
    """
    scope = scope or LabScope()
    if not targets:
        raise ScopeViolation("refusing to run: no in-scope lab targets were provided")
    offenders: list[str] = []
    for asset in targets:
        tags = {t.lower() for t in asset.tags}
        forbidden = tags & scope.forbidden_tags
        if forbidden:
            offenders.append(f"{asset.asset_id} carries forbidden tag(s) {sorted(forbidden)}")
        elif not (tags & scope.allowed_tags):
            offenders.append(f"{asset.asset_id} has no lab/sandbox tag (tags={sorted(tags) or 'none'})")
    if offenders:
        raise ScopeViolation("self-play scope guard blocked the campaign — targets outside the lab: " + "; ".join(offenders))


def filter_lab_targets(candidates: list[Asset], scope: LabScope | None = None) -> list[Asset]:
    """Select only in-scope targets (used by the planner to build a safe plan).

    This is a convenience for planning; :func:`assert_in_scope` is still the
    backstop that runs immediately before execution.
    """
    scope = scope or LabScope()
    return [a for a in candidates if scope.is_in_scope(a)]
