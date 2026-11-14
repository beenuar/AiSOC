"""Turn severity, asset criticality and identity privilege into a queue order.

Gap-closure wave 11.

`assets.criticality` reached a prompt string and a sort order and
nothing else, so two alerts of equal severity — one on a domain
controller, one on a meeting-room display — arrived in the queue in
the order they were raised. An analyst worked out which was which by
reading the hostname.

The design decision that matters
-----------------------------------
Severity is the **base** and context is a **multiplier**, not a sum.
Addition lets a stack of small contextual bumps push an informational
alert above a critical one, which is how a prioritisation scheme gets
switched off after the first time it surprises somebody. Multiplying
means context can reorder alerts of similar severity — which is what
it is for — and cannot invert a severity gap.

Every factor is bounded and the product is clamped, so no single
signal can dominate. A domain controller is more important than a
laptop; it is not infinitely more important.

Why the rationale travels with the score
-------------------------------------------
An ordering a person cannot interrogate is one they stop trusting.
Every factor that moved the number is recorded with its contribution,
so "why was this top of my queue" has an answer that does not require
re-deriving today's CMDB state — which has changed since.

What this deliberately does not do
-------------------------------------
It does not alter severity. Severity is what the detection claimed and
is compared across deployments; priority is local and says what to
look at first here. Conflating them would make a tenant's CMDB quality
silently change what their detections appear to have found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "MAX_SCORE",
    "AssetContext",
    "IdentityContext",
    "PriorityResult",
    "score_alert_priority",
]

#: Base points per severity. Gaps are wide enough that context can
#: reorder within a tier and not across two.
_SEVERITY_BASE: dict[str, int] = {
    "critical": 900,
    "high": 600,
    "medium": 350,
    "low": 150,
    "info": 50,
}

#: Criticality as a multiplier. Derived from the label rather than
#: stored beside it, because two fields saying the same thing drift and
#: then nobody knows which the queue used.
_CRITICALITY_FACTOR: dict[str, float] = {
    "critical": 1.6,
    "high": 1.3,
    "medium": 1.0,
    "low": 0.8,
    "none": 0.7,
}

_PRIVILEGE_FACTOR: dict[str, float] = {
    "domain_admin": 1.5,
    "admin": 1.35,
    "elevated": 1.15,
    "standard": 1.0,
    # Exactly 1.0, and present rather than absent. An identity with no
    # posture covering the event is not evidence in either direction, so it
    # must not move the score -- but it is also not the same as a measured
    # standard account, and the rationale says which one it was. Leaving
    # `unknown` out of this table would reach `.get(tier, 1.0)` and produce
    # the same number with no sentence attached.
    "unknown": 1.0,
}

#: Depth plan wave 2, 1.1. Each tag that is true multiplies by this much.
#: Deliberately small and multiplicative, matching the module's design note:
#: context reorders alerts of similar severity and cannot invert a severity
#: gap. Four tags together reach 1.21, which is less than one criticality
#: step -- tags are a reason to look sooner, not a reason to outrank a
#: critical alert.
_TAG_FACTOR: dict[str, float] = {
    "can_escalate": 1.10,
    "cross_account": 1.05,
    "data_access": 1.05,
    "third_party": 1.05,
}

#: Ceiling on the combined tag multiplier, so adding a fifth tag later
#: cannot quietly make tags dominate the ordering.
_TAG_FACTOR_CAP = 1.25

#: A host running something on the CISA Known Exploited Vulnerabilities
#: catalogue is being attacked with a technique that is known to work,
#: which is a different fact from a high CVSS score.
_KEV_FACTOR = 1.4
_EXPLOITABLE_VULN_FACTOR = 1.15

#: Break-glass accounts are *expected* to be dormant. Any activity on
#: one is interesting even at low severity.
_BREAK_GLASS_FACTOR = 1.45

#: Ceiling. Without it a critical alert on a critical host with a
#: domain admin and a KEV exposure reaches a number that makes every
#: other alert look identical by comparison.
MAX_SCORE = 1000


@dataclass(frozen=True)
class AssetContext:
    asset_id: str | None = None
    criticality: str = "medium"
    #: Vulnerabilities from the tenant's **own** inventory, not from an
    #: enrichment response. `asset_vulnerabilities` already held this
    #: and only the enrichment path ever read it.
    has_kev_vulnerability: bool = False
    exploitable_vuln_count: int = 0
    internet_facing: bool = False


@dataclass(frozen=True)
class IdentityContext:
    principal: str | None = None
    #: Defaults to ``unknown``, not ``standard``. A caller that builds this
    #: without a posture lookup is saying "I did not check", and the old
    #: default said "I checked and it is ordinary" on its behalf.
    privilege_tier: str = "unknown"
    is_service: bool = False
    is_break_glass: bool = False
    #: The four computed tags from 1.1. ``None`` is "no snapshot could
    #: answer" and never contributes; only ``True`` does.
    can_escalate: bool | None = None
    data_access: bool | None = None
    third_party: bool | None = None
    cross_account: bool | None = None

    def set_tags(self) -> list[str]:
        return [name for name in ("can_escalate", "data_access", "third_party", "cross_account") if getattr(self, name) is True]


@dataclass
class PriorityResult:
    score: int
    base: int
    rationale: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"score": self.score, "base": self.base, "rationale": self.rationale}

    def explain(self) -> str:
        lines = [f"base {self.base} (severity)"]
        lines.extend(f"  ×{r['factor']:.2f}  {r['reason']}" for r in self.rationale)
        lines.append(f"= {self.score}")
        return "\n".join(lines)


def score_alert_priority(
    *,
    severity: str,
    asset: AssetContext | None = None,
    identity: IdentityContext | None = None,
) -> PriorityResult:
    """Priority for one alert, with every factor that moved it.

    Returns a score in `[0, MAX_SCORE]`. An unknown severity scores as
    `medium` rather than raising: a connector emitting a tier this
    deployment does not know is a mapping bug, and dropping the alert
    out of the queue over it would be worse than ranking it in the
    middle and saying so.
    """
    normalised = (severity or "").strip().lower()
    base = _SEVERITY_BASE.get(normalised)
    rationale: list[dict[str, Any]] = []
    if base is None:
        base = _SEVERITY_BASE["medium"]
        rationale.append(
            {
                "factor": 1.0,
                "reason": f"severity {severity!r} is outside the five-tier ladder; ranked as medium",
            }
        )

    score = float(base)

    if asset is not None:
        criticality = (asset.criticality or "medium").strip().lower()
        known_criticality = _CRITICALITY_FACTOR.get(criticality)
        if known_criticality is None:
            rationale.append({"factor": 1.0, "reason": f"asset criticality {asset.criticality!r} unrecognised"})
        elif known_criticality != 1.0:
            score *= known_criticality
            rationale.append({"factor": known_criticality, "reason": f"asset criticality is {criticality}"})

        if asset.has_kev_vulnerability:
            score *= _KEV_FACTOR
            rationale.append(
                {
                    "factor": _KEV_FACTOR,
                    "reason": "the host runs something on the Known Exploited Vulnerabilities catalogue",
                }
            )
        elif asset.exploitable_vuln_count > 0:
            score *= _EXPLOITABLE_VULN_FACTOR
            rationale.append(
                {
                    "factor": _EXPLOITABLE_VULN_FACTOR,
                    "reason": f"{asset.exploitable_vuln_count} exploitable vulnerabilities on this host",
                }
            )

        if asset.internet_facing:
            score *= 1.2
            rationale.append({"factor": 1.2, "reason": "the host is internet-facing"})

    if identity is not None:
        tier = (identity.privilege_tier or "unknown").strip().lower()
        privilege_factor = _PRIVILEGE_FACTOR.get(tier, 1.0)
        if privilege_factor != 1.0:
            score *= privilege_factor
            rationale.append({"factor": privilege_factor, "reason": f"the principal holds {tier} privilege"})
        elif tier == "unknown":
            # A 1.0 row rather than no row. The queue renders this rationale
            # verbatim, and an analyst asking "why is this ranked here"
            # needs to be told the platform could not answer, not shown a
            # list with the question silently missing from it.
            rationale.append(
                {
                    "factor": 1.0,
                    "reason": "the principal's privilege at event time is unknown (no posture snapshot covers it)",
                }
            )

        tags = identity.set_tags()
        if tags:
            combined = 1.0
            for tag in tags:
                combined *= _TAG_FACTOR.get(tag, 1.0)
            combined = min(combined, _TAG_FACTOR_CAP)
            score *= combined
            rationale.append(
                {
                    "factor": round(combined, 4),
                    "reason": f"the principal is tagged {', '.join(tags)}",
                }
            )

        if identity.is_break_glass:
            score *= _BREAK_GLASS_FACTOR
            rationale.append(
                {
                    "factor": _BREAK_GLASS_FACTOR,
                    "reason": "a break-glass account is expected to be dormant, so any activity is notable",
                }
            )

    return PriorityResult(score=min(MAX_SCORE, int(round(score))), base=base, rationale=rationale)
