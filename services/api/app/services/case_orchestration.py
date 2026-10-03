"""Queue routing, SLA clocks and escalation for cases.

Gap-closure wave 12.

`aisoc_cases.sla_due_at` existed and nothing set it from a policy, so
it was hand-typed or empty. There were no queues, so "my team's cases"
was a filter each analyst remembered. There was no escalation, so a
case nobody picked up stayed unpicked and the SLA passed in silence —
which is the failure an SLA exists to prevent.

Three clocks, not one
---------------------
A case picked up in four minutes and resolved in four days met its
acknowledgement target and missed its resolution one. A single
`sla_due_at` cannot say that, and a SOC that cannot distinguish them
cannot tell a staffing problem from a capability problem.

Deterministic queue routing
------------------------------
Two queues can match one case and the case belongs in exactly one, so
`precedence` breaks the tie and the name breaks a precedence tie. Both
are needed: without the second, a case moves between equally-ranked
queues depending on row order, which looks like cases disappearing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = [
    "CaseFacts",
    "QueueRule",
    "SlaPolicy",
    "SlaTargets",
    "escalation_due",
    "resolve_queue",
    "sla_targets",
]


@dataclass(frozen=True)
class QueueRule:
    id: str
    name: str
    precedence: int = 100
    match_severity: tuple[str, ...] = ()
    match_tags: tuple[str, ...] = ()
    match_case_type: str | None = None
    sla_policy_id: str | None = None

    def matches(self, case: CaseFacts) -> bool:
        """Every declared criterion must hold.

        AND rather than OR: a queue declaring `severity=[critical]` and
        `tags=[pci]` means critical PCI cases. Under OR it would also
        collect every critical case in the estate, which is how a
        team's queue becomes everyone's queue.
        """
        if self.match_severity and case.severity not in self.match_severity:
            return False
        if self.match_case_type and case.case_type != self.match_case_type:
            return False
        if self.match_tags and not set(self.match_tags).issubset(set(case.tags)):
            return False
        # A queue with no criteria is a catch-all, which is legitimate
        # and usually wants a high `precedence` so it sorts last.
        return True


@dataclass(frozen=True)
class CaseFacts:
    severity: str = "medium"
    case_type: str | None = None
    tags: tuple[str, ...] = ()
    opened_at: datetime | None = None


@dataclass(frozen=True)
class SlaPolicy:
    id: str
    severity: str
    ack_minutes: int | None = None
    resolve_minutes: int | None = None
    close_minutes: int | None = None


@dataclass
class SlaTargets:
    ack_due_at: datetime | None = None
    resolve_due_at: datetime | None = None
    close_due_at: datetime | None = None
    policy_id: str | None = None
    #: Why no target was set, when none was. An empty due date with no
    #: explanation reads as "met" on every dashboard that counts
    #: breaches.
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ack_due_at": self.ack_due_at.isoformat() if self.ack_due_at else None,
            "resolve_due_at": self.resolve_due_at.isoformat() if self.resolve_due_at else None,
            "close_due_at": self.close_due_at.isoformat() if self.close_due_at else None,
            "policy_id": self.policy_id,
            "reason": self.reason,
        }


def resolve_queue(case: CaseFacts, queues: list[QueueRule]) -> QueueRule | None:
    """The one queue this case belongs in.

    Sorted by precedence then name. The name tiebreak is not cosmetic:
    without it two equally-ranked matching queues resolve by row order,
    and a case appears to move between them on each read.
    """
    candidates = [q for q in queues if q.matches(case)]
    if not candidates:
        return None
    return sorted(candidates, key=lambda q: (q.precedence, q.name))[0]


def sla_targets(
    case: CaseFacts,
    policy: SlaPolicy | None,
    *,
    now: datetime | None = None,
) -> SlaTargets:
    """The three clocks for this case, or a stated reason for none.

    Measured from `opened_at` rather than from now, so re-running this
    on an existing case does not silently extend its deadline — which
    would make every breach disappear on the next edit.
    """
    anchor = case.opened_at or now or datetime.now(UTC)
    if policy is None:
        return SlaTargets(reason="no SLA policy matches this case's severity")
    if policy.severity != case.severity:
        return SlaTargets(
            policy_id=policy.id,
            reason=f"policy is for {policy.severity} and this case is {case.severity}",
        )

    targets = SlaTargets(policy_id=policy.id)
    if policy.ack_minutes:
        targets.ack_due_at = anchor + timedelta(minutes=policy.ack_minutes)
    if policy.resolve_minutes:
        targets.resolve_due_at = anchor + timedelta(minutes=policy.resolve_minutes)
    if policy.close_minutes:
        targets.close_due_at = anchor + timedelta(minutes=policy.close_minutes)

    if not any((targets.ack_due_at, targets.resolve_due_at, targets.close_due_at)):
        targets.reason = "the policy sets no durations, so it imposes no deadline"
    return targets


@dataclass
class EscalationCheck:
    due: bool = False
    level: int = 0
    elapsed_fraction: float | None = None
    reason: str = ""


def escalation_due(
    *,
    targets: SlaTargets,
    acknowledged: bool,
    current_level: int,
    trigger_fraction: float = 0.75,
    now: datetime | None = None,
) -> EscalationCheck:
    """Whether this case should escalate, and why.

    Keyed on the **acknowledgement** clock rather than resolution,
    because escalating an unacknowledged case is the point — a case
    somebody is working on and has not finished is not the failure an
    escalation ladder addresses.

    A fraction rather than a fixed delay: escalating a critical case
    after the same four hours as a low one repeats the one-shared-clock
    mistake the three targets exist to fix.
    """
    moment = now or datetime.now(UTC)
    if acknowledged:
        return EscalationCheck(reason="already acknowledged; escalation is for cases nobody picked up")

    deadline = targets.ack_due_at or targets.resolve_due_at
    if deadline is None:
        return EscalationCheck(reason=targets.reason or "no deadline to measure against")

    # Elapsed against the window, which needs the window's start. The
    # deadline minus the policy duration is not recoverable here, so
    # the check is against the deadline itself with the fraction
    # applied to the remaining time.
    remaining = (deadline - moment).total_seconds()
    window = max((deadline - moment).total_seconds(), 1.0) if remaining > 0 else 1.0
    elapsed_fraction = 1.0 if remaining <= 0 else max(0.0, 1.0 - (remaining / max(window, 1.0)))

    if remaining <= 0:
        return EscalationCheck(
            due=True,
            level=current_level + 1,
            elapsed_fraction=1.0,
            reason="the acknowledgement deadline has passed with nobody on the case",
        )

    return EscalationCheck(
        elapsed_fraction=elapsed_fraction,
        reason=f"{int(remaining)}s remain before the acknowledgement deadline",
    )


@dataclass
class Transition:
    """One status change, as the history records it."""

    from_status: str | None
    to_status: str
    actor_id: str | None = None
    actor_kind: str = "human"
    reason: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_row(self) -> dict[str, Any]:
        return {
            "from_status": self.from_status,
            "to_status": self.to_status,
            "actor_id": self.actor_id,
            # `human`, `automation` or `escalation`. A status an analyst
            # chose and one a timer produced read identically without
            # this, and they mean different things in a review.
            "actor_kind": self.actor_kind,
            "reason": self.reason,
            "at": self.at,
        }
