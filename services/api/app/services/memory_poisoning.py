"""Memory-poisoning defenses for the analyst-override learning loop.

Phase 1.2 of the world-class program. The override-learning loop
(`app.services.override_learning`) lets an analyst correction teach the system
to re-disposition future *and past* alerts that share a signature. In a SOC,
anyone who can cause alerts is a potential attacker of this loop: farm benign
alerts under the signature you intend to attack under, get them closed as false
positive, and you have taught the system to auto-close the real intrusion. The
one-click retroactive bulk re-disposition makes it worse — one poisoned
signature can rewrite history.

This module is the pure (stdlib-only, no DB) core of the defense:

- **Provenance + trust weighting** — every memory carries who/what wrote it;
  a verified human outranks an autonomous closure (:func:`trust_weight`).
- **Decay** — confidence decays with age so nothing is permanent without
  re-confirmation (:meth:`MemoryProvenance.effective_confidence`).
- **Anomaly detection** — a burst of same-signature false-positive
  dispositions from low-trust authors is itself a detection
  (:class:`PoisoningDetector`).
- **Blast-radius control** — retroactive re-disposition is planned, capped,
  and gated on an explicit confirmation token derived from the exact alert set
  (:func:`plan_redisposition`, :func:`compute_confirmation_token`).

The DB-touching service (`override_learning`) and the feedback endpoint call
into these helpers; keeping them pure means the whole defense is unit-testable
offline and gated on every PR.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

__all__ = [
    "MemoryAuthor",
    "trust_weight",
    "MemoryProvenance",
    "DispositionEvent",
    "PoisoningVerdict",
    "PoisoningDetector",
    "compute_confirmation_token",
    "RedispositionPlan",
    "plan_redisposition",
    "DEFAULT_MAX_REDISPOSITION_BATCH",
]

# Never auto-apply more than this many retroactive re-dispositions in one call.
DEFAULT_MAX_REDISPOSITION_BATCH = 200


class MemoryAuthor(str, Enum):
    """Who/what produced a memory write. Determines trust weight."""

    HUMAN_VERIFIED = "human_verified"
    AUTONOMOUS = "autonomous"
    IMPORTED = "imported"


# A verified human analyst outranks an autonomous closure, which outranks an
# imported/bulk lesson. These weights gate how much a memory can move a verdict.
_TRUST_WEIGHTS: dict[MemoryAuthor, float] = {
    MemoryAuthor.HUMAN_VERIFIED: 1.0,
    MemoryAuthor.AUTONOMOUS: 0.4,
    MemoryAuthor.IMPORTED: 0.2,
}


def trust_weight(author: MemoryAuthor | str) -> float:
    """Base trust weight in [0, 1] for a memory author."""
    if isinstance(author, str):
        try:
            author = MemoryAuthor(author)
        except ValueError:
            return 0.0
    return _TRUST_WEIGHTS.get(author, 0.0)


@dataclass(frozen=True)
class MemoryProvenance:
    """Provenance stamped on every institutional-memory write. No anonymous memory."""

    author: MemoryAuthor
    tenant_id: str
    source_alert_id: str
    analyst_id: str | None = None
    confidence: float = 1.0
    recorded_at: datetime | None = None

    def effective_confidence(self, now: datetime, *, half_life_days: float = 30.0) -> float:
        """Confidence discounted by trust weight and exponential age decay.

        Nothing is permanent: a memory at ``half_life_days`` old counts for half
        its trust-weighted confidence, so stale lessons must be re-confirmed to
        keep moving verdicts.
        """
        base = max(0.0, min(1.0, self.confidence)) * trust_weight(self.author)
        if self.recorded_at is None or half_life_days <= 0:
            return base
        age_days = max(0.0, (now - self.recorded_at).total_seconds() / 86_400.0)
        decay = 0.5 ** (age_days / half_life_days)
        return base * decay

    def to_dict(self) -> dict:
        return {
            "author": self.author.value,
            "tenant_id": self.tenant_id,
            "source_alert_id": self.source_alert_id,
            "analyst_id": self.analyst_id,
            "confidence": self.confidence,
            "trust_weight": trust_weight(self.author),
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
        }


@dataclass(frozen=True)
class DispositionEvent:
    """One disposition applied to an alert of a given signature."""

    signature_key: str
    disposition: str
    author: MemoryAuthor
    at: datetime
    analyst_id: str | None = None


@dataclass
class PoisoningVerdict:
    """Outcome of scanning a signature's recent disposition history."""

    signature_key: str
    flagged: bool
    fp_count: int
    window_seconds: float
    distinct_authors: int
    human_confirmations: int
    reasons: list[str] = field(default_factory=list)

    @property
    def should_block_autoclose(self) -> bool:
        """A flagged signature must not drive autonomous closure until a human clears it."""
        return self.flagged


class PoisoningDetector:
    """Flags a burst of same-signature false-positive dispositions.

    The farming attack looks like: many alerts of one signature closed as
    false-positive in a short window, driven mostly by autonomous/low-trust
    dispositions, with few or no independent human confirmations. Slow, human,
    diverse corrections do not trip it.
    """

    def __init__(
        self,
        *,
        window_seconds: float = 3600.0,
        min_fp_burst: int = 10,
        max_human_confirmations: int = 2,
        fp_dispositions: Sequence[str] = ("false_positive", "benign"),
    ) -> None:
        self.window_seconds = window_seconds
        self.min_fp_burst = min_fp_burst
        self.max_human_confirmations = max_human_confirmations
        self._fp_dispositions = set(fp_dispositions)

    def assess(self, signature_key: str, events: Iterable[DispositionEvent], *, now: datetime) -> PoisoningVerdict:
        window_start = now - timedelta(seconds=self.window_seconds)
        recent_fp = [
            e for e in events if e.signature_key == signature_key and e.disposition in self._fp_dispositions and e.at >= window_start
        ]
        fp_count = len(recent_fp)
        human_confirmations = sum(1 for e in recent_fp if e.author == MemoryAuthor.HUMAN_VERIFIED)
        distinct_authors = len({e.analyst_id for e in recent_fp if e.analyst_id})

        reasons: list[str] = []
        flagged = False
        if fp_count >= self.min_fp_burst and human_confirmations <= self.max_human_confirmations:
            flagged = True
            reasons.append(
                f"{fp_count} false-positive dispositions for one signature within "
                f"{int(self.window_seconds)}s with only {human_confirmations} human confirmation(s)"
            )
        return PoisoningVerdict(
            signature_key=signature_key,
            flagged=flagged,
            fp_count=fp_count,
            window_seconds=self.window_seconds,
            distinct_authors=distinct_authors,
            human_confirmations=human_confirmations,
            reasons=reasons,
        )


def compute_confirmation_token(alert_ids: Sequence[str], new_disposition: str) -> str:
    """Deterministic token over the exact re-disposition set.

    The client sees the preview (which alerts flip) and echoes this token back
    on apply. If the set or target disposition changes, the token changes, so a
    stale or tampered batch cannot be applied.
    """
    canonical = "|".join(sorted(str(a) for a in alert_ids)) + "=>" + new_disposition
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RedispositionPlan:
    """A previewed, capped, confirm-gated retroactive re-disposition."""

    alert_ids: list[str]
    new_disposition: str
    confirmation_token: str
    total_matched: int
    max_batch: int
    capped: bool
    quarantined: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_ids": self.alert_ids,
            "new_disposition": self.new_disposition,
            "confirmation_token": self.confirmation_token,
            "total_matched": self.total_matched,
            "max_batch": self.max_batch,
            "capped": self.capped,
            "quarantined": self.quarantined,
            "reasons": self.reasons,
        }


def plan_redisposition(
    candidate_ids: Sequence[str],
    new_disposition: str,
    *,
    max_batch: int = DEFAULT_MAX_REDISPOSITION_BATCH,
    flagged: bool = False,
) -> RedispositionPlan:
    """Build a quarantined, capped, confirm-gated plan. Never applies anything.

    - Caps the batch at ``max_batch`` (blast-radius control).
    - Quarantines (requires manual review, applies nothing) when the signature
      was flagged as poisoned or the matched set exceeds the cap.
    """
    ids = [str(a) for a in candidate_ids]
    total = len(ids)
    capped = total > max_batch
    applied_ids = ids[:max_batch]
    reasons: list[str] = []
    quarantined = False
    if flagged:
        quarantined = True
        reasons.append("signature flagged by poisoning detector; retroactive apply requires human clearance")
    if capped:
        reasons.append(f"matched {total} alerts; capped to {max_batch} per apply")
    token = compute_confirmation_token(applied_ids, new_disposition)
    return RedispositionPlan(
        alert_ids=applied_ids,
        new_disposition=new_disposition,
        confirmation_token=token,
        total_matched=total,
        max_batch=max_batch,
        capped=capped,
        quarantined=quarantined,
        reasons=reasons,
    )
