"""Send a sample of auto-closed alerts to an analyst, and measure the result.

Parity plan 3.5.

Why this is the number that matters
-----------------------------------
Closure accuracy on a tenant's own data is what a buyer asks for, and
nothing in this tree measured it. The eval harness grades a synthetic
corpus. The funnel counts how many alerts were closed, which says nothing
about whether closing them was right. "Of the alerts the agent closed on
your data, how many should it have" has only one honest answer, and it
involves a human looking at some of them.

Sampling rather than reviewing everything, because reviewing every
auto-closure costs more than not auto-closing at all, and the point is to
measure the thing rather than to re-do it.

What the sample is drawn with
-----------------------------
A deterministic hash of the alert id, not `random()`. Three reasons, and
the first is the one that bites: a worker with several replicas calling
`random()` samples at the configured rate *per replica*, so three replicas
at 5 percent sample 15 percent. Hashing the alert id gives the same answer
on any replica and on a retry, so a redelivered message does not create a
second sample of the same closure and weight it twice.

The third is that it is reproducible. "Why was this one sampled" has an
answer.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

#: Used when a tenant has no closure policy row. The plan's default.
DEFAULT_SAMPLE_RATE = float(os.getenv("AISOC_CLOSURE_QA_SAMPLE_RATE", "0.05"))

#: The five axes the plan names. Open scores rather than a single
#: pass/fail, because "the verdict was right but it gathered no evidence"
#: and "it gathered everything and concluded wrongly" are different
#: failures needing different fixes.
RUBRIC = ("evidence", "reasoning", "verdict", "response", "report")


def should_sample(alert_id: str, *, rate: float) -> bool:
    """Deterministic, uniform, and the same on every replica.

    `random() < rate` would sample at `rate` **per replica**, so three
    replicas at 5 percent sample 15 percent of closures, and a redelivered
    Kafka message would get a second independent roll.
    """
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    digest = hashlib.sha256(str(alert_id).encode()).digest()
    # First four bytes as a fraction of the range. Uniform enough for a
    # sample rate, and stable across Python versions unlike `hash()`.
    bucket = int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
    return bucket < rate


@dataclass(frozen=True)
class SampleDecision:
    sampled: bool
    rate: float
    reason: str


class ClosureQaSampler:
    """Writes a review row for a fraction of auto-closed alerts."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def rate_for(self, *, tenant_id: str, alert_class: str | None) -> float:
        """The tenant's configured rate for this class, or the default."""
        if self._pool is None:
            return DEFAULT_SAMPLE_RATE
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT qa_sample_rate
                      FROM aisoc_closure_policies
                     WHERE tenant_id = $1::uuid
                       AND (alert_class = $2 OR alert_class IS NULL)
                     ORDER BY alert_class NULLS LAST
                     LIMIT 1
                    """,
                    tenant_id,
                    alert_class,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("closure_qa.rate_unreadable", error=str(exc), tenant_id=tenant_id)
            return DEFAULT_SAMPLE_RATE
        if row is None or row["qa_sample_rate"] is None:
            return DEFAULT_SAMPLE_RATE
        return float(row["qa_sample_rate"])

    async def record(
        self,
        *,
        tenant_id: str,
        alert_id: str,
        alert_class: str | None,
        disposition: str,
        confidence: float,
        closed_at: datetime | None = None,
    ) -> SampleDecision:
        """Sample this closure, or decline, and say which."""
        rate = await self.rate_for(tenant_id=tenant_id, alert_class=alert_class)
        if not should_sample(alert_id, rate=rate):
            return SampleDecision(False, rate, "not in the sample")
        if self._pool is None:
            return SampleDecision(False, rate, "no database available to record the sample")

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO aisoc_closure_qa_samples
                        (tenant_id, alert_id, agent_disposition, agent_confidence, closed_at)
                    VALUES ($1::uuid, $2::uuid, $3, $4, $5)
                    ON CONFLICT (tenant_id, alert_id) DO NOTHING
                    """,
                    tenant_id,
                    alert_id,
                    disposition,
                    float(confidence),
                    closed_at or datetime.now(UTC),
                )
        except Exception as exc:  # noqa: BLE001
            # Warning, not debug. A sampler that silently stops sampling
            # produces an accuracy figure over a shrinking denominator,
            # which looks like a stable measurement and is not one.
            logger.warning("closure_qa.write_failed", error=str(exc), alert_id=alert_id)
            return SampleDecision(False, rate, f"sample write failed: {exc}")

        logger.info("closure_qa.sampled", alert_id=alert_id, rate=rate, disposition=disposition)
        return SampleDecision(True, rate, "sampled for analyst review")


def accuracy_from_reviews(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Measured closure accuracy, with the count it was measured over.

    Every mean travels with its denominator. An accuracy of 1.0 over three
    reviews and over three hundred are different claims, and a figure
    presented without the count invites the reader to assume the second.
    """
    reviewed = [r for r in reviews if r.get("status") == "reviewed"]
    if not reviewed:
        return {
            "measured": False,
            "reason": "no auto-closure has been reviewed yet",
            "reviewed": 0,
            "pending": sum(1 for r in reviews if r.get("status") == "pending"),
        }

    agreed = sum(1 for r in reviewed if r.get("reviewer_disposition") and r["reviewer_disposition"] == r.get("agent_disposition"))
    out: dict[str, Any] = {
        "measured": True,
        "reviewed": len(reviewed),
        "pending": sum(1 for r in reviews if r.get("status") == "pending"),
        "agreed": agreed,
        "disagreed": len(reviewed) - agreed,
        "closure_accuracy": round(agreed / len(reviewed), 4),
    }
    for axis in RUBRIC:
        key = f"score_{axis}"
        scores = [r[key] for r in reviewed if isinstance(r.get(key), int)]
        out[f"mean_{axis}"] = round(sum(scores) / len(scores), 2) if scores else None
        # The denominator per axis too, because a reviewer may score some
        # axes and not others.
        out[f"scored_{axis}"] = len(scores)
    return out
