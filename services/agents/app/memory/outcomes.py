"""Durable outcome-memory priors — close the loop (Wave 1).

Every triage outcome (autonomous OR human) is written back as a per-signature
prior, so a later alert with the same evidence signature can be auto-suppressed
instead of re-triaged. This is what makes alert volume actually shrink over
time: confirmed-benign signatures stop reaching the queue.

Honesty + safety:
* AI-authored priors are trusted less than human-verified ones. A human prior
  suppresses immediately; an AI prior only suppresses once it has been
  corroborated by repeat outcomes (``count``) at high confidence.
* Only auto-closeable dispositions (false_positive / benign / benign_true_positive)
  ever suppress. A prior true-positive never auto-closes a future alert.
* Human authorship is sticky: an AI prior that a human later overrode stays
  ``human`` and never downgrades.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog

from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, normalize_disposition
from app.memory.institutional import institutional_get, institutional_set

logger = structlog.get_logger()

OUTCOME_KEY_PREFIX = "outcome:"
HUMAN = "human"
AI = "ai"

# Suppression gates for AI-authored priors (env-overridable). Human priors are
# always trusted; AI priors need corroboration.
_MIN_AI_COUNT = int(os.getenv("AISOC_MEMORY_MIN_AI_COUNT", "3"))
_AI_CONF_THRESHOLD = float(os.getenv("AISOC_MEMORY_AI_CONFIDENCE", "0.90"))


def outcome_key(signature: str) -> str:
    return f"{OUTCOME_KEY_PREFIX}{signature}"


async def record_outcome(
    tenant_id: str,
    signature: str,
    *,
    disposition: str,
    confidence: float,
    author: str = AI,
    alert_id: Any = None,
) -> dict[str, Any]:
    """Write/refresh the per-signature outcome prior. Best-effort (never raises)."""
    disposition = normalize_disposition(disposition, default="needs_review")
    key = outcome_key(signature)
    now = datetime.now(UTC).isoformat()

    prior = await institutional_get(tenant_id, key)
    if isinstance(prior, dict) and prior.get("disposition") == disposition:
        count = int(prior.get("count", 0)) + 1
        first_seen = prior.get("first_seen", now)
        # Human authorship is sticky and never downgraded to AI.
        if prior.get("author") == HUMAN:
            author = HUMAN
    else:
        count = 1
        first_seen = now

    value: dict[str, Any] = {
        "signature": signature,
        "disposition": disposition,
        "confidence": round(float(confidence or 0.0), 4),
        "author": author,
        "count": count,
        "first_seen": first_seen,
        "last_seen": now,
        "last_alert_id": str(alert_id) if alert_id else None,
    }
    try:
        await institutional_set(
            tenant_id,
            key,
            value,
            tags=["outcome_prior", disposition, author],
            analyst_override=(author == HUMAN),
        )
    except Exception as exc:  # noqa: BLE001 — memory write is best-effort
        logger.debug("outcome_memory.write_failed", signature=signature, error=str(exc))
    return value


async def lookup_prior(tenant_id: str, signature: str) -> dict[str, Any] | None:
    """Return the durable outcome prior for a signature, or None."""
    prior = await institutional_get(tenant_id, outcome_key(signature))
    return prior if isinstance(prior, dict) else None


def should_auto_suppress(
    prior: dict[str, Any] | None,
    *,
    min_ai_count: int = _MIN_AI_COUNT,
    ai_confidence: float = _AI_CONF_THRESHOLD,
) -> bool:
    """Decide whether a prior is trusted enough to auto-suppress a repeat alert."""
    if not isinstance(prior, dict):
        return False
    disposition = str(prior.get("disposition", ""))
    if disposition not in AUTO_CLOSEABLE_DISPOSITIONS:
        return False
    if prior.get("author") == HUMAN:
        return True
    # AI-authored: require corroboration by repeat count + high confidence.
    return int(prior.get("count", 0)) >= min_ai_count and float(prior.get("confidence", 0.0)) >= ai_confidence
