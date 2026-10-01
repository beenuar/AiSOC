"""Durable outcome-memory priors — close the loop (Wave 1).

Every triage outcome (autonomous OR human) is written back as a per-signature
prior, so a later alert with the same evidence signature can be auto-suppressed
instead of re-triaged. This is what makes alert volume actually shrink over
time: confirmed-benign signatures stop reaching the queue.

Honesty + safety:
* **Only a human-confirmed prior suppresses.** An AI prior informs — it is
  still recorded, still surfaced, still counted — but it never auto-closes
  an alert on its own. The previous rule let three AI triages at >=0.90
  confidence close every future alert with that signature, which is a
  teachable control: an attacker who can produce three benign-looking
  alerts sharing one evidence signature trains the system to stop showing
  them that signature, permanently, with no human ever having looked. The
  corroboration threshold did not help, because the attacker chooses how
  many alerts to send.
* **A prior expires.** Environments change: a signature that was benign in
  March is not necessarily benign in September, and a prior that never ages
  out is a decision taken once and applied forever. Default 90 days from
  the last confirmation, so an actively re-confirmed prior stays live and a
  forgotten one lapses into "show it to somebody".
* **Evidence that tripped the prompt-injection guard never suppresses**,
  whoever authored the prior. An alert body is attacker-reachable text; if
  the guard flagged it, the disposition derived from it is exactly what the
  attacker was aiming for. Checked at suppression time rather than only at
  write time, because a prior written before the guard learned a pattern
  must stop suppressing once it does.
* Only auto-closeable dispositions (false_positive / benign / benign_true_positive)
  ever suppress. A prior true-positive never auto-closes a future alert.
* Human authorship is sticky: an AI prior that a human later overrode stays
  ``human`` and never downgrades.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, normalize_disposition
from app.memory.institutional import institutional_get, institutional_set

logger = structlog.get_logger()

OUTCOME_KEY_PREFIX = "outcome:"
HUMAN = "human"
AI = "ai"

#: How long a confirmation keeps suppressing, in days. Measured from
#: ``last_seen``, so re-confirming refreshes it and a prior nobody has seen
#: since lapses into "show it to somebody".
_PRIOR_TTL_DAYS = int(os.getenv("AISOC_MEMORY_PRIOR_TTL_DAYS", "90"))

#: Key an evidence record carries when the prompt-injection guard flagged the
#: text the disposition was derived from.
INJECTION_FLAG = "injection_suspected"


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
    injection_suspected: bool = False,
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
        # Sticky in the unsafe direction: once any evidence for this
        # signature has tripped the guard, later clean evidence does not
        # clear it. An attacker who can get one flagged alert through and
        # then send clean ones would otherwise launder the prior.
        INJECTION_FLAG: bool(injection_suspected) or bool(isinstance(prior, dict) and prior.get(INJECTION_FLAG)),
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


def prior_is_expired(prior: dict[str, Any], *, ttl_days: int = _PRIOR_TTL_DAYS, now: datetime | None = None) -> bool:
    """True when the last confirmation is older than the TTL.

    Measured from ``last_seen`` rather than ``first_seen``: a signature an
    analyst keeps confirming benign stays suppressed, and one nobody has
    looked at since lapses. An unparseable or missing timestamp counts as
    expired, because the alternative is suppressing on a prior whose age
    cannot be established.
    """
    raw = prior.get("last_seen") or prior.get("first_seen")
    if not isinstance(raw, str):
        return True
    try:
        seen = datetime.fromisoformat(raw)
    except ValueError:
        return True
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return (now or datetime.now(UTC)) - seen > timedelta(days=ttl_days)


def suppression_refusal(
    prior: dict[str, Any] | None,
    *,
    ttl_days: int = _PRIOR_TTL_DAYS,
    now: datetime | None = None,
) -> str | None:
    """Why this prior may not auto-close an alert, or None if it may.

    A reason string rather than a bool so the caller can log *which* rule
    refused. "Suppression declined" with no reason is how a control that has
    silently stopped working looks identical to one that is working.
    """
    if not isinstance(prior, dict):
        return "no prior recorded for this signature"

    disposition = str(prior.get("disposition", ""))
    if disposition not in AUTO_CLOSEABLE_DISPOSITIONS:
        return f"disposition {disposition!r} is not auto-closeable"

    if prior.get(INJECTION_FLAG):
        return (
            "the evidence this prior was derived from tripped the prompt-injection guard; "
            "a benign disposition reached that way is what an attacker was aiming for"
        )

    if prior.get("author") != HUMAN:
        return (
            "the prior is AI-authored and no human has confirmed it. An attacker who can "
            "produce benign-looking alerts sharing one signature would otherwise train the "
            "system to stop showing them"
        )

    if prior_is_expired(prior, ttl_days=ttl_days, now=now):
        return (
            f"the last confirmation is older than {ttl_days} days; environments change and a "
            "prior that never ages out is a decision taken once and applied forever"
        )

    return None


def should_auto_suppress(
    prior: dict[str, Any] | None,
    *,
    ttl_days: int = _PRIOR_TTL_DAYS,
    now: datetime | None = None,
) -> bool:
    """Whether a prior is trusted enough to auto-close a repeat alert.

    Kept as a predicate for the existing call sites; `suppression_refusal`
    is the one to call when the reason matters, which at the point of
    closing somebody's alert it usually does.
    """
    return suppression_refusal(prior, ttl_days=ttl_days, now=now) is None
