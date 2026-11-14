"""Write a human-authored outcome prior when an analyst dispositions an alert.

Parity plan 2.3: "Write a human-authored prior whenever an analyst disposes
an alert", and "stop AI-only priors from suppressing anything without
analyst corroboration".

The second half shipped in v15.0.0: `services/agents/app/memory/outcomes.py`
refuses to suppress on an AI-authored prior, on an expired one, or on one
whose evidence tripped the injection guard. This is the first half, which
had no implementation at all: `record_outcome` was called from three
agents-side workers and from nowhere an analyst could reach, so **every
prior in the system was AI-authored** and the refusal rule meant repeat
suppression could never fire on anything.

Why the key matters more than the value
---------------------------------------
A prior is looked up by `outcome:<evidence_fingerprint>`. If this service
computed the fingerprint even slightly differently from the agents worker,
the prior would be written somewhere nothing ever looks, and the symptom
would be silence rather than an error.

That exact failure has already shipped once here: the fingerprint used to
hash the alert row id and the whole raw event, so no two alerts ever
matched and `repeat_alerts_suppressed` could only report zero. So this uses
the **vendored copy** of the agents module, kept byte-identical by
`scripts/sync_vendored_fingerprint.py --check`, rather than a
reimplementation that would be free to drift.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.fingerprint import evidence_fingerprint

logger = logging.getLogger(__name__)

#: Must match `app.memory.outcomes.OUTCOME_KEY_PREFIX` in the agents service.
OUTCOME_KEY_PREFIX = "outcome:"

#: Must match `app.memory.outcomes.HUMAN`.
HUMAN = "human"


#: ORM column to the name `canonical_evidence` looks for. This mapping is
#: the whole job of `_alert_evidence`, and getting it wrong is silent: the
#: canonicaliser would find `rule_id` alone, return `{"rule_id": ...}`, and
#: two alerts on the same rule but different hosts would share a key, so a
#: benign prior for one would suppress the other. A test asserts they do
#: not, which is how this mapping was found missing.
_COLUMN_TO_EVIDENCE_FIELD = {
    "affected_host": "host",
    "affected_user": "username",
    "affected_ip": "src_ip",
    "connector_type": "source",
}

#: Columns whose own name is already what the canonicaliser looks for.
_PASSTHROUGH_COLUMNS = (
    "rule_id",
    "rule_name",
    "detection_id",
    "signature",
    "title",
    "category",
    "severity",
    "entities",
    "mitre_techniques",
)


def _alert_evidence(alert: Any) -> dict[str, Any]:
    """The alert as a dict keyed the way `canonical_evidence` expects.

    Takes the ORM row's columns and renames the ones whose column name
    differs from the evidence field name, rather than hand-picking a subset:
    `canonical_evidence` is what decides which fields count, and duplicating
    that decision here is how the two sides drift apart.
    """
    if isinstance(alert, dict):
        return alert
    out: dict[str, Any] = {}
    for name in _PASSTHROUGH_COLUMNS:
        value = getattr(alert, name, None)
        if value not in (None, "", [], {}):
            out[name] = value
    for column, field in _COLUMN_TO_EVIDENCE_FIELD.items():
        value = getattr(alert, column, None)
        if value not in (None, "", [], {}):
            out.setdefault(field, value)
    return out


async def record_human_prior(
    db: AsyncSession,
    *,
    tenant_id: Any,
    alert: Any,
    disposition: str,
    analyst_id: Any,
    reason: str | None = None,
) -> str | None:
    """Record that a human reached this disposition on this evidence.

    Returns the signature written, or None when nothing was written.

    Best-effort by design: an analyst's disposition must be saved even if
    institutional memory is unavailable, so a failure here is logged and
    swallowed rather than failing their request. The cost of that choice is
    that a prior can silently not be written, so the failure is logged at
    `warning` with the signature, not at `debug`.
    """
    try:
        tenant = str(tenant_id)
        signature = evidence_fingerprint(tenant, _alert_evidence(alert))
        key = f"{OUTCOME_KEY_PREFIX}{signature}"
        now = datetime.now(UTC).isoformat()

        existing = (
            await db.execute(
                text("SELECT value FROM aisoc_institutional_memory WHERE tenant_id = :t AND key = :k").bindparams(t=tenant, k=key)
            )
        ).scalar_one_or_none()

        prior: dict[str, Any] = {}
        if existing:
            prior = existing if isinstance(existing, dict) else json.loads(existing)

        count = int(prior.get("count", 0)) + 1 if prior.get("disposition") == disposition else 1
        value = {
            "disposition": disposition,
            # A human saying so is the strongest evidence this system has.
            "confidence": 1.0,
            "author": HUMAN,
            "count": count,
            "first_seen": prior.get("first_seen", now),
            "last_seen": now,
            "alert_id": str(getattr(alert, "id", "") or ""),
            "analyst_id": str(analyst_id),
            "reason": (reason or "")[:500],
            # Scope travels with the prior so a reader knows what it covers
            # without re-deriving the fingerprint.
            "scope": "evidence_signature",
        }

        await db.execute(
            text("""
                INSERT INTO aisoc_institutional_memory
                    (tenant_id, key, value, tags, analyst_override, override_reason)
                VALUES (:t, :k, CAST(:v AS jsonb), :tags, TRUE, :reason)
                ON CONFLICT (tenant_id, key) DO UPDATE
                    SET value            = EXCLUDED.value,
                        tags             = EXCLUDED.tags,
                        analyst_override = TRUE,
                        override_reason  = EXCLUDED.override_reason,
                        created_at       = now()
            """).bindparams(
                t=tenant,
                k=key,
                v=json.dumps(value),
                tags=["outcome_prior", disposition, HUMAN],
                reason=(reason or "")[:500],
            )
        )
        return signature
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "human_prior.write_failed disposition=%s error=%s",
            str(disposition).replace("\r", "").replace("\n", " ")[:40],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
        return None
