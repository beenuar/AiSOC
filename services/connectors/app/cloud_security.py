"""Materialise CNAPP findings as cloud-posture context.

Depth-2 item 8.1.

Why this exists
---------------
`posture_findings` has shipped since migration 017 with RLS, six indices, a
REST surface and a compliance-evidence mapper. It has had exactly one writer
in the whole tree: `POST /posture/findings`, a route a human calls by hand. No
connector, no scanner and no scheduler has ever written a row.

So `GET /posture/summary` counted an empty table and answered eight confident
zeros on every deployment, and `GET /posture/scans` read a table with no
writer at all. That is the shape this programme keeps finding: a module that
is reachable, runs fine, and reads a table nothing writes. A reachability gate
passes on it, because the code does run.

Why it lives in the connectors service
--------------------------------------
Same reasoning as `vulnerabilities.py`, deliberately not re-litigated: the
API's service principal is a read-only credential whose own docstring says
anything that changes the database is absent on purpose, and widening it for
this would undo that decision for every route at once. This service already
owns a database engine (it decrypts connector credentials at poll time) and
already holds the tenant id the scheduler is polling for.

What it does not do
-------------------
It does not resolve findings that stopped being returned. A poll asks for a
time window, so a finding's absence from one page means "not updated in this
window" far more often than it means "remediated", and writing `resolved` from
that would retire a live misconfiguration on a quiet afternoon. Resolution
stays with the vendor's own `status`, which the collector carries through.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = structlog.get_logger(__name__)

#: One poll must not write an unbounded number of rows. A CNAPP's standing
#: backlog of misconfigurations is routinely tens of thousands, and a
#: five-minute schedule against the shared database is the wrong place to
#: discover that. Same reasoning and same order of magnitude as
#: `MAX_FINDINGS_PER_SYNC` in `vulnerabilities.py`.
MAX_FINDINGS_PER_SYNC = 2_000

#: Mirrors the CHECK migration 133 puts on the column. Declared here too so a
#: bad class is refused with a readable message instead of an IntegrityError
#: from four frames down.
VALID_CLASSES = frozenset({"misconfiguration", "secret", "runtime_detection", "issue"})

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

#: The tenant predicate on every statement below is not redundant with the
#: tenant-scoped SELECT that produced an id. How a row was *addressed* is
#: irrelevant to whether the write is scoped: an id arriving from anywhere
#: else, now or after a later edit, would reach another tenant's row.
#: `scripts/check_tenant_query_predicates.py` makes that the rule.
_FIND_FINDING = text(
    """
    SELECT id FROM posture_findings
     WHERE tenant_id   = CAST(:tenant_id AS uuid)
       AND source      = :source
       AND external_id = :external_id
     LIMIT 1
    """
)

_INSERT_FINDING = text(
    """
    INSERT INTO posture_findings
        (id, tenant_id, source, finding_class, external_id,
         cloud_provider, cloud_account, cloud_region,
         resource_type, resource_id, resource_name, resource_keys,
         rule_id, rule_title, description, severity, status,
         evidence, remediation_guide,
         first_detected_at, last_evaluated_at, last_seen_at,
         created_at, updated_at)
    VALUES (:id, CAST(:tenant_id AS uuid), :source, :finding_class, :external_id,
            :cloud_provider, :cloud_account, :cloud_region,
            :resource_type, :resource_id, :resource_name,
            CAST(:resource_keys AS text[]),
            :rule_id, :rule_title, :description, :severity, 'open',
            CAST(:evidence AS jsonb), :remediation_guide,
            :observed_at, :now, :now, :now, :now)
    """
)

#: `first_detected_at` is deliberately untouched on a re-poll, for the reason
#: `vulnerabilities.py` leaves `first_found` alone: "how long has this been
#: wrong" is the question an exposure window is asked, and a re-poll that
#: resets the clock answers it with the age of the last poll.
_TOUCH_FINDING = text(
    """
    UPDATE posture_findings
       SET last_seen_at      = :now,
           last_evaluated_at = :now,
           severity          = :severity,
           rule_title        = :rule_title,
           description       = :description,
           resource_keys     = CAST(:resource_keys AS text[]),
           evidence          = CAST(:evidence AS jsonb)
     WHERE id        = CAST(:id AS uuid)
       AND tenant_id = CAST(:tenant_id AS uuid)
    """
)

#: The run row is what makes "nobody has collected" distinguishable from
#: "collected, and the estate is clean". Written even when the poll found
#: nothing — especially then, because a zero with no run behind it is the
#: confident zero this module exists to stop publishing.
_INSERT_RUN = text(
    """
    INSERT INTO posture_scan_runs
        (id, tenant_id, source, cloud_provider, finding_classes,
         started_at, completed_at, status,
         findings_total, findings_new, findings_closed, metadata)
    VALUES (:id, CAST(:tenant_id AS uuid), :source, :cloud_provider,
            CAST(:finding_classes AS text[]),
            :started_at, :now, :status,
            :findings_total, :findings_new, 0, CAST(:metadata AS jsonb))
    """
)


def _clean(value: Any, *, limit: int = 2000) -> str | None:
    text_value = str(value).strip() if value is not None else ""
    return text_value[:limit] or None


def _keys(finding: dict[str, Any]) -> list[str]:
    raw = finding.get("resource_keys")
    values: Sequence[Any] = raw if isinstance(raw, list) else []
    out: list[str] = []
    for value in values:
        item = str(value or "").strip().lower()
        if item and item not in out:
            out.append(item)
    return out[:16]


async def sync_cloud_security_findings(
    engine: AsyncEngine,
    *,
    tenant_id: uuid.UUID | str,
    source: str,
    findings: list[dict[str, Any]],
    now: datetime | None = None,
    started_at: datetime | None = None,
) -> dict[str, int]:
    """Write one poll's posture findings for one tenant. Returns what it did.

    Counts are returned rather than only logged because "the sync ran" and
    "the sync wrote something" are different facts, and only the second one
    means a verdict will have posture context to read.
    """
    stamp = now or datetime.now(UTC)
    began = started_at or stamp
    tenant = str(tenant_id)

    truncated = 0
    if len(findings) > MAX_FINDINGS_PER_SYNC:
        truncated = len(findings) - MAX_FINDINGS_PER_SYNC
        logger.warning(
            "cloud_security.sync_truncated",
            tenant_id=tenant,
            source=source,
            received=len(findings),
            cap=MAX_FINDINGS_PER_SYNC,
        )
        findings = findings[:MAX_FINDINGS_PER_SYNC]

    inserted = touched = skipped = 0
    classes: list[str] = []
    providers: list[str] = []

    async with engine.begin() as conn:
        for finding in findings:
            external_id = _clean(finding.get("external_id"), limit=256)
            resource_id = _clean(finding.get("resource_id"), limit=1024)
            finding_class = str(finding.get("finding_class") or "").strip()
            if not external_id or not resource_id or finding_class not in VALID_CLASSES:
                # Counted rather than dropped silently: a collector whose
                # mapping stopped producing ids should show up as a skip
                # count, not as a quiet decline in findings.
                skipped += 1
                continue

            severity = str(finding.get("severity") or "medium").strip().lower()
            if severity not in _VALID_SEVERITIES:
                severity = "medium"

            if finding_class not in classes:
                classes.append(finding_class)
            provider = str(finding.get("cloud_provider") or "other").strip().lower()
            if provider not in providers:
                providers.append(provider)

            shared = {
                "tenant_id": tenant,
                "severity": severity,
                "rule_title": _clean(finding.get("rule_title"), limit=500) or "Cloud security finding",
                "description": _clean(finding.get("description"), limit=4000),
                "resource_keys": _keys(finding),
                "evidence": json.dumps(finding.get("evidence") or {}, default=str)[:20000],
                "now": stamp,
            }

            existing = (
                await conn.execute(
                    _FIND_FINDING,
                    {"tenant_id": tenant, "source": source, "external_id": external_id},
                )
            ).first()

            if existing is not None:
                await conn.execute(_TOUCH_FINDING, {**shared, "id": str(existing[0])})
                touched += 1
                continue

            observed = finding.get("observed_at")
            await conn.execute(
                _INSERT_FINDING,
                {
                    **shared,
                    "id": uuid.uuid4(),
                    "source": source,
                    "finding_class": finding_class,
                    "external_id": external_id,
                    "cloud_provider": provider,
                    "cloud_account": _clean(finding.get("cloud_account"), limit=255),
                    "cloud_region": _clean(finding.get("cloud_region"), limit=100),
                    "resource_type": _clean(finding.get("resource_type"), limit=100) or "unknown",
                    "resource_id": resource_id,
                    "resource_name": _clean(finding.get("resource_name"), limit=500),
                    "rule_id": _clean(finding.get("rule_id"), limit=100) or f"{source}.finding",
                    "remediation_guide": _clean(finding.get("remediation_guide"), limit=4000),
                    # The vendor's own first-seen when it gave one, so an
                    # exposure window is measured from when the estate became
                    # wrong rather than from when AiSOC was connected.
                    "observed_at": _parse_ts(observed) or stamp,
                },
            )
            inserted += 1

        await conn.execute(
            _INSERT_RUN,
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant,
                "source": source,
                # The column is NOT NULL and a poll spans providers, so the
                # run names the estate rather than one cloud.
                "cloud_provider": providers[0] if len(providers) == 1 else "other",
                "finding_classes": classes,
                "started_at": began,
                "now": stamp,
                "status": "completed",
                "findings_total": inserted + touched,
                "findings_new": inserted,
                "metadata": json.dumps({"skipped": skipped, "truncated": truncated}),
            },
        )

    result = {
        "findings_inserted": inserted,
        "findings_touched": touched,
        "skipped": skipped,
        "truncated": truncated,
    }
    logger.info("cloud_security.synced", tenant_id=tenant, source=source, **result)
    return result


def _parse_ts(value: Any) -> datetime | None:
    """A vendor timestamp, or ``None`` when it is not one.

    Never raises: a malformed `firstSeenAt` must not fail a whole poll, and
    the caller substitutes the poll time, which is a weaker but honest answer.
    """
    if isinstance(value, datetime):
        return value
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


__all__ = ["MAX_FINDINGS_PER_SYNC", "VALID_CLASSES", "sync_cloud_security_findings"]
