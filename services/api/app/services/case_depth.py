"""Alert and case merge, bulk triage, tenant custom fields, analyst workload.

Depth plan 9.3 — the open half of parity 5.6.

Four capabilities, one module, because they share the same two tables and the
same rule: **nothing here deletes anything.** A merged alert keeps its row
and gains a pointer; a merged case keeps its row, its audit chain, its
custody entries and whatever vendor ticket already names its id; a retired
custom field keeps the values written against it.

What already existed, so that "new" means something
---------------------------------------------------
``alerts.is_merged``, ``alerts.parent_alert_id`` and
``alerts.child_alert_ids`` have been in the schema since migration 001 and
had **no writer anywhere** — the only mention outside the ORM model was the
ORM model. The alert half of merge therefore needed no schema change, only
this. That is the repository's most common defect and it is worth naming
rather than quietly filling in.

``POST /alerts/bulk-close`` existed and is good: a preflight count, a
snapshot table, one audit row for the batch. It closes, and closing is one
triage decision out of several — an analyst clearing a morning queue also
assigns, re-severities and moves things to in-progress. :func:`bulk_triage`
is the rest of that verb set, and it deliberately reuses bulk-close's two
safety properties (a count the caller must acknowledge, one audit row for
the batch) rather than inventing weaker ones.

Workload is counted, not estimated
----------------------------------
:func:`analyst_workload` returns, per analyst, counts this query computed
over rows it selected — never a stored aggregate. Every mean travels with
the number of rows it averaged, and an analyst with no closed cases gets
``None`` for their mean time to close rather than ``0.0``. A zero there
reads as "instant", which is the opposite of "no data", and that exact
confusion is why two console figures were wrong for months.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: Alert statuses a bulk triage may move rows *to*. ``closed`` is absent on
#: purpose: it already has a route with a snapshot table and a restore
#: target, and a second path to the same destination with weaker guarantees
#: is how one of the two quietly becomes the one everybody uses.
BULK_TRIAGE_STATUSES: frozenset[str] = frozenset({"new", "open", "in_progress", "resolved", "dismissed"})

#: Severities a bulk triage may set.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Custom field types, mirroring the CHECK in migration 106. One validator
#: and one input control each.
FIELD_TYPES: tuple[str, ...] = ("text", "number", "boolean", "date", "select")


class CaseDepthError(ValueError):
    """A refusal the caller can act on. Routes render it as 4xx with the text."""


# ---------------------------------------------------------------------------
# Alert merge
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MergeResult:
    primary_id: uuid.UUID
    merged_ids: list[uuid.UUID]
    case_id: uuid.UUID | None


async def merge_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    primary_id: uuid.UUID,
    duplicate_ids: list[uuid.UUID],
    actor: str,
) -> MergeResult:
    """Fold ``duplicate_ids`` into ``primary_id``. Keeps every row.

    Refusals, each because the alternative loses information silently:

    * a duplicate that is already merged — re-merging would rewrite its
      parent and orphan the chain it is part of;
    * the primary being itself a duplicate — that makes a cycle, and a
      console walking ``parent_alert_id`` would not terminate;
    * an id belonging to another tenant, which simply does not resolve here
      because every statement is tenant-predicated.

    The surviving alert inherits the duplicates' ``case_id`` when it has
    none, so merging two alerts one of which is already on a case leaves the
    survivor on that case rather than detached — which is what the phase's
    "two alerts merge into one case with their history kept" asks for.
    """
    unique = [i for i in dict.fromkeys(duplicate_ids) if i != primary_id]
    if not unique:
        raise CaseDepthError("Nothing to merge: the duplicate list is empty once the primary is removed from it.")

    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, is_merged, parent_alert_id, case_id FROM alerts "
                    "WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))"
                ).bindparams(tenant_id=tenant_id, ids=[str(i) for i in [primary_id, *unique]])
            )
        )
        .mappings()
        .all()
    )
    found = {row["id"]: row for row in rows}

    missing = [str(i) for i in [primary_id, *unique] if i not in found]
    if missing:
        raise CaseDepthError(f"No such alert(s) in this tenant: {', '.join(missing)}")
    if found[primary_id]["is_merged"]:
        raise CaseDepthError(
            f"{primary_id} is itself merged into {found[primary_id]['parent_alert_id']}. "
            "Merge into the surviving alert instead, or a walk of the chain would not terminate."
        )
    already = [str(i) for i in unique if found[i]["is_merged"]]
    if already:
        raise CaseDepthError(
            f"Already merged: {', '.join(already)}. Re-merging would rewrite the parent and orphan the chain those alerts are part of."
        )

    now = datetime.now(UTC)
    await db.execute(
        text(
            "UPDATE alerts SET is_merged = TRUE, parent_alert_id = :primary, "
            "status = CASE WHEN status IN ('closed', 'dismissed') THEN status ELSE 'dismissed' END, "
            "updated_at = :now "
            "WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))"
        ).bindparams(primary=primary_id, now=now, tenant_id=tenant_id, ids=[str(i) for i in unique])
    )

    # `child_alert_ids` is appended to rather than replaced: a second merge
    # into the same primary must not drop the first merge's children.
    await db.execute(
        text(
            "UPDATE alerts SET child_alert_ids = ("
            "  SELECT CAST(jsonb_agg(DISTINCT e) AS jsonb) FROM ("
            "    SELECT jsonb_array_elements_text(child_alert_ids) AS e"
            "    UNION SELECT unnest(CAST(:ids AS text[]))"
            "  ) AS merged"
            "), updated_at = :now "
            "WHERE tenant_id = :tenant_id AND id = :primary"
        ).bindparams(ids=[str(i) for i in unique], now=now, tenant_id=tenant_id, primary=primary_id)
    )

    case_id = found[primary_id]["case_id"]
    if case_id is None:
        inherited = next((found[i]["case_id"] for i in unique if found[i]["case_id"] is not None), None)
        if inherited is not None:
            await db.execute(
                text("UPDATE alerts SET case_id = :case_id, updated_at = :now WHERE tenant_id = :tenant_id AND id = :primary").bindparams(
                    case_id=inherited, now=now, tenant_id=tenant_id, primary=primary_id
                )
            )
            case_id = inherited

    del actor  # recorded by the caller's audit row, which owns the request context
    return MergeResult(primary_id=primary_id, merged_ids=list(unique), case_id=case_id)


# ---------------------------------------------------------------------------
# Case merge
# ---------------------------------------------------------------------------


async def merge_cases(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    primary_id: uuid.UUID,
    duplicate_ids: list[uuid.UUID],
    actor: str,
    reason: str,
) -> MergeResult:
    """Fold cases into one. Alerts follow; both rows survive.

    The absorbed case keeps its row, its audit chain, its custody entries and
    any vendor ticket that already names its id. Its alerts are repointed at
    the survivor, and its ``alert_ids`` array is unioned into the survivor's
    so a reader of either column sees the same set.
    """
    unique = [i for i in dict.fromkeys(duplicate_ids) if i != primary_id]
    if not unique:
        raise CaseDepthError("Nothing to merge: the duplicate list is empty once the primary is removed from it.")

    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, status, merged_into_id FROM aisoc_cases WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))"
                ).bindparams(tenant_id=tenant_id, ids=[str(i) for i in [primary_id, *unique]])
            )
        )
        .mappings()
        .all()
    )
    found = {row["id"]: row for row in rows}

    missing = [str(i) for i in [primary_id, *unique] if i not in found]
    if missing:
        raise CaseDepthError(f"No such case(s) in this tenant: {', '.join(missing)}")
    if found[primary_id]["merged_into_id"] is not None:
        raise CaseDepthError(
            f"{primary_id} was itself merged into {found[primary_id]['merged_into_id']}. Merge into the surviving case instead."
        )
    already = [str(i) for i in unique if found[i]["merged_into_id"] is not None]
    if already:
        raise CaseDepthError(f"Already merged: {', '.join(already)}.")

    now = datetime.now(UTC)
    ids = [str(i) for i in unique]

    # Alerts follow the merge. Done before the case rows change so a failure
    # leaves the alerts pointing at a case that is still open rather than at
    # one already marked merged.
    await db.execute(
        text(
            "UPDATE alerts SET case_id = :primary, updated_at = :now WHERE tenant_id = :tenant_id AND case_id = ANY(CAST(:ids AS uuid[]))"
        ).bindparams(primary=primary_id, now=now, tenant_id=tenant_id, ids=ids)
    )

    # `aisoc_cases.alert_ids` is `uuid[]`, not JSONB -- unlike `ioc_ids` and
    # `artifact_ids` beside it, and unlike `alerts.child_alert_ids` above.
    # The first version of this statement assumed JSONB and raised
    # `jsonb_array_elements_text(uuid[]) does not exist` against the real
    # schema. A SQLite stand-in would have accepted either and shipped it.
    await db.execute(
        text(
            "UPDATE aisoc_cases SET alert_ids = ("
            "  SELECT COALESCE(array_agg(DISTINCT e), '{}'::uuid[]) FROM ("
            "    SELECT unnest(p.alert_ids) AS e FROM aisoc_cases p"
            "      WHERE p.id = :primary AND p.tenant_id = :tenant_id"
            "    UNION"
            "    SELECT unnest(d.alert_ids) AS e FROM aisoc_cases d"
            "      WHERE d.tenant_id = :tenant_id AND d.id = ANY(CAST(:ids AS uuid[]))"
            "  ) AS combined"
            "), updated_at = :now "
            "WHERE tenant_id = :tenant_id AND id = :primary"
        ).bindparams(primary=primary_id, tenant_id=tenant_id, ids=ids, now=now)
    )

    await db.execute(
        text(
            "UPDATE aisoc_cases SET merged_into_id = :primary, merged_at = :now, merged_by = :actor, "
            "status = 'closed', closed_at = COALESCE(closed_at, :now), "
            "resolution = COALESCE(NULLIF(resolution, ''), :reason), updated_at = :now "
            "WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))"
        ).bindparams(
            primary=primary_id,
            now=now,
            actor=actor,
            reason=reason or f"merged into {primary_id}",
            tenant_id=tenant_id,
            ids=ids,
        )
    )

    return MergeResult(primary_id=primary_id, merged_ids=list(unique), case_id=primary_id)


# ---------------------------------------------------------------------------
# Bulk triage
# ---------------------------------------------------------------------------


#: One static statement rather than a SET list assembled in Python.
#:
#: The assembled form was correct — every fragment came from a literal in
#: this module and nothing from a caller — and it still read as dynamic SQL
#: to every scanner that looks at it, which is a cost paid forever by every
#: reviewer. `COALESCE(:p, column)` says "leave it alone when the parameter
#: is NULL" in the database instead, and the assignment pair needs a CASE
#: because "set it to NULL" and "do not touch it" are different intentions
#: that COALESCE alone cannot tell apart.
#:
#: Every parameter carries an explicit cast: inside a COALESCE or a CASE a
#: bare parameter has no inferable type and asyncpg refuses the whole
#: statement with `could not determine data type of parameter $n`.
_BULK_TRIAGE_SQL = """
UPDATE alerts SET
    status         = COALESCE(CAST(:status AS text), status),
    severity       = COALESCE(CAST(:severity AS text), severity),
    assigned_to_id = CASE
                       WHEN CAST(:unassign AS boolean) THEN NULL
                       WHEN CAST(:assignee AS uuid) IS NOT NULL THEN CAST(:assignee AS uuid)
                       ELSE assigned_to_id
                     END,
    assigned_at    = CASE
                       WHEN CAST(:unassign AS boolean) THEN NULL
                       WHEN CAST(:assignee AS uuid) IS NOT NULL THEN :now
                       ELSE assigned_at
                     END,
    updated_at     = :now
WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))
"""


@dataclass(frozen=True)
class BulkTriageResult:
    matched_count: int
    updated_count: int
    changes: dict[str, Any]


async def bulk_triage(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_ids: list[uuid.UUID],
    set_status: str | None,
    set_severity: str | None,
    assign_to: uuid.UUID | None,
    unassign: bool,
    max_count: int,
) -> BulkTriageResult:
    """Apply one triage decision to many alerts.

    Two safety properties, taken from ``bulk_close_alerts`` rather than
    reinvented, because a second bulk path with weaker guarantees is how the
    weaker one becomes the one everybody uses:

    * the caller states ``max_count`` and a larger match is **refused** with
      the real count, so the first call is a free dry run;
    * the caller's audit row covers the batch, written by the route.

    ``closed`` is deliberately not reachable here: it has its own route with
    a snapshot table and a named restore target.
    """
    if set_status is None and set_severity is None and assign_to is None and not unassign:
        raise CaseDepthError("Nothing to do: name at least one of status, severity, assign_to or unassign.")
    if set_status is not None and set_status not in BULK_TRIAGE_STATUSES:
        raise CaseDepthError(
            f"status must be one of {sorted(BULK_TRIAGE_STATUSES)}. "
            "Closing in bulk is POST /alerts/bulk-close, which snapshots every row first."
        )
    if set_severity is not None and set_severity not in SEVERITIES:
        raise CaseDepthError(f"severity must be one of {list(SEVERITIES)}")
    if assign_to is not None and unassign:
        raise CaseDepthError("assign_to and unassign contradict each other.")

    unique = list(dict.fromkeys(alert_ids))
    if not unique:
        raise CaseDepthError("No alert ids supplied.")

    matched = (
        await db.execute(
            text("SELECT count(*) AS n FROM alerts WHERE tenant_id = :tenant_id AND id = ANY(CAST(:ids AS uuid[]))").bindparams(
                tenant_id=tenant_id, ids=[str(i) for i in unique]
            )
        )
    ).scalar_one()

    if matched > max_count:
        # Nothing written. The caller raises max_count past the real figure
        # to execute, which makes the first call a dry run they did not have
        # to ask for.
        raise CaseDepthError(
            f"{matched} alert(s) match and max_count is {max_count}. Nothing was changed. "
            f"Re-send with max_count at least {matched} to apply."
        )

    now = datetime.now(UTC)
    changes: dict[str, Any] = {}
    if set_status is not None:
        changes["status"] = set_status
    if set_severity is not None:
        changes["severity"] = set_severity
    if assign_to is not None:
        changes["assigned_to_id"] = str(assign_to)
    if unassign:
        changes["assigned_to_id"] = None

    result = await db.execute(
        text(_BULK_TRIAGE_SQL).bindparams(
            status=set_status,
            severity=set_severity,
            assignee=str(assign_to) if assign_to is not None else None,
            unassign=unassign,
            now=now,
            tenant_id=tenant_id,
            ids=[str(i) for i in unique],
        )
    )
    return BulkTriageResult(matched_count=int(matched), updated_count=int(result.rowcount or 0), changes=changes)


# ---------------------------------------------------------------------------
# Tenant custom fields
# ---------------------------------------------------------------------------


def validate_custom_value(field: dict[str, Any], raw: str) -> str:
    """Canonicalise a value against its definition, or refuse with the reason.

    Canonicalising on write is what makes one TEXT column safe: a reader that
    ignores the definition gets a string rather than a wrong number, and a
    date is always ISO-8601 whatever the analyst typed.
    """
    field_type = field["field_type"]
    value = (raw or "").strip()
    if value == "":
        if field["required"]:
            raise CaseDepthError(f"{field['key']} is required.")
        return ""
    if field_type == "number":
        try:
            float(value)
        except ValueError as exc:
            raise CaseDepthError(f"{field['key']} must be a number, got {value!r}.") from exc
        return value
    if field_type == "boolean":
        lowered = value.lower()
        if lowered in ("true", "1", "yes"):
            return "true"
        if lowered in ("false", "0", "no"):
            return "false"
        raise CaseDepthError(f"{field['key']} must be true or false, got {value!r}.")
    if field_type == "date":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CaseDepthError(f"{field['key']} must be an ISO-8601 date, got {value!r}.") from exc
        return parsed.isoformat()
    if field_type == "select":
        if value not in (field["choices"] or []):
            raise CaseDepthError(f"{field['key']} must be one of {list(field['choices'] or [])}, got {value!r}.")
        return value
    return value


# ---------------------------------------------------------------------------
# Per-analyst workload
# ---------------------------------------------------------------------------

#: One statement, so the open counts and the throughput counts cannot drift
#: apart by being computed in two places over two windows -- which is exactly
#: how `cases_closed_7d` and `mttr_hours` came to disagree about the same
#: rows. `assignee` is the column `aisoc_cases` actually carries for a human;
#: `assigned_to_id` exists beside it and is written by the orchestration
#: path, so both are coalesced into one identity.
_WORKLOAD_SQL = """
WITH scoped AS (
    SELECT
        COALESCE(NULLIF(assignee, ''), assigned_to_id::text) AS analyst,
        status,
        severity,
        created_at,
        closed_at,
        sla_due_at,
        merged_into_id
    FROM aisoc_cases
    WHERE tenant_id = :tenant_id
      AND created_at >= :since
      -- A case absorbed by a merge is not work anybody still has to do, and
      -- counting it would make a merge look like it created throughput.
      AND merged_into_id IS NULL
)
SELECT
    analyst,
    count(*)                                                       AS total,
    count(*) FILTER (WHERE status NOT IN ('closed', 'cancelled'))  AS open_cases,
    count(*) FILTER (WHERE status = 'closed')                      AS closed_cases,
    count(*) FILTER (WHERE status NOT IN ('closed', 'cancelled')
                       AND severity IN ('high', 'critical'))       AS open_high,
    count(*) FILTER (WHERE status NOT IN ('closed', 'cancelled')
                       AND sla_due_at IS NOT NULL
                       AND sla_due_at < :now)                      AS overdue,
    -- The mean travels with the count of rows it averaged, which is the
    -- `closed_cases` column above. NULL when nothing closed; the caller
    -- renders that as "no data", never as 0.0.
    avg(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)
        FILTER (WHERE status = 'closed' AND closed_at IS NOT NULL)  AS mean_hours_to_close
FROM scoped
WHERE analyst IS NOT NULL
GROUP BY analyst
ORDER BY open_cases DESC, analyst
"""

#: Unassigned work is a real queue and the thing a lead looks at first, but
#: it is not an analyst, so it is counted separately rather than appearing as
#: a row named "null".
_UNASSIGNED_SQL = """
SELECT
    count(*) FILTER (WHERE status NOT IN ('closed', 'cancelled')) AS open_cases,
    count(*) FILTER (WHERE status NOT IN ('closed', 'cancelled')
                       AND severity IN ('high', 'critical'))      AS open_high
FROM aisoc_cases
WHERE tenant_id = :tenant_id
  AND created_at >= :since
  AND merged_into_id IS NULL
  AND COALESCE(NULLIF(assignee, ''), assigned_to_id::text) IS NULL
"""


async def analyst_workload(db: AsyncSession, *, tenant_id: uuid.UUID, since: datetime) -> dict[str, Any]:
    """Per-analyst open, closed, overdue and mean-time-to-close, counted now.

    Nothing here reads a stored aggregate. Every number is computed from the
    rows this query selected, and ``mean_hours_to_close`` is ``None`` for an
    analyst who has closed nothing — a zero there reads as "instant", which
    is the opposite of "no data" and is the exact confusion that left two
    console figures wrong for months.
    """
    now = datetime.now(UTC)
    rows = (await db.execute(text(_WORKLOAD_SQL).bindparams(tenant_id=tenant_id, since=since, now=now))).mappings().all()
    unassigned = (await db.execute(text(_UNASSIGNED_SQL).bindparams(tenant_id=tenant_id, since=since))).mappings().one()

    analysts = [
        {
            "analyst": row["analyst"],
            "total": int(row["total"]),
            "open_cases": int(row["open_cases"]),
            "closed_cases": int(row["closed_cases"]),
            "open_high_or_critical": int(row["open_high"]),
            "overdue": int(row["overdue"]),
            "mean_hours_to_close": float(row["mean_hours_to_close"]) if row["mean_hours_to_close"] is not None else None,
            # The denominator travels with the mean. A mean over three cases
            # and a mean over three hundred are different claims.
            "mean_over_cases": int(row["closed_cases"]),
        }
        for row in rows
    ]
    return {
        "since": since.isoformat(),
        "computed_at": now.isoformat(),
        "analysts": analysts,
        "unassigned": {
            "open_cases": int(unassigned["open_cases"] or 0),
            "open_high_or_critical": int(unassigned["open_high"] or 0),
        },
    }
