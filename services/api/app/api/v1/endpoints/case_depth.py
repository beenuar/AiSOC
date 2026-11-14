"""Routes for case depth: merge, bulk triage, custom fields, workload.

Depth plan 9.3 (parity 5.6 remainder).

* ``POST /case-depth/alerts/merge``            fold duplicate alerts into one
* ``POST /case-depth/cases/merge``             fold duplicate cases into one
* ``POST /case-depth/alerts/bulk-triage``      one triage decision, many alerts
* ``GET/POST/PATCH/DELETE /case-depth/custom-fields``  the tenant's case schema
* ``GET/PUT /case-depth/cases/{id}/custom-values``     the values on one case
* ``GET /case-depth/workload``                 per-analyst counts, computed now

Why a prefix of its own rather than hanging these off ``/alerts`` and
``/cases``
---------------------------------------------------------------------
``cases.py`` is 1,400 lines and already owns a six-state machine, SLA
projection and connector fan-out; ``alerts.py`` is larger. Both have a
history of a path parameter swallowing a sibling segment — ``GET /{hunt_id}``
ate ``/runs`` and ``/findings`` because a path parameter compiles to
``[^/]+``. Adding ``/alerts/merge`` beside ``/alerts/{alert_id}`` is exactly
that shape again, and the fix for it last time was a path convertor rather
than a declaration-order convention a later edit can undo. A separate prefix
has no such parameter to collide with.

Authorization is per verb, not per module
-----------------------------------------
Merging and bulk triage are ``alerts:write`` / ``cases:write``. Defining the
tenant's case schema is ``settings:write``, because it changes what every
analyst's form looks like. Reading workload is ``cases:read``: a lead
looking at their team's queue is reading cases.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.services.audit import emit_audit
from app.services.case_depth import (
    BULK_TRIAGE_STATUSES,
    FIELD_TYPES,
    SEVERITIES,
    CaseDepthError,
    analyst_workload,
    bulk_triage,
    merge_alerts,
    merge_cases,
    validate_custom_value,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/case-depth", tags=["case-depth"])


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class MergeRequest(BaseModel):
    primary_id: uuid.UUID
    duplicate_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=500)


class MergeResponse(BaseModel):
    primary_id: str
    merged_ids: list[str]
    case_id: str | None


class BulkTriageRequest(BaseModel):
    alert_ids: list[uuid.UUID] = Field(min_length=1, max_length=5_000)
    set_status: str | None = None
    set_severity: str | None = None
    assign_to: uuid.UUID | None = None
    unassign: bool = False
    #: The caller states what they expect to touch. A larger match is refused
    #: with the real figure and nothing is written, so the first call is a
    #: dry run the caller did not have to ask for. Same contract as
    #: ``POST /alerts/bulk-close``.
    max_count: int = Field(default=100, ge=1, le=5_000)
    comment: str = Field(default="", max_length=500)


class BulkTriageResponse(BaseModel):
    matched_count: int
    updated_count: int
    changes: dict[str, Any]


class CustomFieldIn(BaseModel):
    key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    label: str = Field(min_length=1, max_length=120)
    field_type: str
    help_text: str = Field(default="", max_length=400)
    choices: list[str] = Field(default_factory=list, max_length=50)
    required: bool = False
    position: int = Field(default=0, ge=0, le=999)


class CustomFieldPatch(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    help_text: str | None = Field(default=None, max_length=400)
    choices: list[str] | None = Field(default=None, max_length=50)
    required: bool | None = None
    position: int | None = Field(default=None, ge=0, le=999)
    active: bool | None = None


class CustomFieldOut(BaseModel):
    id: str
    key: str
    label: str
    help_text: str
    field_type: str
    choices: list[str]
    required: bool
    position: int
    active: bool


class CustomValuesIn(BaseModel):
    #: ``{field key: value}``. A key the tenant has not defined is refused
    #: rather than stored: an unvalidated value under an unknown key is the
    #: JSONB-blob failure this schema exists to avoid.
    values: dict[str, str]


class CustomValueOut(BaseModel):
    key: str
    label: str
    field_type: str
    value: str
    required: bool
    updated_by: str
    updated_at: datetime | None


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


@router.post("/alerts/merge", response_model=MergeResponse)
async def merge_alerts_route(
    body: MergeRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("alerts:write"))],
) -> MergeResponse:
    """Fold duplicate alerts into one. Every row survives."""
    actor = current_user.api_key_prefix or current_user.email
    try:
        result = await merge_alerts(
            db,
            tenant_id=current_user.tenant_id,
            primary_id=body.primary_id,
            duplicate_ids=body.duplicate_ids,
            actor=actor,
        )
    except CaseDepthError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="alerts:merge",
        resource="alert",
        resource_id=str(result.primary_id),
        changes={"merged": [str(i) for i in result.merged_ids], "reason": body.reason},
        request=request,
    )
    await db.commit()
    return MergeResponse(
        primary_id=str(result.primary_id),
        merged_ids=[str(i) for i in result.merged_ids],
        case_id=str(result.case_id) if result.case_id else None,
    )


@router.post("/cases/merge", response_model=MergeResponse)
async def merge_cases_route(
    body: MergeRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:write"))],
) -> MergeResponse:
    """Fold duplicate cases into one. Alerts follow; both rows survive."""
    actor = current_user.api_key_prefix or current_user.email
    try:
        result = await merge_cases(
            db,
            tenant_id=current_user.tenant_id,
            primary_id=body.primary_id,
            duplicate_ids=body.duplicate_ids,
            actor=actor,
            reason=body.reason,
        )
    except CaseDepthError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="cases:merge",
        resource="case",
        resource_id=str(result.primary_id),
        changes={"merged": [str(i) for i in result.merged_ids], "reason": body.reason},
        request=request,
    )
    await db.commit()
    return MergeResponse(
        primary_id=str(result.primary_id),
        merged_ids=[str(i) for i in result.merged_ids],
        case_id=str(result.primary_id),
    )


# ---------------------------------------------------------------------------
# Bulk triage
# ---------------------------------------------------------------------------


@router.post("/alerts/bulk-triage", response_model=BulkTriageResponse)
async def bulk_triage_route(
    body: BulkTriageRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("alerts:write"))],
) -> BulkTriageResponse:
    """Apply one triage decision to many alerts, with a preflight count.

    A match larger than ``max_count`` is a **409 carrying the real figure**
    and nothing is written — the same contract ``POST /alerts/bulk-close``
    uses, deliberately, because a second bulk path with weaker guarantees is
    how the weaker one becomes the one everybody reaches for.
    """
    try:
        result = await bulk_triage(
            db,
            tenant_id=current_user.tenant_id,
            alert_ids=body.alert_ids,
            set_status=body.set_status,
            set_severity=body.set_severity,
            assign_to=body.assign_to,
            unassign=body.unassign,
            max_count=body.max_count,
        )
    except CaseDepthError as exc:
        code = status.HTTP_409_CONFLICT if "max_count" in str(exc) else status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(status_code=code, detail=str(exc)) from exc

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="alerts:bulk_triage",
        resource="alert",
        resource_id=f"{result.updated_count} alert(s)",
        changes={"changes": result.changes, "matched": result.matched_count, "comment": body.comment},
        request=request,
    )
    await db.commit()
    return BulkTriageResponse(
        matched_count=result.matched_count,
        updated_count=result.updated_count,
        changes=result.changes,
    )


# ---------------------------------------------------------------------------
# Tenant custom fields
# ---------------------------------------------------------------------------


#: Every column COALESCEd against itself, so an absent field in the PATCH
#: body leaves the column alone without the statement changing shape. Each
#: parameter carries an explicit cast: inside a COALESCE a bare parameter
#: has no inferable type and asyncpg refuses the statement with
#: `could not determine data type of parameter $n`.
_UPDATE_FIELD_SQL = """
UPDATE aisoc_tenant_custom_fields SET
    label      = COALESCE(CAST(:label AS text), label),
    help_text  = COALESCE(CAST(:help_text AS text), help_text),
    required   = COALESCE(CAST(:required AS boolean), required),
    position   = COALESCE(CAST(:position AS integer), position),
    active     = COALESCE(CAST(:active AS boolean), active),
    choices    = COALESCE(CAST(:choices AS text[]), choices),
    updated_at = NOW()
WHERE id = :id AND tenant_id = :tenant_id
RETURNING *
"""


def _field_out(row: Any) -> CustomFieldOut:
    return CustomFieldOut(
        id=str(row["id"]),
        key=row["key"],
        label=row["label"],
        help_text=row["help_text"],
        field_type=row["field_type"],
        choices=list(row["choices"] or []),
        required=row["required"],
        position=row["position"],
        active=row["active"],
    )


@router.get("/custom-fields", response_model=list[CustomFieldOut])
async def list_custom_fields(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:read"))],
    include_inactive: bool = Query(default=False),
) -> list[CustomFieldOut]:
    # A parameter, not a clause spliced into the statement. Both forms were
    # correct and only this one stops reading as dynamic SQL to every
    # scanner and every reviewer that looks at it.
    rows = (
        (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_tenant_custom_fields "
                    "WHERE tenant_id = :tenant_id AND (active OR CAST(:include_inactive AS boolean)) "
                    "ORDER BY position, key"
                ).bindparams(tenant_id=current_user.tenant_id, include_inactive=include_inactive)
            )
        )
        .mappings()
        .all()
    )
    return [_field_out(row) for row in rows]


@router.post("/custom-fields", response_model=CustomFieldOut, status_code=status.HTTP_201_CREATED)
async def create_custom_field(
    body: CustomFieldIn,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> CustomFieldOut:
    if body.field_type not in FIELD_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"field_type must be one of {list(FIELD_TYPES)}",
        )
    if body.field_type == "select" and not body.choices:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="a select field needs at least one choice; an empty dropdown is one a required field makes unsaveable",
        )
    existing = (
        await db.execute(
            text("SELECT id FROM aisoc_tenant_custom_fields WHERE tenant_id = :tenant_id AND key = :key").bindparams(
                tenant_id=current_user.tenant_id, key=body.key
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{body.key} already exists. Keys are immutable by convention: a rename in place "
            "silently changes the meaning of every value already written against it.",
        )

    row = (
        (
            await db.execute(
                text(
                    "INSERT INTO aisoc_tenant_custom_fields "
                    "(tenant_id, key, label, help_text, field_type, choices, required, position) "
                    "VALUES (:tenant_id, :key, :label, :help_text, :field_type, CAST(:choices AS text[]), :required, :position) "
                    "RETURNING *"
                ).bindparams(
                    tenant_id=current_user.tenant_id,
                    key=body.key,
                    label=body.label,
                    help_text=body.help_text,
                    field_type=body.field_type,
                    choices=body.choices,
                    required=body.required,
                    position=body.position,
                )
            )
        )
        .mappings()
        .one()
    )

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="case_custom_field:create",
        resource="case_custom_field",
        resource_id=body.key,
        changes={"field_type": body.field_type, "required": body.required},
        request=request,
    )
    await db.commit()
    return _field_out(row)


@router.patch("/custom-fields/{field_id}", response_model=CustomFieldOut)
async def update_custom_field(
    field_id: uuid.UUID,
    body: CustomFieldPatch,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> CustomFieldOut:
    # One static statement with COALESCE per column, rather than a SET list
    # assembled in Python. The assembled form was correct -- every fragment
    # came from the literal tuple above -- and it still read as dynamic SQL
    # to every scanner and every reviewer, forever.
    row = (
        (
            await db.execute(
                text(_UPDATE_FIELD_SQL).bindparams(
                    id=field_id,
                    tenant_id=current_user.tenant_id,
                    label=body.label,
                    help_text=body.help_text,
                    required=body.required,
                    position=body.position,
                    active=body.active,
                    choices=body.choices,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such custom field")

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="case_custom_field:update",
        resource="case_custom_field",
        resource_id=row["key"],
        changes=body.model_dump(exclude_none=True),
        request=request,
    )
    await db.commit()
    return _field_out(row)


@router.delete("/custom-fields/{field_id}", response_model=CustomFieldOut)
async def retire_custom_field(
    field_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> CustomFieldOut:
    """Retire, never delete: values already written stay readable and attributable."""
    row = (
        (
            await db.execute(
                text(
                    "UPDATE aisoc_tenant_custom_fields SET active = FALSE, updated_at = NOW() "
                    "WHERE id = :id AND tenant_id = :tenant_id RETURNING *"
                ).bindparams(id=field_id, tenant_id=current_user.tenant_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such custom field")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="case_custom_field:retire",
        resource="case_custom_field",
        resource_id=row["key"],
        changes={"active": False},
        request=request,
    )
    await db.commit()
    return _field_out(row)


@router.get("/cases/{case_id}/custom-values", response_model=list[CustomValueOut])
async def get_custom_values(
    case_id: uuid.UUID,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:read"))],
) -> list[CustomValueOut]:
    """Every active field, with this case's value or an empty one.

    Returns the *fields*, not the stored rows, so a field defined after the
    case was created still renders — the alternative is a form that silently
    omits whatever was added last week.
    """
    rows = (
        (
            await db.execute(
                text(
                    "SELECT f.key, f.label, f.field_type, f.required, "
                    "       COALESCE(v.value, '') AS value, "
                    "       COALESCE(v.updated_by, '') AS updated_by, v.updated_at "
                    "FROM aisoc_tenant_custom_fields f "
                    "LEFT JOIN aisoc_case_custom_values v "
                    "  ON v.field_id = f.id AND v.case_id = :case_id AND v.tenant_id = f.tenant_id "
                    "WHERE f.tenant_id = :tenant_id AND f.active "
                    "ORDER BY f.position, f.key"
                ).bindparams(case_id=case_id, tenant_id=current_user.tenant_id)
            )
        )
        .mappings()
        .all()
    )
    return [
        CustomValueOut(
            key=row["key"],
            label=row["label"],
            field_type=row["field_type"],
            value=row["value"],
            required=row["required"],
            updated_by=row["updated_by"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]


@router.put("/cases/{case_id}/custom-values", response_model=list[CustomValueOut])
async def set_custom_values(
    case_id: uuid.UUID,
    body: CustomValuesIn,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:write"))],
) -> list[CustomValueOut]:
    case_exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=case_id, tenant_id=current_user.tenant_id
            )
        )
    ).scalar_one_or_none()
    if case_exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such case")

    fields = {
        row["key"]: row
        for row in (
            await db.execute(
                text("SELECT * FROM aisoc_tenant_custom_fields WHERE tenant_id = :tenant_id AND active").bindparams(
                    tenant_id=current_user.tenant_id
                )
            )
        )
        .mappings()
        .all()
    }
    unknown = sorted(set(body.values) - set(fields))
    if unknown:
        # An unvalidated value under an unknown key is precisely the
        # JSONB-blob failure the two-table schema exists to avoid.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"no such custom field(s): {unknown}. Define them first at POST /case-depth/custom-fields.",
        )

    actor = current_user.api_key_prefix or current_user.email
    try:
        canonical = {key: validate_custom_value(dict(fields[key]), raw) for key, raw in body.values.items()}
    except CaseDepthError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    for key, value in canonical.items():
        await db.execute(
            text(
                "INSERT INTO aisoc_case_custom_values (tenant_id, case_id, field_id, value, updated_by, updated_at) "
                "VALUES (:tenant_id, :case_id, :field_id, :value, :actor, NOW()) "
                "ON CONFLICT (case_id, field_id) DO UPDATE SET "
                "  value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at"
            ).bindparams(
                tenant_id=current_user.tenant_id,
                case_id=case_id,
                field_id=fields[key]["id"],
                value=value,
                actor=actor,
            )
        )

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="case_custom_values:set",
        resource="case",
        resource_id=str(case_id),
        changes={"keys": sorted(canonical)},
        request=request,
    )
    await db.commit()
    return await get_custom_values(case_id, db, current_user, None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Workload
# ---------------------------------------------------------------------------


@router.get("/workload")
async def workload(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:read"))],
    days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    """Per-analyst open, closed, overdue and mean time to close.

    Every number is counted by this request over rows it selected. An analyst
    who has closed nothing gets ``mean_hours_to_close: null`` and the console
    renders that as "no data" — never ``0.0``, which reads as "instant".
    """
    since = datetime.now(UTC) - timedelta(days=days)
    return await analyst_workload(db, tenant_id=current_user.tenant_id, since=since)


#: Exported so a test can assert the route module and the service agree about
#: what a bulk triage may do, rather than each carrying its own list.
ALLOWED_BULK_STATUSES = BULK_TRIAGE_STATUSES
ALLOWED_SEVERITIES = SEVERITIES
