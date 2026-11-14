"""Vertical detection pack REST API (t3d-api).

Surfaces the vertical-pack registry and per-tenant calibration store as
HTTP endpoints. Three concerns share this router because they are
naturally read by the same caller (an admin tuning detections for one
tenant):

1. **Catalog** — what packs exist? Platform-wide rows in
   :class:`VerticalPack`. Authenticated but not tenant-scoped data;
   we still require a tenant context so an unauthenticated client
   cannot enumerate our content offering.

2. **Assignments** — which packs has *this* tenant turned on? Backed
   by :class:`TenantPackAssignment`. Mutations idempotent on
   ``(tenant_id, pack)``.

3. **Calibrations** — per-rule overrides for *this* tenant. Backed by
   :class:`PackRuleCalibration`. Mutations idempotent on
   ``(tenant_id, rule_id)``.

All mutations delegate to :mod:`app.detections.calibration`, which is
the only place allowed to write these tables. That keeps the
registry cache invalidation paired with every write — bypassing the
service layer would leave stale tenant engines around until process
restart.

Design notes:

- We accept either pack ``slug`` or numeric ``id`` in URL paths so
  the API stays usable from CLI tooling that only knows slugs and
  from UIs that hold the id from a previous list call.

- ``GET /detections/packs/effective`` exists so analysts can verify
  what rules their tenant will actually run *after* assignments
  and calibration compose. Without it, the only way to inspect the
  composed pack is to look at hits — too noisy for tuning.

- We deliberately do NOT expose a "reload registry" endpoint. Pack
  reconciliation runs once per process; reloading on demand would
  invalidate every tenant engine and is an operator-level (not
  per-tenant) action. Provide it via a CLI / admin route instead.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.detections import calibration as calibration_service
from app.detections import registry as registry_service
from app.detections import runtime as runtime_service
from app.models.detection_packs import (
    PackRuleCalibration,
    TenantPackAssignment,
    VerticalPack,
)
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detections/packs", tags=["detections-packs"])


# ──────────────────────────────────────────────────────────────────────
# Response shapes
# ──────────────────────────────────────────────────────────────────────


class VerticalPackOut(BaseModel):
    """Catalog row over the wire."""

    id: int
    slug: str
    name: str
    description: str
    version: str
    industry_tags: list[str]
    active: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class VerticalPackListResponse(BaseModel):
    packs: list[VerticalPackOut]


class RulePreview(BaseModel):
    """Minimal rule descriptor for introspection.

    We deliberately omit the rule body — the full Sigma YAML is part
    of the on-disk content distribution, not something a tuning UI
    needs to see inline.
    """

    id: str
    title: str
    severity: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)


class VerticalPackDetail(VerticalPackOut):
    """Catalog row + the rules it contributes."""

    path: str
    rule_count: int
    rules: list[RulePreview]


class AssignmentOut(BaseModel):
    id: int
    tenant_id: str
    vertical_pack_id: int
    pack_slug: Optional[str] = None
    enabled: bool
    assigned_by: str
    notes: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AssignmentsResponse(BaseModel):
    tenant_id: str
    assignments: list[AssignmentOut]


class CalibrationOut(BaseModel):
    id: int
    tenant_id: str
    vertical_pack_id: int
    pack_slug: Optional[str] = None
    rule_id: str
    enabled: bool
    severity_override: Optional[str] = None
    baseline: dict[str, Any]
    notes: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CalibrationsResponse(BaseModel):
    tenant_id: str
    calibrations: list[CalibrationOut]


class EffectiveEngineResponse(BaseModel):
    """The composed tenant-effective rule pack.

    Returned by ``GET /detections/packs/effective``; lets analysts
    confirm which rules their tenant currently runs.
    """

    tenant_id: str
    rule_count: int
    rules: list[RulePreview]


# ──────────────────────────────────────────────────────────────────────
# Request bodies
# ──────────────────────────────────────────────────────────────────────


class AssignmentCreate(BaseModel):
    """Body for ``POST /detections/packs/assignments``."""

    pack: str = Field(
        ...,
        description="Pack slug or numeric id as a string (e.g. 'finserv').",
    )
    enabled: bool = True
    notes: str = ""


class CalibrationUpsert(BaseModel):
    """Body for ``PUT /detections/packs/calibrations/{rule_id}``."""

    pack: str = Field(
        ...,
        description="Pack slug or numeric id that owns this rule.",
    )
    enabled: bool = True
    severity_override: Optional[str] = Field(
        default=None,
        description="One of: low, medium, high, critical. None reverts to pack default.",
    )
    baseline: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────


def _coerce_pack_id(raw: str) -> str | int:
    """Accept ``'42'`` as int, anything else as slug.

    The service layer accepts ``str | int``; numeric strings come in
    from URL paths as ``str`` so we normalize here.
    """
    s = (raw or "").strip()
    if s.isdigit():
        return int(s)
    return s


def _vertical_pack_out(row: VerticalPack) -> VerticalPackOut:
    return VerticalPackOut(
        id=row.id,  # type: ignore[arg-type]
        slug=row.slug,
        name=row.name,
        description=row.description,
        version=row.version,
        industry_tags=list(row.industry_tags or []),
        active=row.active,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _rule_preview(rule: Any) -> RulePreview:
    sev = rule.severity
    sev_str = sev.value if hasattr(sev, "value") else str(sev)
    return RulePreview(
        id=rule.id,
        title=rule.title,
        severity=sev_str,
        description=getattr(rule, "description", "") or "",
        tags=list(getattr(rule, "tags", ()) or ()),
    )


def _assignment_out(
    row: TenantPackAssignment, *, slug_by_id: dict[int, str]
) -> AssignmentOut:
    return AssignmentOut(
        id=row.id,  # type: ignore[arg-type]
        tenant_id=row.tenant_id,
        vertical_pack_id=row.vertical_pack_id,
        pack_slug=slug_by_id.get(row.vertical_pack_id),
        enabled=row.enabled,
        assigned_by=row.assigned_by,
        notes=row.notes,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _calibration_out(
    row: PackRuleCalibration, *, slug_by_id: dict[int, str]
) -> CalibrationOut:
    return CalibrationOut(
        id=row.id,  # type: ignore[arg-type]
        tenant_id=row.tenant_id,
        vertical_pack_id=row.vertical_pack_id,
        pack_slug=slug_by_id.get(row.vertical_pack_id),
        rule_id=row.rule_id,
        enabled=row.enabled,
        severity_override=row.severity_override,
        baseline=dict(row.baseline or {}),
        notes=row.notes,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _build_slug_index() -> dict[int, str]:
    """Cheap one-shot index from pack id → slug for join-on-the-way-out.

    We fetch this once per request rather than per-row to avoid N+1
    work. The catalog is small (handful of packs); a full list is
    cheaper than caching invalidation logic.
    """
    return {
        p.id: p.slug
        for p in registry_service.list_vertical_packs()
        if p.id is not None
    }


# ──────────────────────────────────────────────────────────────────────
# Catalog (read-only, platform-wide)
# ──────────────────────────────────────────────────────────────────────


@router.get("", response_model=VerticalPackListResponse)
def list_packs(
    include_inactive: bool = False,
    _: TenantContext = Depends(require_tenant),
) -> VerticalPackListResponse:
    """List every vertical pack the platform knows about.

    Defaults to active packs only; pass ``?include_inactive=true``
    to see deprecated ones too (useful when reviewing why an
    assignment stopped contributing rules).
    """
    rows = registry_service.list_vertical_packs()
    if not include_inactive:
        rows = [r for r in rows if r.active]
    return VerticalPackListResponse(packs=[_vertical_pack_out(r) for r in rows])


# NOTE: The catalog detail endpoint ``GET /{pack}`` lives at the bottom
# of this module. FastAPI matches routes in declaration order, and a
# bare ``/{pack}`` would otherwise swallow ``/assignments``,
# ``/calibrations``, and ``/effective``. Keep specific paths above it.


# ──────────────────────────────────────────────────────────────────────
# Assignments (per-tenant CRUD)
# ──────────────────────────────────────────────────────────────────────


@router.get("/assignments", response_model=AssignmentsResponse)
def list_assignments(
    ctx: TenantContext = Depends(require_tenant),
) -> AssignmentsResponse:
    tenant_id = ctx.active_tenant_id
    slug_by_id = _build_slug_index()
    rows = calibration_service.list_assignments(tenant_id=tenant_id)
    return AssignmentsResponse(
        tenant_id=tenant_id,
        assignments=[
            _assignment_out(r, slug_by_id=slug_by_id)
            for r in rows
            if r.id is not None
        ],
    )


@router.post(
    "/assignments",
    response_model=AssignmentOut,
    status_code=201,
)
def upsert_assignment(
    payload: AssignmentCreate,
    ctx: TenantContext = Depends(require_tenant),
) -> AssignmentOut:
    """Assign a pack to the active tenant (or update an existing assignment).

    Idempotent on ``(tenant_id, pack)``. Reposting the same body is
    safe — it bumps ``updated_at`` and re-invalidates the tenant's
    cached engine.
    """
    tenant_id = ctx.active_tenant_id
    coerced = _coerce_pack_id(payload.pack)
    try:
        row = calibration_service.assign_pack(
            tenant_id=tenant_id,
            pack=coerced,
            enabled=payload.enabled,
            assigned_by=ctx.subject,
            notes=payload.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    slug_by_id = _build_slug_index()
    return _assignment_out(row, slug_by_id=slug_by_id)


@router.delete("/assignments/{pack}", status_code=204)
def delete_assignment(
    pack: str,
    ctx: TenantContext = Depends(require_tenant),
) -> Response:
    """Hard-delete a tenant's assignment to a pack.

    Returns 204 even if no row existed — the desired end state
    (no assignment) is reached either way. Audit trail lives in the
    activity log, not in this row.
    """
    tenant_id = ctx.active_tenant_id
    coerced = _coerce_pack_id(pack)
    try:
        calibration_service.unassign_pack(tenant_id=tenant_id, pack=coerced)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


# ──────────────────────────────────────────────────────────────────────
# Calibrations (per-tenant CRUD)
# ──────────────────────────────────────────────────────────────────────


@router.get("/calibrations", response_model=CalibrationsResponse)
def list_calibrations(
    pack: Optional[str] = None,
    ctx: TenantContext = Depends(require_tenant),
) -> CalibrationsResponse:
    """List a tenant's calibrations.

    Optional ``?pack=<slug|id>`` filters to one pack.
    """
    tenant_id = ctx.active_tenant_id
    coerced = _coerce_pack_id(pack) if pack else None
    try:
        rows = calibration_service.list_calibrations(tenant_id, pack=coerced)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    slug_by_id = _build_slug_index()
    return CalibrationsResponse(
        tenant_id=tenant_id,
        calibrations=[
            _calibration_out(r, slug_by_id=slug_by_id)
            for r in rows
            if r.id is not None
        ],
    )


@router.get(
    "/calibrations/{rule_id}",
    response_model=CalibrationOut,
)
def get_calibration(
    rule_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> CalibrationOut:
    """Single calibration row, or 404 if no override exists for this rule.

    A 404 here means "use pack defaults" — it is not an error
    condition for the calling UI, just a signal to render the
    "no override set" state.
    """
    tenant_id = ctx.active_tenant_id
    row = calibration_service.get_calibration(tenant_id=tenant_id, rule_id=rule_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"no calibration for rule {rule_id!r}",
        )
    slug_by_id = _build_slug_index()
    return _calibration_out(row, slug_by_id=slug_by_id)


@router.put(
    "/calibrations/{rule_id}",
    response_model=CalibrationOut,
)
def upsert_calibration(
    rule_id: str,
    payload: CalibrationUpsert,
    ctx: TenantContext = Depends(require_tenant),
) -> CalibrationOut:
    """Set or update the calibration for one rule for the active tenant.

    Idempotent on ``(tenant_id, rule_id)``. The rule itself does not
    have to exist in the currently-composed pack — we accept the
    write so that an admin can pre-stage calibration before turning
    on the parent pack.
    """
    tenant_id = ctx.active_tenant_id
    coerced = _coerce_pack_id(payload.pack)
    try:
        row = calibration_service.set_calibration(
            tenant_id=tenant_id,
            pack=coerced,
            rule_id=rule_id,
            enabled=payload.enabled,
            severity_override=payload.severity_override,
            baseline=payload.baseline,
            notes=payload.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    slug_by_id = _build_slug_index()
    return _calibration_out(row, slug_by_id=slug_by_id)


@router.delete("/calibrations/{rule_id}", status_code=204)
def delete_calibration(
    rule_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> Response:
    """Drop a tenant's override for one rule — reverts to pack defaults.

    Returns 204 regardless of whether a row existed; the desired end
    state (no override) is reached either way.
    """
    tenant_id = ctx.active_tenant_id
    calibration_service.delete_calibration(tenant_id=tenant_id, rule_id=rule_id)
    return Response(status_code=204)


# ──────────────────────────────────────────────────────────────────────
# Effective engine introspection
# ──────────────────────────────────────────────────────────────────────


@router.get("/effective", response_model=EffectiveEngineResponse)
def get_effective_engine(
    ctx: TenantContext = Depends(require_tenant),
) -> EffectiveEngineResponse:
    """Return the composed, calibrated rule list this tenant actually runs.

    Materializes through :func:`registry.get_tenant_engine`, the same
    cache path the detection pipeline uses. If this endpoint and
    detection disagree, the tenant cache is stale — call any
    mutation through this API and the cache will be invalidated.
    """
    tenant_id = ctx.active_tenant_id
    engine = runtime_service.get_engine_for_tenant(tenant_id)
    rules = [_rule_preview(r) for r in engine.pack]
    return EffectiveEngineResponse(
        tenant_id=tenant_id,
        rule_count=len(rules),
        rules=rules,
    )


# ──────────────────────────────────────────────────────────────────────
# Catalog detail (declared LAST so it does not shadow literal routes)
# ──────────────────────────────────────────────────────────────────────


@router.get("/{pack}", response_model=VerticalPackDetail)
def get_pack(
    pack: str,
    _: TenantContext = Depends(require_tenant),
) -> VerticalPackDetail:
    """Catalog row + the rules contributed by this pack.

    ``pack`` is slug or numeric id. The rule list reflects what was
    loaded from disk at startup, not the tenant-effective view —
    use ``/detections/packs/effective`` for that.
    """
    rows = registry_service.list_vertical_packs()
    coerced = _coerce_pack_id(pack)
    catalog_row = next(
        (
            r
            for r in rows
            if (isinstance(coerced, int) and r.id == coerced)
            or (isinstance(coerced, str) and r.slug == coerced)
        ),
        None,
    )
    if catalog_row is None:
        raise HTTPException(status_code=404, detail=f"pack {pack!r} not found")

    rule_pack = registry_service.get_vertical_pack(catalog_row.slug)
    rules = [_rule_preview(r) for r in rule_pack] if rule_pack is not None else []
    base = _vertical_pack_out(catalog_row).model_dump()
    return VerticalPackDetail(
        **base,
        path=catalog_row.path,
        rule_count=len(rules),
        rules=rules,
    )


__all__ = ["router"]
