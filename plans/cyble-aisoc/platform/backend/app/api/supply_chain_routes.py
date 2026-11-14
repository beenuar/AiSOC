"""Supply-Chain Risk REST API (t3f-supply-chain).

Analyst-facing surface for the Third-party / Supply-Chain Risk Fusion
Agent (:mod:`app.agents.supply_chain`). Five workflows:

- ``POST /vendors``               — register/update a tenant vendor.
- ``GET  /vendors``               — list active tenant vendors.
- ``GET  /vendors/{slug}``        — vendor card (vendor + recent
  signals + computed rolling score).
- ``DELETE /vendors/{slug}``      — soft-delete (sets ``active=False``;
  audit history survives).
- ``POST /supply-chain/sweep``    — on-demand sweep (the scheduler
  runs every ``supply_chain_scan_interval_seconds``, but during a
  vendor-due-diligence review you want fresh data *now*).

Design echoes the actor / brand / exposure routes:

1. Tenant-scoped via ``require_tenant``. MSSP analysts pivoting into
   a child tenant see only that child's vendor catalogue.
2. Routes delegate to the agent for sweeps; the API never reimplements
   collect / score / case-open logic.
3. Read endpoints are pure SQL — no tool calls, no graph traversal —
   so dashboards can poll on a tight refresh cadence.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlmodel import select

from app.agents.supply_chain import SupplyChainAgent
from app.config import settings
from app.db import session_scope
from app.models.supply_chain import (
    SignalKind,
    Vendor,
    VendorCategory,
    VendorCriticality,
    VendorRiskSignal,
)
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(tags=["supply_chain"])


# ──────────────────────────────────────────────────────────────────────
# Request / response shapes
# ──────────────────────────────────────────────────────────────────────


class VendorUpsert(BaseModel):
    """Request body for ``POST /vendors``."""

    slug: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    category: VendorCategory = VendorCategory.SAAS
    criticality: VendorCriticality = VendorCriticality.MEDIUM
    description: str = ""
    monitored_terms: list[str] = Field(default_factory=list)
    monitored_domains: list[str] = Field(default_factory=list)
    monitored_cves: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    contact_email: str | None = None
    active: bool = True

    @field_validator("slug")
    @classmethod
    def _normalise_slug(cls, v: str) -> str:
        out = v.strip().lower()
        if not out:
            raise ValueError("slug must be non-empty")
        if any(c.isspace() for c in out):
            raise ValueError("slug must not contain whitespace")
        return out


class VendorResponse(BaseModel):
    """Compact vendor row returned by the list / upsert endpoints."""

    id: int
    tenant_id: str
    slug: str
    name: str
    category: str
    criticality: str
    description: str
    monitored_terms: list[str]
    monitored_domains: list[str]
    monitored_cves: list[str]
    affected_assets: list[str]
    affected_users: list[str]
    contact_email: str | None
    active: bool
    created_at: str | None
    updated_at: str | None


class VendorListResponse(BaseModel):
    tenant_id: str
    vendors: list[VendorResponse]
    total: int


class VendorSignalResponse(BaseModel):
    """Row from ``VendorRiskSignal`` for the vendor-card timeline."""

    id: int
    kind: str
    source: str
    score: int
    summary: str
    evidence: dict[str, Any]
    observed_at: str | None
    case_id: int | None


class VendorCardResponse(BaseModel):
    """``GET /vendors/{slug}`` payload."""

    vendor: VendorResponse
    rolling_score: int
    """Sum of recent signal scores within the rolling window."""
    rolling_window_days: int
    case_open_threshold: int
    recent_signals: list[VendorSignalResponse]


class SupplyChainSweepResponse(BaseModel):
    tenant_id: str
    vendors_scanned: int
    signals_recorded: int
    cases_opened: list[int]
    graph_nodes_upserted: int
    graph_edges_upserted: int
    errors: list[str]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _row_to_response(row: Vendor) -> VendorResponse:
    return VendorResponse(
        id=int(row.id) if row.id is not None else 0,
        tenant_id=row.tenant_id,
        slug=row.slug,
        name=row.name,
        category=row.category.value,
        criticality=row.criticality.value,
        description=row.description or "",
        monitored_terms=list(row.monitored_terms or []),
        monitored_domains=list(row.monitored_domains or []),
        monitored_cves=list(row.monitored_cves or []),
        affected_assets=list(row.affected_assets or []),
        affected_users=list(row.affected_users or []),
        contact_email=row.contact_email,
        active=row.active,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _signal_to_response(row: VendorRiskSignal) -> VendorSignalResponse:
    return VendorSignalResponse(
        id=int(row.id) if row.id is not None else 0,
        kind=row.kind.value,
        source=row.source,
        score=row.score,
        summary=row.summary or "",
        evidence=dict(row.evidence or {}),
        observed_at=row.observed_at.isoformat() if row.observed_at else None,
        case_id=row.case_id,
    )


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────


@router.post("/vendors", status_code=201, response_model=VendorResponse)
def upsert_vendor(
    payload: VendorUpsert,
    ctx: TenantContext = Depends(require_tenant),
) -> VendorResponse:
    """Idempotent on ``(tenant_id, slug)``: same slug overwrites in place.

    Returns 201 (Created) even on update so the analyst UI can use a
    single code path; the resource id is stable across upserts.
    """
    tenant_id = ctx.active_tenant_id
    now = datetime.now(timezone.utc)

    snapshot: VendorResponse | None = None
    with session_scope() as session:
        existing = session.exec(
            select(Vendor)
            .where(Vendor.tenant_id == tenant_id)
            .where(Vendor.slug == payload.slug)
        ).first()
        if existing is None:
            row = Vendor(
                tenant_id=tenant_id,
                slug=payload.slug,
                name=payload.name,
                category=payload.category,
                criticality=payload.criticality,
                description=payload.description,
                monitored_terms=list(payload.monitored_terms),
                monitored_domains=list(payload.monitored_domains),
                monitored_cves=list(payload.monitored_cves),
                affected_assets=list(payload.affected_assets),
                affected_users=list(payload.affected_users),
                contact_email=payload.contact_email,
                active=payload.active,
                created_at=now,
                updated_at=now,
            )
        else:
            row = existing
            row.name = payload.name
            row.category = payload.category
            row.criticality = payload.criticality
            row.description = payload.description
            row.monitored_terms = list(payload.monitored_terms)
            row.monitored_domains = list(payload.monitored_domains)
            row.monitored_cves = list(payload.monitored_cves)
            row.affected_assets = list(payload.affected_assets)
            row.affected_users = list(payload.affected_users)
            row.contact_email = payload.contact_email
            row.active = payload.active
            row.updated_at = now
        session.add(row)
        session.commit()
        session.refresh(row)
        snapshot = _row_to_response(row)

    assert snapshot is not None  # appeases mypy; session.commit() always returns
    return snapshot


@router.get("/vendors", response_model=VendorListResponse)
def list_vendors(
    ctx: TenantContext = Depends(require_tenant),
    active_only: bool = Query(default=True),
    category: VendorCategory | None = Query(default=None),
    criticality: VendorCriticality | None = Query(default=None),
) -> VendorListResponse:
    """List vendors for the active tenant.

    Filters are AND-combined. Default is ``active_only=true`` because
    the analyst dashboard rarely cares about archived vendors.
    """
    tenant_id = ctx.active_tenant_id

    vendors: list[VendorResponse] = []
    with session_scope() as session:
        stmt = select(Vendor).where(Vendor.tenant_id == tenant_id)
        if active_only:
            stmt = stmt.where(Vendor.active == True)  # noqa: E712
        if category is not None:
            stmt = stmt.where(Vendor.category == category)
        if criticality is not None:
            stmt = stmt.where(Vendor.criticality == criticality)
        stmt = stmt.order_by(
            Vendor.criticality.desc(), Vendor.name.asc()
        )
        for row in session.exec(stmt).all():
            vendors.append(_row_to_response(row))

    return VendorListResponse(
        tenant_id=tenant_id, vendors=vendors, total=len(vendors)
    )


@router.get("/vendors/{slug}", response_model=VendorCardResponse)
def get_vendor_card(
    slug: str,
    ctx: TenantContext = Depends(require_tenant),
    signal_limit: int = Query(default=50, ge=1, le=500),
) -> VendorCardResponse:
    """Vendor card: the row plus the rolling-window risk timeline."""
    tenant_id = ctx.active_tenant_id
    slug_clean = slug.strip().lower()

    cutoff = datetime.now(timezone.utc) - timedelta(
        days=settings.supply_chain_rolling_window_days
    )

    vendor_resp: VendorResponse | None = None
    signals: list[VendorSignalResponse] = []
    rolling_score = 0
    with session_scope() as session:
        row = session.exec(
            select(Vendor)
            .where(Vendor.tenant_id == tenant_id)
            .where(Vendor.slug == slug_clean)
        ).first()
        if row is None:
            raise HTTPException(
                status_code=404, detail=f"Unknown vendor: {slug_clean}"
            )
        vendor_resp = _row_to_response(row)

        sig_rows = session.exec(
            select(VendorRiskSignal)
            .where(VendorRiskSignal.tenant_id == tenant_id)
            .where(VendorRiskSignal.vendor_id == row.id)
            .where(VendorRiskSignal.observed_at >= cutoff)
            .order_by(VendorRiskSignal.observed_at.desc())
            .limit(signal_limit)
        ).all()
        signals = [_signal_to_response(r) for r in sig_rows]
        # Rolling score is the sum across the *full* window — not just
        # the limit-truncated slice — so analysts see the same number
        # the agent uses for the case-open gate.
        sum_rows = session.exec(
            select(VendorRiskSignal)
            .where(VendorRiskSignal.tenant_id == tenant_id)
            .where(VendorRiskSignal.vendor_id == row.id)
            .where(VendorRiskSignal.observed_at >= cutoff)
        ).all()
        rolling_score = sum(int(r.score) for r in sum_rows)

    assert vendor_resp is not None
    return VendorCardResponse(
        vendor=vendor_resp,
        rolling_score=rolling_score,
        rolling_window_days=settings.supply_chain_rolling_window_days,
        case_open_threshold=settings.supply_chain_case_open_threshold,
        recent_signals=signals,
    )


@router.delete("/vendors/{slug}", status_code=204)
def archive_vendor(
    slug: str,
    ctx: TenantContext = Depends(require_tenant),
) -> None:
    """Soft-delete: flips ``active`` to False so audit history survives."""
    tenant_id = ctx.active_tenant_id
    slug_clean = slug.strip().lower()

    with session_scope() as session:
        row = session.exec(
            select(Vendor)
            .where(Vendor.tenant_id == tenant_id)
            .where(Vendor.slug == slug_clean)
        ).first()
        if row is None:
            raise HTTPException(
                status_code=404, detail=f"Unknown vendor: {slug_clean}"
            )
        if row.active:
            row.active = False
            row.updated_at = datetime.now(timezone.utc)
            session.add(row)
            session.commit()


@router.post("/supply-chain/sweep", response_model=SupplyChainSweepResponse)
async def trigger_supply_chain_sweep(
    ctx: TenantContext = Depends(require_tenant),
) -> SupplyChainSweepResponse:
    """Run one on-demand sweep for the caller's active tenant."""
    tenant_id = ctx.active_tenant_id
    try:
        with session_scope() as session:
            agent = SupplyChainAgent(session=session, tenant_id=tenant_id)
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.supply_chain_sweep_timeout_seconds,
            )
    except asyncio.TimeoutError as exc:
        logger.warning(
            "supply_chain_routes: on-demand sweep tenant=%s exceeded %ds",
            tenant_id,
            settings.supply_chain_sweep_timeout_seconds,
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"Supply-chain sweep exceeded "
                f"{settings.supply_chain_sweep_timeout_seconds}s; increase "
                "supply_chain_sweep_timeout_seconds or wait for the "
                "scheduled run."
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "supply_chain_routes: on-demand sweep tenant=%s failed", tenant_id
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return SupplyChainSweepResponse(
        tenant_id=result.tenant_id,
        vendors_scanned=result.vendors_scanned,
        signals_recorded=result.signals_recorded,
        cases_opened=list(result.cases_opened),
        graph_nodes_upserted=result.graph_nodes_upserted,
        graph_edges_upserted=result.graph_edges_upserted,
        errors=list(result.errors),
    )


__all__ = ["router"]
