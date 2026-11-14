"""Brand Responder REST API (t3c-brand-takedown).

Analyst-facing surface for the proactive Brand & typosquat takedown
loop implemented in :mod:`app.brand_responder`.

Endpoints (all tenant-scoped via :func:`require_tenant`):

- ``POST /brand/assets``           — register a protected brand surface
- ``GET  /brand/assets``           — list registered brand assets
- ``POST /brand/sweep``            — trigger one bounded sweep on demand
- ``GET  /brand/candidates``       — list discovered typosquat candidates
- ``POST /brand/candidates/{id}/dismiss`` — mark a candidate as false positive
- ``GET  /brand/takedowns``        — list takedown requests + status

Design rules:

1. Sweeps delegate wholly to :meth:`BrandResponderAgent.sweep` — there
   must be exactly one code path (scheduled or manual) that drives the
   pipeline.

2. Asset registration is an explicit POST: we do **not** auto-create
   brand assets from CTI hits. The brand surface is a policy decision
   the operator owns.

3. Dismissals are append-only on status; we never delete candidate
   rows because they are part of the audit trail (someone has to be
   able to explain why a takedown was or wasn't filed).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import select

from app.brand_responder import BrandResponderAgent
from app.config import settings
from app.db import session_scope
from app.models.brand import (
    BrandAsset,
    CandidateStatus,
    TakedownRequest,
    TyposquatCandidate,
)
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/brand", tags=["brand"])


# ──────────────────────────────────────────────────────────────────────
# Request / response shapes
# ──────────────────────────────────────────────────────────────────────


class BrandAssetCreate(BaseModel):
    name: str = Field(..., min_length=1)
    root_domain: str = Field(..., min_length=3)
    aliases: list[str] = Field(default_factory=list)
    monitored_terms: list[str] = Field(default_factory=list)
    active: bool = True


class BrandAssetOut(BaseModel):
    id: int
    tenant_id: str
    name: str
    root_domain: str
    aliases: list[str]
    monitored_terms: list[str]
    active: bool
    created_at: str | None = None


class BrandAssetsResponse(BaseModel):
    tenant_id: str
    assets: list[BrandAssetOut]


class SweepResponse(BaseModel):
    """Mirror of :class:`BrandSweepReport` over the wire."""

    tenant_id: str
    candidates_considered: int
    candidates_recorded: int
    candidates_auto_filed: int
    candidates_parked: int
    takedowns_submitted: int
    takedowns_acknowledged: int
    takedowns_failed: int
    cases_opened: list[int]
    errors: list[str]


class CandidateOut(BaseModel):
    id: int
    tenant_id: str
    brand_asset_id: int
    candidate_domain: str
    score: int
    severity: str
    reasons: list[str]
    enrichment: dict[str, Any]
    status: str
    first_seen: str | None = None
    last_seen: str | None = None


class CandidatesResponse(BaseModel):
    tenant_id: str
    candidates: list[CandidateOut]


class TakedownOut(BaseModel):
    id: int
    tenant_id: str
    candidate_id: int
    channel: str
    status: str
    recipient: str
    provider_ticket: str | None
    status_history: list[dict[str, Any]]
    submitted_by: str
    created_at: str | None = None
    updated_at: str | None = None


class TakedownsResponse(BaseModel):
    tenant_id: str
    takedowns: list[TakedownOut]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _asset_out(row: BrandAsset) -> BrandAssetOut:
    return BrandAssetOut(
        id=row.id,  # type: ignore[arg-type]
        tenant_id=row.tenant_id,
        name=row.name,
        root_domain=row.root_domain,
        aliases=list(row.aliases or []),
        monitored_terms=list(row.monitored_terms or []),
        active=row.active,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


def _candidate_out(row: TyposquatCandidate) -> CandidateOut:
    return CandidateOut(
        id=row.id,  # type: ignore[arg-type]
        tenant_id=row.tenant_id,
        brand_asset_id=row.brand_asset_id,
        candidate_domain=row.candidate_domain,
        score=row.score,
        severity=row.severity,
        reasons=list(row.reasons or []),
        enrichment=dict(row.enrichment or {}),
        status=row.status.value if hasattr(row.status, "value") else str(row.status),
        first_seen=row.first_seen.isoformat() if row.first_seen else None,
        last_seen=row.last_seen.isoformat() if row.last_seen else None,
    )


def _takedown_out(row: TakedownRequest) -> TakedownOut:
    return TakedownOut(
        id=row.id,  # type: ignore[arg-type]
        tenant_id=row.tenant_id,
        candidate_id=row.candidate_id,
        channel=row.channel.value if hasattr(row.channel, "value") else str(row.channel),
        status=row.status.value if hasattr(row.status, "value") else str(row.status),
        recipient=row.recipient,
        provider_ticket=row.provider_ticket,
        status_history=list(row.status_history or []),
        submitted_by=row.submitted_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


# ──────────────────────────────────────────────────────────────────────
# Brand asset registration
# ──────────────────────────────────────────────────────────────────────


@router.post("/assets", response_model=BrandAssetOut, status_code=201)
def register_brand_asset(
    payload: BrandAssetCreate,
    ctx: TenantContext = Depends(require_tenant),
) -> BrandAssetOut:
    """Register a brand surface for the active tenant.

    Idempotent on ``(tenant_id, root_domain)``: re-posting the same
    root domain refreshes the human-facing name, aliases, monitored
    terms, and active flag instead of creating a duplicate.
    """
    tenant_id = ctx.active_tenant_id
    root = payload.root_domain.strip().lower()
    if not root:
        raise HTTPException(status_code=400, detail="root_domain required")

    with session_scope() as session:
        existing = session.exec(
            select(BrandAsset)
            .where(BrandAsset.tenant_id == tenant_id)
            .where(BrandAsset.root_domain == root)
        ).first()
        if existing is not None:
            existing.name = payload.name
            existing.aliases = list(payload.aliases or [])
            existing.monitored_terms = list(payload.monitored_terms or [])
            existing.active = payload.active
            row = existing
        else:
            row = BrandAsset(
                tenant_id=tenant_id,
                name=payload.name,
                root_domain=root,
                aliases=list(payload.aliases or []),
                monitored_terms=list(payload.monitored_terms or []),
                active=payload.active,
            )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _asset_out(row)


@router.get("/assets", response_model=BrandAssetsResponse)
def list_brand_assets(
    include_inactive: bool = False,
    ctx: TenantContext = Depends(require_tenant),
) -> BrandAssetsResponse:
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        stmt = select(BrandAsset).where(BrandAsset.tenant_id == tenant_id)
        if not include_inactive:
            stmt = stmt.where(BrandAsset.active == True)  # noqa: E712
        rows = session.exec(stmt.order_by(BrandAsset.created_at.desc())).all()
        return BrandAssetsResponse(
            tenant_id=tenant_id,
            assets=[_asset_out(r) for r in rows if r.id is not None],
        )


# ──────────────────────────────────────────────────────────────────────
# On-demand sweep
# ──────────────────────────────────────────────────────────────────────


@router.post("/sweep", response_model=SweepResponse)
async def trigger_sweep(
    ctx: TenantContext = Depends(require_tenant),
) -> SweepResponse:
    """Run one on-demand Brand Responder sweep for the active tenant.

    Subject to the same per-sweep timeout the scheduler uses
    (``settings.brand_sweep_timeout_seconds``).
    """
    tenant_id = ctx.active_tenant_id
    try:
        with session_scope() as session:
            agent = BrandResponderAgent(session=session, tenant_id=tenant_id)
            report = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.brand_sweep_timeout_seconds,
            )
    except asyncio.TimeoutError as exc:
        logger.warning(
            "brand_routes: on-demand sweep tenant=%s exceeded %ds",
            tenant_id,
            settings.brand_sweep_timeout_seconds,
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"Brand sweep exceeded "
                f"{settings.brand_sweep_timeout_seconds}s; "
                "increase brand_sweep_timeout_seconds or wait for the "
                "scheduled run."
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001 — surface to caller
        logger.exception(
            "brand_routes: on-demand sweep tenant=%s failed", tenant_id
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return SweepResponse(
        tenant_id=report.tenant_id,
        candidates_considered=report.candidates_considered,
        candidates_recorded=report.candidates_recorded,
        candidates_auto_filed=report.candidates_auto_filed,
        candidates_parked=report.candidates_parked,
        takedowns_submitted=report.takedowns_submitted,
        takedowns_acknowledged=report.takedowns_acknowledged,
        takedowns_failed=report.takedowns_failed,
        cases_opened=list(report.cases_opened),
        errors=list(report.errors),
    )


# ──────────────────────────────────────────────────────────────────────
# Candidate triage surface
# ──────────────────────────────────────────────────────────────────────


@router.get("/candidates", response_model=CandidatesResponse)
def list_candidates(
    status: str | None = None,
    min_score: int | None = None,
    ctx: TenantContext = Depends(require_tenant),
) -> CandidatesResponse:
    """List discovered typosquat candidates.

    Optional filters:
    - ``status``  — one of :class:`CandidateStatus` values
    - ``min_score`` — only candidates at or above this score
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        stmt = select(TyposquatCandidate).where(
            TyposquatCandidate.tenant_id == tenant_id
        )
        if status:
            try:
                stmt = stmt.where(TyposquatCandidate.status == CandidateStatus(status))
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail=f"unknown status: {status}"
                ) from exc
        if min_score is not None:
            stmt = stmt.where(TyposquatCandidate.score >= min_score)
        rows = session.exec(
            stmt.order_by(TyposquatCandidate.score.desc())
        ).all()
        return CandidatesResponse(
            tenant_id=tenant_id,
            candidates=[_candidate_out(r) for r in rows if r.id is not None],
        )


@router.post("/candidates/{candidate_id}/dismiss", response_model=CandidateOut)
def dismiss_candidate(
    candidate_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> CandidateOut:
    """Mark a candidate as a false positive.

    The row is never deleted (audit trail); the detector will not
    reopen a DISMISSED candidate unless its severity climbs to
    high/critical on a future sweep.
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        row = session.exec(
            select(TyposquatCandidate)
            .where(TyposquatCandidate.id == candidate_id)
            .where(TyposquatCandidate.tenant_id == tenant_id)
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="candidate not found")
        row.status = CandidateStatus.DISMISSED
        session.add(row)
        session.commit()
        session.refresh(row)
        return _candidate_out(row)


# ──────────────────────────────────────────────────────────────────────
# Takedown ledger
# ──────────────────────────────────────────────────────────────────────


@router.get("/takedowns", response_model=TakedownsResponse)
def list_takedowns(
    candidate_id: int | None = None,
    ctx: TenantContext = Depends(require_tenant),
) -> TakedownsResponse:
    """List takedown requests for the active tenant.

    Optional ``candidate_id`` filter to scope the result to one
    candidate's filing history.
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        stmt = select(TakedownRequest).where(
            TakedownRequest.tenant_id == tenant_id
        )
        if candidate_id is not None:
            stmt = stmt.where(TakedownRequest.candidate_id == candidate_id)
        rows = session.exec(
            stmt.order_by(TakedownRequest.created_at.desc())
        ).all()
        return TakedownsResponse(
            tenant_id=tenant_id,
            takedowns=[_takedown_out(r) for r in rows if r.id is not None],
        )


__all__ = ["router"]
