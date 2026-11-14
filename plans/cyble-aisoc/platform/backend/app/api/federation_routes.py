"""Cross-tenant federation REST API (t3b-federated).

Tenant-facing surface for the opt-in, k-anonymity-gated, differentially
private signal pool implemented in :mod:`app.federated`.

Endpoints (all tenant-scoped via :func:`require_tenant`):

- ``POST /federation/consents``        — opt in to a signal class.
- ``DELETE /federation/consents/{cls}``— opt out of a signal class.
- ``GET  /federation/consents``        — list this tenant's consents.
- ``POST /federation/signals``         — contribute one signal (validated).
- ``GET  /federation/aggregate``       — query the pool for one
  ``(signal_class, signal_key)`` and receive a noisy count or a
  k-anonymity refusal.

Design rules:

1. The aggregate endpoint NEVER returns ``tenant_id`` or contributor
   lists. The wire shape mirrors :class:`FederatedAggregate` exactly
   so we cannot accidentally widen the contract in the route layer.

2. Ingest errors caused by missing consent or malformed signal_key /
   payload are surfaced as 400, not 500 — the caller did something
   wrong, not the server.

3. Consent grants are idempotent under the current ``terms_hash``;
   the route returns the active row either way.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.db import session_scope
from app.federated import (
    SignalIngestError,
    aggregate_signal,
    grant_consent,
    ingest_signal,
    list_consents,
    revoke_consent,
)
from app.models.federated import SignalClass
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/federation", tags=["federation"])


# ──────────────────────────────────────────────────────────────────────
# Request / response shapes
# ──────────────────────────────────────────────────────────────────────


class ConsentGrantRequest(BaseModel):
    signal_class: SignalClass


class ConsentRecord(BaseModel):
    signal_class: SignalClass
    terms_hash: str
    active: bool
    granted_at: str
    deactivated_at: Optional[str] = None
    granted_by: str


class ConsentListResponse(BaseModel):
    tenant_id: str
    consents: list[ConsentRecord]


class SignalIngestRequest(BaseModel):
    signal_class: SignalClass
    signal_key: str = Field(..., min_length=1, max_length=256)
    payload: dict[str, Any] = Field(default_factory=dict)


class SignalIngestResponse(BaseModel):
    accepted: bool
    signal_class: SignalClass
    signal_key: str


class AggregateResponse(BaseModel):
    """Wire mirror of :class:`FederatedAggregate`.

    Note the absence of ``tenant_id``, contributor list, or any field
    that would let a caller learn *who* contributed — only the count
    and the k-anonymity flag cross the wire.
    """

    signal_class: SignalClass
    signal_key: str
    meets_k_anonymity: bool
    noisy_count: Optional[float] = None


# ──────────────────────────────────────────────────────────────────────
# Consent management
# ──────────────────────────────────────────────────────────────────────


@router.post("/consents", response_model=ConsentRecord)
def grant(
    body: ConsentGrantRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> ConsentRecord:
    """Opt the active tenant into contributing ``signal_class``.

    Idempotent under the current ``terms_hash``: returns the live row.
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        row = grant_consent(
            session,
            tenant_id=tenant_id,
            signal_class=body.signal_class,
            granted_by=ctx.subject or "system",
        )
        return ConsentRecord(
            signal_class=row.signal_class,
            terms_hash=row.terms_hash,
            active=row.active,
            granted_at=row.granted_at.isoformat(),
            deactivated_at=(
                row.deactivated_at.isoformat() if row.deactivated_at else None
            ),
            granted_by=row.granted_by,
        )


@router.delete("/consents/{signal_class}")
def revoke(
    signal_class: SignalClass,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Opt the active tenant out of ``signal_class``.

    Past contributions remain in the ledger for audit, but the
    aggregator stops counting them immediately on the next query.
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        n = revoke_consent(
            session,
            tenant_id=tenant_id,
            signal_class=signal_class,
            revoked_by=ctx.subject or "system",
        )
    return {"revoked_rows": n, "signal_class": signal_class.value}


@router.get("/consents", response_model=ConsentListResponse)
def my_consents(
    active_only: bool = True,
    ctx: TenantContext = Depends(require_tenant),
) -> ConsentListResponse:
    """List the active tenant's consent rows (audit trail).

    ``active_only=False`` includes withdrawn consents for compliance
    review.
    """
    tenant_id = ctx.active_tenant_id
    with session_scope() as session:
        rows = list(
            list_consents(
                session, tenant_id=tenant_id, active_only=active_only
            )
        )
        records = [
            ConsentRecord(
                signal_class=r.signal_class,
                terms_hash=r.terms_hash,
                active=r.active,
                granted_at=r.granted_at.isoformat(),
                deactivated_at=(
                    r.deactivated_at.isoformat()
                    if r.deactivated_at
                    else None
                ),
                granted_by=r.granted_by,
            )
            for r in rows
        ]
    return ConsentListResponse(tenant_id=tenant_id, consents=records)


# ──────────────────────────────────────────────────────────────────────
# Signal ingest and aggregate query
# ──────────────────────────────────────────────────────────────────────


@router.post("/signals", response_model=SignalIngestResponse)
def contribute(
    body: SignalIngestRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> SignalIngestResponse:
    """Contribute one signal from the active tenant.

    Rejected with 400 if the tenant lacks active consent for the class,
    if the ``signal_key`` is PII-shaped or wrong-typed for the class,
    or if the ``payload`` falls outside the allow-listed shape.
    """
    tenant_id = ctx.active_tenant_id
    try:
        with session_scope() as session:
            ingest_signal(
                session,
                tenant_id=tenant_id,
                signal_class=body.signal_class,
                signal_key=body.signal_key,
                payload=body.payload,
            )
    except SignalIngestError as exc:
        # Safe to surface: the error message never echoes the raw key.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SignalIngestResponse(
        accepted=True,
        signal_class=body.signal_class,
        signal_key=body.signal_key,
    )


@router.get("/aggregate", response_model=AggregateResponse)
def aggregate(
    signal_class: SignalClass,
    signal_key: str,
    ctx: TenantContext = Depends(require_tenant),
) -> AggregateResponse:
    """Query the pool for one ``(signal_class, signal_key)``.

    Reciprocity rule: the requesting tenant must hold an active
    consent for the class. Non-contributors get the same "no answer"
    shape as a k-anonymity refusal, so callers cannot use the
    aggregator to probe their own consent state.
    """
    tenant_id = ctx.active_tenant_id
    if not signal_key.strip():
        raise HTTPException(status_code=400, detail="signal_key is empty")
    with session_scope() as session:
        agg = aggregate_signal(
            session,
            requester_tenant_id=tenant_id,
            signal_class=signal_class,
            signal_key=signal_key.strip(),
        )
    return AggregateResponse(
        signal_class=agg.signal_class,
        signal_key=agg.signal_key,
        meets_k_anonymity=agg.meets_k_anonymity,
        noisy_count=agg.noisy_count,
    )


__all__ = ["router"]
