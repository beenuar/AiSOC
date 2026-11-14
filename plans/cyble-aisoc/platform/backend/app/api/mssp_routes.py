"""FastAPI routes for the MSSP white-label platform (t5-mssp-whitelabel).

Three groups of endpoints:

  /mssp/branding                — public-ish, returns white-label
                                  config for the current tenant. Used
                                  by the analyst console at boot.
  /mssp/fleet                   — MSSP-only, aggregates across the
                                  authenticated MSSP's child tenants.
  /mssp/admin/...               — MSSP-admin, manages partner record,
                                  tenant links, and feature flags.

Routes enforce that:
  - Anyone can hit ``/mssp/branding/<tid>``: branding is not secret.
  - ``/mssp/fleet`` requires an MSSP token *or* a platform admin.
  - ``/mssp/admin/*`` requires the caller to be operating as the MSSP
    parent (``ctx.claims.tenant_id == mssp_tenant_id``) or a platform
    admin.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.mssp.service import (
    add_tenant_link,
    branding_for,
    fleet_for_mssp,
    list_links,
    remove_tenant_link,
    set_feature_flag,
    upsert_partner,
)
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/mssp", tags=["mssp"])


# ─── Branding ───────────────────────────────────────────────────────


@router.get("/branding/{mssp_tenant_id}")
def get_branding(mssp_tenant_id: str) -> dict[str, Any]:
    """Public branding payload.

    Branding contains nothing sensitive (logo URL, colors, support
    email). The analyst console resolves the MSSP id from the request
    host (when ``custom_domain`` is configured) or from the active
    tenant claim, and fetches branding before the auth dance — so we
    deliberately do not gate this behind a tenant token.
    """
    branding = branding_for(mssp_tenant_id)
    if branding is None:
        raise HTTPException(status_code=404, detail="MSSP partner not found")
    return branding.to_dict()


@router.get("/branding")
def get_my_branding(
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Branding for the *currently authenticated* MSSP.

    Resolution:
      - If the caller is an MSSP analyst (``mssp_parent_tid`` set on
        the token), return the parent's branding.
      - Otherwise, return the caller's own tenant's branding (it may
        itself be an MSSP record), or a 404 if none is registered.
    """
    target = ctx.claims.mssp_parent_tenant_id or ctx.claims.tenant_id
    branding = branding_for(target)
    if branding is None:
        raise HTTPException(status_code=404, detail="no MSSP branding registered")
    return branding.to_dict()


# ─── Fleet view ─────────────────────────────────────────────────────


@router.get("/fleet")
def get_fleet(
    include_suspended: bool = False,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Aggregated KPI view across the MSSP's child tenants.

    Visibility:
      - MSSP analysts see exactly the children their JWT lists in
        ``allowed_tenants``. Empty list = all children for that MSSP.
      - Non-MSSP tenants get a 403; the fleet view only makes sense
        for the MSSP role.
      - Platform admins see every fleet entry under any MSSP they
        pivot to (operator console).
    """
    if not (ctx.is_mssp or ctx.is_admin):
        raise HTTPException(
            status_code=403,
            detail="fleet view is only available to MSSP or admin tokens",
        )
    mssp_tid = ctx.claims.mssp_parent_tenant_id or ctx.claims.tenant_id
    visible: Optional[list[str]]
    if ctx.is_admin:
        visible = None
    else:
        visible = ctx.viewable_tenant_ids()
    entries = fleet_for_mssp(
        mssp_tid,
        visible_tenant_ids=visible,
        include_suspended=include_suspended,
    )
    return {
        "mssp_tenant_id": mssp_tid,
        "count": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


# ─── Admin ──────────────────────────────────────────────────────────


def _require_partner_admin(
    ctx: TenantContext, *, mssp_tenant_id: str
) -> None:
    """Caller must be that MSSP's tenant or a platform admin."""
    if ctx.is_admin:
        return
    if ctx.claims.tenant_id == mssp_tenant_id:
        return
    raise HTTPException(
        status_code=403,
        detail="caller is not authorized to administer this MSSP partner",
    )


class UpsertPartnerRequest(BaseModel):
    display_name: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = Field(default=None, pattern=r"^#?[0-9a-fA-F]{6}$")
    accent_color: Optional[str] = Field(default=None, pattern=r"^#?[0-9a-fA-F]{6}$")
    support_email: Optional[str] = None
    custom_domain: Optional[str] = None
    program_tier: Optional[str] = None
    tenant_quota: Optional[int] = Field(default=None, ge=1, le=10000)


@router.put("/admin/partners/{mssp_tenant_id}")
def admin_upsert_partner(
    mssp_tenant_id: str,
    body: UpsertPartnerRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _require_partner_admin(ctx, mssp_tenant_id=mssp_tenant_id)
    payload = body.model_dump(exclude_unset=True)

    def _normalize_color(c: Optional[str]) -> Optional[str]:
        if not c:
            return c
        return c if c.startswith("#") else f"#{c}"

    payload["primary_color"] = _normalize_color(payload.get("primary_color"))
    payload["accent_color"] = _normalize_color(payload.get("accent_color"))
    partner = upsert_partner(tenant_id=mssp_tenant_id, **payload)
    return {
        "tenant_id": partner.tenant_id,
        "display_name": partner.display_name,
        "primary_color": partner.primary_color,
        "accent_color": partner.accent_color,
        "program_tier": partner.program_tier,
        "tenant_quota": partner.tenant_quota,
    }


class FlagRequest(BaseModel):
    flag: str = Field(min_length=1, max_length=64)
    enabled: bool


@router.post("/admin/partners/{mssp_tenant_id}/flags")
def admin_set_flag(
    mssp_tenant_id: str,
    body: FlagRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _require_partner_admin(ctx, mssp_tenant_id=mssp_tenant_id)
    try:
        flags = set_feature_flag(
            tenant_id=mssp_tenant_id, flag=body.flag, enabled=body.enabled
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"flags": flags}


class TenantLinkRequest(BaseModel):
    customer_tenant_id: str = Field(min_length=2, max_length=100)
    display_name: Optional[str] = None
    notes: str = ""


@router.post("/admin/partners/{mssp_tenant_id}/tenants")
def admin_add_tenant(
    mssp_tenant_id: str,
    body: TenantLinkRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _require_partner_admin(ctx, mssp_tenant_id=mssp_tenant_id)
    try:
        link = add_tenant_link(
            mssp_tenant_id=mssp_tenant_id,
            customer_tenant_id=body.customer_tenant_id,
            display_name=body.display_name,
            notes=body.notes,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "mssp_tenant_id": link.mssp_tenant_id,
        "customer_tenant_id": link.customer_tenant_id,
        "display_name": link.display_name,
        "suspended": link.suspended,
    }


@router.delete("/admin/partners/{mssp_tenant_id}/tenants/{customer_tenant_id}")
def admin_remove_tenant(
    mssp_tenant_id: str,
    customer_tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _require_partner_admin(ctx, mssp_tenant_id=mssp_tenant_id)
    removed = remove_tenant_link(
        mssp_tenant_id=mssp_tenant_id, customer_tenant_id=customer_tenant_id
    )
    if not removed:
        raise HTTPException(status_code=404, detail="link not found")
    return {"removed": True}


@router.get("/admin/partners/{mssp_tenant_id}/tenants")
def admin_list_tenants(
    mssp_tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _require_partner_admin(ctx, mssp_tenant_id=mssp_tenant_id)
    links = list_links(mssp_tenant_id)
    return {
        "count": len(links),
        "links": [
            {
                "customer_tenant_id": l.customer_tenant_id,
                "display_name": l.display_name,
                "suspended": l.suspended,
                "notes": l.notes,
            }
            for l in links
        ],
    }
