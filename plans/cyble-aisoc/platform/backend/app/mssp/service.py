"""MSSP fleet aggregation + white-label branding.

The :func:`fleet_for_mssp` query is the hot path: every time an MSSP
analyst loads their landing page or refreshes the fleet view, we
aggregate across every child tenant they manage.

Aggregations per child tenant:
  * total open cases (status not in closed_*)
  * cases by severity bucket
  * count of HITL approvals waiting on a human
  * tool-call success rate over the last 24h (proxy for connector
    health on the customer side)
  * latest case updated-at timestamp

We deliberately keep the join fan-out small: the fleet view is bounded
by an MSSP's ``allowed_tenants``, which is at most a few hundred even
for the largest enterprise MSSP we expect on the platform. SQL is the
single source of truth — no caching layer until we actually see
slowness on production data.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlmodel import select

from app.db import session_scope
from app.models.case import Case, CaseStatus
from app.models.hitl import HitlRequest, HitlState
from app.models.mssp import MsspPartner, MsspProgramTier, MsspTenantLink
from app.models.tool_call import ToolCall

logger = logging.getLogger(__name__)


# ─── DTOs ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MsspBranding:
    """White-label branding payload for the analyst console."""

    mssp_tenant_id: str
    display_name: str
    logo_url: Optional[str]
    primary_color: str
    accent_color: str
    support_email: Optional[str]
    custom_domain: Optional[str]
    program_tier: str
    feature_flags: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FleetEntry:
    """One row in an MSSP's fleet view."""

    customer_tenant_id: str
    display_name: str
    suspended: bool
    open_cases: int = 0
    awaiting_hitl: int = 0
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    tool_call_success_24h_pct: float = 0.0
    latest_case_updated_at: Optional[datetime] = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(self.latest_case_updated_at, datetime):
            d["latest_case_updated_at"] = self.latest_case_updated_at.isoformat()
        return d


# ─── Helpers ────────────────────────────────────────────────────────


_OPEN_STATUSES = {
    CaseStatus.NEW.value,
    CaseStatus.TRIAGING.value,
    CaseStatus.INVESTIGATING.value,
    CaseStatus.AWAITING_HITL.value,
    CaseStatus.RESPONDING.value,
    CaseStatus.ESCALATED.value,
}


def _decode_flags(blob: str) -> dict[str, bool]:
    if not blob:
        return {}
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        logger.warning("mssp:bad_feature_flag_json blob=%r", blob[:80])
        return {}
    return {str(k): bool(v) for k, v in parsed.items() if isinstance(v, (bool, int))}


# ─── Partner / link lifecycle ──────────────────────────────────────


def upsert_partner(
    *,
    tenant_id: str,
    display_name: str | None = None,
    logo_url: str | None = None,
    primary_color: str | None = None,
    accent_color: str | None = None,
    support_email: str | None = None,
    custom_domain: str | None = None,
    program_tier: MsspProgramTier | str | None = None,
    tenant_quota: int | None = None,
) -> MsspPartner:
    """Create or update a :class:`MsspPartner` row.

    Idempotent: re-calling with the same ``tenant_id`` updates the
    existing row. ``None`` for any field means "leave the existing
    value untouched" (no implicit reset to defaults).
    """
    with session_scope() as session:
        existing = session.exec(
            select(MsspPartner).where(MsspPartner.tenant_id == tenant_id)
        ).one_or_none()
        if existing is None:
            partner = MsspPartner(
                tenant_id=tenant_id,
                display_name=display_name or "MSSP Partner",
                logo_url=logo_url,
                primary_color=primary_color or "#0F172A",
                accent_color=accent_color or "#22C55E",
                support_email=support_email,
                custom_domain=custom_domain,
                program_tier=(
                    program_tier.value
                    if isinstance(program_tier, MsspProgramTier)
                    else (program_tier or MsspProgramTier.REGISTERED.value)
                ),
                tenant_quota=tenant_quota,
            )
            session.add(partner)
        else:
            partner = existing
            if display_name is not None:
                partner.display_name = display_name
            if logo_url is not None:
                partner.logo_url = logo_url
            if primary_color is not None:
                partner.primary_color = primary_color
            if accent_color is not None:
                partner.accent_color = accent_color
            if support_email is not None:
                partner.support_email = support_email
            if custom_domain is not None:
                partner.custom_domain = custom_domain
            if program_tier is not None:
                partner.program_tier = (
                    program_tier.value
                    if isinstance(program_tier, MsspProgramTier)
                    else program_tier
                )
            if tenant_quota is not None:
                partner.tenant_quota = tenant_quota
            partner.updated_at = datetime.now(timezone.utc)
            session.add(partner)
        session.commit()
        session.refresh(partner)
        # Snapshot before the session closes so the caller can use the
        # object without DetachedInstanceError.
        return MsspPartner(
            id=partner.id,
            tenant_id=partner.tenant_id,
            display_name=partner.display_name,
            logo_url=partner.logo_url,
            primary_color=partner.primary_color,
            accent_color=partner.accent_color,
            support_email=partner.support_email,
            custom_domain=partner.custom_domain,
            program_tier=partner.program_tier,
            tenant_quota=partner.tenant_quota,
            feature_flags=partner.feature_flags,
            created_at=partner.created_at,
            updated_at=partner.updated_at,
        )


def set_feature_flag(*, tenant_id: str, flag: str, enabled: bool) -> dict[str, bool]:
    """Toggle a single feature flag on the partner record."""
    with session_scope() as session:
        partner = session.exec(
            select(MsspPartner).where(MsspPartner.tenant_id == tenant_id)
        ).one_or_none()
        if partner is None:
            raise LookupError(f"MSSP partner {tenant_id!r} not found")
        flags = _decode_flags(partner.feature_flags or "{}")
        flags[str(flag)] = bool(enabled)
        partner.feature_flags = json.dumps(flags)
        partner.updated_at = datetime.now(timezone.utc)
        session.add(partner)
        session.commit()
        return flags


def add_tenant_link(
    *,
    mssp_tenant_id: str,
    customer_tenant_id: str,
    display_name: str | None = None,
    notes: str = "",
) -> MsspTenantLink:
    """Hook a customer tenant under an MSSP parent.

    Enforces the partner's ``tenant_quota`` if set. Idempotent: a
    second call for the same (mssp, customer) pair updates the row
    rather than inserting a duplicate.
    """
    with session_scope() as session:
        partner = session.exec(
            select(MsspPartner).where(MsspPartner.tenant_id == mssp_tenant_id)
        ).one_or_none()
        if partner is None:
            raise LookupError(
                f"MSSP partner {mssp_tenant_id!r} does not exist; "
                "call upsert_partner first"
            )
        existing = session.exec(
            select(MsspTenantLink)
            .where(MsspTenantLink.mssp_tenant_id == mssp_tenant_id)
            .where(MsspTenantLink.customer_tenant_id == customer_tenant_id)
        ).one_or_none()

        if existing is None:
            if partner.tenant_quota is not None:
                current = session.exec(
                    select(MsspTenantLink).where(
                        MsspTenantLink.mssp_tenant_id == mssp_tenant_id
                    )
                ).all()
                if len(list(current)) >= partner.tenant_quota:
                    raise PermissionError(
                        f"MSSP {mssp_tenant_id!r} has reached its tenant "
                        f"quota of {partner.tenant_quota}; raise quota or "
                        "remove an existing link first"
                    )
            link = MsspTenantLink(
                mssp_tenant_id=mssp_tenant_id,
                customer_tenant_id=customer_tenant_id,
                display_name=display_name,
                notes=notes,
            )
            session.add(link)
        else:
            link = existing
            if display_name is not None:
                link.display_name = display_name
            if notes:
                link.notes = notes
            link.updated_at = datetime.now(timezone.utc)
            session.add(link)
        session.commit()
        session.refresh(link)
        return MsspTenantLink(
            id=link.id,
            mssp_tenant_id=link.mssp_tenant_id,
            customer_tenant_id=link.customer_tenant_id,
            display_name=link.display_name,
            suspended=link.suspended,
            notes=link.notes,
            created_at=link.created_at,
            updated_at=link.updated_at,
        )


def remove_tenant_link(*, mssp_tenant_id: str, customer_tenant_id: str) -> bool:
    """Hard-delete a (mssp, customer) link. Returns True if a row was removed."""
    with session_scope() as session:
        link = session.exec(
            select(MsspTenantLink)
            .where(MsspTenantLink.mssp_tenant_id == mssp_tenant_id)
            .where(MsspTenantLink.customer_tenant_id == customer_tenant_id)
        ).one_or_none()
        if link is None:
            return False
        session.delete(link)
        session.commit()
        return True


def list_links(mssp_tenant_id: str) -> list[MsspTenantLink]:
    """Return every link under one MSSP, ordered by display_name."""
    with session_scope() as session:
        rows = list(
            session.exec(
                select(MsspTenantLink).where(
                    MsspTenantLink.mssp_tenant_id == mssp_tenant_id
                )
            ).all()
        )
        # Snapshot before the session closes.
        snapshots = [
            MsspTenantLink(
                id=r.id,
                mssp_tenant_id=r.mssp_tenant_id,
                customer_tenant_id=r.customer_tenant_id,
                display_name=r.display_name,
                suspended=r.suspended,
                notes=r.notes,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in rows
        ]
    snapshots.sort(
        key=lambda r: ((r.display_name or r.customer_tenant_id).lower(),)
    )
    return snapshots


# ─── Branding ───────────────────────────────────────────────────────


def branding_for(mssp_tenant_id: str) -> Optional[MsspBranding]:
    """Resolve white-label branding for the analyst console.

    Returns ``None`` when the tenant is not registered as an MSSP —
    callers fall back to the default Cyble branding in that case.
    """
    with session_scope() as session:
        partner = session.exec(
            select(MsspPartner).where(MsspPartner.tenant_id == mssp_tenant_id)
        ).one_or_none()
        if partner is None:
            return None
        return MsspBranding(
            mssp_tenant_id=partner.tenant_id,
            display_name=partner.display_name,
            logo_url=partner.logo_url,
            primary_color=partner.primary_color,
            accent_color=partner.accent_color,
            support_email=partner.support_email,
            custom_domain=partner.custom_domain,
            program_tier=partner.program_tier,
            feature_flags=_decode_flags(partner.feature_flags or "{}"),
        )


# ─── Fleet aggregation ─────────────────────────────────────────────


def fleet_for_mssp(
    mssp_tenant_id: str,
    *,
    visible_tenant_ids: Iterable[str] | None = None,
    include_suspended: bool = False,
) -> list[FleetEntry]:
    """Aggregate per-customer KPIs for an MSSP's fleet view.

    ``visible_tenant_ids`` lets the caller intersect the materialised
    links with the JWT's ``allowed_tenants`` so we never leak a row
    that the caller's token can't see — defense in depth even though
    the MSSP record itself should mirror the JWT ACL.

    Concretely, for each customer:
      * ``open_cases`` = count where status not in closed_*
      * ``awaiting_hitl`` = count of HITL requests with state PENDING
      * ``severity_breakdown`` = histogram of severity for *open* cases
      * ``tool_call_success_24h_pct`` = success/(success+fail) over the
        last 24h. ``0.0`` if the customer had zero tool calls in the
        window — UI renders that as "—".
      * ``latest_case_updated_at`` = max(updated_at) across all cases.
    """
    visible_set: Optional[set[str]]
    if visible_tenant_ids is None:
        visible_set = None
    else:
        visible_set = {t for t in visible_tenant_ids if t}

    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    with session_scope() as session:
        link_rows = session.exec(
            select(MsspTenantLink).where(
                MsspTenantLink.mssp_tenant_id == mssp_tenant_id
            )
        ).all()
        links = [
            (
                r.customer_tenant_id,
                r.display_name or r.customer_tenant_id,
                r.suspended,
                r.notes,
            )
            for r in link_rows
        ]

        entries: list[FleetEntry] = []
        for cust_id, display_name, suspended, notes in links:
            if visible_set is not None and cust_id not in visible_set:
                continue
            if suspended and not include_suspended:
                continue

            cases = session.exec(
                select(Case).where(Case.tenant_id == cust_id)
            ).all()
            open_cases = 0
            severity_breakdown: dict[str, int] = {}
            latest_updated: Optional[datetime] = None
            for c in cases:
                status_v = (
                    c.status.value if hasattr(c.status, "value") else str(c.status)
                )
                sev_v = (
                    c.severity.value
                    if hasattr(c.severity, "value")
                    else str(c.severity)
                )
                if status_v in _OPEN_STATUSES:
                    open_cases += 1
                    severity_breakdown[sev_v] = (
                        severity_breakdown.get(sev_v, 0) + 1
                    )
                if c.updated_at is not None:
                    if latest_updated is None or c.updated_at > latest_updated:
                        latest_updated = c.updated_at

            hitl_pending = session.exec(
                select(HitlRequest)
                .where(HitlRequest.tenant_id == cust_id)
                .where(HitlRequest.state == HitlState.PENDING.value)
            ).all()
            awaiting = len(list(hitl_pending))

            tcs = session.exec(
                select(ToolCall)
                .where(ToolCall.tenant_id == cust_id)
                .where(ToolCall.created_at >= cutoff_24h)
            ).all()
            tcs_list = list(tcs)
            total = len(tcs_list)
            success = sum(1 for tc in tcs_list if tc.success)
            tcs_pct = round((success / total) * 100.0, 2) if total else 0.0

            entries.append(
                FleetEntry(
                    customer_tenant_id=cust_id,
                    display_name=display_name,
                    suspended=suspended,
                    open_cases=open_cases,
                    awaiting_hitl=awaiting,
                    severity_breakdown=severity_breakdown,
                    tool_call_success_24h_pct=tcs_pct,
                    latest_case_updated_at=latest_updated,
                    notes=notes,
                )
            )

    entries.sort(
        key=lambda e: (
            -e.awaiting_hitl,  # urgent customers first
            -e.open_cases,
            e.display_name.lower(),
        )
    )
    return entries
