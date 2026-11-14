"""MSSP (Managed Security Service Provider) records (t5-mssp-whitelabel).

The platform already supports MSSP analysts via JWT claims
(``mssp_parent_tid``, ``allowed_tenants``) plumbed through
:class:`app.security.jwt.TenantClaims`. What was missing was a
*durable record* of the MSSP itself: which parent tenant is operating
which child tenants, and what white-label branding to render in the
co-branded analyst console.

Two tables:

1. :class:`MsspPartner` — one row per MSSP parent tenant. Holds the
   white-label branding (logo, primary color, custom domain), a
   tenant quota, and program-tier metadata.

2. :class:`MsspTenantLink` — one row per (parent, child) edge. The
   parent's ``MsspPartner.tenant_id`` is the MSSP itself; the
   ``customer_tenant_id`` is the end-customer tenant the MSSP
   manages. Links carry per-customer overrides (display name shown
   in the MSSP's fleet view, suspended flag for billing holds).

We deliberately keep the MSSP row in the same SQLite mirror as the
rest of the platform so the dashboard's MSSP filter is a single SQL
join and the JWT plumbing in :mod:`app.security.tenant` can keep
treating ``allowed_tenants`` as the authoritative ACL while this
table remains a *materialised* view of the same intent. JWT remains
the security boundary; the table is for product surface (branding,
fleet inventory, program tier).

Why not put branding on the customer tenant?
  An MSSP that manages 50 customers wants to set the logo once on
  their parent record and have every child inherit it — not patch
  50 children manually. Putting branding on the *parent* makes the
  inheritance natural and avoids fan-out writes when the MSSP wants
  to refresh their logo.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class MsspProgramTier(str, Enum):
    """Cyble MSSP program tiers.

    Drives revenue-share, support SLA, and platform-feature gating.
    Tiers are deliberately fewer than typical channel programs (3
    instead of 5+) — the SOC operator's daily flow shouldn't depend
    on the partner tier.
    """

    REGISTERED = "registered"  # default for any MSSP that signs up
    SELECT = "select"          # >= 5 paying child tenants
    ELITE = "elite"            # >= 25 paying child tenants + RFP wins


class MsspPartner(SQLModel, table=True):
    """One row per MSSP organisation operating on AiSOC."""

    __tablename__ = "mssp_partner"

    id: Optional[int] = Field(default=None, primary_key=True)

    # The MSSP's own tenant id. This is the value that appears as
    # ``mssp_parent_tid`` in the analyst JWTs. Unique because we
    # never want two MsspPartner rows for the same parent.
    tenant_id: str = Field(unique=True, index=True)

    # Display surface — what gets rendered in the co-branded console.
    display_name: str = Field(default="MSSP Partner")
    logo_url: Optional[str] = Field(default=None)
    primary_color: str = Field(default="#0F172A")  # WCAG-AA-safe slate
    accent_color: str = Field(default="#22C55E")
    support_email: Optional[str] = Field(default=None)
    custom_domain: Optional[str] = Field(default=None)  # e.g. soc.acmemssp.com

    # Operational metadata.
    program_tier: str = Field(default=MsspProgramTier.REGISTERED.value)
    # Soft cap on child tenants. The MSSP can request a raise via
    # the support channel; default keeps abuse / billing surprises
    # under control. ``None`` (set by an admin) means unlimited.
    tenant_quota: Optional[int] = Field(default=50)

    # Per-MSSP feature toggles. Keys are short flags like
    # ``"deepfake_detection"``, values are booleans. JSON column
    # because the set evolves; we don't want to migrate for each new
    # feature gate. Stored as a serialised string to keep this table
    # readable on the SQLite mirror.
    feature_flags: str = Field(default="{}")  # JSON-encoded {flag: bool}

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MsspTenantLink(SQLModel, table=True):
    """One row per (MSSP, customer) management relationship.

    The link carries per-customer presentation knobs:
      - ``display_name`` overrides the customer's tenant name in the
        MSSP fleet view (e.g. an MSSP wants to see "Acme Hospital" not
        the random uuid we use as ``tenant_id``).
      - ``suspended`` hides the link from the MSSP's fleet on billing
        hold without losing the durable record.
    """

    __tablename__ = "mssp_tenant_link"

    id: Optional[int] = Field(default=None, primary_key=True)

    # The MSSP's own tenant id (== ``MsspPartner.tenant_id``).
    mssp_tenant_id: str = Field(index=True)
    # The customer tenant id this MSSP manages.
    customer_tenant_id: str = Field(index=True)

    display_name: Optional[str] = Field(default=None)
    suspended: bool = Field(default=False)
    # Free-form notes (last billing review, contract end date, etc.)
    # surfaced in the MSSP admin console.
    notes: str = Field(default="")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
