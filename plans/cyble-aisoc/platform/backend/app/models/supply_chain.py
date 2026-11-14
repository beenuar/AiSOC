"""Third-party / supply-chain risk models (t3f-supply-chain).

The Supply-Chain agent fuses three Cyble-native signal sources against a
tenant's declared third-party footprint:

  * dark-web mentions of vendor data leaks (cti.darkweb_search),
  * brand-intel hits against the vendor name (cti.brand_intel),
  * vuln-intel on the vendor's known software stack (cti.vuln_intel),

and materialises proactive cases when a vendor's risk score crosses a
configured threshold. The agent never writes to the canonical actor
catalogue or the IOC store directly — it only reads CTI tools and
records observations against tenant-scoped Vendor / VendorRiskSignal
rows.

Two persistence concerns are kept separate:

- :class:`Vendor` — the tenant's declared third-party dependency. One
  row per (tenant_id, slug). Ownership: the tenant. Creation surface:
  the supply-chain REST API. The agent treats this table as read-only
  catalogue input; it never invents vendors.
- :class:`VendorRiskSignal` — one row per observed signal per sweep.
  An immutable audit log of *what the agent saw and when*. Cases open
  off the rolling sum of recent signal scores; analysts can replay the
  audit log to understand any verdict the agent published.

Why a dedicated table instead of leaning on Case + AgentTrace alone?

1. Per-vendor risk decay needs a queryable history. "vendor X scored
   75 over the last 14 days" requires a SUM(score) WHERE observed_at >
   now - 14d. Squashing this into Case.notes makes the dashboard query
   an O(N) string parse.
2. The agent runs on a cadence; multiple sweeps can re-observe the
   same signal kind. Idempotency by (vendor_id, signal_kind, source)
   keeps re-runs from inflating the score.
3. Some signals are informational (a 2-mention dark-web post) and
   shouldn't open a case alone, but should still surface in the vendor
   card as context. The signal log makes this UX possible without
   creating Case noise.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel, UniqueConstraint


class VendorCriticality(str, Enum):
    """How important is this vendor to tenant operations?

    Used as a multiplier on observed risk score: a critical vendor
    having a moderate-severity exposure is still a high-priority case;
    a low-criticality vendor with the same signal can wait.
    """

    LOW = "low"
    """Marginal dependency: a single product, easily replaceable."""
    MEDIUM = "medium"
    """Standard SaaS dependency, swap-out cost in days."""
    HIGH = "high"
    """Material business dependency, swap-out cost in weeks/months."""
    CRITICAL = "critical"
    """Existential dependency: payroll, identity, primary CRM, etc."""


class VendorCategory(str, Enum):
    """Coarse vendor taxonomy.

    Drives default risk weights (an identity provider breach is more
    impactful than a marketing-tool breach) and report grouping. We
    keep the set small on purpose — over-granular categories rot fast
    and don't drive different downstream decisions.
    """

    IDENTITY = "identity"  # IdP / SSO / MFA (Okta, Auth0)
    INFRASTRUCTURE = "infrastructure"  # IaaS / PaaS (AWS, Azure GCP)
    SAAS = "saas"  # generic SaaS (Salesforce, Zendesk)
    DATA = "data"  # data warehouse / BI (Snowflake, Looker)
    SOFTWARE = "software"  # software supplier / OSS publisher
    SECURITY = "security"  # security vendor (EDR, SIEM)
    PAYMENT = "payment"  # payment processor / billing
    HARDWARE = "hardware"  # hardware OEM / firmware supplier
    PROFESSIONAL = "professional"  # consultancy / outsourced services
    OTHER = "other"


class SignalKind(str, Enum):
    """What kind of breach signal was observed.

    Maps 1:1 to a CTI tool the agent invoked. Centralising the enum
    keeps the agent's branch logic and the per-vendor card UI in sync.
    """

    DARKWEB_LEAK = "darkweb_leak"
    """Mention on a leak forum / paste site referencing the vendor."""
    BRAND_IMPERSONATION = "brand_impersonation"
    """Typosquat / fake-app / executive-impersonation against vendor."""
    VULN_DISCLOSURE = "vuln_disclosure"
    """CVE published in a product the vendor ships."""
    ASM_EXPOSURE = "asm_exposure"
    """High-risk asset on the vendor's external attack surface."""
    PUBLIC_BREACH = "public_breach"
    """Self-disclosed breach / regulatory filing referencing vendor."""


class Vendor(SQLModel, table=True):
    """A tenant's declared third-party dependency.

    The natural key is ``(tenant_id, slug)``. Slugs are lowercase,
    hyphenated handles ("okta", "salesforce", "aws") so the ID is
    stable across UI / API / agent code paths.

    Tenant scope: every Vendor row carries a tenant_id. Unlike
    ``ThreatActor``, vendors are *not* shared globally because the
    tenant's relationship with a vendor is private (which assets
    depend on it, what the contract scope is). The CTI signal we
    observe *about* a vendor (e.g. an Okta dark-web leak) is
    inherently global — but materialising the link to "this tenant
    is at risk because they depend on Okta" is per-tenant.
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "slug", name="uq_vendor_tenant_slug"
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    slug: str = Field(
        index=True,
        description="Stable lowercase id: 'okta', 'salesforce', 'snowflake'.",
    )
    name: str = Field(
        index=True,
        description="Human-friendly display name ('Okta', 'AWS').",
    )
    category: VendorCategory = Field(
        default=VendorCategory.SAAS,
        index=True,
    )
    criticality: VendorCriticality = Field(
        default=VendorCriticality.MEDIUM,
        index=True,
    )
    description: str = Field(
        default="",
        description="Short blurb on the relationship (used by the Reporter).",
    )
    monitored_terms: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description=(
            "Search keywords passed to cti.darkweb_search and "
            "cti.brand_intel. Defaults to [name, slug] but tenants "
            "can add product names, SKUs, or contact emails."
        ),
    )
    monitored_domains: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description=(
            "Domains to feed cti.asm_lookup. Empty means skip the ASM "
            "phase for this vendor."
        ),
    )
    monitored_cves: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description=(
            "CVE IDs the tenant tracks against this vendor's products. "
            "Empty means skip the vuln-intel phase."
        ),
    )
    affected_assets: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description=(
            "Asset/host identifiers that depend on this vendor. Used "
            "to populate Case.affected_hosts and graph DEPENDS_ON edges."
        ),
    )
    affected_users: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description=(
            "User principals depending on this vendor (typically all "
            "employees for an IdP, a smaller list for a niche SaaS)."
        ),
    )
    contact_email: Optional[str] = Field(default=None)
    """Internal vendor-relationship owner — used by the Reporter."""
    active: bool = Field(default=True, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


class VendorRiskSignal(SQLModel, table=True):
    """One observation of a CTI signal against a vendor.

    Append-only. The agent never updates an existing signal in place;
    a re-observation is a new row. We keep a uniqueness constraint on
    ``(tenant_id, vendor_id, kind, source, observed_at)`` so a single
    sweep can't double-insert the same signal, but consecutive sweeps
    that re-observe the same dark-web post on different days both
    record (giving us "this leak has been hot for N days" without
    extra schema).
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "vendor_id",
            "kind",
            "source",
            "observed_at",
            name="uq_vendor_signal_idempotent",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    vendor_id: int = Field(index=True, foreign_key="vendor.id")
    kind: SignalKind = Field(index=True)
    source: str = Field(
        index=True,
        description="The CTI tool the signal came from ('cti.darkweb_search').",
    )
    score: int = Field(
        default=0,
        description=(
            "Per-signal severity score 0-100, before vendor "
            "criticality multiplier."
        ),
    )
    summary: str = Field(
        default="",
        description="One-line analyst-facing description.",
    )
    evidence: dict = Field(
        default_factory=dict,
        sa_column=Column(JSON),
        description="Structured payload: forum, ts, snippet, CVE id, etc.",
    )
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    case_id: Optional[int] = Field(
        default=None,
        index=True,
        description=(
            "Set once the signal contributed to opening a proactive "
            "Case. NULL means the signal stayed informational (below "
            "the case-open threshold)."
        ),
    )


__all__ = [
    "SignalKind",
    "Vendor",
    "VendorCategory",
    "VendorCriticality",
    "VendorRiskSignal",
]
