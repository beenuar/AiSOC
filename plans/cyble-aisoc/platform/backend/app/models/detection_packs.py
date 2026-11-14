"""Vertical detection pack registry + per-tenant calibration (t3d-vertical-packs).

The vertical-pack subsystem in `app/detections/registry.py` owns the
in-memory `RulePack` instances. This module is the *durable* side: which
packs the platform knows about, which tenants are assigned to which
packs, and how each tenant has tuned the rules in those packs.

Three tables, all tenant-scoped where it matters:

- :class:`VerticalPack` — catalog row for a pack we ship (finserv,
  healthcare, retail, manufacturing, public_sector). Carries the
  on-disk path so the registry can rebuild the in-memory `RulePack`
  after process restart, plus a version string for upgrade tracking.
  These rows are NOT tenant-scoped — the catalog is platform-wide.

- :class:`TenantPackAssignment` — which packs a tenant has enabled.
  A tenant may enable zero, one, or many vertical packs on top of
  the built-in pack. We carry an ``enabled`` flag rather than
  deleting rows so we keep an audit trail of "tenant X had finserv
  enabled from 2026-03-01 to 2026-05-12".

- :class:`PackRuleCalibration` — per-tenant, per-rule overrides:
  severity bump/drop, disable, or attach a baseline JSON blob the
  rule's matcher can consult (e.g. "this tenant's normal ACH
  transfer volume is 800/hour ± 200"). The registry layer applies
  these overrides when materializing the tenant-effective `RulePack`.

Why split assignment from calibration?
  Assignment is coarse (pack on/off). Calibration is fine
  (individual rule). Most tenants will assign 1-2 packs and never
  calibrate; a few will calibrate aggressively. Keeping the rows
  small means tenant-effective-pack rebuilds in the registry don't
  scan a huge JSON blob just to find that no overrides exist.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import UniqueConstraint
from sqlmodel import JSON, Column, Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VerticalPack(SQLModel, table=True):
    """Catalog entry for a vertical detection pack we ship.

    A pack is a directory under
    ``app/detections/rules/verticals/<slug>/`` containing Sigma YAML
    rules. The registry boots by reconciling rows in this table against
    what it finds on disk: missing rows get inserted, stale rows get
    marked inactive. Tenants then opt in via :class:`TenantPackAssignment`.
    """

    __tablename__ = "verticalpack"

    id: Optional[int] = Field(default=None, primary_key=True)
    slug: str = Field(
        index=True,
        unique=True,
        description=(
            "Stable machine identifier for the pack — matches the "
            "directory name under rules/verticals/ (e.g. 'finserv')."
        ),
    )
    name: str = Field(description="Human-readable name (e.g. 'Financial Services').")
    description: str = Field(
        default="",
        description="One-paragraph rationale shown in the marketplace UI.",
    )
    path: str = Field(
        description=(
            "Path on disk where the pack's YAML rules live. Relative "
            "paths resolve under the built-in rules root."
        ),
    )
    version: str = Field(
        default="1.0.0",
        description="SemVer-ish content version; bumped when rules change.",
    )
    industry_tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Free-form tags (e.g. ['finserv', 'pci-dss']).",
    )
    active: bool = Field(
        default=True,
        index=True,
        description="False means the pack is deprecated; assignments stay but no new ones.",
    )
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)


class TenantPackAssignment(SQLModel, table=True):
    """One tenant's opt-in to one :class:`VerticalPack`.

    A tenant's *effective* rule set is::

        builtin_pack
          + every (VerticalPack referenced by an enabled TenantPackAssignment)
          - rules disabled via PackRuleCalibration
          ± severity overrides via PackRuleCalibration

    The registry layer is the only place that materializes this — see
    ``app/detections/registry.py::get_tenant_engine``.
    """

    __tablename__ = "tenantpackassignment"
    __table_args__ = (
        # A tenant can have AT MOST one assignment row per pack. The
        # calibration service does an app-layer upsert, but a concurrent
        # second writer would otherwise be able to insert a duplicate
        # before the first commit lands. The constraint makes that
        # structurally impossible.
        UniqueConstraint(
            "tenant_id",
            "vertical_pack_id",
            name="uq_tenant_pack_assignment",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    vertical_pack_id: int = Field(foreign_key="verticalpack.id", index=True)
    enabled: bool = Field(
        default=True,
        index=True,
        description="False keeps the row for audit but excludes the pack at runtime.",
    )
    assigned_by: str = Field(
        default="system",
        description="Subject of the JWT that created the assignment.",
    )
    notes: str = Field(
        default="",
        description="Optional free-form note from the admin who turned this on.",
    )
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)


class PackRuleCalibration(SQLModel, table=True):
    """Per-tenant override for a single rule inside an assigned pack.

    Calibration is *additive*: the absence of a row means "use the
    pack default". A row can:

    - Disable the rule for this tenant (``enabled=False``)
    - Bump or drop severity (``severity_override``)
    - Attach a baseline blob the rule's matcher consults at eval time
      (``baseline``). The schema of ``baseline`` is rule-specific; the
      engine passes it through opaquely so individual rules can read
      "thresholds.requests_per_minute" or similar.
    """

    __tablename__ = "packrulecalibration"
    __table_args__ = (
        # The natural key is (tenant_id, rule_id) — see the rationale in
        # ``calibration.set_calibration``. Enforce it at the DB so a
        # racing second writer can't bypass the upsert.
        UniqueConstraint(
            "tenant_id",
            "rule_id",
            name="uq_tenant_rule_calibration",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    vertical_pack_id: int = Field(foreign_key="verticalpack.id", index=True)
    rule_id: str = Field(
        index=True,
        description="Sigma rule id (UUID-like string) that this row tunes.",
    )
    enabled: bool = Field(
        default=True,
        index=True,
        description="False disables the rule for this tenant.",
    )
    severity_override: Optional[str] = Field(
        default=None,
        index=True,
        description="One of: low, medium, high, critical. None = pack default.",
    )
    baseline: dict = Field(
        default_factory=dict,
        sa_column=Column(JSON),
        description=(
            "Rule-specific baseline / threshold blob. Opaque to the "
            "engine; consumed by individual rules that opt in."
        ),
    )
    notes: str = Field(
        default="",
        description="Free-form rationale (why was this tuned?).",
    )
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)


__all__ = [
    "PackRuleCalibration",
    "TenantPackAssignment",
    "VerticalPack",
]
