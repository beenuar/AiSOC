"""Per-tenant calibration store (t3d-calibration).

The durable CRUD layer over :class:`TenantPackAssignment` and
:class:`PackRuleCalibration`. The registry layer (``registry.py``) is
the *consumer* — it materializes a tenant's effective rule pack by
reading these rows. This module is the *producer* — anyone wanting to
mutate calibration (REST API, CLI, agent tool, future UI) goes through
the helpers here so that:

  1. Tenant cache invalidation is paired with every mutation. Forget
     to call :func:`registry.invalidate_tenant` after writing a row and
     the change won't take effect until the cached engine is rebuilt
     (process restart, registry reload). Bundling the two together in
     this module is the only way to make that bug structurally
     impossible.

  2. Severity overrides are validated up front against
     :class:`~app.detections.sigma.Severity` rather than being stored
     as arbitrary strings that blow up at composition time.

  3. We never mutate the on-disk YAML; calibration is purely a
     database-level overlay applied at engine-composition time.

Two parallel CRUD surfaces:

  * **Assignments** — coarse, per-pack opt-in/opt-out.
  * **Calibrations** — fine, per-rule overrides (disable, severity,
    baseline JSON).

Both upsert on the natural key (``tenant_id`` + pack slug for
assignments; ``tenant_id`` + ``rule_id`` for calibrations) so the
caller doesn't have to differentiate "first set" vs. "update".
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from sqlmodel import Session, select

from app.db import session_scope
from app.models.detection_packs import (
    PackRuleCalibration,
    TenantPackAssignment,
    VerticalPack,
)

from . import registry
from .sigma import Severity

logger = logging.getLogger(__name__)


# Calibration's severity_override is stored as a free string for schema
# tolerance, but mutations validate against the canonical enum. We
# accept anything Severity.from_str recognises plus ``None`` (meaning
# "no override; use pack default").
_VALID_SEVERITY_STRINGS = {"low", "medium", "high", "critical"}


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _resolve_pack_id(session: Session, pack: str | int) -> int:
    """Accept either a slug (``'finserv'``) or a numeric id; return id.

    Raises :class:`KeyError` if no active pack matches.
    """
    if isinstance(pack, int):
        row = session.get(VerticalPack, pack)
        if row is None or not row.active:
            raise KeyError(f"VerticalPack id={pack} not found or inactive")
        return pack
    row = session.exec(
        select(VerticalPack).where(VerticalPack.slug == pack)
    ).first()
    if row is None or not row.active:
        raise KeyError(f"VerticalPack slug={pack!r} not found or inactive")
    return row.id  # type: ignore[return-value]


def _detach(session: Session, rows: Iterable[Any]) -> None:
    """Expunge ORM rows so callers can read columns after the session closes.

    SQLAlchemy's default ``expire_on_commit=True`` invalidates every
    attribute on session commit — touching them later raises
    :class:`DetachedInstanceError`. We materialize columns we care about
    first, then expunge.
    """
    for r in rows:
        # Force load of every mapped column by reading them.
        for col in r.__table__.columns:
            getattr(r, col.name)
        session.expunge(r)


# --------------------------------------------------------------------------- #
# Assignment CRUD
# --------------------------------------------------------------------------- #


def assign_pack(
    *,
    tenant_id: str,
    pack: str | int,
    enabled: bool = True,
    assigned_by: str = "system",
    notes: str = "",
) -> TenantPackAssignment:
    """Opt ``tenant_id`` into a vertical pack (or update an existing opt-in).

    Idempotent: calling twice with the same arguments returns the same
    row, with ``updated_at`` bumped. The tenant cache is invalidated
    regardless — a no-op update still warrants a rebuild because the
    caller may have changed their mind about ``enabled``.
    """
    with session_scope() as session:
        pack_id = _resolve_pack_id(session, pack)
        row = session.exec(
            select(TenantPackAssignment).where(
                TenantPackAssignment.tenant_id == tenant_id,
                TenantPackAssignment.vertical_pack_id == pack_id,
            )
        ).first()
        if row is None:
            row = TenantPackAssignment(
                tenant_id=tenant_id,
                vertical_pack_id=pack_id,
                enabled=enabled,
                assigned_by=assigned_by,
                notes=notes,
            )
            session.add(row)
            action = "insert"
        else:
            row.enabled = enabled
            row.assigned_by = assigned_by
            row.notes = notes
            row.updated_at = _now()
            session.add(row)
            action = "update"
        session.commit()
        session.refresh(row)
        _detach(session, [row])

    logger.info(
        "calibration:assign_pack tenant=%s pack=%s enabled=%s action=%s",
        tenant_id,
        pack,
        enabled,
        action,
    )
    registry.invalidate_tenant(tenant_id)
    return row


def unassign_pack(*, tenant_id: str, pack: str | int) -> bool:
    """Remove a tenant's assignment to a pack.

    Returns True if a row was deleted, False if no assignment existed.
    We hard-delete here (rather than ``enabled=False``) on the theory
    that an unassign is a deliberate, auditable admin action — keeping
    soft-deleted rows around forever bloats the table without value.
    The audit trail lives in the activity log, not this row.
    """
    with session_scope() as session:
        pack_id = _resolve_pack_id(session, pack)
        row = session.exec(
            select(TenantPackAssignment).where(
                TenantPackAssignment.tenant_id == tenant_id,
                TenantPackAssignment.vertical_pack_id == pack_id,
            )
        ).first()
        if row is None:
            return False
        session.delete(row)
        session.commit()

    logger.info("calibration:unassign_pack tenant=%s pack=%s", tenant_id, pack)
    registry.invalidate_tenant(tenant_id)
    return True


def list_assignments(tenant_id: str) -> list[TenantPackAssignment]:
    """Every assignment row belonging to ``tenant_id`` (enabled or not)."""
    with session_scope() as session:
        rows = session.exec(
            select(TenantPackAssignment)
            .where(TenantPackAssignment.tenant_id == tenant_id)
            .order_by(TenantPackAssignment.vertical_pack_id)
        ).all()
        _detach(session, rows)
        return list(rows)


# --------------------------------------------------------------------------- #
# Calibration CRUD
# --------------------------------------------------------------------------- #


def set_calibration(
    *,
    tenant_id: str,
    pack: str | int,
    rule_id: str,
    enabled: bool = True,
    severity_override: str | None = None,
    baseline: dict | None = None,
    notes: str = "",
) -> PackRuleCalibration:
    """Upsert a calibration row.

    The natural key is (tenant_id, rule_id). We don't key on
    vertical_pack_id because a rule_id is globally unique across packs —
    two packs containing the same rule_id would be an authoring bug.
    Including pack_id on the row is purely so the API can show "this
    rule belongs to finserv" without a separate lookup.

    Raises :class:`ValueError` for an unrecognized severity string.
    """
    if severity_override is not None:
        normalized = severity_override.strip().lower()
        if normalized not in _VALID_SEVERITY_STRINGS:
            raise ValueError(
                f"severity_override={severity_override!r} is not one of "
                f"{sorted(_VALID_SEVERITY_STRINGS)}"
            )
        # Round-trip through the enum to canonicalise (e.g. 'info' → 'low').
        severity_override = Severity.from_str(normalized).value

    payload_baseline = baseline or {}

    with session_scope() as session:
        pack_id = _resolve_pack_id(session, pack)
        row = session.exec(
            select(PackRuleCalibration).where(
                PackRuleCalibration.tenant_id == tenant_id,
                PackRuleCalibration.rule_id == rule_id,
            )
        ).first()
        if row is None:
            row = PackRuleCalibration(
                tenant_id=tenant_id,
                vertical_pack_id=pack_id,
                rule_id=rule_id,
                enabled=enabled,
                severity_override=severity_override,
                baseline=payload_baseline,
                notes=notes,
            )
            session.add(row)
            action = "insert"
        else:
            row.vertical_pack_id = pack_id
            row.enabled = enabled
            row.severity_override = severity_override
            row.baseline = payload_baseline
            row.notes = notes
            row.updated_at = _now()
            session.add(row)
            action = "update"
        session.commit()
        session.refresh(row)
        _detach(session, [row])

    logger.info(
        "calibration:set tenant=%s rule=%s enabled=%s severity=%s baseline_keys=%s action=%s",
        tenant_id,
        rule_id,
        enabled,
        severity_override,
        sorted(payload_baseline.keys()),
        action,
    )
    registry.invalidate_tenant(tenant_id)
    return row


def delete_calibration(*, tenant_id: str, rule_id: str) -> bool:
    """Drop a tenant's override for a rule — reverts to pack defaults.

    Returns True if a row was deleted, False otherwise.
    """
    with session_scope() as session:
        row = session.exec(
            select(PackRuleCalibration).where(
                PackRuleCalibration.tenant_id == tenant_id,
                PackRuleCalibration.rule_id == rule_id,
            )
        ).first()
        if row is None:
            return False
        session.delete(row)
        session.commit()

    logger.info("calibration:delete tenant=%s rule=%s", tenant_id, rule_id)
    registry.invalidate_tenant(tenant_id)
    return True


def list_calibrations(
    tenant_id: str,
    *,
    pack: str | int | None = None,
) -> list[PackRuleCalibration]:
    """Every calibration row belonging to ``tenant_id``.

    Pass ``pack`` to scope to a single vertical pack (slug or id).
    """
    with session_scope() as session:
        stmt = select(PackRuleCalibration).where(
            PackRuleCalibration.tenant_id == tenant_id
        )
        if pack is not None:
            pack_id = _resolve_pack_id(session, pack)
            stmt = stmt.where(PackRuleCalibration.vertical_pack_id == pack_id)
        stmt = stmt.order_by(
            PackRuleCalibration.vertical_pack_id,
            PackRuleCalibration.rule_id,
        )
        rows = session.exec(stmt).all()
        _detach(session, rows)
        return list(rows)


def get_calibration(
    *, tenant_id: str, rule_id: str
) -> PackRuleCalibration | None:
    """Single calibration row or None if no override exists."""
    with session_scope() as session:
        row = session.exec(
            select(PackRuleCalibration).where(
                PackRuleCalibration.tenant_id == tenant_id,
                PackRuleCalibration.rule_id == rule_id,
            )
        ).first()
        if row is None:
            return None
        _detach(session, [row])
        return row


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


def _now():
    # Indirection so tests can freeze time if needed.
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


__all__ = [
    "assign_pack",
    "delete_calibration",
    "get_calibration",
    "list_assignments",
    "list_calibrations",
    "set_calibration",
    "unassign_pack",
]
