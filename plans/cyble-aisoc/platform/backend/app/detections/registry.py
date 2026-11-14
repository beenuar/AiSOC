"""Vertical pack registry + tenant-effective engine composition (t3d-registry).

The built-in `RulePack` in :mod:`app.detections.runtime` ships the
horizontal, vertical-agnostic rules every tenant gets. This module adds
the *vertical* layer on top: a finserv tenant gets ACH-velocity and SWIFT
rules; a healthcare tenant gets PHI-egress and EMR after-hours rules;
etc. Per-rule tenant calibration (severity bumps, baseline thresholds,
disabled rules) is applied during composition so the tenant-effective
engine carries the analyst's tuning, not just the shipped defaults.

Lifecycle:

1. **Reconciliation** — on first use (or on explicit
   :func:`reload_registry`) we walk
   ``app/detections/rules/verticals/<slug>/`` and reconcile what we
   find against the :class:`VerticalPack` catalog table:

   - Slugs on disk but missing in DB → INSERT.
   - Slugs in DB but missing on disk → mark ``active=False``.
   - Existing rows are left alone (operators may have edited
     ``name`` / ``description``).

   Each disk pack is loaded into a `RulePack` and cached.

2. **Tenant composition** — :func:`get_tenant_engine` returns a
   `DetectionEngine` whose pack is::

       builtin + (enabled vertical packs for tenant)
                 with PackRuleCalibration applied

   The composed pack is cached per tenant. Cache entries are
   invalidated by :func:`invalidate_tenant` (called by API handlers
   that change assignments or calibrations).

3. **Thread safety** — every mutation goes through ``_lock``. Reads
   that hit the cache are lock-free; reads that miss take the lock to
   compose. We deliberately avoid sharing `RulePack` instances across
   tenants (a calibration override mutates the pack object), so cache
   misses always produce a fresh, owned `RulePack`.

This module never imports `runtime.py` to avoid an import cycle —
instead, callers pass the builtin pack in or we lazily import inside
the function body.
"""

from __future__ import annotations

import logging
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlmodel import Session, select

from app.db import session_scope
from app.models.detection_packs import (
    PackRuleCalibration,
    TenantPackAssignment,
    VerticalPack,
)

from .engine import DetectionEngine
from .pack import RulePack
from .sigma import Severity, SigmaRule

logger = logging.getLogger(__name__)


# Resolve to ``app/detections/rules/verticals``. Importable for tests.
_BUILTIN_RULES_ROOT = Path(__file__).parent / "rules"
_VERTICALS_ROOT = _BUILTIN_RULES_ROOT / "verticals"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Module state
# --------------------------------------------------------------------------- #

_lock = threading.Lock()

# Loaded-from-disk vertical packs, keyed by slug. Treated as immutable
# templates — never mutated after load; tenant composition deep-copies
# rules before applying calibration.
_vertical_packs: dict[str, RulePack] = {}

# Tenant-effective engines, keyed by tenant_id. Invalidate via
# :func:`invalidate_tenant` whenever the tenant's assignments or
# calibrations change.
_tenant_engines: dict[str, DetectionEngine] = {}

_reconciled: bool = False


# --------------------------------------------------------------------------- #
# Filesystem discovery + DB reconciliation
# --------------------------------------------------------------------------- #


def _discover_verticals_on_disk(root: Path) -> list[Path]:
    """Return every immediate subdirectory under ``rules/verticals/``."""
    if not root.exists() or not root.is_dir():
        return []
    return sorted(
        p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")
    )


def _humanize(slug: str) -> str:
    """Turn ``"public_sector"`` into ``"Public Sector"`` for the catalog UI."""
    return slug.replace("_", " ").replace("-", " ").title()


def _reconcile_with_db(
    session: Session, disk_dirs: list[Path]
) -> dict[str, tuple[str, bool]]:
    """Insert/deactivate :class:`VerticalPack` rows to match disk state.

    Returns ``{slug: (rel_path, active)}`` — plain values, **not** ORM
    instances. The session that loaded these rows closes immediately
    after this function returns, so handing back attached ``VerticalPack``
    objects would land callers in :class:`DetachedInstanceError` the
    moment they touched a column.

    We intentionally do **not** delete rows for disappeared packs:
    :class:`TenantPackAssignment` rows reference them, and an inactive
    catalog row is the safer history-preserving choice.
    """
    on_disk_slugs = {d.name for d in disk_dirs}
    existing = {p.slug: p for p in session.exec(select(VerticalPack)).all()}

    # INSERT missing.
    for d in disk_dirs:
        if d.name in existing:
            continue
        row = VerticalPack(
            slug=d.name,
            name=_humanize(d.name),
            description=f"Vertical detection pack for {_humanize(d.name)}.",
            path=str(d.relative_to(_BUILTIN_RULES_ROOT)),
            industry_tags=[d.name],
            active=True,
        )
        session.add(row)
        existing[d.name] = row
        logger.info("vertical_registry:insert slug=%s", d.name)

    # DEACTIVATE rows whose disk dir disappeared.
    for slug, row in list(existing.items()):
        if slug not in on_disk_slugs and row.active:
            row.active = False
            row.updated_at = _utcnow()
            session.add(row)
            logger.warning("vertical_registry:deactivate slug=%s", slug)

    session.commit()
    # Snapshot to plain values before the session closes — callers must
    # not touch row.active / row.path after session_scope() exits.
    return {slug: (row.path, row.active) for slug, row in existing.items()}


def _load_pack_from_disk(slug: str, rel_path: str) -> RulePack:
    """Load a single vertical pack's YAML rules into a `RulePack`."""
    abs_path = _BUILTIN_RULES_ROOT / rel_path
    pack = RulePack.load_directory(abs_path, name=f"vertical:{slug}", strict=False)
    return pack


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def reload_registry() -> dict[str, RulePack]:
    """Reconcile DB↔disk and reload every vertical pack into memory.

    Called automatically on first use of :func:`get_tenant_engine` and
    explicitly by tests / admin tools that just added a pack on disk.
    All tenant caches are invalidated since composed engines may now
    reference a stale pack.
    """
    global _reconciled
    disk_dirs = _discover_verticals_on_disk(_VERTICALS_ROOT)

    with _lock:
        with session_scope() as session:
            catalog = _reconcile_with_db(session, disk_dirs)

        loaded: dict[str, RulePack] = {}
        for slug, (rel_path, active) in catalog.items():
            if not active:
                continue
            try:
                loaded[slug] = _load_pack_from_disk(slug, rel_path)
            except FileNotFoundError:
                logger.warning(
                    "vertical_registry:missing_dir slug=%s path=%s", slug, rel_path
                )
                continue
        _vertical_packs.clear()
        _vertical_packs.update(loaded)
        _tenant_engines.clear()
        _reconciled = True
        logger.info(
            "vertical_registry:reloaded packs=%d rules=%d",
            len(loaded),
            sum(len(p) for p in loaded.values()),
        )
        return dict(loaded)


def _ensure_reconciled() -> None:
    if _reconciled:
        return
    reload_registry()


def list_vertical_packs() -> list[VerticalPack]:
    """Return the catalog rows for every known vertical pack.

    Rows are eagerly read and detached from the session so callers can
    safely access columns after this returns. ``session_scope()`` commits
    on exit, which under SQLAlchemy's default ``expire_on_commit=True``
    invalidates every attribute; we work around that by reading the
    columns we care about and expunging.
    """
    _ensure_reconciled()
    with session_scope() as session:
        rows = session.exec(
            select(VerticalPack).order_by(VerticalPack.slug)
        ).all()
        # Touch every column so SQLAlchemy loads them while the session
        # is still alive, then expunge to fully detach.
        for r in rows:
            _ = (r.id, r.slug, r.name, r.description, r.path, r.industry_tags, r.active, r.created_at, r.updated_at)
        for r in rows:
            session.expunge(r)
        return list(rows)


def get_vertical_pack(slug: str) -> RulePack | None:
    """Return the in-memory `RulePack` for a vertical, or None if unknown."""
    _ensure_reconciled()
    return _vertical_packs.get(slug)


def _apply_calibration(rule: SigmaRule, cal: PackRuleCalibration) -> Optional[SigmaRule]:
    """Apply one calibration row to a (deep-copied) rule.

    Returns None when the calibration disables the rule — the composer
    drops it from the pack rather than carrying a flagged-but-inert rule
    that would still show up in introspection endpoints.
    """
    if not cal.enabled:
        return None

    if cal.severity_override:
        try:
            rule.severity = Severity.from_str(cal.severity_override)
        except Exception:  # pragma: no cover - Severity.from_str is permissive
            logger.warning(
                "vertical_registry:bad_severity_override rule=%s value=%s",
                rule.id,
                cal.severity_override,
            )

    if cal.baseline:
        # Stash the baseline on the rule's `raw` dict — that's the
        # explicit passthrough container SigmaRule reserves for fields
        # the parser didn't recognize. Rule matchers that opt in can
        # read ``rule.raw.get("_calibration_baseline", {})`` and consult
        # tenant-specific thresholds (e.g. "this tenant's normal ACH
        # transfer rate is 800/hour ± 200"). The engine treats it as
        # opaque — only the rule body knows the schema.
        if isinstance(rule.raw, dict):
            rule.raw["_calibration_baseline"] = cal.baseline
        else:  # pragma: no cover - SigmaRule.raw always inits to {}
            rule.raw = {"_calibration_baseline": cal.baseline}

    return rule


def _compose_tenant_pack(
    tenant_id: str,
    session: Session,
    builtin_pack: RulePack,
) -> RulePack:
    """Build the tenant-effective `RulePack`.

    Composition order:
      1. Start with a deep copy of the built-in pack (always present).
      2. For every *enabled* :class:`TenantPackAssignment`, fold in a
         deep copy of the named vertical pack.
      3. For every :class:`PackRuleCalibration` row, apply the override
         to the matching rule (by ``rule_id``). Calibrations for a rule
         that is not in the composed pack are silently ignored — they
         may belong to a pack the tenant un-assigned.

    Deep-copying is necessary because calibration mutates rule fields
    (severity, custom dict). Sharing pack rules across tenants would
    cross-contaminate.
    """
    composed = RulePack(name=f"tenant:{tenant_id}")
    # 1. Built-in.
    for r in builtin_pack:
        composed.add(deepcopy(r))

    # 2. Enabled vertical packs.
    assignments = session.exec(
        select(TenantPackAssignment).where(
            TenantPackAssignment.tenant_id == tenant_id,
            TenantPackAssignment.enabled == True,  # noqa: E712 - SQLModel comparison
        )
    ).all()
    pack_id_to_slug: dict[int, str] = {}
    for assign in assignments:
        catalog_row = session.get(VerticalPack, assign.vertical_pack_id)
        if catalog_row is None or not catalog_row.active:
            continue
        pack = _vertical_packs.get(catalog_row.slug)
        if pack is None:
            logger.warning(
                "vertical_registry:assigned_pack_not_loaded tenant=%s slug=%s",
                tenant_id,
                catalog_row.slug,
            )
            continue
        pack_id_to_slug[assign.vertical_pack_id] = catalog_row.slug
        for r in pack:
            composed.add(deepcopy(r))

    # 3. Per-rule calibration.
    calibrations = session.exec(
        select(PackRuleCalibration).where(
            PackRuleCalibration.tenant_id == tenant_id,
            PackRuleCalibration.vertical_pack_id.in_(list(pack_id_to_slug.keys())),
        )
        if pack_id_to_slug
        else select(PackRuleCalibration).where(
            PackRuleCalibration.tenant_id == tenant_id
        )
    ).all()

    for cal in calibrations:
        rule = composed.by_id(cal.rule_id)
        if rule is None:
            continue
        tuned = _apply_calibration(rule, cal)
        if tuned is None:
            composed.rules = [r for r in composed.rules if r.id != cal.rule_id]

    logger.info(
        "vertical_registry:composed tenant=%s rules=%d packs=%d cals=%d",
        tenant_id,
        len(composed),
        len(pack_id_to_slug),
        len(calibrations),
    )
    return composed


def get_tenant_engine(
    tenant_id: str, builtin_pack: RulePack | None = None
) -> DetectionEngine:
    """Return the tenant-effective `DetectionEngine`, building on cache miss.

    ``builtin_pack`` is the horizontal pack served by ``runtime.py``.
    Callers normally don't pass it — we lazily import ``runtime`` to
    avoid an import cycle at module load — but tests can inject a
    fixture pack for hermeticity.
    """
    if not tenant_id:
        raise ValueError("get_tenant_engine requires a non-empty tenant_id")

    cached = _tenant_engines.get(tenant_id)
    if cached is not None:
        return cached

    _ensure_reconciled()

    if builtin_pack is None:
        # Local import to break cycle: runtime.py is the canonical
        # owner of the built-in pack, and it does not depend on this
        # module.
        from . import runtime as _runtime

        builtin_pack = _runtime.get_pack()

    with _lock:
        # Re-check under lock (double-checked locking).
        cached = _tenant_engines.get(tenant_id)
        if cached is not None:
            return cached
        with session_scope() as session:
            composed = _compose_tenant_pack(tenant_id, session, builtin_pack)
        engine = DetectionEngine(pack=composed)
        _tenant_engines[tenant_id] = engine
        return engine


def invalidate_tenant(tenant_id: str) -> None:
    """Drop the cached engine for ``tenant_id``.

    Call after any write to :class:`TenantPackAssignment` or
    :class:`PackRuleCalibration` rows belonging to this tenant.
    """
    with _lock:
        _tenant_engines.pop(tenant_id, None)
    logger.info("vertical_registry:invalidated tenant=%s", tenant_id)


def invalidate_all() -> None:
    """Drop every cached tenant engine.

    Called by :func:`reload_registry` and by tests; production code
    should prefer :func:`invalidate_tenant` to keep cache pressure low.
    """
    with _lock:
        _tenant_engines.clear()


def reset() -> None:
    """Hard reset — for tests. Forces a full reconcile on next access."""
    global _reconciled
    with _lock:
        _vertical_packs.clear()
        _tenant_engines.clear()
        _reconciled = False


__all__ = [
    "get_tenant_engine",
    "get_vertical_pack",
    "invalidate_all",
    "invalidate_tenant",
    "list_vertical_packs",
    "reload_registry",
    "reset",
]
