"""Smoke check for the vertical pack registry + tenant composition (t3d-registry).

End-to-end verification of the registry layer that sits between the
built-in horizontal rule pack and the per-tenant ``DetectionEngine``.
Exercises every wire-in:

  * Disk discovery — five vertical pack directories ship under
    ``app/detections/rules/verticals/`` (finserv, healthcare, retail,
    manufacturing, public_sector). The registry walks that tree and
    inserts a :class:`VerticalPack` catalog row for each.
  * DB↔disk reconciliation — first call to
    :func:`registry.reload_registry` populates the empty catalog; a
    second call against the same disk state is a no-op (idempotent).
  * Built-in pack isolation — :func:`runtime.get_pack` must NOT
    include any rule tagged ``aisoc.vertical.*`` (verifies the
    ``exclude_subdirs`` plumbing added to ``RulePack.load_directory``
    and ``runtime._build_engine``). Verticals are exclusively owned
    by the registry; loading them twice (once via builtin, once via
    a tenant assignment) would double-fire and break multi-tenancy.
  * Unassigned tenant — :func:`registry.get_tenant_engine` for a
    tenant with zero :class:`TenantPackAssignment` rows returns an
    engine whose pack rule-count equals the built-in pack's. No
    vertical rules leak in.
  * Assigned tenant — after persisting a single
    :class:`TenantPackAssignment` row for the finserv pack, the
    composed pack carries every built-in rule **plus** every finserv
    rule, and finserv rule IDs resolve via ``pack.by_id``.
  * Disable calibration — a :class:`PackRuleCalibration` row with
    ``enabled=False`` drops the matching finserv rule from the
    composed pack; ``by_id`` returns None after cache invalidation.
  * Severity override — ``severity_override='critical'`` mutates the
    composed rule's :class:`~app.detections.sigma.Severity` without
    touching the on-disk template (verified via deep-copy semantics:
    the loaded ``_vertical_packs`` snapshot stays untouched).
  * Baseline passthrough — a non-empty ``baseline`` JSON blob lands
    on the composed rule under ``rule.raw["_calibration_baseline"]``,
    which is the explicit passthrough container ``SigmaRule`` reserves
    for unrecognized / custom metadata. Rule matchers consult it at
    eval time.
  * Tenant cache invalidation — :func:`registry.invalidate_tenant`
    drops the cached engine for one tenant without disturbing other
    tenants' caches.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_vertical_pack_registry.py

Exits non-zero on any failure with a FAIL marker; prints PASS on green.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-vpack-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import select  # noqa: E402

from app.db import init_db, session_scope  # noqa: E402
from app.detections import registry, runtime  # noqa: E402
from app.detections.sigma import Severity  # noqa: E402
from app.models.detection_packs import (  # noqa: E402
    PackRuleCalibration,
    TenantPackAssignment,
    VerticalPack,
)


EXPECTED_SLUGS = {"finserv", "healthcare", "manufacturing", "public_sector", "retail"}
FINSERV_RULE_ID = "aisoc-vt-fin-0004-ach-velocity-anomaly"
RULES_PER_PACK = 5  # 25 vertical rules / 5 packs
TENANT_A = "tenant-finserv-a"
TENANT_B = "tenant-noverticals-b"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"ok   {msg}")


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


def check_reconciliation() -> dict[str, int]:
    """Reload the registry from a clean DB and verify catalog rows.

    Returns a slug → VerticalPack.id map for downstream checks that
    need the integer FK.
    """
    loaded = registry.reload_registry()
    if set(loaded.keys()) != EXPECTED_SLUGS:
        _fail(
            f"loaded slugs {sorted(loaded.keys())} != expected {sorted(EXPECTED_SLUGS)}"
        )
    _ok(f"loaded {len(loaded)} vertical packs from disk: {sorted(loaded.keys())}")

    # Each pack should carry exactly RULES_PER_PACK rules (5 each, 25 total).
    rule_counts = {slug: len(p.rules) for slug, p in loaded.items()}
    for slug, n in rule_counts.items():
        if n != RULES_PER_PACK:
            _fail(f"pack {slug} has {n} rules, expected {RULES_PER_PACK}")
    _ok(f"each pack carries {RULES_PER_PACK} rules ({sum(rule_counts.values())} total)")

    # Catalog rows match disk.
    with session_scope() as session:
        rows = session.exec(select(VerticalPack)).all()
        if len(rows) != len(EXPECTED_SLUGS):
            _fail(f"catalog has {len(rows)} rows, expected {len(EXPECTED_SLUGS)}")
        for row in rows:
            if not row.active:
                _fail(f"catalog row {row.slug} is inactive on first reconcile")
            if not row.path:
                _fail(f"catalog row {row.slug} has empty path")
        slug_to_id = {row.slug: row.id for row in rows}
    _ok("catalog rows persisted with active=True and non-empty paths")

    # Idempotency: a second reconcile against the same disk state must
    # produce the same catalog (no duplicate inserts, no deactivations).
    loaded2 = registry.reload_registry()
    if set(loaded2.keys()) != EXPECTED_SLUGS:
        _fail(f"second reload produced different slugs: {sorted(loaded2.keys())}")
    with session_scope() as session:
        rows2 = session.exec(select(VerticalPack)).all()
        if len(rows2) != len(EXPECTED_SLUGS):
            _fail(f"second reconcile inserted dupes: {len(rows2)} rows")
    _ok("second reconcile is idempotent (no dupe inserts)")
    return slug_to_id


def check_builtin_excludes_verticals() -> int:
    """The horizontal built-in pack must NOT contain any vertical rules."""
    builtin_pack = runtime.get_pack()
    builtin_count = len(builtin_pack)
    # Tag check: vertical rules carry an ``aisoc.vertical.<slug>`` tag.
    leaked = [
        r.id
        for r in builtin_pack
        if any(t.startswith("aisoc.vertical.") for t in (r.tags or []))
    ]
    if leaked:
        _fail(
            f"builtin pack leaked {len(leaked)} vertical rules: {leaked[:5]}"
        )
    _ok(f"builtin pack carries {builtin_count} rules, zero vertical leakage")
    return builtin_count


def check_unassigned_tenant(builtin_count: int) -> None:
    """A tenant with no assignments gets the built-in pack verbatim."""
    engine = registry.get_tenant_engine(TENANT_B)
    n = len(engine.pack)
    if n != builtin_count:
        _fail(
            f"unassigned tenant pack has {n} rules, expected {builtin_count} (builtin)"
        )
    _ok(f"unassigned tenant gets {n} rules (= builtin count)")


def check_assigned_tenant(slug_to_id: dict[str, int], builtin_count: int) -> None:
    """A tenant assigned to finserv gets builtin + 5 finserv rules."""
    finserv_id = slug_to_id["finserv"]
    with session_scope() as session:
        session.add(
            TenantPackAssignment(
                tenant_id=TENANT_A,
                vertical_pack_id=finserv_id,
                enabled=True,
                assigned_by="smoke-test",
            )
        )
        session.commit()

    # Cache miss path: nothing cached yet for TENANT_A.
    engine = registry.get_tenant_engine(TENANT_A)
    expected = builtin_count + RULES_PER_PACK
    if len(engine.pack) != expected:
        _fail(
            f"assigned tenant pack has {len(engine.pack)} rules, "
            f"expected {expected} (builtin + finserv)"
        )
    if engine.pack.by_id(FINSERV_RULE_ID) is None:
        _fail(f"finserv rule {FINSERV_RULE_ID} missing from composed pack")
    _ok(
        f"assigned tenant gets {len(engine.pack)} rules "
        f"(builtin {builtin_count} + finserv {RULES_PER_PACK})"
    )

    # Cache hit: second call returns the same object.
    engine2 = registry.get_tenant_engine(TENANT_A)
    if engine2 is not engine:
        _fail("tenant cache miss on second call — composition is not memoized")
    _ok("tenant engine is memoized across calls")


def check_calibration_disable(slug_to_id: dict[str, int], builtin_count: int) -> None:
    """A calibration row with enabled=False drops the rule from the pack."""
    finserv_id = slug_to_id["finserv"]
    with session_scope() as session:
        session.add(
            PackRuleCalibration(
                tenant_id=TENANT_A,
                vertical_pack_id=finserv_id,
                rule_id=FINSERV_RULE_ID,
                enabled=False,
                notes="smoke-test: disable ACH velocity",
            )
        )
        session.commit()

    # Invalidate so the next get_tenant_engine recomposes.
    registry.invalidate_tenant(TENANT_A)
    engine = registry.get_tenant_engine(TENANT_A)
    expected = builtin_count + RULES_PER_PACK - 1  # one rule dropped
    if len(engine.pack) != expected:
        _fail(
            f"after disable, pack has {len(engine.pack)} rules, expected {expected}"
        )
    if engine.pack.by_id(FINSERV_RULE_ID) is not None:
        _fail(f"disabled rule {FINSERV_RULE_ID} still in pack")
    _ok(
        f"calibration disable dropped {FINSERV_RULE_ID} "
        f"(pack now {len(engine.pack)} rules)"
    )

    # The on-disk template is untouched — composition deep-copies before
    # mutating. Re-loading from disk would still produce 5 finserv rules.
    template = registry.get_vertical_pack("finserv")
    assert template is not None
    if len(template) != RULES_PER_PACK:
        _fail(
            f"vertical pack template mutated: has {len(template)} rules, "
            f"expected {RULES_PER_PACK}"
        )
    if template.by_id(FINSERV_RULE_ID) is None:
        _fail("vertical pack template lost the rule we disabled for a tenant")
    _ok("vertical pack template unchanged (deep-copy isolation holds)")


def check_calibration_severity_and_baseline(
    slug_to_id: dict[str, int], builtin_count: int
) -> None:
    """severity_override + baseline land on the composed rule."""
    finserv_id = slug_to_id["finserv"]
    target_rule = "aisoc-vt-fin-0001-swift-unusual-correspondent"
    baseline_blob = {
        "thresholds": {"transfers_per_hour": 800, "stdev_window_days": 30},
        "tenant_notes": "ACH baseline for region EMEA-1",
    }
    with session_scope() as session:
        session.add(
            PackRuleCalibration(
                tenant_id=TENANT_A,
                vertical_pack_id=finserv_id,
                rule_id=target_rule,
                enabled=True,
                severity_override="critical",
                baseline=baseline_blob,
                notes="smoke-test: bump severity + attach baseline",
            )
        )
        session.commit()

    registry.invalidate_tenant(TENANT_A)
    engine = registry.get_tenant_engine(TENANT_A)
    rule = engine.pack.by_id(target_rule)
    if rule is None:
        _fail(f"target rule {target_rule} missing after calibration")
    if rule.severity != Severity.CRITICAL:
        _fail(
            f"severity_override didn't take: rule.severity={rule.severity}, "
            "expected CRITICAL"
        )
    _ok(f"severity_override='critical' applied to {target_rule}")

    cal_baseline = rule.raw.get("_calibration_baseline")
    if cal_baseline != baseline_blob:
        _fail(
            f"baseline didn't land on rule.raw: got {cal_baseline!r}, "
            f"expected {baseline_blob!r}"
        )
    _ok("baseline JSON landed on rule.raw['_calibration_baseline']")

    # Other tenant still untouched.
    engine_b = registry.get_tenant_engine(TENANT_B)
    if any(
        r.id == target_rule for r in engine_b.pack
    ):
        _fail("calibration leaked across tenants (TENANT_B sees finserv rule)")
    _ok("calibration is tenant-scoped (TENANT_B unaffected)")


def check_invalidation_isolation() -> None:
    """invalidate_tenant only drops the named tenant's cache."""
    # Prime both caches.
    eng_a_before = registry.get_tenant_engine(TENANT_A)
    eng_b_before = registry.get_tenant_engine(TENANT_B)

    registry.invalidate_tenant(TENANT_A)

    eng_a_after = registry.get_tenant_engine(TENANT_A)
    eng_b_after = registry.get_tenant_engine(TENANT_B)

    if eng_a_after is eng_a_before:
        _fail("invalidate_tenant(A) did not drop A's cache (same object returned)")
    if eng_b_after is not eng_b_before:
        _fail("invalidate_tenant(A) collateral-damaged B's cache")
    _ok("invalidate_tenant is scoped to the named tenant only")


def check_unknown_tenant_empty_assignments(builtin_count: int) -> None:
    """A fresh tenant id (no DB rows) yields the builtin-only pack."""
    eng = registry.get_tenant_engine("ad-hoc-tenant-never-assigned")
    if len(eng.pack) != builtin_count:
        _fail(
            f"unknown tenant pack has {len(eng.pack)} rules, "
            f"expected {builtin_count}"
        )
    _ok("unknown tenant_id returns builtin-only engine without errors")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> None:
    init_db()
    _ok(f"isolated DB initialized at {DB_PATH}")

    slug_to_id = check_reconciliation()
    builtin_count = check_builtin_excludes_verticals()
    check_unassigned_tenant(builtin_count)
    check_assigned_tenant(slug_to_id, builtin_count)
    check_calibration_disable(slug_to_id, builtin_count)
    check_calibration_severity_and_baseline(slug_to_id, builtin_count)
    check_invalidation_isolation()
    check_unknown_tenant_empty_assignments(builtin_count)

    print("PASS vertical pack registry smoke test")


if __name__ == "__main__":
    main()
