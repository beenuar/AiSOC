"""Smoke check for tenant-aware engine routing in detections/runtime.py (t3d-runtime).

The runtime module owns the process-wide builtin engine but also acts
as the public facade that ingestion code calls into. This test pins
down the delegation contract between ``runtime`` and ``registry``:

  * ``get_engine_for_tenant`` returns the *tenant-effective* engine —
    builtin rules plus any verticals the tenant is assigned to plus
    calibrations applied. It must NOT return the global builtin engine
    when the tenant has assignments, because that would silently skip
    every vertical pack the tenant paid for.
  * ``get_pack_for_tenant`` mirrors ``get_engine_for_tenant`` and
    exposes the composed RulePack for introspection (rule list
    endpoints).
  * ``invalidate_tenant`` clears one tenant's cache without touching
    the global builtin engine or other tenants' caches.
  * ``reload()`` rebuilds the builtin engine AND invalidates every
    cached tenant engine. Tenants that had assignments before the
    reload re-compose against the new builtin without leaking stale
    references to the pre-reload pack.
  * ``reset()`` drops the global builtin engine *and* clears every
    tenant cache. Required for tests that swap rule directories
    between cases; without it, the stale builtin would haunt the
    next composition.
  * The global :func:`get_engine` and tenant-aware
    :func:`get_engine_for_tenant` are NOT interchangeable: for a
    tenant with at least one assignment, they MUST return different
    engines with different rule counts. This is the regression test
    for the original tenant-agnostic ingest code path.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_tenant_engine_routing.py

Exits non-zero on failure with a FAIL marker; prints PASS on green.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-runtime-routing-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import select  # noqa: E402

from app.db import init_db, session_scope  # noqa: E402
from app.detections import registry, runtime  # noqa: E402
from app.models.detection_packs import TenantPackAssignment, VerticalPack  # noqa: E402


TENANT_FIN = "tenant-routing-finserv"
TENANT_BARE = "tenant-routing-bare"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"ok   {msg}")


def _assign_finserv(tenant_id: str) -> None:
    """Assign the finserv vertical pack to ``tenant_id``."""
    with session_scope() as session:
        finserv = session.exec(
            select(VerticalPack).where(VerticalPack.slug == "finserv")
        ).first()
        if finserv is None:
            _fail("finserv pack not in catalog — registry.reload_registry() didn't run")
        session.add(
            TenantPackAssignment(
                tenant_id=tenant_id,
                vertical_pack_id=finserv.id,
                enabled=True,
                assigned_by="routing-smoke-test",
            )
        )
        session.commit()


def check_global_vs_tenant_diverge() -> None:
    """get_engine() and get_engine_for_tenant() must differ for assigned tenants.

    This is the headline regression: before t3d-runtime, ``/events``
    called ``get_engine()`` and never saw a single vertical rule even
    for tenants explicitly assigned to a pack.
    """
    global_engine = runtime.get_engine()
    tenant_engine = runtime.get_engine_for_tenant(TENANT_FIN)

    if global_engine is tenant_engine:
        _fail(
            "get_engine() and get_engine_for_tenant() returned the SAME object "
            "for an assigned tenant — tenant routing is bypassed"
        )

    g_count = len(global_engine.pack)
    t_count = len(tenant_engine.pack)
    if t_count <= g_count:
        _fail(
            f"assigned tenant pack ({t_count} rules) is not larger than "
            f"builtin ({g_count} rules) — vertical rules didn't compose in"
        )
    _ok(
        f"global engine has {g_count} rules; finserv-assigned tenant has "
        f"{t_count} rules (delta={t_count - g_count})"
    )


def check_bare_tenant_matches_builtin() -> None:
    """A tenant with no assignments shares the builtin rule-count."""
    g_count = len(runtime.get_engine().pack)
    bare = runtime.get_engine_for_tenant(TENANT_BARE)
    if len(bare.pack) != g_count:
        _fail(
            f"unassigned tenant has {len(bare.pack)} rules, expected "
            f"{g_count} (builtin)"
        )
    _ok(f"unassigned tenant gets builtin-only pack ({g_count} rules)")


def check_get_pack_for_tenant_mirrors_engine() -> None:
    """``get_pack_for_tenant`` returns the same pack as ``get_engine_for_tenant``."""
    engine = runtime.get_engine_for_tenant(TENANT_FIN)
    pack = runtime.get_pack_for_tenant(TENANT_FIN)
    if pack is not engine.pack:
        _fail("get_pack_for_tenant returned a different pack object than the engine's")
    _ok("get_pack_for_tenant mirrors the engine's pack (same identity)")


def check_invalidate_tenant_scoped() -> None:
    """invalidate_tenant clears one tenant; builtin + other tenants survive."""
    eng_fin_before = runtime.get_engine_for_tenant(TENANT_FIN)
    eng_bare_before = runtime.get_engine_for_tenant(TENANT_BARE)
    global_before = runtime.get_engine()

    runtime.invalidate_tenant(TENANT_FIN)

    eng_fin_after = runtime.get_engine_for_tenant(TENANT_FIN)
    eng_bare_after = runtime.get_engine_for_tenant(TENANT_BARE)
    global_after = runtime.get_engine()

    if eng_fin_after is eng_fin_before:
        _fail("invalidate_tenant(FIN) did not drop FIN's cache")
    if eng_bare_after is not eng_bare_before:
        _fail("invalidate_tenant(FIN) collateral-damaged BARE's cache")
    if global_after is not global_before:
        _fail("invalidate_tenant(FIN) rebuilt the global builtin engine")
    _ok("invalidate_tenant is scoped: FIN dropped, BARE + builtin survived")


def check_reload_invalidates_all_tenants() -> None:
    """runtime.reload() must rebuild builtin AND clear every tenant cache."""
    # Prime caches.
    eng_fin_before = runtime.get_engine_for_tenant(TENANT_FIN)
    eng_bare_before = runtime.get_engine_for_tenant(TENANT_BARE)
    global_before = runtime.get_engine()

    runtime.reload()

    # All three should be new objects.
    if runtime.get_engine() is global_before:
        _fail("runtime.reload() did not rebuild the global engine")
    if runtime.get_engine_for_tenant(TENANT_FIN) is eng_fin_before:
        _fail("runtime.reload() did not invalidate tenant FIN's cache")
    if runtime.get_engine_for_tenant(TENANT_BARE) is eng_bare_before:
        _fail("runtime.reload() did not invalidate tenant BARE's cache")

    # And the composed pack still includes verticals for the assigned tenant.
    refreshed = runtime.get_engine_for_tenant(TENANT_FIN)
    g_count = len(runtime.get_engine().pack)
    if len(refreshed.pack) <= g_count:
        _fail(
            "after reload, finserv tenant pack didn't re-compose: "
            f"{len(refreshed.pack)} rules <= builtin {g_count}"
        )
    _ok(
        f"runtime.reload() rebuilt builtin and re-composed tenant packs "
        f"(finserv now {len(refreshed.pack)} rules)"
    )


def check_reset_drops_everything() -> None:
    """runtime.reset() drops the global engine and every tenant cache."""
    # Make sure caches are populated.
    runtime.get_engine()
    runtime.get_engine_for_tenant(TENANT_FIN)

    runtime.reset()

    # Internal state should be cleared; we probe via the registry cache
    # directly since runtime exposes no introspection of _engine.
    if registry._tenant_engines:  # noqa: SLF001 — internals check is the point
        _fail(
            f"runtime.reset() left tenant cache populated: "
            f"{list(registry._tenant_engines.keys())}"  # noqa: SLF001
        )
    _ok("runtime.reset() cleared the registry tenant cache")

    # Next call rebuilds cleanly with the right composition.
    eng = runtime.get_engine_for_tenant(TENANT_FIN)
    g_count = len(runtime.get_engine().pack)
    if len(eng.pack) <= g_count:
        _fail(
            "after reset, finserv tenant pack didn't re-compose: "
            f"{len(eng.pack)} rules <= builtin {g_count}"
        )
    _ok(f"post-reset compositions work (finserv: {len(eng.pack)} rules)")


def main() -> None:
    init_db()
    _ok(f"isolated DB initialized at {DB_PATH}")

    # Bring the registry's catalog in sync with disk so finserv has an id.
    registry.reload_registry()
    _ok("registry reconciled with disk")

    _assign_finserv(TENANT_FIN)
    _ok(f"assigned finserv pack to {TENANT_FIN}")

    check_global_vs_tenant_diverge()
    check_bare_tenant_matches_builtin()
    check_get_pack_for_tenant_mirrors_engine()
    check_invalidate_tenant_scoped()
    check_reload_invalidates_all_tenants()
    check_reset_drops_everything()

    print("PASS tenant engine routing smoke test")


if __name__ == "__main__":
    main()
