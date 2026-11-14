#!/usr/bin/env python3
"""No literal route may be unreachable behind an earlier parameterised one.

FastAPI matches in registration order. ``DELETE /{action}`` declared before
``DELETE /grants`` takes every request for ``/grants`` with ``action="grants"``,
so the literal handler never runs. Both routes exist, both look correct where
they are written, and they are usually hundreds of lines apart.

This has shipped twice. ``GET /api/v1/assets/vulnerabilities`` went first, and
``DELETE /api/v1/autonomy-policy/grants`` went the same way: an operator could
earn an autonomy grant and had no working path to hand it back, which is a
safety control failing in the one direction that matters.

Why this is a second gate rather than the only one
--------------------------------------------------
``services/api/tests/test_route_shadowing.py`` decides reachability the honest
way: it builds the app, takes the inventory from ``app.openapi()``, sends a
request for every published operation and reads back which route Starlette
matched. Nothing approximates anything. But that needs the service's whole
driver stack importable, so it can only ever speak for one service at a time,
and twelve others were covered by nothing at all.

This gate is the breadth half: one AST pass over ``services/``, no imports, so
every service is read in one run. It is the weaker instrument of the two and
says so in its own output rather than implying otherwise:

* it pairs routes within a module and router, because that is where
  registration order is legible statically. Two modules included under one
  prefix can shadow each other and this will not see it.
* a parameter carrying a path convertor is *not* judged here. A convertor
  takes part in matching and can be exactly what makes the literal reachable
  (it is, in ``autonomy_policy``), and whether it does is a question about a
  compiled regex this pass never sees. Those pairs are counted and named on
  every run, so deferring them stays visible instead of turning into silence.

It shares ``check_route_tenant_scope``'s collector for the same reason
``check_route_auth`` does: one corpus and one floor, so a third scanner cannot
drift from the first two.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Imported as a module, never by name: `REPO_ROOT` and `SERVICES_DIR` are
# module state the shared empty-corpus self-test rebinds to a scratch tree,
# and a from-import would copy the originals and go on scanning the real
# checkout while believing it was pointed at an empty one.
import check_route_tenant_scope as route_scan  # noqa: E402

#: Convertors that constrain nothing a literal segment could not satisfy. A
#: parameter carrying one of these swallows a sibling literal exactly as a
#: bare `{param}` does, so it is judged rather than deferred.
UNCONSTRAINING_CONVERTORS = frozenset({"", "str", "path"})


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _is_param(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _convertor(segment: str) -> str:
    """The convertor named on a path parameter, or ``""`` for a bare one."""
    inner = segment[1:-1]
    return inner.split(":", 1)[1].strip() if ":" in inner else ""


def shadows(earlier: str, later: str) -> tuple[bool, bool]:
    """Whether ``earlier`` captures ``later``, and whether that is decidable here.

    Returns ``(captures, decidable)``. A parameter carrying a custom convertor
    makes the pair undecidable statically: the convertor is part of the
    matching regex and may well be the reason the literal is reachable.
    """
    a, b = _segments(earlier), _segments(later)
    if len(a) != len(b):
        return False, True

    captures = False
    decidable = True
    for seg_a, seg_b in zip(a, b, strict=True):
        if seg_a == seg_b:
            continue
        if _is_param(seg_a) and not _is_param(seg_b):
            captures = True
            if _convertor(seg_a) not in UNCONSTRAINING_CONVERTORS:
                decidable = False
            continue
        return False, True
    return captures, decidable


def unresolved_paths(routes: list[route_scan.Route]) -> list[str]:
    """Routes whose path this pass could not read, and so never judged.

    A decorator handed a variable rather than a string literal is invisible
    here. That is not hypothetical: the fix this gate was written alongside
    used a shared constant at first, and the gate went on printing OK while
    silently skipping the very pair it exists for. Naming them costs one line
    and makes the blind spot countable.
    """
    return sorted(f"{r.path}:{r.lineno} {r.function}()" for r in routes if not r.path_is_literal)


def find_shadowed(routes: list[route_scan.Route]) -> tuple[list[str], list[str]]:
    """Every unreachable route, and every pair left to the runtime check."""
    groups: dict[tuple[str, str, str], list[route_scan.Route]] = {}
    for route in routes:
        # A route with no resolvable router object cannot be ordered against
        # anything, so it forms its own group and is compared with nothing.
        for router in route.router_objs or [f"?{route.lineno}"]:
            groups.setdefault((route.service, route.path, router), []).append(route)

    unreachable: list[str] = []
    deferred: list[str] = []
    for (_service, path, _router), group in sorted(groups.items()):
        group.sort(key=lambda r: r.lineno)
        for index, later in enumerate(group):
            for earlier in group[:index]:
                shared = sorted(set(earlier.methods) & set(later.methods))
                if not shared:
                    continue
                captures, decidable = shadows(earlier.route_path, later.route_path)
                if not captures:
                    continue
                where = f"{path}:{later.lineno} {[m.upper() for m in shared]} {later.route_path}"
                if decidable:
                    unreachable.append(
                        f"{where} is unreachable: {earlier.route_path} is registered first "
                        f"(line {earlier.lineno}, {earlier.function}) and will match it. "
                        "Constrain the parameter with a path convertor, or give the literal a path it cannot collide with."
                    )
                else:
                    deferred.append(f"{where} is guarded by a convertor on {earlier.route_path} (line {earlier.lineno})")
    return unreachable, deferred


# ── self-test ──────────────────────────────────────────────────────────────

_SHADOWED = """
from fastapi import APIRouter
router = APIRouter(prefix="/autonomy-policy")

@router.delete("/{action}")
async def reset(action: str) -> None:
    return None

@router.delete("/grants")
async def revoke() -> None:
    return None
"""

_CONSTRAINED = _SHADOWED.replace("/{action}", "/{action:autonomy_action}")

_CLEAN = """
from fastapi import APIRouter
router = APIRouter(prefix="/autonomy-policy")

@router.delete("/grants")
async def revoke() -> None:
    return None

@router.delete("/{action}")
async def reset(action: str) -> None:
    return None
"""

_TWO_ROUTERS = """
from fastapi import APIRouter
router = APIRouter(prefix="/policy")
other = APIRouter(prefix="/elsewhere")

@router.delete("/{action}")
async def reset(action: str) -> None:
    return None

@other.delete("/grants")
async def revoke() -> None:
    return None
"""


def _scan_source(source: str) -> tuple[list[str], list[str]]:
    """Run the gate over a scratch ``services/`` tree holding one module."""
    global_root, global_services = route_scan.REPO_ROOT, route_scan.SERVICES_DIR
    with tempfile.TemporaryDirectory(prefix="route_shadow_") as tmp:
        root = Path(tmp)
        module = root / "services" / "api" / "app" / "endpoints.py"
        module.parent.mkdir(parents=True)
        module.write_text(source, encoding="utf-8")
        route_scan.REPO_ROOT, route_scan.SERVICES_DIR = root, root / "services"
        try:
            return find_shadowed(route_scan.collect_routes())
        finally:
            route_scan.REPO_ROOT, route_scan.SERVICES_DIR = global_root, global_services


def _self_test() -> int:
    """A gate nobody has seen fail is indistinguishable from one that cannot.

    Each case is the real defect or a near miss of it, so a refactor that
    quietly breaks detection shows up here rather than in an incident.
    """
    failures = 0

    cases: list[tuple[str, str, bool, bool]] = [
        ("the shipped defect: DELETE /grants behind DELETE /{action}", _SHADOWED, True, False),
        ("a bare parameter is judged, not deferred", _SHADOWED, True, False),
        ("the literal declared first is reachable", _CLEAN, False, False),
        ("a convertor on the parameter is deferred, not called clean or broken", _CONSTRAINED, False, True),
        ("routes on two different routers are not paired", _TWO_ROUTERS, False, False),
    ]
    for label, source, expect_unreachable, expect_deferred in cases:
        unreachable, deferred = _scan_source(source)
        ok = bool(unreachable) is expect_unreachable and bool(deferred) is expect_deferred
        failures += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            print(f"        unreachable={unreachable} deferred={deferred}")

    failures += route_scan.self_test_empty_corpus("check_route_shadowing", lambda: main([]))

    print()
    if failures:
        print(f"check_route_shadowing: self-test FAILED ({failures} case(s))")
        return 1
    print("check_route_shadowing: self-test OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects the defect it exists for")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not route_scan.SERVICES_DIR.is_dir():
        print(
            f"ERROR: no services/ directory under {route_scan.REPO_ROOT}, so there is no tree to report a result for.",
            file=sys.stderr,
        )
        return 2

    routes = route_scan.collect_routes()

    # Zero routes scanned is not zero routes shadowed. Shared with the gate
    # that owns the collector, so there is one floor rather than two.
    refusal = route_scan.empty_corpus_refusal(routes, route_scan.SERVICES_DIR)
    if refusal is not None:
        print(f"check_route_shadowing: scanned 0 routes under {route_scan.SERVICES_DIR}")
        print(f"\nFAIL: {refusal}", file=sys.stderr)
        return 2

    unreachable, deferred = find_shadowed(routes)
    unreadable = unresolved_paths(routes)

    files = len({r.path for r in routes})
    services = len({r.service for r in routes})
    print(
        f"check_route_shadowing: scanned {len(routes)} routes across {files} files "
        f"in {services} services under {route_scan.SERVICES_DIR}; "
        f"{len(deferred)} deferred to the runtime check, {len(unreadable)} path(s) not statically readable"
    )
    for line in deferred:
        print(f"  deferred to the runtime check: {line}")
    for line in unreadable:
        print(f"  path not a string literal, not judged here: {line}")

    if unreachable:
        print(f"\nFAIL: {len(unreachable)} unreachable route(s):", file=sys.stderr)
        for line in unreachable:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(f"OK: no literal route is shadowed by an earlier parameterised one ({len(deferred)} deferred to the runtime check).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
