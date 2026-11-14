#!/usr/bin/env python3
"""A route on an authenticated router must bind the principal it authenticated.

The defect this exists for
--------------------------
``services/agents/app/api/playbooks.py`` declared
``APIRouter(..., dependencies=[Depends(require_console_or_service_auth)])``.
That dependency *returns* a ``TenantPrincipal``, and a router-level dependency
discards the return value — so a principal was resolved on every request and
handed nowhere. Not one of the eight handlers took it. The service knew who was
asking and never asked, which is the whole of GHSA-27wx-pcv5-pr7q: the run store
was a process-global dict with no tenant key, ``GET /runs`` returned every
tenant's runs with their alert context to anyone, and execution took its tenant
from the request body.

Why a gate and not just the fix
-------------------------------
Row 52 of ``docs/audit/CLAIM_TO_GATE_MATRIX.md`` claimed "each of the eight route
functions takes an authenticated principal" and was GATED on
``services/api/tests/test_tenant_scope_and_auth_holes.py``, which imports
``from app.api.v1.endpoints import playbooks`` — the **API** service's proxy,
whose routes genuinely do bind principals. Two modules share a name and a route
list; the gate measured the safe one and printed OK throughout.

It could not have measured the other one either: both services name their
top-level package ``app``, so importing one shadows the other in a single
process. Hence a path-based AST walk here rather than a test in either suite.

What it measures
----------------
Only the *binding* — that a handler declares the principal — which is exactly
what is statically decidable. Whether the handler then compares anything against
it is behaviour, measured against the real ASGI app in
``services/agents/tests/test_playbook_tenant_binding.py``.

Two tiers, because they want different answers:

* **STRICT** modules must have zero unbound routes, bar a named exemption that
  states why the route holds no tenant-scoped state.
* Everywhere else is a **ratchet**: a debt balance, not a target. 29 routes
  across 7 services are in this shape today; this fails if that grows, so a new
  one cannot be added in silence while the existing ones are worked down.

Both the strict exemptions and the ratchet are checked in **both directions** —
a stale exemption and an unexpectedly-low count are findings too, because a
ratchet nobody can fail is the same as no ratchet.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

#: The tree git says we are in, not whatever sits two levels above this
#: file. A gate run from a copied `scripts/` directory would otherwise
#: judge a tree it never opened.
ROOT = repo_root()

#: A router-level dependency that looks like authentication.
_AUTH_HINT = re.compile(r"require_|auth|principal|current_user", re.I)

#: A parameter that is, or is annotated as, the resolved caller.
_PRINCIPAL = re.compile(
    r"principal|current_user|\buser\b|TenantPrincipal|CurrentUser|AuthUser|ScopedPrincipal",
    re.I,
)

_VERBS = {"get", "post", "put", "patch", "delete"}

#: Modules where the answer must be zero. These are the routers that read or
#: write per-tenant state behind a router-level guard — the exact shape the
#: advisory was about.
STRICT: dict[str, dict[str, str]] = {
    "services/agents/app/api/playbooks.py": {
        "draft_playbook_from_nl": (
            "turns a prompt into an unsaved draft; reads no stored state and writes none, so there is no tenant to compare against"
        ),
    },
    "services/agents/app/api/hunts.py": {
        "list_hunts": "reads the shipped YAML hunt corpus, which is shared content like detection rules",
        "get_hunt": "reads the shipped YAML hunt corpus, which is shared content like detection rules",
    },
}

#: The debt balance everywhere else. Not a target: lowering it is the work, and
#: it is lowered as routes are bound, never raised to make a build pass.
#:
#: 26 -> 25: `hunt_search` in `services/agents/app/api/hunt_search.py` now
#: binds a principal. It bound none at all, which was survivable only while
#: the handler touched no store — it returned synthetic events. The moment it
#: reads the tenant's event lake there is no tenant to scope by without one.
MAX_UNBOUND_ELSEWHERE = 25


@dataclass(frozen=True)
class Route:
    path: str
    function: str
    lineno: int
    router: str


def _authenticated_routers(tree: ast.Module) -> set[str]:
    """Routers whose constructor carries an auth-looking ``dependencies=``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        fn = node.value.func
        if (getattr(fn, "id", None) or getattr(fn, "attr", None)) != "APIRouter":
            continue
        for kw in node.value.keywords:
            if kw.arg == "dependencies" and _AUTH_HINT.search(ast.unparse(kw.value)):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _binds_principal(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = fn.args
    for arg in args.posonlyargs + args.args + args.kwonlyargs:
        if _PRINCIPAL.search(arg.arg):
            return True
        if arg.annotation is not None and _PRINCIPAL.search(ast.unparse(arg.annotation)):
            return True
    return False


def _parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return None


def unbound_routes(path: Path) -> list[Route]:
    """Routes on an authenticated router that declare no principal."""
    tree = _parse(path)
    if tree is None:
        return []

    routers = _authenticated_routers(tree)
    if not routers:
        return []

    found: list[Route] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            if dec.func.attr not in _VERBS or getattr(dec.func.value, "id", None) not in routers:
                continue
            if not _binds_principal(node):
                found.append(
                    Route(
                        path=str(path),
                        function=node.name,
                        lineno=node.lineno,
                        router=getattr(dec.func.value, "id", "?"),
                    )
                )
    return found


class EmptyRead(RuntimeError):
    """The corpus this gate judges was not there.

    "Found nothing" and "scanned nothing" are the same word on a terminal and
    opposite facts, which is how a gate comes to credit a tree it never
    opened. Every mode raises this rather than reporting a clean bill over an
    empty read.
    """


def scan(root: Path = ROOT) -> dict[str, list[Route]]:
    """Unbound routes per module, raising when there was nothing to scan."""
    out: dict[str, list[Route]] = {}
    scanned = 0
    routed = 0
    for path in sorted(root.glob("services/*/app/**/*.py")):
        scanned += 1
        rel = str(path.relative_to(root))
        tree = _parse(path)
        if tree is not None and _authenticated_routers(tree):
            routed += 1
        routes = unbound_routes(path)
        if routes:
            out[rel] = routes

    if scanned == 0:
        raise EmptyRead(f"no Python file under {root}/services/*/app — nothing was judged")
    if routed == 0:
        raise EmptyRead(
            f"{scanned} file(s) under {root}/services/*/app and not one declares an "
            "authenticated router, so this gate had no corpus to measure"
        )
    return out


def run(root: Path = ROOT) -> tuple[list[str], int]:
    """Problems, and the number of unbound routes outside the strict modules.

    Raises :class:`EmptyRead` when there was no corpus; the caller turns that
    into a refusal, never into a pass.
    """
    found = scan(root)
    problems: list[str] = []

    for module, exemptions in STRICT.items():
        routes = {r.function: r for r in found.get(module, [])}
        if not (root / module).is_file():
            problems.append(f"{module} is a STRICT module and does not exist; re-point this gate")
            continue
        for name, route in routes.items():
            if name not in exemptions:
                problems.append(
                    f"{module}:{route.lineno} {name}() is on an authenticated router "
                    f"({route.router}) and binds no principal. A router-level dependency "
                    f"resolves the caller and discards it; declare it as a handler parameter."
                )
        # Both directions: an exemption for a route that is now bound, or gone,
        # is a claim about the tree that is no longer true.
        for name in exemptions:
            if name not in routes:
                problems.append(
                    f"{module}: the exemption for {name}() is stale — it now binds a "
                    f"principal, or no longer exists. Remove it from STRICT in the same commit."
                )

    elsewhere = sum(len(routes) for module, routes in found.items() if module not in STRICT)
    if elsewhere > MAX_UNBOUND_ELSEWHERE:
        offenders = "\n".join(
            f"      {module}:{r.lineno} {r.function}()" for module, routes in sorted(found.items()) if module not in STRICT for r in routes
        )
        problems.append(
            f"{elsewhere} unbound routes outside the strict modules, ceiling {MAX_UNBOUND_ELSEWHERE}. "
            f"This is a debt balance, not an allowance — bind the new one rather than raising it:\n{offenders}"
        )
    elif elsewhere < MAX_UNBOUND_ELSEWHERE:
        problems.append(
            f"{elsewhere} unbound routes outside the strict modules, below the ceiling of "
            f"{MAX_UNBOUND_ELSEWHERE}. Lower MAX_UNBOUND_ELSEWHERE to {elsewhere} in the same "
            f"commit, or the ratchet stops measuring the progress that was just made."
        )

    return problems, elsewhere


def _self_test() -> int:
    """Inject each shape and require the gate to name it."""
    failures: list[str] = []

    def expect(label: str, got: bool, want: bool) -> None:
        if got != want:
            failures.append(f"{label}: expected {'a finding' if want else 'none'}, got the opposite")

    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "routes.py"

        probe.write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(dependencies=[Depends(require_console_or_service_auth)])\n"
            "@router.get('/runs')\n"
            "async def list_runs(limit: int = 50) -> list:\n"
            "    return []\n"
        )
        expect("unbound route on an authed router", bool(unbound_routes(probe)), True)

        probe.write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(dependencies=[Depends(require_console_or_service_auth)])\n"
            "@router.get('/runs')\n"
            "async def list_runs(principal: ScopedPrincipal, limit: int = 50) -> list:\n"
            "    return []\n"
        )
        expect("principal bound by name", bool(unbound_routes(probe)), False)

        probe.write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(dependencies=[Depends(require_console_or_service_auth)])\n"
            "@router.post('/x')\n"
            "async def x(who: Annotated[TenantPrincipal, Depends(resolve)]) -> dict:\n"
            "    return {}\n"
        )
        expect("principal bound by annotation only", bool(unbound_routes(probe)), False)

        probe.write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/public')\nasync def public() -> dict:\n    return {}\n"
        )
        expect("router with no auth dependency is out of scope", bool(unbound_routes(probe)), False)

    # An empty tree must refuse, not pass. This is the defect the repository's
    # own gate-coverage meta-check found in the first cut of this file:
    # `--report` exited 0 inside a bare repository, so "found nothing" and
    # "scanned nothing" were the same answer.
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp)
        (empty / "services" / "api" / "app").mkdir(parents=True)
        try:
            scan(empty)
        except EmptyRead:
            expect("an empty tree is refused", True, True)
        else:
            expect("an empty tree is refused", False, True)

    # The real tree, and the pre-fix shape re-created in it.
    problems, elsewhere = run()
    expect("current tree is clean", bool(problems), False)
    print(f"  (scanned the tree: {elsewhere} unbound outside the strict modules, ceiling {MAX_UNBOUND_ELSEWHERE})")

    if failures:
        print("SELF-TEST FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELF-TEST OK — each shape injected and caught, and the tree passes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", action="store_true", help="list every unbound route and exit 0")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    if args.report:
        try:
            found = scan()
        except EmptyRead as empty:
            print(f"REFUSED — {empty}")
            return 1
        for module, routes in sorted(found.items()):
            tier = "STRICT" if module in STRICT else "ratchet"
            for r in routes:
                exempt = " (exempt)" if r.function in STRICT.get(module, {}) else ""
                print(f"{tier:8} {module}:{r.lineno} {r.function}(){exempt}")
        return 0

    try:
        problems, elsewhere = run()
    except EmptyRead as empty:
        print(f"REFUSED — {empty}")
        return 1
    if problems:
        print("FAIL — a route authenticates its caller and never binds them:")
        for p in problems:
            print(f"  - {p}")
        return 1

    exempt_count = sum(len(v) for v in STRICT.values())
    print(
        f"OK — {len(STRICT)} strict modules with 0 unbound routes "
        f"({exempt_count} recorded exemptions, each still accurate); "
        f"{elsewhere} elsewhere at the ceiling of {MAX_UNBOUND_ELSEWHERE}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
