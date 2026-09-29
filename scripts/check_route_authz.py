#!/usr/bin/env python3
"""Ratchet: state-changing API routes that authenticate but never authorize.

``check_route_auth.py`` asks whether a route authenticates. That question was
answered "yes" for every route in ``remediation.py``, and a ``viewer`` could
still raise the tenant's autonomy tier to L4, pre-approve a high blast-radius
verb with no expiry, and suppress a containment verb mid-incident
(GHSA-wj5c-88hg-5926). Authentication had been standing in for authorization,
and the gate that would have noticed was asking the other question.

So this one asks: does a state-changing route make an *authorization* decision
at all? A route that only resolves an identity is counted, because "is this a
valid session?" is not "may this session do this?".

Why a count and not a list
--------------------------
The honest answer on the day this was written is that many routes are in this
state, and most are not defects — a handful are genuinely self-scoped (a
caller editing their own preferences, their own passkeys, their own on-call
status), and the rest need a per-route decision by someone who knows what the
route is for. Enumerating them here would be a list of things somebody once
found inconvenient, and it would be wrong within a week.

A ceiling is honest about that. It cannot rise: a new ungated route fails the
gate on the pull request that adds it. And it must not be *stale* either — if
the real count drops below the ceiling the gate fails too, demanding the
ceiling come down with it, so the number only ever moves toward zero.

``MAX_UNAUTHORIZED`` is not a target. It is a debt balance.

Usage::

    python scripts/check_route_authz.py              # gate
    python scripts/check_route_authz.py --inventory  # per-module table
    python scripts/check_route_authz.py --json
    python scripts/check_route_authz.py --self-test  # prove it detects drift

Exit codes: 0 clean, 1 violations, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Imported as a module, not by name: `REPO_ROOT` is module state that the
# self-test rebinds to a scratch tree, and a from-import would copy the
# original at import time so this gate would go on scanning the real checkout
# while believing it was pointed somewhere else.
import check_route_tenant_scope as route_scan  # noqa: E402

#: Verbs that change state. GET and HEAD are out of scope: this gate is about
#: who may *write*, and read authorization is a different (real) question with
#: a different answer per route. Lower-case because the shared scanner records
#: the decorator attribute (``@router.post``) rather than the HTTP verb.
MUTATING = {"post", "put", "patch", "delete"}

#: The service whose surface this covers. `services/api` holds the tenant
#: control plane and is where `require_permission` lives.
SERVICE = "api"

#: Calls that constitute an authorization decision, as opposed to resolving an
#: identity. `require_permission` is the dependency factory in
#: `app/api/v1/deps.py`; the `*_db` forms are its RBAC-table equivalents.
AUTHZ_CALLS = frozenset(
    {
        "require_permission",
        "require_permission_db",
        "has_permission",
        "has_permission_db",
    }
)

#: The measured ceiling. Lower it whenever routes are gated; never raise it.
#: 2026-09-29: 106 on the v12.3.0 tree, 103 once GHSA-wj5c-88hg-5926 closed
#: the three write routes in `remediation.py`.
MAX_UNAUTHORIZED = 103


def _authorizing_names(tree: ast.Module) -> set[str]:
    """Module-level names that carry an authorization decision.

    Three indirections hide enforcement from a naive scan, and all three are
    in this tree:

    * an ``Annotated`` alias — ``WriteUser = Annotated[AuthUser,
      Depends(require_permission("playbooks:write"))]`` in ``playbooks.py``;
    * a dependency helper — ``_admin_scope`` in ``mssp.py``;
    * a plain helper called from the handler body — ``_require_admin`` in
      ``waitlist.py`` and ``tenant_provision.py``.

    Missing any of them reports a gated route as ungated, which would inflate
    the ceiling with routes that are already fine and hide the real ones.
    """
    names: set[str] = set()

    for node in ast.walk(tree):
        # Alias assignments: NAME = Annotated[..., Depends(require_permission(...))]
        if isinstance(node, ast.Assign):
            if any(_calls_authz(node.value)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        # Helper functions whose body reaches an authorization call.
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(_calls_authz(node)):
                names.add(node.name)

    # A helper that calls a helper that authorizes. One extra hop is enough
    # for this tree; a fixpoint would be over-engineering until it is not.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name not in names:
            called = {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            called |= {c.func.attr for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
            if called & names:
                names.add(node.name)

    return names


def _calls_authz(node: ast.AST) -> list[str]:
    """Authorization calls reachable directly inside *node*."""
    found: list[str] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name in AUTHZ_CALLS:
            found.append(name)
    return found


def _route_authorizes(fn: ast.FunctionDef | ast.AsyncFunctionDef, authorizing: set[str]) -> bool:
    """True when this handler makes an authorization decision."""
    # In the signature: Depends(require_permission("x")), or an alias of one.
    if _calls_authz(fn.args):
        return True
    for arg in [*fn.args.args, *fn.args.kwonlyargs, *fn.args.posonlyargs]:
        if arg.annotation is not None and _names_used(arg.annotation) & authorizing:
            return True
    for default in [*fn.args.defaults, *[d for d in fn.args.kw_defaults if d is not None]]:
        if _names_used(default) & authorizing:
            return True
    # In the body: user.require_permission("x"), or a helper that does.
    if _calls_authz(fn):
        return True
    called = {c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    return bool(called & authorizing)


def _names_used(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def collect(root: Path | None = None) -> list[dict[str, object]]:
    """Every state-changing route in ``services/api``, with its authz verdict."""
    base = root or route_scan.REPO_ROOT
    routes = [r for r in route_scan.collect_routes(base) if r.service == SERVICE]

    trees: dict[str, ast.Module] = {}
    authorizing: dict[str, set[str]] = {}
    handlers: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for route in routes:
        if route.path in trees:
            continue
        tree = ast.parse((base / route.path).read_text(encoding="utf-8"))
        trees[route.path] = tree
        authorizing[route.path] = _authorizing_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                handlers[route.path, node.name] = node

    out: list[dict[str, object]] = []
    for route in routes:
        if not (set(route.methods) & MUTATING):
            continue
        # A route with no authentication at all is `check_route_auth.py`'s
        # finding, and it keeps the tables recording which of those are public
        # by design — the sign-in flow, the IdP callbacks, the HMAC-verified
        # webhooks. Counting them here would mix two different defects and
        # make this ceiling unreachable for a reason it does not describe.
        if not route.has_auth:
            continue
        fn = handlers.get((route.path, route.function))
        if fn is None:
            continue
        out.append(
            {
                "module": route.path,
                "function": route.function,
                "methods": sorted(set(route.methods) & MUTATING),
                "route_path": route.route_path,
                "lineno": route.lineno,
                "authorized": _route_authorizes(fn, authorizing[route.path]),
            }
        )
    return out


def _refuse_empty_corpus(rows: list[dict[str, object]]) -> str | None:
    """A gate that scanned nothing must fail, not pass.

    ``security_audit.py`` once credited a tree with no manifests. The same
    shape here would report zero unauthorized routes because it found zero
    routes.
    """
    if len(rows) < 100:
        return f"found only {len(rows)} state-changing routes in services/{SERVICE}; the scanner is broken, not the tree clean"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", action="store_true", help="print every state-changing route and its verdict")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects a removed permission")
    parser.add_argument("--max-unauthorized", type=int, default=MAX_UNAUTHORIZED)
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    rows = collect()
    broken = _refuse_empty_corpus(rows)
    if broken:
        print(f"FAIL: {broken}")
        return 2

    ungated = [r for r in rows if not r["authorized"]]

    if args.json:
        print(json.dumps({"total": len(rows), "unauthorized": len(ungated), "routes": ungated}, indent=2))
        return 0

    if args.inventory:
        by_module: dict[str, list[dict[str, object]]] = {}
        for row in ungated:
            by_module.setdefault(str(row["module"]), []).append(row)
        for module in sorted(by_module):
            print(f"\n{module}")
            for row in sorted(by_module[module], key=lambda r: r["lineno"]):
                print(f"  {','.join(row['methods']):18s} {row['route_path'] or '/':34s} {row['function']}()")
        print(f"\n{len(ungated)} of {len(rows)} state-changing routes make no authorization decision")
        return 0

    print(f"state-changing routes in services/{SERVICE}: {len(rows)}")
    print(f"  authorize:        {len(rows) - len(ungated)}")
    print(f"  identity only:    {len(ungated)}  (ceiling {args.max_unauthorized})")

    # Forward: the debt may not grow.
    if len(ungated) > args.max_unauthorized:
        added = sorted(f"{r['module']}:{r['lineno']} {r['function']}()" for r in ungated)
        print(f"\nFAIL: {len(ungated)} exceeds the ceiling of {args.max_unauthorized}.")
        print("A state-changing route must make an authorization decision, not just resolve an identity.")
        print('Add Depends(require_permission("...")) — see services/api/app/api/v1/endpoints/remediation.py.')
        print(f"\ncurrent identity-only routes ({len(added)}):")
        for line in added:
            print(f"  {line}")
        return 1

    # Reverse: a ceiling that no longer describes the tree is stale, and a
    # stale ceiling is how a list of exemptions turns into a list of excuses.
    if len(ungated) < args.max_unauthorized:
        print(f"\nFAIL: the ceiling is stale. {len(ungated)} routes are identity-only but MAX_UNAUTHORIZED is {args.max_unauthorized}.")
        print(f"Lower MAX_UNAUTHORIZED in {Path(__file__).name} to {len(ungated)}.")
        return 1

    print("\nOK")
    return 0


def _self_test() -> int:
    """Prove the gate fails when a permission is removed from a real route.

    A gate must be proven against a tree that has the defect. Asserting it
    passes on a clean tree proves only that it can print OK.
    """
    import shutil  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    target = Path("services/api/app/api/v1/endpoints/remediation.py")
    original = (route_scan.REPO_ROOT / target).read_text(encoding="utf-8")
    if "require_permission" not in original:
        print("FAIL: self-test fixture is stale — remediation.py no longer enforces a permission")
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "tree"
        shutil.copytree(route_scan.REPO_ROOT / "services", scratch / "services", dirs_exist_ok=True)

        before = [r for r in collect(scratch) if not r["authorized"]]

        # Regress exactly the defect the advisory described.
        regressed = original.replace("Depends(require_permission(_WRITE))", "Depends(get_current_user)").replace(
            "Depends(require_permission(_READ))", "Depends(get_current_user)"
        )
        if regressed == original:
            print("FAIL: self-test could not regress remediation.py; its dependency spelling changed")
            return 2
        (scratch / target).write_text(regressed, encoding="utf-8")

        after = [r for r in collect(scratch) if not r["authorized"]]

    gained = len(after) - len(before)
    if gained != 3:
        print(f"FAIL: removing authorization from remediation.py's 3 write routes changed the count by {gained}, not 3")
        return 1

    print(f"self-test OK: identity-only routes {len(before)} -> {len(after)} when remediation.py's permissions are removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
