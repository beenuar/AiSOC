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
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Imported as a module, not by name: `REPO_ROOT` is module state that the
# self-test rebinds to a scratch tree, and a from-import would copy the
# original at import time so this gate would go on scanning the real checkout
# while believing it was pointed somewhere else.
import check_route_tenant_scope as route_scan  # noqa: E402


class RouteVerdict(TypedDict):
    """One state-changing route and whether it authorizes.

    A TypedDict rather than a loose ``dict[str, object]`` so the fields the
    inventory sorts and joins on are typed where they are produced.
    """

    module: str
    function: str
    methods: list[str]
    route_path: str
    lineno: int
    authorized: bool


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
#: the three write routes in `remediation.py`, then 90 once the MSSP write
#: surface took a permission (rule packs and overrides `rules:write`,
#: delegations `users:write`, adoption and organisation founding
#: `settings:write`, provider notes `cases:write`), then 77 once the hunt
#: surface took `lake:query` (a hunt is a stored query; authoring and running
#: it are one entitlement) and the three detection-drafting routes took
#: `rules:read` (they persist nothing, so the floor is entitlement to read
#: detection logic; promoting a draft is separately `rules:write`), then 61
#: once the asset inventory and both entity graphs took `settings:write` (CMDB
#: data and correlation infrastructure, matching `/graph/context/import`, which
#: already required it), insider threat took `cases:write` (investigative
#: judgement about a subject) and `/identity-timeline/build` took `alerts:read`
#: (a read-shaped POST over the only table it queries).
#:
#: Four routes under `/mssp/organizations` remain in this count and are not
#: debt: they authorize through `_admin_scope`, an organisation owner/admin
#: check, which is the right vocabulary for a portfolio-scoped act and is not
#: interchangeable with a tenant role. This gate reads `require_permission`
#: only, so it cannot see them; `test_mssp_route_permissions.py` asserts they
#: still resolve that scope.
MAX_UNAUTHORIZED = 61


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
            # An alias can carry the discarded shape too, and then every route
            # using it is credited for a permission FastAPI never calls. The
            # alias is the worse place for it: one edit silently disarms a
            # whole module.
            if _discarded_in_annotation(node.value):
                continue
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


def _discarded_in_annotation(annotation: ast.expr | None) -> list[str]:
    """``require_permission(...)`` sitting in ``Annotated`` metadata unwrapped.

    ``Annotated[Any, require_permission("users:write")]`` has no ``Depends()``.
    FastAPI honours only ``Annotated`` metadata that is a ``Depends`` or a
    ``FieldInfo`` and silently drops everything else, so the permission is
    never checked and the parameter degrades into a query parameter. Eleven
    routes across four modules shipped like this, and they read as gated —
    which is worse than an obviously missing dependency, because a reviewer,
    `_authorizing_names` and the ratchet all count them as authorizing.
    """
    if not isinstance(annotation, ast.Subscript):
        return []
    base = annotation.value
    if (getattr(base, "id", None) or getattr(base, "attr", None)) != "Annotated":
        return []
    metadata = annotation.slice.elts[1:] if isinstance(annotation.slice, ast.Tuple) else []
    found: list[str] = []
    for item in metadata:
        if isinstance(item, ast.Call):
            name = item.func.attr if isinstance(item.func, ast.Attribute) else getattr(item.func, "id", None)
            if name == "require_permission":
                found.append(ast.unparse(item))
    return found


def find_discarded_permissions(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str]]:
    """Discarded permissions in *fn*'s own signature.

    Reported rather than folded into the ratchet because the ceiling is a debt
    balance and this is not debt. There is no correct reason to write it, so
    it has no ceiling: one occurrence fails the gate.
    """
    return [
        (arg.arg, source)
        for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        for source in _discarded_in_annotation(arg.annotation)
    ]


def _route_authorizes(fn: ast.FunctionDef | ast.AsyncFunctionDef, authorizing: set[str]) -> bool:
    """True when this handler makes an authorization decision."""
    # A permission that FastAPI discards is not an authorization decision,
    # whatever it looks like. Checked first because `_calls_authz` below walks
    # the argument subtree and would match the call itself, crediting the
    # route for enforcement that never happens.
    if find_discarded_permissions(fn):
        return False
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


def collect_discarded(root: Path | None = None) -> list[str]:
    """Every ``require_permission`` in the tree that FastAPI will never call.

    Not restricted to state-changing routes: two of the eleven found were on
    reads, and a read permission that enforces nothing is the same bug with a
    smaller blast radius.
    """
    base = root or route_scan.REPO_ROOT
    out: list[str] = []
    for path in sorted((base / "services" / SERVICE / "app" / "api").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover - not ours to fix
            continue
        shown = path.relative_to(base)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for parameter, source in find_discarded_permissions(node):
                    out.append(f"{shown}:{node.lineno} {node.name}() parameter '{parameter}' annotates {source} with no Depends()")
            elif isinstance(node, ast.Assign):
                for source in _discarded_in_annotation(node.value):
                    alias = ", ".join(t.id for t in node.targets if isinstance(t, ast.Name)) or "<alias>"
                    out.append(f"{shown}:{node.lineno} alias '{alias}' annotates {source} with no Depends()")
    return out


def collect(root: Path | None = None) -> list[RouteVerdict]:
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

    out: list[RouteVerdict] = []
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


def _refuse_empty_corpus(rows: list[RouteVerdict]) -> str | None:
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
    discarded = collect_discarded()

    if args.json:
        print(json.dumps({"total": len(rows), "unauthorized": len(ungated), "discarded": discarded, "routes": ungated}, indent=2))
        return 0

    if args.inventory:
        by_module: dict[str, list[RouteVerdict]] = {}
        for row in ungated:
            by_module.setdefault(row["module"], []).append(row)
        for module in sorted(by_module):
            print(f"\n{module}")
            for row in sorted(by_module[module], key=lambda r: r["lineno"]):
                print(f"  {','.join(row['methods']):18s} {row['route_path'] or '/':34s} {row['function']}()")
        print(f"\n{len(ungated)} of {len(rows)} state-changing routes make no authorization decision")
        return 0

    print(f"state-changing routes in services/{SERVICE}: {len(rows)}")
    print(f"  authorize:        {len(rows) - len(ungated)}")
    print(f"  identity only:    {len(ungated)}  (ceiling {args.max_unauthorized})")
    print(f"  discarded perms:  {len(discarded)}  (ceiling 0)")

    # No ceiling, and no exemptions: there is no correct reason to write a
    # permission where FastAPI cannot see it. Reported separately from the
    # ratchet so the diagnostic names the actual mistake — the permission is
    # present and spelled correctly, it is simply not wired to anything.
    if discarded:
        print(f"\nFAIL: {len(discarded)} permission(s) declared as Annotated metadata with no Depends().")
        print("FastAPI honours only Depends/FieldInfo metadata and drops the rest, so these are never checked")
        print("and the parameter becomes a query parameter. Write Annotated[AuthUser, Depends(require_permission('x'))].")
        for line in discarded:
            print(f"  {line}")
        return 1

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

        # Second defect: the permission is still there and still correct, but
        # written where FastAPI never reads it. Unwrapping `Depends` is the
        # exact edit that produced the eleven shipped instances.
        (scratch / target).write_text(original, encoding="utf-8")
        if collect_discarded(scratch):
            print("FAIL: self-test baseline already reports discarded permissions; the scratch tree is not clean")
            return 2

        unwrapped = original.replace("Depends(require_permission(_WRITE))", "require_permission(_WRITE)")
        if unwrapped == original:
            print("FAIL: self-test could not produce the discarded shape; remediation.py's dependency spelling changed")
            return 2
        (scratch / target).write_text(unwrapped, encoding="utf-8")

        discarded = collect_discarded(scratch)
        if len(discarded) != 1:
            print(f"FAIL: unwrapping Depends() on the WriteUser alias was detected {len(discarded)} time(s), not 1")
            return 1

        # And it must stop crediting them, or the ratchet keeps counting a
        # route as gated while it enforces nothing.
        still_credited = [r for r in collect(scratch) if r["module"].endswith("remediation.py") and r["authorized"]]
        if still_credited:
            print(f"FAIL: {len(still_credited)} route(s) using a discarded alias are still counted as authorizing")
            return 1

    print(f"self-test OK: identity-only routes {len(before)} -> {len(after)} when remediation.py's permissions are removed;")
    print("unwrapping Depends() on the WriteUser alias is reported once and stops crediting all 3 routes it gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
