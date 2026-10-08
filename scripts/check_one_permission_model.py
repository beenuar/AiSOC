#!/usr/bin/env python3
"""There is one permission model, and the database is authoritative.

Two shipped side by side. 275 route dependencies called the synchronous
`require_permission`, reading the hardcoded `ROLE_PERMISSIONS` map; 27
called `require_permission_db`, reading the `user_roles` /
`role_permissions` tables the console's RBAC screen writes to. An operator
could grant a permission, watch it appear in the UI, and have 275 of 302
routes ignore it.

The fix made the one factory they all already call read what authentication
resolved from the database, so there is nothing left to edit per route —
and nothing left for this gate to count. What it checks instead is that the
single path stays single:

1. **`CurrentUser.require_permission` consults the resolved set.** If it
   goes back to reading only the static map, every route silently reverts.
2. **`get_current_user` resolves one.** A principal built without it falls
   through to the static map by design, which is right for a test double
   and wrong for a real session.
3. **Every RBAC write invalidates.** A grant that does not bump the version
   leaves stale permissions cached on every replica, and for a *revoke*
   that is the dangerous direction.
4. **The static map is not read directly by route modules.** One importer
   is the resolver's bootstrap path; a second is a route deciding for
   itself, which is how the second model gets rebuilt.

Depth 8.2 added two more things the path has to do, and the reason they
are checked *here* rather than by a gate of their own is the whole point
of the item: attribute conditions and time-boxed elevation have to be
evaluated inside this one path. A condition applied beside the permission
check would be a second authority that can disagree with the first, which
is the shape that produced GHSA-pm3f-h6gc-rvgp.

5. **Conditions narrow inside the check.** `require_permission` must reach
   the condition evaluator on every branch — not only the database-backed
   one — or a tenant's attribute rule binds sessions and silently not API
   keys.
6. **Elevation is applied at use.** The check must consult live grants
   rather than a set frozen at authentication, or `expires_at` stops
   meaning anything until a cache entry happens to lapse.

Each is checked structurally with `ast`, because every one of them is a
question about which function calls which, and a text search cannot tell a
call from a mention in a docstring.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

DEPS = "services/api/app/api/v1/deps.py"
RESOLVER = "services/api/app/core/permission_cache.py"
RBAC_ROUTES = "services/api/app/api/v1/endpoints/rbac.py"
ENDPOINTS = "services/api/app/api/v1/endpoints"

#: Modules allowed to import the static map, each because it is the one
#: place the fallback is supposed to live.
STATIC_MAP_IMPORTERS = {
    "services/api/app/core/permission_cache.py": "the resolver's bootstrap path, when a tenant has no roles",
    "services/api/app/core/security.py": "defines it",
    "services/api/app/core/role_grants.py": "derives the grantable-role ladder from it",
    "services/api/app/api/v1/deps.py": "the fallback when nothing resolved a set",
}


@dataclass
class Report:
    findings: list[str] = field(default_factory=list)
    files_read: int = 0
    rbac_commits: int = 0
    rbac_invalidations: int = 0
    static_importers: list[str] = field(default_factory=list)


def _tree(root: pathlib.Path, rel: str) -> ast.Module | None:
    path = root / rel
    if not path.is_file():
        return None
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return None


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _calls(node: ast.AST) -> set[str]:
    return {getattr(c.func, "id", getattr(c.func, "attr", "")) for c in ast.walk(node) if isinstance(c, ast.Call)}


def _reads(node: ast.AST, attribute: str) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr == attribute for n in ast.walk(node))


def _conditions_are_branch_local(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether the condition call sits inside an `if`, rather than after it.

    The distinction a text search cannot make, and the one that matters: a
    call nested in the database-backed branch leaves API-key and
    static-map principals unconstrained, and the tenant's console shows
    the rule as configured either way.

    Implemented as "does any statement at the function's own top level
    call it", because that is exactly the placement that binds every
    branch.
    """
    for statement in fn.body:
        if isinstance(statement, (ast.If, ast.Try, ast.For, ast.While, ast.With)):
            continue
        if "_narrow_by_conditions" in _calls(statement):
            return False
    return True


def inspect(root: pathlib.Path) -> Report:
    report = Report()

    deps = _tree(root, DEPS)
    if deps is None:
        report.findings.append(f"{DEPS} is missing or unparseable")
        return report
    report.files_read += 1

    # 1. the check consults the resolved set
    check = _function(deps, "require_permission")
    enforcer = None
    for node in ast.walk(deps):
        if isinstance(node, ast.ClassDef) and node.name == "CurrentUser":
            enforcer = _function(node, "require_permission")
    if enforcer is None:
        report.findings.append("CurrentUser.require_permission is gone")
    else:
        if not _reads(enforcer, "resolved_permissions"):
            report.findings.append(
                "CurrentUser.require_permission does not read `resolved_permissions`, so every route is back on the static map"
            )
        if "grants" not in _calls(enforcer):
            report.findings.append(
                "CurrentUser.require_permission does not call `grants()`, so wildcard handling has drifted from the resolver's"
            )
        # 5. conditions narrow inside the check, on every branch
        #
        # Asserted on the *function body* rather than on a branch, because
        # the property is "whichever branch allowed, conditions still run".
        # A call placed inside the database-backed `elif` would satisfy a
        # naive search while leaving API-key and static-map principals
        # unconstrained — and those are the two a tenant is least likely to
        # notice, because nothing errors.
        if "_narrow_by_conditions" not in _calls(enforcer):
            report.findings.append(
                "CurrentUser.require_permission does not apply attribute conditions, so every "
                "`permission_conditions` row a tenant configured is inert"
            )
        elif _conditions_are_branch_local(enforcer):
            report.findings.append(
                "CurrentUser.require_permission applies conditions inside a branch, so they bind "
                "only one kind of principal; they must run after whichever branch allowed"
            )

        # 6. elevation is applied at use, not frozen at authentication
        if not any(name in _calls(enforcer) for name in ("elevated_permissions", "effective_permissions")):
            report.findings.append(
                "CurrentUser.require_permission does not consult live elevation, so an approved "
                "`privilege_grants` row confers nothing and `expires_at` governs nothing"
            )

    elevated = None
    for node in ast.walk(deps):
        if isinstance(node, ast.ClassDef) and node.name == "CurrentUser":
            elevated = _function(node, "elevated_permissions")
    if elevated is None:
        report.findings.append("CurrentUser.elevated_permissions is gone, so elevation is no longer resolved at use")
    elif not _reads(elevated, "elevation"):
        report.findings.append("CurrentUser.elevated_permissions no longer reads the grants, so elevation is decorative")

    narrower = None
    for node in ast.walk(deps):
        if isinstance(node, ast.ClassDef) and node.name == "CurrentUser":
            narrower = _function(node, "_narrow_by_conditions")
    if narrower is None:
        report.findings.append("CurrentUser._narrow_by_conditions is gone")
    elif "narrow_by_conditions" not in _calls(narrower):
        report.findings.append(
            "CurrentUser._narrow_by_conditions no longer calls the shared evaluator, so a second "
            "condition implementation exists and the two can disagree"
        )

    if check is None:
        report.findings.append("the require_permission factory is gone")

    # 2. authentication resolves one
    #
    # Followed through one hop of delegation, because the property is "the
    # authenticated principal carries a resolved set" and not "this particular
    # function contains this particular call". `get_current_user` used to
    # inline the whole JWT path; it now hands off to `resolve_jwt_principal`,
    # which the WebSocket upgrade also uses -- and the reason it does is that
    # the WebSocket had its *own* copy which resolved no permissions at all
    # (GHSA-25fh-rxp8-67j8). A gate keyed on the function name would have
    # reported that refactor as a regression while the thing it guards got
    # stronger, which is the shape that gets a gate deleted.
    auth = _function(deps, "get_current_user")
    if auth is None:
        report.findings.append("get_current_user is gone")
    else:
        resolvers = [auth]
        for name in sorted(_calls(auth)):
            if name == "get_current_user":
                continue
            delegate = _function(deps, name)
            if delegate is not None:
                resolvers.append(delegate)
        if not any("resolve_permissions" in _calls(fn) for fn in resolvers):
            report.findings.append(
                "no function on the authentication path calls `resolve_permissions`, so no "
                "principal ever carries a database-backed set and the static map is the only "
                "model again"
            )

    # 3. every RBAC write invalidates
    rbac = _tree(root, RBAC_ROUTES)
    if rbac is None:
        report.findings.append(f"{RBAC_ROUTES} is missing or unparseable")
    else:
        report.files_read += 1
        for node in ast.walk(rbac):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = _calls(node)
            commits = sum(
                1 for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "commit"
            )
            if not commits:
                continue
            report.rbac_commits += commits
            if "bump_version" in calls:
                report.rbac_invalidations += 1
            else:
                report.findings.append(
                    f"{RBAC_ROUTES}:{node.lineno} {node.name}() commits an RBAC change and never "
                    "calls bump_version, so the old permissions stay cached on every replica"
                )

    # 4. no route module reads the static map directly
    directory = root / ENDPOINTS
    if directory.is_dir():
        for path in sorted(directory.glob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel in STATIC_MAP_IMPORTERS:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            report.files_read += 1
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "app.core.security":
                    if any(a.name in ("ROLE_PERMISSIONS", "has_permission") for a in node.names):
                        report.static_importers.append(f"{rel}:{node.lineno}")

    for site in report.static_importers:
        report.findings.append(
            f"{site} imports the static permission map directly. A route deciding for itself is "
            "how the second model gets rebuilt; depend on require_permission instead"
        )

    return report


def _verdict(report: Report) -> int:
    if report.files_read == 0:
        print(
            "check_one_permission_model: read no files — refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2
    if report.findings:
        print("check_one_permission_model: FAIL", file=sys.stderr)
        for finding in report.findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(
        f"check_one_permission_model: OK — the permission check reads what authentication "
        f"resolved from the database, {report.rbac_invalidations} RBAC mutation(s) covering "
        f"{report.rbac_commits} commit(s) invalidate the cache, and no route module reads the "
        f"static map directly ({report.files_read} files)."
    )
    return 0


def self_test() -> int:
    import tempfile

    root = repo_root()
    extra: list[tuple[str, bool]] = [("the real tree passes", not inspect(root).findings)]

    deps_source = (root / DEPS).read_text(encoding="utf-8")
    rbac_source = (root / RBAC_ROUTES).read_text(encoding="utf-8")

    def probe(description: str, *, deps: str | None = None, rbac: str | None = None) -> None:
        with tempfile.TemporaryDirectory(prefix="aisoc-perm-gate-") as tmp:
            base = pathlib.Path(tmp)
            (base / DEPS).parent.mkdir(parents=True, exist_ok=True)
            (base / RBAC_ROUTES).parent.mkdir(parents=True, exist_ok=True)
            (base / DEPS).write_text(deps if deps is not None else deps_source, encoding="utf-8")
            (base / RBAC_ROUTES).write_text(rbac if rbac is not None else rbac_source, encoding="utf-8")
            extra.append((description, bool(inspect(base).findings)))

    # The whole branch, not just its condition. A first draft flipped the
    # condition to `False` and the case passed — `grants(self.resolved_...)`
    # was still in the body, so the attribute was still mentioned and the
    # structural read still found it. A regression removes the branch.
    resolved_branch = """        elif self.resolved_permissions is not None:
            # Database-backed: what the RBAC tables actually grant, plus
            # any elevation live at this instant.
            if not grants(self.elevated_permissions(), permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}",
                )
        elif not has_permission(self.role, permission):"""
    assert resolved_branch in deps_source, (
        "the self-test's probe text no longer matches deps.py, so the probes below would be no-ops "
        "and this gate would report PASS for a tree it never modified"
    )

    probe(
        "detects a check that stops reading the resolved set",
        deps=deps_source.replace(resolved_branch, """        elif not has_permission(self.role, permission):"""),
    )
    probe(
        "detects authentication that stops resolving one",
        deps=deps_source.replace("await resolve_permissions(", "await _disabled("),
    )
    probe(
        "detects an RBAC write that does not invalidate",
        rbac=rbac_source.replace("await bump_version(str(current_user.tenant_id))", "pass", 1),
    )

    # Depth 8.2. Each of the three below is a way the wiring could be
    # removed while the tables, the routes and the console all still look
    # configured — which is precisely the state this item repaired.
    probe(
        "detects conditions dropped from the permission check",
        deps=deps_source.replace("        self._narrow_by_conditions(permission)\n", "", 1),
    )
    # The realistic shape of this regression: somebody tucks the call into
    # the database-backed branch, where it reads as correct and leaves
    # API-key and static-map principals unconstrained.
    branch_local = deps_source.replace(
        resolved_branch,
        resolved_branch.replace(
            "        elif not has_permission(self.role, permission):",
            "            self._narrow_by_conditions(permission)\n        elif not has_permission(self.role, permission):",
        ),
    ).replace("\n        self._narrow_by_conditions(permission)\n", "\n", 1)
    assert branch_local != deps_source, "the branch-local probe did not modify deps.py, so it proves nothing"
    probe("detects conditions moved inside a branch, binding one principal type", deps=branch_local)
    probe(
        "detects elevation frozen at authentication instead of applied at use",
        deps=deps_source.replace("grants(self.elevated_permissions(), permission)", "grants(self.resolved_permissions, permission)"),
    )
    probe(
        "detects a second condition evaluator replacing the shared one",
        deps=deps_source.replace("verdict = narrow_by_conditions(permission, applicable, self.attributes)", "verdict = _local_evaluator()"),
    )

    # And a direction it must not fire in.
    with tempfile.TemporaryDirectory(prefix="aisoc-perm-gate-ok-") as tmp:
        base = pathlib.Path(tmp)
        (base / DEPS).parent.mkdir(parents=True, exist_ok=True)
        (base / RBAC_ROUTES).parent.mkdir(parents=True, exist_ok=True)
        (base / DEPS).write_text(deps_source, encoding="utf-8")
        (base / RBAC_ROUTES).write_text(rbac_source, encoding="utf-8")
        extra.append(("accepts the unmodified pair", not inspect(base).findings))

    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
