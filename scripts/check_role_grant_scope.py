#!/usr/bin/env python3
"""Every route that confers authority must decide whether the caller may.

Why this gate exists
--------------------
``POST /api/v1/tenants/me/users`` wrote a client-supplied ``role`` string into
``users.role`` — the column every ``require_permission`` reads — with no
allow-list and no comparison against the caller's own authority. Because
``platform_admin`` and ``admin`` are declared ``["*"]``, a ``tenant_admin``
could create an account holding every permission in the product
(GHSA-pm3f-h6gc-rvgp).

Five more routes had the same defect and the report named one, which is the
shape this repository keeps finding: the fix is applied where the finding
points and the siblings keep shipping. So the thing enforced here is not "this
handler validates its input" but the property that makes enumeration
unnecessary — **no principal confers authority it does not itself hold** —
and the check is that every role-conferring write reaches the one place that
decides it.

Three directions, because a one-directional gate passes while drift goes the
way things actually change:

*forward*
    A handler writes a role, scope or membership field from request data and
    never reaches ``app.core.role_grants``. This is the defect itself.

*reverse*
    An allow-list entry names a handler that no longer writes a role. A
    waiver covering nothing is a waiver nobody will notice is load-bearing
    when the handler comes back.

*vocabulary*
    A role is added to ``ROLE_PERMISSIONS`` and nothing classifies it, or a
    grantable role acquires the wildcard, or ``app/services/scim/roles.py``
    goes back to keeping its own copy of the list. The last one matters
    because SCIM had already refused wildcard roles from a directory group
    while the tenant API shipped without the rule; two lists that agree today
    are two lists that disagree later.

Run:  python3 scripts/check_role_grant_scope.py [--self-test]
"""

from __future__ import annotations

import ast
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

REPO_ROOT = repo_root()

ENDPOINTS = Path("services/api/app/api/v1/endpoints")
SECURITY = Path("services/api/app/core/security.py")
ROLE_GRANTS = Path("services/api/app/core/role_grants.py")
SCIM_ROLES = Path("services/api/app/services/scim/roles.py")

#: Fields whose value is authority rather than data. A request model that
#: declares one of these lets the client choose what the resulting principal
#: may do, whatever the column is called.
#:
#: ``role_id`` and ``permission_ids`` are here because the database-backed
#: RBAC tables are a second authorization path, not documentation:
#: ``CurrentUser.has_permission_db`` prefers ``user_roles`` over the static
#: map for any principal holding a row in it.
ROLE_FIELDS: frozenset[str] = frozenset(
    {
        "role",
        "org_role",
        "granted_role",
        "mapped_role",
        "scopes",
        "role_id",
        "permission_ids",
    }
)

#: Names that mean the decision was made. The module-level helpers are listed
#: alongside the chokepoint functions because a handler calling a helper that
#: calls the chokepoint has made the decision just as much as one calling it
#: directly — and reading only the chokepoint's own name would push every
#: handler into inlining it.
CHOKEPOINT_CALLS: frozenset[str] = frozenset(
    {
        "authorize_role_grant",
        "authorize_role_change",
        "authorize_permission_grant",
        "_authorize_scopes",
        "_authorize_permission_grant",
        "_require_org_grant_scope",
    }
)

#: The functions that decide a grant, as opposed to the helpers that reach
#: them. Every call to one of these must say which authority to measure the
#: grant against — see the ``authority`` direction in :func:`audit`.
GRANT_DECIDERS: frozenset[str] = frozenset(
    {
        "authorize_role_grant",
        "authorize_role_change",
        "authorize_permission_grant",
    }
)

#: The keyword that carries the caller's database-resolved permissions.
#: ``CurrentUser`` resolves authority in three tiers and prefers this one over
#: the static role whenever the principal has RBAC rows, so a call that omits
#: it measures the grant against an authority the caller was not admitted on.
EFFECTIVE_KEYWORD = "granter_permissions"

#: Handlers that accept one of those field names and deliberately do not
#: consult the chokepoint, with the reason. ``(module, function)``.
#:
#: Both entries are name collisions rather than exemptions: the field means
#: something that is not authority *in this product*. Recorded here rather
#: than excluded by a narrower field list, so the decision is visible and the
#: reverse check below notices when it stops applying.
ALLOWED: dict[tuple[str, str], str] = {
    (
        "oauth.py",
        "upsert_oauth_app",
    ): "scopes are the third-party provider's OAuth scopes for a connector, not AiSOC permissions; they confer nothing here",
    (
        "waitlist.py",
        "signup",
    ): "role is the free-text job title on a public marketing signup row and is never read as authority",
}


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _module_literal(tree: ast.Module, name: str) -> object | None:
    """A module-level name bound to a literal, or ``None``."""
    for node in ast.walk(tree):
        target: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            target = node.value
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            target = node.value
        if target is None:
            continue
        try:
            return ast.literal_eval(target)
        except (ValueError, TypeError, SyntaxError):
            return None
    return None


#: The permission string that means "every permission", as
#: `app/core/role_grants.py` declares it.
WILDCARD = "*"


def _subscript_assigned_keys(tree: ast.Module, name: str) -> dict[str, ast.expr]:
    """Roles bound by ``NAME["role"] = <expr>`` after the dict literal.

    `_module_literal` only matches an `ast.Name` target, so a role defined
    this way is invisible to it -- and `infosec` is defined exactly this way,
    as a set expression derived from two other roles so the two cannot drift.
    The gate therefore reported it as "grantable but grants nothing" while the
    role resolves to 18 permissions at runtime, which is a false positive on
    working code and is how a gate gets suppressed.
    """
    found: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == name
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                found[target.slice.value] = node.value
    return found


def _mentions_wildcard(expr: ast.expr) -> bool:
    """Whether an expression could produce the wildcard permission.

    Conservative: a literal ``"*"`` anywhere in the subtree counts. A role
    built by *subtracting* from other roles cannot gain a permission none of
    them had, and the callers below resolve the roles it reads, so this only
    has to catch the wildcard being introduced here.
    """
    return any(isinstance(n, ast.Constant) and n.value == WILDCARD for n in ast.walk(expr))


def _referenced_roles(expr: ast.expr, name: str) -> set[str]:
    """Roles an expression reads out of ``NAME[...]``."""
    out: set[str] = set()
    for n in ast.walk(expr):
        if (
            isinstance(n, ast.Subscript)
            and isinstance(n.value, ast.Name)
            and n.value.id == name
            and isinstance(n.slice, ast.Constant)
            and isinstance(n.slice.value, str)
        ):
            out.add(n.slice.value)
    return out


def _binding(tree: ast.Module, name: str) -> ast.expr | None:
    """The expression a module-level name is bound to, literal or not."""
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return node.value
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return node.value
    return None


def _called_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            func = inner.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def _request_models(tree: ast.Module) -> dict[str, set[str]]:
    """Module-level Pydantic models, mapped to the field names they declare.

    Only ``BaseModel`` subclasses. A response projection that happens to carry
    a ``role`` field is not the subject here — what matters is a shape the
    *client* fills in, and that is the one FastAPI binds to a request body.
    """
    models: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {b.id for b in node.bases if isinstance(b, ast.Name)} | {b.attr for b in node.bases if isinstance(b, ast.Attribute)}
        if "BaseModel" not in bases and not (bases & set(models)):
            continue
        fields = {stmt.target.id for stmt in node.body if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)}
        inherited: set[str] = set()
        for base in bases:
            inherited |= models.get(base, set())
        models[node.name] = fields | inherited
    return models


def _annotation_names(annotation: ast.expr | None) -> set[str]:
    """Every bare name inside a parameter annotation, including ``Annotated``."""
    if annotation is None:
        return set()
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        # `from __future__ import annotations` makes these strings.
        try:
            annotation = ast.parse(annotation.value, mode="eval").body
        except SyntaxError:
            return set()
    return {node.id for node in ast.walk(annotation) if isinstance(node, ast.Name)}


def _granted_fields(func: ast.FunctionDef | ast.AsyncFunctionDef, models: dict[str, set[str]]) -> set[str]:
    """Authority fields this handler accepts from a request body.

    Derived from the *bound model*, not from the assignments in the body.
    Reading assignments was the first version of this gate and it produced
    eight false reports: `scopes=list(row.scopes)` in a response projection
    and `org_role=str(member.org_role)` in a member listing look identical to
    a grant at the syntax level and are not one. What distinguishes a grant is
    that a client chose the value, which is exactly what a request model says.
    """
    granted: set[str] = set()
    args = func.args
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        for name in _annotation_names(arg.annotation):
            granted |= models.get(name, set()) & ROLE_FIELDS
    return granted


def audit(root: Path) -> tuple[list[str], dict[str, int]]:
    """Return ``(problems, counts)``. Counts prove the gate read something."""
    problems: list[str] = []
    counts = {"modules": 0, "handlers": 0, "writes": 0, "roles": 0, "decisions": 0}

    endpoints = root / ENDPOINTS
    security = root / SECURITY
    role_grants = root / ROLE_GRANTS
    scim_roles = root / SCIM_ROLES

    if not endpoints.is_dir():
        problems.append(f"{ENDPOINTS} is absent, so no route was examined")
        return problems, counts
    if not role_grants.is_file():
        # Reported and then carried on with, deliberately. Returning here
        # would answer "the chokepoint is missing" and hide *which* routes
        # confer authority without one, which is the list an operator needs.
        problems.append(f"{ROLE_GRANTS} is absent: there is no chokepoint for a role grant to reach")

    # --- forward: every role-conferring write reaches the chokepoint -------
    matched_waivers: set[tuple[str, str]] = set()
    for module in sorted(endpoints.glob("*.py")):
        counts["modules"] += 1
        tree = _parse(module)
        models = _request_models(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            granted = _granted_fields(node, models)
            if not granted:
                continue
            counts["handlers"] += 1
            counts["writes"] += len(granted)
            key = (module.name, node.name)
            if key in ALLOWED:
                matched_waivers.add(key)
                continue
            if not (_called_names(node) & CHOKEPOINT_CALLS):
                problems.append(
                    f"{module.name}::{node.name} accepts {', '.join(sorted(granted))} from the request body and never reaches "
                    "app.core.role_grants, so the caller chooses the authority it confers"
                )

    # --- authority: the grant is measured against what admitted the caller -
    #
    # The forward direction above asks whether a handler *reaches* the
    # chokepoint. It cannot ask whether it hands over the right authority,
    # and GHSA-4gx4-x7gm-4xq8 was exactly that gap: six call sites reached
    # `role_grants`, passed this gate, and compared the requested grant
    # against the caller's static role while `require_permission` had
    # admitted the caller on its narrower database permissions.
    for module in sorted([*endpoints.glob("*.py"), role_grants]):
        if not module.is_file():
            continue
        for node in ast.walk(_parse(module)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in GRANT_DECIDERS:
                continue
            counts["decisions"] += 1
            if not any(kw.arg == EFFECTIVE_KEYWORD for kw in node.keywords):
                problems.append(
                    f"{module.name}:{node.lineno} calls {name}() without {EFFECTIVE_KEYWORD}=, so the grant is measured "
                    "against the caller's static role rather than the permissions it was admitted on"
                )

    # --- reverse: no waiver covers a handler that no longer grants ---------
    for key, reason in sorted(ALLOWED.items()):
        if key not in matched_waivers:
            problems.append(
                f"ALLOWED names {key[0]}::{key[1]} ({reason}) and that handler no longer accepts an authority field; remove the entry"
            )

    # --- vocabulary --------------------------------------------------------
    if not security.is_file():
        problems.append(f"{SECURITY} is absent, so the enforced role map could not be read")
        return problems, counts

    security_tree = _parse(security)
    enforced = _module_literal(security_tree, "ROLE_PERMISSIONS")
    # Roles added after the literal, which `_module_literal` cannot see.
    derived = _subscript_assigned_keys(security_tree, "ROLE_PERMISSIONS")
    if isinstance(enforced, dict):
        for role, expr in derived.items():
            if role in enforced:
                continue
            # A derived role holds the wildcard only if it introduces one or
            # reads a role that already has it. Recorded as the permission
            # list so the wildcard scan below reads it the same way as a
            # literal row.
            inherits_wildcard = any(WILDCARD in (enforced.get(r) or []) for r in _referenced_roles(expr, "ROLE_PERMISSIONS"))
            enforced[role] = [WILDCARD] if (_mentions_wildcard(expr) or inherits_wildcard) else ["<derived>"]
        counts["roles"] = len(enforced)
    if not role_grants.is_file():
        return problems, counts

    grants_tree = _parse(role_grants)
    grantable = _module_literal(grants_tree, "GRANTABLE_ROLES")
    explicit = _module_literal(grants_tree, "_NEVER_GRANTABLE_EXPLICIT")

    if not isinstance(enforced, dict) or not isinstance(grantable, list | tuple) or not isinstance(explicit, dict):
        problems.append("the role vocabulary is no longer a set of literals this gate can read")
        return problems, counts

    # counted above, before the early return
    wildcard = {role for role, perms in enforced.items() if WILDCARD in (perms or [])}
    refused = wildcard | set(explicit)

    for role in sorted(set(grantable) & wildcard):
        problems.append(f"{role!r} is grantable and holds the wildcard: one unchecked string would confer every permission")
    for role in sorted(set(grantable) - set(enforced)):
        problems.append(f"GRANTABLE_ROLES names {role!r}, which ROLE_PERMISSIONS does not define; it grants nothing")
    for role in sorted(set(enforced) - set(grantable) - refused):
        problems.append(
            f"ROLE_PERMISSIONS defines {role!r} and app/core/role_grants.py neither makes it grantable nor records why it is refused"
        )

    # --- vocabulary: SCIM shares it rather than copying it -----------------
    if not scim_roles.is_file():
        problems.append(f"{SCIM_ROLES} is absent")
        return problems, counts

    scim_tree = _parse(scim_roles)
    precedence = _binding(scim_tree, "ROLE_PRECEDENCE")
    unreachable = _binding(scim_tree, "UNREACHABLE_BY_GROUP")
    if not (isinstance(precedence, ast.Name) and precedence.id == "GRANTABLE_ROLES"):
        problems.append(
            "app/services/scim/roles.py::ROLE_PRECEDENCE no longer *is* GRANTABLE_ROLES. SCIM refused wildcard roles "
            "before the tenant API did and kept its own copy; a second list is how they diverge again"
        )
    if not (isinstance(unreachable, ast.Call) and getattr(unreachable.func, "id", "") == "never_grantable"):
        problems.append(
            "app/services/scim/roles.py::UNREACHABLE_BY_GROUP no longer calls never_grantable(), so a role declared "
            "with the wildcard later would stay conferrable by a directory group name"
        )

    return problems, counts


def _self_test_cases() -> list[tuple[str, bool]]:
    """Prove the gate detects each drift it exists to catch.

    Mutations are applied to a copy of the real tree rather than to a fixture,
    because a gate proven against a fixture is proven against the fixture.
    """
    cases: list[tuple[str, bool]] = []
    clean, counts = audit(REPO_ROOT)
    cases.append(("the real tree passes", not clean))
    cases.append(("the real tree has role-conferring writes to judge", counts["writes"] > 0))

    read = (ENDPOINTS, SECURITY, ROLE_GRANTS, SCIM_ROLES)
    mutations: list[tuple[str, Path, str, str]] = [
        (
            "a handler that stops consulting the chokepoint is reported",
            Path("services/api/app/api/v1/endpoints/tenants.py"),
            "        granted_role = authorize_role_grant(",
            "        granted_role = request.role or _unchecked(",
        ),
        (
            "an API-key handler that stops authorizing its scopes is reported",
            Path("services/api/app/api/v1/endpoints/api_keys.py"),
            "    _authorize_scopes(body.scopes, current_user)\n\n    raw_key",
            "\n    raw_key",
        ),
        (
            "a grantable role that acquires the wildcard is reported",
            SECURITY,
            '    "tenant_admin": [\n        "alerts:read",',
            '    "tenant_admin": [\n        "*",\n        "alerts:read",',
        ),
        (
            "a new role nobody classified is reported",
            SECURITY,
            'ROLE_PERMISSIONS: dict[str, list[str]] = {\n    "platform_admin": ["*"],',
            'ROLE_PERMISSIONS: dict[str, list[str]] = {\n    "break_glass": ["alerts:read"],\n    "platform_admin": ["*"],',
        ),
        (
            "SCIM keeping its own copy of the vocabulary is reported",
            SCIM_ROLES,
            "ROLE_PRECEDENCE: Final[tuple[str, ...]] = GRANTABLE_ROLES",
            'ROLE_PRECEDENCE: Final[tuple[str, ...]] = ("viewer", "soc_analyst", "tenant_admin")',
        ),
        (
            "a grant measured against the static role instead of the resolved set is reported",
            Path("services/api/app/api/v1/endpoints/rbac.py"),
            "            granter_permissions=current_user.resolved_permissions,\n",
            "",
        ),
        (
            "a waiver that no longer covers anything is reported",
            Path(__file__).relative_to(REPO_ROOT),
            '    (\n        "scim.py",\n        "_apply_group_rename",\n    ):',
            '    (\n        "scim.py",\n        "gone_away",\n    ):',
        ),
    ]

    for description, target, old, new in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            for rel in read:
                source = REPO_ROOT / rel
                destination = tree / rel
                if source.is_dir():
                    shutil.copytree(source, destination)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
            if target == Path(__file__).relative_to(REPO_ROOT):
                # The waiver list lives in this file, so that case is proven by
                # rewriting the constant in memory rather than on disk.
                original = dict(ALLOWED)
                ALLOWED.clear()
                ALLOWED[("scim.py", "gone_away")] = "deliberately stale"
                problems, _ = audit(tree)
                ALLOWED.clear()
                ALLOWED.update(original)
                cases.append((description, bool(problems)))
                continue
            patched = tree / target
            source_text = patched.read_text(encoding="utf-8")
            if old not in source_text:
                cases.append((f"{description} (self-test anchor missing; case did not run)", False))
                continue
            patched.write_text(source_text.replace(old, new, 1), encoding="utf-8")
            problems, _ = audit(tree)
            cases.append((description, bool(problems)))

    return cases


def main() -> int:
    if SELF_TEST_FLAG in sys.argv[1:]:
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    problems, counts = audit(REPO_ROOT)

    print(
        f"check_role_grant_scope: read {counts['modules']} endpoint module(s), {counts['handlers']} handler(s) "
        f"conferring authority across {counts['writes']} write(s), {counts['decisions']} grant decision(s), "
        f"and {counts['roles']} enforced role(s)"
    )

    # "found nothing" and "scanned nothing" must not print the same word.
    if counts["modules"] == 0 or counts["roles"] == 0 or counts["writes"] == 0 or counts["decisions"] == 0:
        print(
            "\nFAIL: the endpoint surface or the role map read as empty. A clean result over nothing is "
            "indistinguishable from a wrong root or a glob that stopped matching.",
            file=sys.stderr,
        )
        return 2

    if problems:
        print(f"\nFAIL: {len(problems)} role-grant problem(s).", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        "OK: every role-conferring route reaches app.core.role_grants, every grant is measured against the "
        "authority its caller was admitted on, and the grantable vocabulary excludes the wildcard."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
