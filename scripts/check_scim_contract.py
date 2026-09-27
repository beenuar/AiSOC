#!/usr/bin/env python3
"""Keep the SCIM surface honest about itself, in both directions.

Why this gate exists
--------------------
SCIM has an unusual property for a write surface: the client decides what to
attempt by reading a document the server publishes. ``ServiceProviderConfig``
says whether PATCH works, whether filtering works, whether bulk works. An
identity provider reads it once at setup and configures itself accordingly.

That makes the discovery documents a claim, and a claim with no gate behind it
drifts. Two directions, both of which have a concrete failure:

*forward*
    The config advertises something the router does not implement. A provider
    configures itself to use it, and an administrator sees failed syncs whose
    cause is a JSON document rather than the code they are reading.

*reverse*
    The router grows an operation the config does not advertise. The provider
    never attempts it, so the capability is dead on arrival while every test
    for it passes. This is the shape that has repeated across this program:
    the mechanism exists, is tested, and nothing calls it.

Beyond the documents, two more disagreements would each be silent:

*role vocabulary*
    ``app.services.scim.roles`` maps directory groups onto the roles
    ``ROLE_PERMISSIONS`` enforces. Renaming a role there leaves the mapping
    pointing at a string that grants nothing, which reads in a console as
    though it grants something. Checked in both directions, so a *new* role
    must also be classified as assignable or recorded as deliberately not.

*mounting*
    A router nobody includes serves nothing. ``include_router`` does not
    populate ``app.routes`` on the pinned FastAPI, so an inventory assertion
    can measure nothing and pass; this reads the call itself out of
    ``main.py``, and ``test_scim_provisioning.py`` proves reachability by
    sending real requests.

Run:  python3 scripts/check_scim_contract.py [--self-test]
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

REPO_ROOT = repo_root()

ROUTER = REPO_ROOT / "services/api/app/api/v1/endpoints/scim.py"
RESOURCES = REPO_ROOT / "services/api/app/services/scim/resources.py"
ROLES = REPO_ROOT / "services/api/app/services/scim/roles.py"
SECURITY = REPO_ROOT / "services/api/app/core/security.py"
MAIN = REPO_ROOT / "services/api/app/main.py"

#: Operations RFC 7644 defines that this deployment intends to serve, mapped
#: to the ``ServiceProviderConfig`` key that advertises them. A key absent
#: from here is one the config declares and no route corresponds to, which is
#: reported rather than assumed harmless.
CAPABILITY_ROUTES: dict[str, tuple[str, ...]] = {
    "patch": ("PATCH",),
}

#: Endpoints every declared ResourceType promises. Checked against the routes
#: that actually exist, because a ResourceType naming an endpoint nobody
#: serves is a 404 a provider discovers during its first sync.
REQUIRED_RESOURCE_ROUTES: dict[str, tuple[str, ...]] = {
    "/Users": ("GET", "POST"),
    "/Users/{user_id}": ("GET", "PUT", "PATCH", "DELETE"),
    "/Groups": ("GET", "POST"),
    "/Groups/{group_id}": ("GET", "PUT", "PATCH", "DELETE"),
    "/ServiceProviderConfig": ("GET",),
    "/ResourceTypes": ("GET",),
    "/Schemas": ("GET",),
}

#: Handlers that change state. Each must reach the audit helper: a SCIM write
#: whose only record is the provider's own log is a change this platform
#: cannot account for.
MUTATING_HANDLERS: frozenset[str] = frozenset(
    {
        "create_user",
        "replace_user",
        "patch_user",
        "delete_user",
        "create_group",
        "replace_group",
        "patch_group",
        "delete_group",
    }
)

AUDIT_HELPER = "_audit"


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _routes(tree: ast.Module) -> dict[str, set[str]]:
    """Every ``@router.<method>("<path>")`` in the module."""
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            if not isinstance(dec.func.value, ast.Name) or dec.func.value.id != "router":
                continue
            method = dec.func.attr.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            if not dec.args or not isinstance(dec.args[0], ast.Constant):
                continue
            found.setdefault(str(dec.args[0].value), set()).add(method)
    return found


def _handler_calls(tree: ast.Module) -> dict[str, set[str]]:
    """Names each route handler calls, for the audit check."""
    calls: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        names: set[str] = set()
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                func = inner.func
                if isinstance(func, ast.Name):
                    names.add(func.id)
                elif isinstance(func, ast.Attribute):
                    names.add(func.attr)
        calls[node.name] = names
    return calls


def _module_constants(tree: ast.Module) -> dict[str, object]:
    """Module-level names bound to a literal.

    ``service_provider_config()`` names ``MAX_PAGE_SIZE`` inside the document
    it returns, which is right: a page cap written twice is a page cap that
    disagrees with itself. Resolving the name here is what lets the document
    stay readable to this gate without flattening it in the source.
    """
    constants: dict[str, object] = {}
    for node in tree.body:
        targets: list[str] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        if not targets or value is None:
            continue
        try:
            constants[targets[0]] = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError):
            continue
    return constants


def _resolve(node: ast.expr, constants: dict[str, object]) -> object:
    """``ast.literal_eval`` that also resolves module-level constant names."""
    if isinstance(node, ast.Name):
        if node.id not in constants:
            raise ValueError(f"unresolved name {node.id!r}")
        return constants[node.id]
    if isinstance(node, ast.Dict):
        return {
            _resolve(key, constants): _resolve(val, constants) for key, val in zip(node.keys, node.values, strict=True) if key is not None
        }
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [_resolve(item, constants) for item in node.elts]
    if isinstance(node, ast.JoinedStr):
        # The documents build their `location` fields from the mount point,
        # so the base path is written once. Without this the whole document
        # reads as unparseable and the gate reports a drift that is really a
        # limitation of the gate.
        parts: list[str] = []
        for piece in node.values:
            if isinstance(piece, ast.Constant):
                parts.append(str(piece.value))
            elif isinstance(piece, ast.FormattedValue):
                parts.append(str(_resolve(piece.value, constants)))
            else:
                raise ValueError("unsupported f-string component")
        return "".join(parts)
    return ast.literal_eval(node)


def _dict_literal(tree: ast.Module, function: str) -> dict | None:
    """The dict a zero-argument function returns, when it returns a literal."""
    constants = _module_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name != function:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Return) and inner.value is not None:
                try:
                    resolved = _resolve(inner.value, constants)
                except (ValueError, TypeError, SyntaxError):
                    return None
                return resolved if isinstance(resolved, dict) else None
    return None


def _assigned_names(tree: ast.Module, variable: str) -> set[str] | None:
    """Keys of a module-level dict, or members of a tuple/set/frozenset."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if variable not in targets:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            return None
        if isinstance(value, dict):
            return set(value)
        if isinstance(value, list | tuple | set | frozenset):
            return set(value)
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == variable:
            if node.value is None:
                return None
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError):
                return None
            if isinstance(value, dict):
                return set(value)
            if isinstance(value, list | tuple | set | frozenset):
                return set(value)
    return None


def _group_rule_roles(tree: ast.Module) -> set[str]:
    """Roles the group-name rules can produce."""
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "GROUP_NAME_RULES":
            try:
                rules = ast.literal_eval(node.value) if node.value is not None else ()
            except (ValueError, TypeError, SyntaxError):
                return set()
            return {role for _fragments, role in rules}
    return set()


def audit(root: Path) -> tuple[list[str], dict[str, int]]:
    """Return ``(problems, counts)``. Counts prove the gate read something."""
    problems: list[str] = []
    counts = {"routes": 0, "capabilities": 0, "roles": 0, "mutating_handlers": 0}

    router_path = root / ROUTER.relative_to(REPO_ROOT)
    resources_path = root / RESOURCES.relative_to(REPO_ROOT)
    roles_path = root / ROLES.relative_to(REPO_ROOT)
    security_path = root / SECURITY.relative_to(REPO_ROOT)
    main_path = root / MAIN.relative_to(REPO_ROOT)

    missing = [p for p in (router_path, resources_path, roles_path, security_path, main_path) if not p.is_file()]
    if missing:
        problems.append("SCIM modules are absent: " + ", ".join(str(p.relative_to(root)) for p in missing))
        return problems, counts

    router_tree = _parse(router_path)
    resources_tree = _parse(resources_path)
    roles_tree = _parse(roles_path)
    security_tree = _parse(security_path)

    routes = _routes(router_tree)
    counts["routes"] = sum(len(methods) for methods in routes.values())

    # --- the router is mounted -------------------------------------------
    main_source = main_path.read_text(encoding="utf-8")
    if "include_router(scim_router)" not in main_source:
        problems.append("services/api/app/main.py does not include the SCIM router, so none of these routes are served")

    # --- declared resource endpoints exist --------------------------------
    for path, methods in REQUIRED_RESOURCE_ROUTES.items():
        served = routes.get(path, set())
        for method in methods:
            if method not in served:
                problems.append(f"the SCIM surface promises {method} {path} and the router does not define it")

    # --- ServiceProviderConfig agrees with the router ---------------------
    config = _dict_literal(resources_tree, "service_provider_config")
    if config is None:
        problems.append("service_provider_config() no longer returns a literal this gate can read")
    else:
        counts["capabilities"] = len(CAPABILITY_ROUTES)
        served_methods = {method for methods in routes.values() for method in methods}
        for capability, required in CAPABILITY_ROUTES.items():
            advertised = bool((config.get(capability) or {}).get("supported"))
            implemented = all(method in served_methods for method in required)
            if advertised and not implemented:
                problems.append(f"ServiceProviderConfig advertises {capability!r} and the router serves no {'/'.join(required)} route")
            if implemented and not advertised:
                problems.append(
                    f"the router serves {'/'.join(required)} and ServiceProviderConfig does not advertise {capability!r}, "
                    "so no identity provider will ever attempt it"
                )
        # Bulk is declared unsupported. If a /Bulk route ever appears, the
        # document has to stop saying otherwise.
        bulk_advertised = bool((config.get("bulk") or {}).get("supported"))
        bulk_served = any(path.rstrip("/").endswith("/Bulk") or path == "/Bulk" for path in routes)
        if bulk_served and not bulk_advertised:
            problems.append("a /Bulk route exists while ServiceProviderConfig declares bulk unsupported")
        if bulk_advertised and not bulk_served:
            problems.append("ServiceProviderConfig advertises bulk and no /Bulk route exists")

    # --- every mutating handler audits ------------------------------------
    calls = _handler_calls(router_tree)
    for handler in sorted(MUTATING_HANDLERS):
        if handler not in calls:
            problems.append(f"{handler}() is named as a mutating SCIM handler and no longer exists")
            continue
        counts["mutating_handlers"] += 1
        if AUDIT_HELPER not in calls[handler]:
            problems.append(f"{handler}() changes state and does not call {AUDIT_HELPER}(), so the change is unaccounted for")

    # --- the role vocabulary agrees, in both directions -------------------
    enforced = _assigned_names(security_tree, "ROLE_PERMISSIONS")
    precedence = _assigned_names(roles_tree, "ROLE_PRECEDENCE")
    unreachable = _assigned_names(roles_tree, "UNREACHABLE_BY_GROUP")
    rule_roles = _group_rule_roles(roles_tree)

    if enforced is None or precedence is None or unreachable is None:
        problems.append("the role vocabulary is no longer a literal this gate can read")
    else:
        counts["roles"] = len(enforced)
        for role in sorted(precedence):
            if role not in enforced:
                problems.append(f"ROLE_PRECEDENCE names {role!r}, which ROLE_PERMISSIONS does not define; it grants nothing")
        for role in sorted(rule_roles):
            if role not in precedence:
                problems.append(f"a group-name rule maps to {role!r}, which is not an assignable role")
        for role in sorted(unreachable):
            if role not in enforced:
                problems.append(f"UNREACHABLE_BY_GROUP names {role!r}, which ROLE_PERMISSIONS no longer defines")
            if role in precedence:
                problems.append(f"{role!r} is both assignable from a group and recorded as unreachable")
        for role in sorted(enforced - precedence - unreachable):
            problems.append(
                f"ROLE_PERMISSIONS defines {role!r} and app/services/scim/roles.py neither makes it assignable "
                "nor records why a directory group may not confer it"
            )

    return problems, counts


def _self_test_cases() -> list[tuple[str, bool]]:
    """Prove the gate detects each drift it exists to catch.

    Each case mutates a copy of the real tree, because a gate proven only
    against a hand-built fixture is proven against the fixture.
    """
    import shutil
    import tempfile

    cases: list[tuple[str, bool]] = []
    clean, _counts = audit(REPO_ROOT)
    cases.append(("the real tree passes", not clean))

    mutations: list[tuple[str, Path, str, str]] = [
        (
            "an unmounted router is reported",
            MAIN,
            "app.include_router(scim_router)",
            "pass  # router not mounted",
        ),
        (
            "a mutating handler that stops auditing is reported",
            ROUTER,
            'await _audit(\n        db,\n        principal,\n        request,\n        action="scim:user:create",',
            'await _unrecorded(\n        db,\n        principal,\n        request,\n        action="scim:user:create",',
        ),
        (
            "a role the mapping does not classify is reported",
            SECURITY,
            'ROLE_PERMISSIONS: dict[str, list[str]] = {\n    "platform_admin": ["*"],',
            'ROLE_PERMISSIONS: dict[str, list[str]] = {\n    "brand_new_role": ["*"],\n    "platform_admin": ["*"],',
        ),
        (
            "a capability advertised with no route is reported",
            ROUTER,
            '@router.patch("/Users/{user_id}")',
            '@router.post("/Users/{user_id}/patched")',
        ),
    ]

    for description, target, old, new in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            # Copy only what the gate reads, so the self-test stays fast.
            for source in {ROUTER, RESOURCES, ROLES, SECURITY, MAIN}:
                destination = tree / source.relative_to(REPO_ROOT)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            patched = tree / target.relative_to(REPO_ROOT)
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
        # The injected cases run alongside the shared empty-tree floor, so one
        # command answers "does this gate still detect what it claims to".
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    problems, counts = audit(REPO_ROOT)

    print(
        f"check_scim_contract: read {counts['routes']} SCIM route(s), {counts['capabilities']} advertised capability(ies), "
        f"{counts['mutating_handlers']} mutating handler(s) and {counts['roles']} enforced role(s)"
    )

    # "found nothing" and "scanned nothing" must not print the same word.
    if counts["routes"] == 0 or counts["roles"] == 0:
        print(
            "\nFAIL: the SCIM surface or the role map read as empty. A clean result over nothing is indistinguishable from a wrong root.",
            file=sys.stderr,
        )
        return 2

    if problems:
        print(f"\nFAIL: {len(problems)} disagreement(s) between the SCIM surface and what it claims.", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("OK: the SCIM discovery documents, routes, audit trail and role mapping all agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
