#!/usr/bin/env python3
"""Fail the build when a route lets its caller name the tenant.

Tenant isolation in this codebase is enforced at read time, per store, and the
authoritative tenant is the authenticated principal's. A route that accepts
``tenant_id`` from the client and carries no authentication is not a scoping
bug that better validation fixes: validating the *value* of the parameter does
nothing, because any caller can still name any tenant UUID. The scope has to
come from somewhere the caller does not control.

So this gate asks two questions of every route in the tree, and both have to
hold:

1. **A route that takes a tenant identifier must carry an auth dependency.**
   Otherwise the tenant is whatever the caller typed.
2. **A route that accepts a tenant identifier *alongside* authentication must
   intersect it with the caller's authorised scope.** An MSSP operator
   narrowing to one managed tenant is legitimate; reaching a tenant they do
   not manage is not, and only an intersection tells the two apart. Naming an
   outside tenant must narrow the result to nothing rather than reach out.

Both directions are checked because a one-directional gate is the dominant
failure shape here: it compares A against B, never B against A, and prints OK
while drift accumulates in the direction things actually change. ``--self-test``
injects a violation of each kind and asserts the scanner catches both.

The scan is an AST pass rather than a grep because the thing being looked for
is structural — a parameter's name and annotation, a decorator's ``dependencies``
list, the router object the decorator hangs off — and every one of those
survives a rename that a regex would miss.

Usage::

    python scripts/check_route_tenant_scope.py              # gate (exit 1 on violations)
    python scripts/check_route_tenant_scope.py --inventory  # full route inventory
    python scripts/check_route_tenant_scope.py --json       # machine-readable
    python scripts/check_route_tenant_scope.py --self-test  # prove it detects drift

Exit codes: 0 clean, 1 violations found, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _repo_root() -> Path:
    """Resolve the repository root, preferring git over this file's location.

    A gate that derives its root from ``__file__`` will happily scan a stale
    copy of the tree and print a confident OK about a checkout it never
    opened. Asking git means the answer describes the working tree the caller
    is actually in; the ``__file__`` walk is only the fallback for a tarball
    with no ``.git``.
    """
    env = os.environ.get("AISOC_REPO_ROOT")
    if env:
        return Path(env).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parent,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(__file__).resolve().parent.parent


REPO_ROOT = _repo_root()
SERVICES_DIR = REPO_ROOT / "services"

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "websocket"}

#: Parameter names that carry a tenant identity. Matched exactly, plus a
#: suffix rule below, so ``tenant_id`` and ``target_tenant_id`` both count but
#: ``tenant_name`` (a display string, not a selector) does not.
TENANT_PARAM_NAMES = {
    "tenant",
    "tenant_id",
    "tenant_uuid",
    "tenantid",
    "tenant_ids",
    "tenant_ref",
    "tenant_slug",
    "org_id",
    "organization_id",
    "customer_id",
}
TENANT_PARAM_SUFFIXES = ("_tenant_id", "_tenant", "_tenant_ids")

#: A field the caller must *retype to confirm* a destructive action is not a
#: selector — the tenant still comes from the principal and the field is only
#: ever compared for equality. Treating it as a selector would push routes
#: toward removing the confirmation, which is the opposite of the point.
TENANT_PARAM_CONFIRMATION_PREFIXES = ("confirm_", "confirmation_", "expected_")

#: Dependency callables and annotated aliases that establish an authenticated
#: principal. A route naming any of these has an identity to scope against.
AUTH_DEPENDENCY_NAMES = {
    # services/api
    "get_current_user",
    "get_current_active_user",
    "require_permission",
    "AuthUser",
    "CurrentUser",
    "ReadUser",
    "WriteUser",
    "AdminUser",
    "TenantDBSession",
    # per-service bearer guards (the services/actions pattern)
    "require_service_auth",
    "require_actor_auth",
    "require_valid_node_key",
    # dual-mode console-JWT-or-service-token guard (app/security/tenant_scope.py)
    "require_console_or_service_auth",
    "TenantPrincipal",
    "ScopedPrincipal",
    # MSSP cross-tenant surfaces resolve a portfolio instead of one tenant
    "PortfolioScope",
    "_scope",
    "_admin_scope",
}

#: Helpers that intersect a caller-supplied tenant with authorised scope.
#: Calling one of these is what makes accepting the parameter legitimate.
SCOPE_INTERSECTION_NAMES = {
    "narrow",
    "require_scope",
    "resolve_scoped_tenant",
    "scoped_tenant_or_403",
    "intersect_tenant_scope",
    "authorize_tenant_access",
    "assert_tenant_access",
}

#: Per-file resolvers that intersect a client tenant with authorised scope but
#: are local to one module, so their names do not belong in the global
#: vocabulary above. Scoped by path so an unrelated function that happens to
#: share a name elsewhere gets no credit.
FILE_LOCAL_RESOLVERS: dict[str, dict[str, str]] = {
    "services/api/app/api/v1/endpoints/mssp.py": {
        "_require_own_child": ("parent/child delegation: verifies the child consented to adoption and is already this parent's"),
    },
    "services/api/app/api/v1/endpoints/alert_writeback.py": {
        "_resolve_caller": ("a session's tenant wins over the body's; a service caller must name one and gets no default"),
    },
    "services/api/app/api/v1/endpoints/playbook_steps.py": {
        "_resolve_caller": (
            "same shape as alert_writeback: a session's tenant comes from the session, "
            "so an authenticated user cannot drive a containment against another tenant's estate"
        ),
    },
}

#: Routes that *define* a tenant scope rather than read within one. Onboarding
#: a customer into a portfolio, or granting a member reach over one, cannot
#: intersect with the scope it is about to create — that would make the
#: operation impossible rather than safe. Each still validates against the
#: organisation's portfolio; the reason records which check stands in.
SCOPE_DEFINING_ROUTES: dict[str, str] = {
    "services/api/app/api/v1/endpoints/mssp.py::add_tenants_to_portfolio": (
        "onboarding: rejects any tenant already claimed by another organisation, "
        "enforced by a unique constraint on organization_tenants.tenant_id"
    ),
    "services/api/app/api/v1/endpoints/mssp.py::set_member_tenant_grants": (
        "grant: refuses tenant_ids outside the organisation's portfolio, backed by the composite FK onto organization_tenants"
    ),
    "services/api/app/api/v1/endpoints/mssp.py::remove_tenant_from_portfolio": (
        "offboarding: deletes only the link row matching this organisation's org_id, so a tenant outside the portfolio resolves to 404"
    ),
}

#: Routes whose credential is a per-tenant pre-shared value verified in-band,
#: rather than a bearer token resolved by a dependency. An agent calling its
#: enrolment endpoint has no session yet — that call is what establishes one —
#: so requiring a bearer dependency would mean it could never enrol.
#:
#: The exemption is conditional, not a free pass: it only applies when the
#: route actually calls the named verifier. Deleting the verification and
#: keeping the entry fails the gate, which is the failure mode an unconditional
#: allowlist cannot catch.
IN_BAND_CREDENTIAL_ROUTES: dict[str, tuple[str, str]] = {
    "services/osquery-tls/app/api/v1/endpoints/enroll.py::enroll": (
        "verify_enroll_secret",
        "osqueryd bootstraps here and holds no bearer token; the per-tenant "
        "enroll secret is the credential and is checked before any write",
    ),
}

#: Routes that are public by design. Each entry is (service, reason) and the
#: reason is load-bearing — an exemption without one is how a gate rots into a
#: list of things somebody once found inconvenient.
EXEMPT_SERVICES = {
    # Ed25519-signed + k-anonymous federation. A bearer token here would break
    # federation between independent deployments rather than secure anything:
    # the whole point is that peers have no shared credential.
    "mesh": "public by design — Ed25519 signatures + k-anonymity, no shared credential exists",
}

#: Path fragments never scanned: tests exercise the routes, vendored copies are
#: read-path mirrors, and the historical prototype is not deployable code.
SKIP_FRAGMENTS = (
    "/tests/",
    "/test_",
    "/_vendor/",
    "/plans/",
    "/node_modules/",
    "/.venv/",
    "/migrations/",
)


@dataclass
class Route:
    service: str
    path: str  # repo-relative file
    lineno: int
    function: str
    methods: list[str]
    route_path: str
    tenant_params: list[str] = field(default_factory=list)
    auth_deps: list[str] = field(default_factory=list)
    scope_calls: list[str] = field(default_factory=list)
    router_level_auth: bool = False
    #: Names called in the body, retained so a conditional exemption can
    #: verify the check it claims still exists.
    body_calls: list[str] = field(default_factory=list)

    @property
    def takes_tenant(self) -> bool:
        return bool(self.tenant_params)

    @property
    def has_auth(self) -> bool:
        return bool(self.auth_deps) or self.router_level_auth

    @property
    def intersects_scope(self) -> bool:
        return bool(self.scope_calls)

    def location(self) -> str:
        return f"{self.path}:{self.lineno} {self.function}()"


def _is_tenant_param(name: str) -> bool:
    if name.startswith(TENANT_PARAM_CONFIRMATION_PREFIXES):
        return False
    if name in TENANT_PARAM_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in TENANT_PARAM_SUFFIXES)


def _names_in(node: ast.AST) -> set[str]:
    """Every bare and dotted name mentioned anywhere under ``node``."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
    return found


def _annotation_names(annotation: ast.expr | None) -> set[str]:
    if annotation is None:
        return set()
    return _names_in(annotation)


def _decorator_route_info(dec: ast.expr) -> tuple[str, str, str] | None:
    """Return (router_object, method, route_path) for a route decorator."""
    if not isinstance(dec, ast.Call):
        return None
    func = dec.func
    if not isinstance(func, ast.Attribute) or func.attr not in HTTP_METHODS:
        return None
    if not isinstance(func.value, ast.Name):
        return None
    router_obj = func.value.id
    route_path = ""
    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
        route_path = dec.args[0].value
    return router_obj, func.attr, route_path


def _pydantic_models_with_tenant(tree: ast.AST) -> dict[str, list[str]]:
    """Request models defined in this module that carry a tenant field.

    A tenant on a POST body is the same hole as a tenant in the query string —
    ``POST /easm/scan {"tenant_id": "<someone else's>"}`` reads exactly like
    ``?tenant_id=``. Only looking at route signatures would miss it, and the
    body is where the mutating routes carry it.
    """
    models: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in node.bases}
        if not bases & {"BaseModel", "BaseSettings"}:
            continue
        fields = [
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and _is_tenant_param(stmt.target.id)
        ]
        if fields:
            models[node.name] = fields
    return models


def auth_annotation_aliases(tree: ast.AST) -> set[str]:
    """Module-local ``X = Annotated[..., Depends(<auth callable>)]`` names.

    ``playbooks.py`` declares ``ExecuteUser = Annotated[AuthUser,
    Depends(require_permission("playbooks:execute"))]`` — a perfectly
    authenticated route that a hardcoded vocabulary reports as wide open,
    because the vocabulary happened to list ``ReadUser`` and ``WriteUser``
    and nobody thought of the third.

    Resolving the alias by *what it wraps* removes the naming dependency
    entirely, which matters in both directions: a false positive sends
    somebody to "fix" a closed route, and the reflex fix — appending the new
    name to the list — is how a list stops describing anything.
    """
    aliases: set[str] = set()
    for node in ast.walk(tree):
        target_names: list[str] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_names = [node.targets[0].id]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target_names = [node.target.id]
            value = node.value
        if not target_names or value is None:
            continue
        if not (isinstance(value, ast.Subscript) and _names_in(value.value) & {"Annotated"}):
            continue
        # Credit only when a Depends(...) inside the annotation names an auth
        # callable; Annotated[AsyncSession, Depends(get_db)] is not auth.
        for sub in ast.walk(value):
            if isinstance(sub, ast.Call) and _names_in(sub.func) & {"Depends", "Security"}:
                if _names_in(sub) & AUTH_DEPENDENCY_NAMES:
                    aliases.update(target_names)
    return aliases


def _router_level_auth_objects(tree: ast.AST) -> set[str]:
    """Router objects constructed with a ``dependencies=`` list naming an auth guard.

    ``APIRouter(dependencies=[Depends(require_service_auth)])`` is how the
    previous default-deny pass secured purple-team, honeytokens and ueba, so a
    scanner that only reads per-route signatures would report those three as
    wide open and send somebody to "fix" routes that are already closed.
    """
    secured: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        callee = call.func
        callee_name = callee.id if isinstance(callee, ast.Name) else (callee.attr if isinstance(callee, ast.Attribute) else "")
        if callee_name not in {"APIRouter", "FastAPI"}:
            continue
        for kw in call.keywords:
            if kw.arg != "dependencies":
                continue
            if _names_in(kw.value) & AUTH_DEPENDENCY_NAMES:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        secured.add(target.id)
    return secured


def _scan_tree(tree: ast.AST, *, service: str, rel_path: str) -> list[Route]:
    routes: list[Route] = []
    secured_routers = _router_level_auth_objects(tree)
    tenant_models = _pydantic_models_with_tenant(tree)
    # Per-file vocabulary: the global names plus any module-local alias that
    # resolves to one of them.
    auth_vocabulary = AUTH_DEPENDENCY_NAMES | auth_annotation_aliases(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue

        methods: list[str] = []
        route_path = ""
        router_objs: set[str] = set()
        decorator_auth: set[str] = set()

        for dec in node.decorator_list:
            info = _decorator_route_info(dec)
            if info is None:
                continue
            router_obj, method, path = info
            router_objs.add(router_obj)
            methods.append(method)
            route_path = route_path or path
            # dependencies=[...] declared on the route decorator itself
            assert isinstance(dec, ast.Call)
            for kw in dec.keywords:
                if kw.arg == "dependencies":
                    decorator_auth |= _names_in(kw.value) & auth_vocabulary

        if not methods:
            continue

        args = node.args
        all_args = [*args.posonlyargs, *args.args, *args.kwonlyargs]

        tenant_params: list[str] = []
        auth_deps: set[str] = set(decorator_auth)
        for arg in all_args:
            ann = _annotation_names(arg.annotation)
            hit = ann & auth_vocabulary
            if hit:
                auth_deps |= hit
            if _is_tenant_param(arg.arg):
                # A tenant that arrives *via* an auth dependency is the
                # principal's, not the caller's — not a finding.
                if not hit:
                    tenant_params.append(arg.arg)
            # A request body whose model declares a tenant field is the same
            # client-supplied tenant, one indirection further away.
            for model_name in ann & tenant_models.keys():
                tenant_params.extend(f"{arg.arg}.{f}" for f in tenant_models[model_name])

        # Defaults can carry Depends(...) without an annotation.
        for default in [*args.defaults, *[d for d in args.kw_defaults if d is not None]]:
            auth_deps |= _names_in(default) & auth_vocabulary

        body_names = set()
        for stmt in node.body:
            body_names |= _names_in(stmt)
        recognised = SCOPE_INTERSECTION_NAMES | FILE_LOCAL_RESOLVERS.get(rel_path, {}).keys()
        scope_calls = sorted(body_names & recognised)

        routes.append(
            Route(
                service=service,
                path=rel_path,
                lineno=node.lineno,
                function=node.name,
                methods=sorted(set(methods)),
                route_path=route_path,
                tenant_params=tenant_params,
                auth_deps=sorted(auth_deps),
                scope_calls=scope_calls,
                router_level_auth=bool(router_objs & secured_routers),
                body_calls=sorted(body_names),
            )
        )
    return routes


def collect_routes(root: Path | None = None) -> list[Route]:
    base = (root or REPO_ROOT) / "services"
    if not base.is_dir():
        raise SystemExit(f"services directory not found under {root or REPO_ROOT}")
    routes: list[Route] = []
    for py in sorted(base.rglob("*.py")):
        posix = py.as_posix()
        if any(fragment in posix for fragment in SKIP_FRAGMENTS):
            continue
        rel = py.relative_to(root or REPO_ROOT).as_posix()
        service = rel.split("/")[1] if rel.startswith("services/") else "?"
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except SyntaxError as exc:
            raise SystemExit(f"could not parse {rel}: {exc}") from exc
        routes.extend(_scan_tree(tree, service=service, rel_path=rel))
    return routes


def find_violations(routes: list[Route]) -> tuple[list[Route], list[Route]]:
    """Return (unauthenticated_tenant_routes, unintersected_tenant_routes)."""
    unauthenticated: list[Route] = []
    unintersected: list[Route] = []
    for route in routes:
        if route.service in EXEMPT_SERVICES or not route.takes_tenant:
            continue
        key = f"{route.path}::{route.function}"
        if key in SCOPE_DEFINING_ROUTES:
            continue
        if key in IN_BAND_CREDENTIAL_ROUTES:
            verifier, _reason = IN_BAND_CREDENTIAL_ROUTES[key]
            if verifier in route.body_calls:
                continue
            # The entry claims a check the route no longer performs. Report it
            # rather than honour a stale exemption.
            unauthenticated.append(route)
            continue
        if not route.has_auth:
            unauthenticated.append(route)
        elif not route.intersects_scope:
            unintersected.append(route)
    return unauthenticated, unintersected


def empty_corpus_refusal(routes: list[Route], services_dir: Path) -> str | None:
    """Why a scan that found no routes must not render a verdict, or ``None``.

    Shared with ``check_route_auth.py``, which imports this scanner. One
    corpus, one floor: two copies would be two floors, and the second one
    written is the one that gets the condition subtly wrong.

    The directory-missing guard in each ``main()`` is not this case. A corpus
    is lost by a renamed package, a changed decorator spelling or a walk that
    stops descending — none of which removes ``services/``, and all of which
    leave the gate with nothing to look at and a clean verdict to print. This
    gate did exactly that: ``scanned 0 routes across 0 files`` on one line and
    ``OK: every route taking a tenant identifier authenticates`` on the next,
    which is the sentence CI shows on a real pass.
    """
    if routes:
        return None
    return (
        f"no routes found under {services_dir}. Zero routes scanned is not zero routes "
        "unscoped — either the walk, SERVICES_DIR or the decorator patterns have stopped "
        "describing where the routes are."
    )


def self_test_empty_corpus(label: str, run: Callable[[], int]) -> int:
    """Run a route gate against a ``services/`` tree with no routes; require a refusal.

    ``run`` is the gate's own ``main``, called with the module-level roots
    rebound to a scratch tree. Rebinding is done here rather than in each
    gate because ``check_route_auth`` imports the names *from* this module:
    a gate that rebound its own copy would leave the collector pointed at the
    real checkout and prove nothing. Returns 0 on success, 1 on failure.
    """
    global REPO_ROOT, SERVICES_DIR  # noqa: PLW0603 - the scanned root is module state
    original_root, original_services = REPO_ROOT, SERVICES_DIR
    with tempfile.TemporaryDirectory(prefix="route_corpus_empty_") as tmp:
        root = Path(tmp)
        (root / "services" / "api" / "app").mkdir(parents=True)
        (root / "services" / "api" / "app" / "nothing.py").write_text("VALUE = 1\n", encoding="utf-8")
        REPO_ROOT, SERVICES_DIR = root, root / "services"
        try:
            status = run()
        finally:
            REPO_ROOT, SERVICES_DIR = original_root, original_services
    if status != 0:
        print(f"  [PASS] {label}: a services/ tree with no routes exits {status} rather than reporting it clean")
        return 0
    print(f"  [FAIL] {label}: reported OK having scanned zero routes")
    return 1


def _print_inventory(routes: list[Route]) -> None:
    services = sorted({r.service for r in routes})
    print(f"Route inventory — scanned {SERVICES_DIR}")
    print(f"{'service':<20}{'routes':>8}{'tenant-param':>14}{'authed':>9}{'tenant+auth':>13}{'intersects':>12}")
    print("-" * 76)
    for svc in services:
        rs = [r for r in routes if r.service == svc]
        tenant = [r for r in rs if r.takes_tenant]
        note = "  (exempt: public by design)" if svc in EXEMPT_SERVICES else ""
        print(
            f"{svc:<20}{len(rs):>8}{len(tenant):>14}{sum(1 for r in rs if r.has_auth):>9}"
            f"{sum(1 for r in tenant if r.has_auth):>13}{sum(1 for r in tenant if r.intersects_scope):>12}{note}"
        )
    print("-" * 76)
    tenant_all = [r for r in routes if r.takes_tenant]
    print(
        f"{'TOTAL':<20}{len(routes):>8}{len(tenant_all):>14}"
        f"{sum(1 for r in routes if r.has_auth):>9}{sum(1 for r in tenant_all if r.has_auth):>13}"
        f"{sum(1 for r in tenant_all if r.intersects_scope):>12}"
    )


def _self_test() -> int:
    """Prove the scanner detects drift in both directions.

    A gate nobody has seen fail is indistinguishable from a gate that cannot
    fail. Each case below is a route the scanner must reject, and the clean
    control must pass, so a refactor that quietly breaks detection shows up
    here rather than in an incident.
    """
    clean = """
from fastapi import APIRouter
from app.api.v1.deps import AuthUser
router = APIRouter()

@router.get("/queue")
async def queue(user: AuthUser):
    return {"tenant_id": str(user.tenant_id)}
"""
    unauthenticated = """
from uuid import UUID
from fastapi import APIRouter
router = APIRouter()

@router.get("/queue")
async def queue(tenant_id: UUID):
    return {"tenant_id": str(tenant_id)}
"""
    unintersected = """
from uuid import UUID
from fastapi import APIRouter
from app.api.v1.deps import AuthUser
router = APIRouter()

@router.get("/queue")
async def queue(user: AuthUser, tenant_id: UUID):
    return {"tenant_id": str(tenant_id)}
"""
    intersected = """
from uuid import UUID
from fastapi import APIRouter
from app.api.v1.deps import AuthUser
from app.services.org_scope import narrow
router = APIRouter()

@router.get("/queue")
async def queue(user: AuthUser, tenant_id: UUID):
    scope = narrow(user.scope, [tenant_id])
    return {"tenants": scope.ordered_ids()}
"""
    cases = [
        ("clean (auth, no client tenant)", clean, 0, 0),
        ("drift A: tenant param, no auth", unauthenticated, 1, 0),
        ("drift B: tenant param + auth, no intersection", unintersected, 0, 1),
        ("control: tenant param + auth + intersection", intersected, 0, 0),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, source, want_unauth, want_unint in cases:
            root = Path(tmp) / label.split(":")[0].strip().replace(" ", "_")
            target = root / "services" / "probe" / "app"
            target.mkdir(parents=True, exist_ok=True)
            (target / "routes.py").write_text(source, encoding="utf-8")
            routes = collect_routes(root=root)
            unauth, unint = find_violations(routes)
            ok = len(unauth) == want_unauth and len(unint) == want_unint
            status = "PASS" if ok else "FAIL"
            if not ok:
                failures += 1
            print(
                f"  [{status}] {label}: found {len(unauth)} unauthenticated, {len(unint)} unintersected (want {want_unauth}, {want_unint})"
            )

    # Third direction: an exemption must stop protecting a route the moment
    # the check it names is removed. An allowlist that keeps passing after its
    # justification is deleted is worse than no allowlist, because it reads
    # like a decision somebody made rather than one that lapsed.
    failures += _self_test_stale_exemption()

    # Fourth: a scan that found no routes must not report on them. This gate
    # printed "scanned 0 routes across 0 files" and then "OK: every route
    # taking a tenant identifier authenticates" against a services/ directory
    # with nothing in it — the clean verdict CI shows on a real pass.
    failures += self_test_empty_corpus("empty corpus", lambda: main([]))

    if failures:
        print(f"\nself-test FAILED: {failures} case(s) did not behave as specified", file=sys.stderr)
        return 1
    print(
        "\nself-test passed: the gate detects drift in both directions, clears both clean controls, "
        "drops a stale exemption, and refuses a corpus it never found."
    )
    return 0


def _self_test_stale_exemption() -> int:
    """Assert IN_BAND_CREDENTIAL_ROUTES stops exempting once its verifier is gone.

    The constant is named "credential" rather than "secret" deliberately: it
    holds route keys and function names, never a credential value, but a
    `secret`-shaped identifier flowing into `print` trips CodeQL's
    clear-text-logging heuristic — the same false positive a counter named
    `secret*` caused in a previous pass.
    """
    failures = 0
    for key, (verifier, _reason) in IN_BAND_CREDENTIAL_ROUTES.items():
        rel, func = key.split("::")
        path = REPO_ROOT / rel
        if not path.is_file():
            print(f"  [FAIL] exemption names a file that does not exist: {rel}")
            failures += 1
            continue
        source = path.read_text(encoding="utf-8")
        if verifier not in source:
            print(f"  [FAIL] exemption for {func}() names {verifier}(), which {rel} never calls")
            failures += 1
            continue
        # Re-scan the file with the verification call stripped out; the route
        # must now be reported.
        blinded = source.replace(verifier, f"{verifier}_REMOVED_BY_SELF_TEST")
        tree = ast.parse(blinded, filename=str(path))
        routes = [r for r in _scan_tree(tree, service=rel.split("/")[1], rel_path=rel) if r.function == func]
        unauth, _ = find_violations(routes)
        if len(unauth) == 1:
            print(f"  [PASS] stale exemption: {func}() is reported once {verifier}() no longer runs")
        else:
            print(f"  [FAIL] stale exemption: removing {verifier}() from {func}() produced {len(unauth)} findings, want 1")
            failures += 1
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", action="store_true", help="print the per-service route inventory")
    parser.add_argument("--json", action="store_true", help="emit the full inventory as JSON")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift both ways")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not SERVICES_DIR.is_dir():
        print(f"ERROR: no services/ directory under {REPO_ROOT} — refusing to report a result for a tree I did not open.", file=sys.stderr)
        return 2

    routes = collect_routes()

    # Before any output mode. Naming the count was half the fix; see
    # empty_corpus_refusal() for why the directory check above is not this
    # case, and for the two-line output that made it invisible.
    #
    # Ahead of `--inventory` as well as the default, because CI runs the
    # inventory as its own step: a green step printing `TOTAL 0 0 0 0 0` is
    # the same defect one level out, and it survived the first fix because
    # only the default path was given a floor.
    refusal = empty_corpus_refusal(routes, SERVICES_DIR)
    if refusal is not None:
        print(f"check_route_tenant_scope: scanned 0 routes across 0 files under {SERVICES_DIR}")
        print(f"\nFAIL: {refusal}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(r) for r in routes], indent=2))
        return 0

    if args.inventory:
        _print_inventory(routes)
        return 0

    unauthenticated, unintersected = find_violations(routes)

    # Name what was scanned. A gate that prints OK without saying what it
    # opened cannot be distinguished from one that opened nothing.
    files = len({r.path for r in routes})
    print(f"check_route_tenant_scope: scanned {len(routes)} routes across {files} files under {SERVICES_DIR}")

    if unauthenticated:
        print(f"\nFAIL: {len(unauthenticated)} route(s) take a tenant identifier with no auth dependency.", file=sys.stderr)
        print("      The tenant is whatever the caller typed. Derive it from the authenticated principal.", file=sys.stderr)
        for route in unauthenticated:
            print(f"  - {route.location()} takes {route.tenant_params}", file=sys.stderr)

    if unintersected:
        print(f"\nFAIL: {len(unintersected)} route(s) accept a tenant identifier without intersecting it with scope.", file=sys.stderr)
        print(
            f"      Authenticated is not the same as authorised. Pass it through one of: {sorted(SCOPE_INTERSECTION_NAMES)}.",
            file=sys.stderr,
        )
        for route in unintersected:
            print(f"  - {route.location()} takes {route.tenant_params} (auth: {route.auth_deps or 'router-level'})", file=sys.stderr)

    if unauthenticated or unintersected:
        return 1

    print("OK: every route taking a tenant identifier authenticates and intersects it with the caller's scope.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
