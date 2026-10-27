"""The kill switch is reachable, authorized and audited.

Parity plan 2.2. The agents-side half (that an engaged switch actually stops
closure) lives in `services/agents/tests/test_closure_policy.py`, which
drives the resolver. This covers the API surface: that the routes exist,
that writing requires a permission while reading does not, and that the
reason is mandatory.
"""

from __future__ import annotations

import inspect

import pytest
from app.api.v1.endpoints import kill_switch
from app.core.rbac_catalog import PERMISSIONS
from app.core.security import ROLE_PERMISSIONS
from app.db.database import get_db
from app.main import app
from fastapi.testclient import TestClient

#: The permission the platform-wide routes require. Read from the module so
#: the test cannot keep passing against a renamed constant, and defaulted so
#: that a tree without the surface fails each assertion with its own reason
#: rather than aborting collection and taking the rest of this file with it.
PLATFORM_KILL_SWITCH = getattr(kill_switch, "PLATFORM_KILL_SWITCH_PERMISSION", "<no platform kill-switch permission is declared>")

#: One client for the module. Resolution is by **sending a request**, not
#: by walking `app.routes`: that is not the route table and what it holds
#: changes with the FastAPI minor, which made the sibling compliance file
#: pass locally and report every path unreachable in CI.
#:
#: A 401 answers the question as well as a 200 does, because authentication
#: runs after the route has matched.
_CLIENT = TestClient(app, raise_server_exceptions=False)


def _reaches_a_route(path: str, method: str = "GET") -> bool:
    return _CLIENT.request(method, path).status_code != 404


def _handler_for(path: str, method: str = "GET") -> str | None:
    """The handler that owns `path`, from the OpenAPI document."""
    spec = app.openapi()
    operation = spec.get("paths", {}).get(path, {}).get(method.lower())
    if not operation:
        return None
    return operation.get("operationId", "").split("_api_v1_")[0] or None


def _route_object(path: str, method: str):
    """The router's own route, for assertions about the dependency tree.

    Taken off ``kill_switch.router`` rather than ``app.routes``: what the
    latter holds changes with the FastAPI minor, and a gate that enumerated it
    once compared zero pairs and reported success.
    """
    for route in kill_switch.router.routes:
        if route.path == path and method in set(getattr(route, "methods", set())):
            return route
    raise AssertionError(f"no route {method} {path}")


def _required_permissions(route) -> set[str]:
    """Every permission the route's dependency tree actually resolves.

    ``require_permission`` returns a closure, so the permission it enforces
    lives in that closure's cells rather than anywhere readable from the
    route. Walking the resolved tree is what makes this an assertion about
    enforcement instead of about spelling.
    """
    found: set[str] = set()

    def walk(dependant) -> None:
        call = dependant.call
        closure = getattr(call, "__closure__", None) or ()
        if getattr(call, "__name__", "") == "_check":
            found.update(cell.cell_contents for cell in closure if isinstance(cell.cell_contents, str))
        for sub in dependant.dependencies:
            walk(sub)

    walk(route.dependant)
    return found


class TestTheRoutesExist:
    @pytest.mark.parametrize(
        ("path", "method", "handler"),
        [
            ("/api/v1/kill-switch", "GET", "read_kill_switch"),
            ("/api/v1/kill-switch/engage", "POST", "engage"),
            ("/api/v1/kill-switch/release", "POST", "release"),
        ],
    )
    def test_each_route_reaches_its_handler(self, path: str, method: str, handler: str) -> None:
        assert _reaches_a_route(path, method), f"{method} {path} answers 404"
        assert _handler_for(path, method) == handler


class TestAuthorization:
    def test_writing_requires_a_permission(self) -> None:
        for name in ("engage", "release"):
            source = inspect.getsource(getattr(kill_switch, name))
            assert 'require_permission("settings:write")' in source, (
                f"{name} does not require a permission, so any authenticated user could freeze or unfreeze the platform"
            )

    def test_reading_does_not(self) -> None:
        """An analyst watching the queue stop moving has to be able to find
        out why without asking an administrator."""
        source = inspect.getsource(kill_switch.read_kill_switch)
        assert "require_permission" not in source
        assert "user: AuthUser" in source, "reading must still be authenticated"


class TestTheReasonIsMandatory:
    """A switch with no reason is one nobody can safely disengage: the next
    operator cannot tell a deliberate freeze from a forgotten test."""

    def test_engaging_requires_a_reason(self) -> None:
        field = kill_switch.EngageRequest.model_fields["reason"]
        assert field.is_required()
        assert any(getattr(m, "min_length", None) for m in field.metadata), "an empty-ish reason would satisfy a bare required field"

    def test_releasing_requires_one_too(self) -> None:
        assert kill_switch.ReleaseRequest.model_fields["reason"].is_required()


class TestItIsAudited:
    def test_both_transitions_write_an_audit_row(self) -> None:
        for name, action in (("engage", "'engage'"), ("release", "'release'")):
            source = inspect.getsource(getattr(kill_switch, name))
            assert "aisoc_kill_switch_audit" in source, f"{name} writes no audit row"
            assert action in source

    def test_the_log_line_cannot_be_forged_by_the_reason(self) -> None:
        """The reason is operator-supplied text that lands in a log line."""
        assert "\n" not in kill_switch._sanitize("a\nb")
        assert "\r" not in kill_switch._sanitize("a\rb")
        assert len(kill_switch._sanitize("x" * 5000)) <= 200


class TestThePlatformSwitchHasASurface:
    """The global switch had two readers and no writer.

    Every write in this module bound ``t=user.tenant_id``, so the only scope
    any caller could reach was their own tenant, while ``GET /kill-switch``
    and ``services/agents`` ``kill_switch_engaged`` both consult the global
    row on every alert. A reader over a table nothing writes is not a
    control, and this one was labelled an emergency stop.
    """

    @pytest.mark.parametrize(
        ("path", "handler"),
        [
            ("/api/v1/kill-switch/global/engage", "engage_global"),
            ("/api/v1/kill-switch/global/release", "release_global"),
        ],
    )
    def test_the_global_routes_exist(self, path: str, handler: str) -> None:
        assert _reaches_a_route(path, "POST"), f"POST {path} answers 404, so the platform-wide stop has no product surface"
        assert _handler_for(path, "POST") == handler

    @pytest.mark.parametrize("verb", ["engage", "release"])
    def test_they_require_the_platform_permission(self, verb: str) -> None:
        """Not ``settings:write``. A tenant administrator holds that, and the
        global switch stops every *other* tenant on the deployment too.

        Read off the **resolved** dependency tree rather than the handler's
        source. A substring assertion would pass on
        ``Annotated[Any, require_permission(...)]`` with no ``Depends()``,
        which FastAPI silently drops — that exact shape left eleven routes
        reading as gated while enforcing nothing.
        """
        required = _required_permissions(_route_object(f"/kill-switch/global/{verb}", "POST"))
        assert PLATFORM_KILL_SWITCH in required, (
            f"{verb}_global resolves {sorted(required) or 'no permission check'}, not {PLATFORM_KILL_SWITCH}, "
            "so it is reachable by a principal whose authority stops at their own tenant"
        )

    def test_no_tenant_scoped_role_holds_it(self) -> None:
        """The permission is the authorization. If a tenant role held it,
        requiring it would be theatre."""
        holders = [role for role, perms in ROLE_PERMISSIONS.items() if PLATFORM_KILL_SWITCH in perms]
        assert holders == [], (
            f"{PLATFORM_KILL_SWITCH} is granted to {holders}, which are tenant-scoped roles. "
            "Only the wildcard roles may freeze the whole deployment."
        )
        wildcard = [role for role, perms in ROLE_PERMISSIONS.items() if "*" in perms]
        assert wildcard, "no role holds the wildcard, so nobody could ever engage the platform switch"

    def test_it_is_in_the_seeded_catalog(self) -> None:
        """A permission absent from the catalog renders blank on the Roles
        screen and cannot be granted to a custom role."""
        assert PLATFORM_KILL_SWITCH in {name for name, _d, _c in PERMISSIONS}

    @pytest.mark.parametrize("name", ["engage_global", "release_global"])
    def test_they_run_on_an_unbound_session(self, name: str) -> None:
        """The inverse of the tenant routes, and load-bearing rather than an
        oversight: the global row is admitted by ``WITH CHECK`` only when
        ``current_tenant_id()`` is NULL, so a tenant-scoped session is exactly
        the one that cannot write it.

        Asserted on the resolved dependency so it cannot drift into
        ``get_tenant_db`` the way the tenant routes once drifted out of it.
        """
        route = _route_object("/kill-switch/global/" + name.split("_")[0], "POST")
        db = next((d.call for d in route.dependant.dependencies if d.name == "db"), None)
        assert db is get_db, f"{name} must take the unbound session; a tenant-bound one cannot write the global row"

    @pytest.mark.parametrize("name", ["engage_global", "release_global"])
    def test_both_transitions_are_audited_as_global(self, name: str) -> None:
        source = inspect.getsource(getattr(kill_switch, name))
        assert "aisoc_kill_switch_audit" in source, f"{name} writes no audit row"
        assert "'global'" in source, f"{name} does not record the scope as global"


class TestReleasingAGlobalSwitch:
    def test_a_tenant_cannot_release_the_platform_switch(self) -> None:
        """And is told so, rather than getting a success that changes
        nothing. Reporting success over a switch that stays engaged is how
        an operator concludes the stop button is broken."""
        source = inspect.getsource(kill_switch.release)
        assert "409" in source or "HTTP_409_CONFLICT" in source
        assert "platform operator" in source
