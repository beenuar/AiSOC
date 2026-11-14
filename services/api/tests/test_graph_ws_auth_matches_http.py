"""The WebSocket auth contract is the HTTP one, not a weaker copy of it.

GHSA-25fh-rxp8-67j8. Reported through private vulnerability reporting.

What was wrong
--------------
`_authenticate_ws` in `graph_ws.py` resolved a JWT by hand: decode, check the
type, load the user, build a `CurrentUser`. Its docstring said *"We reuse the
same helpers `get_current_user` uses so the auth contract is identical."* It
did not, in two ways that matter:

* **No revocation check.** `get_current_user` calls `token_is_revoked` against
  `users.sessions_revoked_at`, so a token minted before a session revocation is
  refused with `401 Session revoked`. The WebSocket path never looked, so a
  de-provisioned principal kept a live subscription to the tenant graph stream
  for the remaining lifetime of its access token -- while the *same token* was
  being refused over HTTP.

* **No database RBAC.** `get_current_user` calls `resolve_permissions` and puts
  the result in `resolved_permissions`. The hand-built principal left it
  `None`, so `require_permission("graph:read")` fell back to the static
  `ROLE_PERMISSIONS` map. A wildcard role passes that unconditionally, which
  means a database-backed grant revocation had no effect on this surface
  either.

The reporter's proof of concept is the shape worth keeping: `GET
/api/v1/graph/overview` answers 401, and `GET /api/v1/graph_ws/stream?token=`
with the *same token* answers 101 and keeps streaming.

What this file asserts
----------------------
That the two paths cannot diverge again: the WebSocket resolver delegates to
the same function the HTTP dependency uses, rather than reimplementing it. A
test that merely checked "a revoked token is refused" would pass against a
second hand-rolled copy that happens to call `token_is_revoked` today and stops
calling it after the next edit.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GRAPH_WS = REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "graph_ws.py"


def _authenticate_ws_calls() -> set[str]:
    """Every function `_authenticate_ws` calls, by name."""
    tree = ast.parse(GRAPH_WS.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_authenticate_ws":
            names: set[str] = set()
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    func = call.func
                    if isinstance(func, ast.Name):
                        names.add(func.id)
                    elif isinstance(func, ast.Attribute):
                        names.add(func.attr)
            return names
    raise AssertionError("graph_ws.py no longer defines _authenticate_ws")


class TestTheSocketDoesNotReimplementAuthentication:
    def test_it_delegates_to_the_shared_resolver(self) -> None:
        """The durable property. Two implementations of one security contract
        drift, and this one drifted silently for the whole time it shipped."""
        calls = _authenticate_ws_calls()

        assert "resolve_jwt_principal" in calls, (
            "_authenticate_ws still resolves the JWT itself. The HTTP dependency and the "
            "WebSocket must share one resolver, or the next edit to one leaves the other behind"
        )

    def test_it_no_longer_builds_a_principal_by_hand_on_the_jwt_path(self) -> None:
        """A hand-built `CurrentUser` is how `resolved_permissions` became
        `None`, which is what demoted the permission check to the static role
        map."""
        source = GRAPH_WS.read_text(encoding="utf-8")
        tree = ast.parse(source)

        built = 0
        for node in ast.walk(tree):
            if not (isinstance(node, ast.AsyncFunctionDef) and node.name == "_authenticate_ws"):
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                if isinstance(call.func, ast.Name) and call.func.id == "CurrentUser":
                    built += 1

        # One remains, and only one: the dev-mode demo principal, which is
        # gated by `is_dev_mode()` and carries no real identity.
        assert built <= 1, f"{built} hand-built CurrentUser(...) calls remain in _authenticate_ws"


class TestTheSharedResolverEnforcesBothChecks:
    def test_the_resolver_checks_revocation(self) -> None:
        from app.api.v1 import deps

        source = inspect.getsource(deps.resolve_jwt_principal)

        assert "token_is_revoked" in source, "the shared resolver does not check session revocation"

    def test_the_resolver_resolves_database_permissions(self) -> None:
        from app.api.v1 import deps

        source = inspect.getsource(deps.resolve_jwt_principal)

        assert "resolve_permissions" in source, (
            "the shared resolver does not load database RBAC, so require_permission falls back "
            "to the static role map and a wildcard role passes unconditionally"
        )

    def test_the_http_dependency_uses_the_same_resolver(self) -> None:
        """The negative control on the refactor: if `get_current_user` stopped
        using it, this test would still pass on the WebSocket side while the
        two had silently diverged again -- in the other direction."""
        from app.api.v1 import deps

        source = inspect.getsource(deps.get_current_user)

        assert "resolve_jwt_principal" in source, (
            "get_current_user no longer uses the shared resolver, so HTTP and WebSocket have diverged again"
        )
