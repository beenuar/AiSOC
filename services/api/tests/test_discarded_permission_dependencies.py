"""A permission that FastAPI never calls, on eleven routes across four modules.

Found while closing GHSA-wj5c-88hg-5926, which was the same omission wearing
no disguise: `remediation.py` authenticated and never authorized. These eleven
*look* authorized. They are written

    current_user: Annotated[Any, require_permission("users:write")]

with no `Depends()`. FastAPI honours only `Annotated` metadata that is a
`Depends` or a `FieldInfo` and silently drops the rest, so the permission is
never checked and `current_user` degrades into a required query parameter.
`POST /api-keys`, `PUT /branding` and `POST /scim-tokens` were all in this
state — minting API keys and rotating SCIM tokens among them.

This is the worse version of the bug. A reviewer reads the permission and
moves on, and `scripts/check_route_authz.py` counted these routes among the
143 that "authorize" because it matched the call and not the wiring.

Asserted against the resolved dependency tree and against live requests rather
than the source, because the source is exactly what is misleading here.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys, branding, scim_tokens, usage
from app.api.v1.endpoints.auth import get_current_user
from app.core.security import ROLE_PERMISSIONS
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

#: Every route that carried a permission FastAPI discarded, and the permission
#: it was meant to enforce.
DISCARDED_ROUTES: list[tuple[Any, str, str]] = [
    (api_keys, "create_api_key", "users:write"),
    (api_keys, "update_api_key", "users:write"),
    (api_keys, "revoke_api_key", "users:write"),
    (branding, "put_branding", "settings:write"),
    (branding, "upload_asset", "settings:write"),
    (branding, "delete_asset", "settings:write"),
    (scim_tokens, "create_scim_token", "settings:write"),
    (scim_tokens, "rotate_scim_token", "settings:write"),
    (scim_tokens, "revoke_scim_token", "settings:write"),
    (usage, "get_reconciliation", "settings:read"),
    (usage, "export_month", "reports:read"),
]

MODULES = [api_keys, branding, scim_tokens, usage]


def _viewer() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="viewer",
        email="viewer@example.com",
    )


def _route_for(module: Any, handler_name: str) -> Any:
    handler = getattr(module, handler_name)
    for route in module.router.routes:
        if getattr(route, "endpoint", None) is handler:
            return route
    raise AssertionError(f"no route registered for {module.__name__}.{handler_name}")


def _permissions_on(route: Any) -> list[str]:
    """Permissions FastAPI will actually enforce, from the resolved tree.

    `require_permission` returns a closure holding the permission string, so a
    dependency that is really wired carries it here. Metadata FastAPI dropped
    does not appear, which is the whole point: this reads what will run, not
    what was written.
    """
    found: list[str] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        for cell in getattr(call, "__closure__", None) or ():
            try:
                value = cell.cell_contents
            except ValueError:  # pragma: no cover - empty cell
                continue
            if isinstance(value, str) and ":" in value:
                found.append(value)
        for sub in getattr(dependant, "dependencies", []) or []:
            walk(sub)

    walk(route.dependant)
    return found


class TestThePermissionIsActuallyEnforced:
    @pytest.mark.parametrize(("module", "handler", "permission"), DISCARDED_ROUTES, ids=[r[1] for r in DISCARDED_ROUTES])
    def test_the_declared_permission_reaches_the_dependency_tree(self, module: Any, handler: str, permission: str) -> None:
        enforced = _permissions_on(_route_for(module, handler))
        assert permission in enforced, (
            f"{module.__name__}.{handler} declares {permission!r} but FastAPI will enforce {enforced or 'nothing'}; "
            f"the annotation is missing Depends()"
        )

    @pytest.mark.parametrize("module", MODULES, ids=[m.__name__.rsplit(".", 1)[-1] for m in MODULES])
    def test_no_route_takes_the_principal_as_a_query_parameter(self, module: Any) -> None:
        """The observable symptom, stated without reference to the cause.

        When FastAPI drops the metadata it does not drop the parameter — with
        no recognised dependency, `current_user` becomes an ordinary query
        parameter. Any route asking the caller to *supply* their own principal
        in the URL is broken however it came to be written.
        """
        for route in module.router.routes:
            if not hasattr(route, "dependant"):
                continue
            supplied = [p.name for p in route.dependant.query_params if p.name in {"current_user", "user", "current_active_user"}]
            assert not supplied, f"{module.__name__}{route.path} takes {supplied} from the query string"


class TestAViewerIsRefused:
    """The impact, asserted through a request rather than a signature.

    Deliberately does not import any new symbol. A test that only imports
    something the pre-fix tree lacks fails with ImportError, which proves the
    symbol is absent rather than that the hole is closed. Everything here
    exists on both trees, so the failure is the 200 itself.
    """

    @pytest.fixture
    def client(self) -> TestClient:
        app = FastAPI()
        for module in MODULES:
            app.include_router(module.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = _viewer
        app.dependency_overrides[get_db] = lambda: None
        return TestClient(app, raise_server_exceptions=False)

    def test_the_viewer_role_holds_none_of_the_permissions_under_test(self) -> None:
        """Without this the refusals below could pass for the wrong reason."""
        held = set(ROLE_PERMISSIONS["viewer"])
        required = {permission for _, _, permission in DISCARDED_ROUTES}
        assert not (held & required - {"reports:read"}), f"viewer unexpectedly holds {held & required}"

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("post", "/api/v1/api-keys"),
            ("patch", f"/api/v1/api-keys/{uuid.uuid4()}"),
            ("delete", f"/api/v1/api-keys/{uuid.uuid4()}"),
            ("put", "/api/v1/branding"),
            ("delete", "/api/v1/branding/assets/logo"),
            ("post", "/api/v1/scim-tokens"),
            ("delete", f"/api/v1/scim-tokens/{uuid.uuid4()}"),
            ("get", "/api/v1/usage/reconciliation"),
        ],
    )
    def test_a_read_only_token_cannot_reach_the_handler(self, client: TestClient, method: str, path: str) -> None:
        # `request` rather than `client.get(...)`: the GET and DELETE helpers
        # take no `json` argument, and the body is irrelevant to a 403 anyway.
        response = client.request(method.upper(), path, json={})
        assert response.status_code == 403, (
            f"{method.upper()} {path} answered {response.status_code} for a viewer token. "
            f"403 is the only acceptable answer; a 422 means the principal became a query parameter, "
            f"and anything else means the handler was reached."
        )

    def test_an_authorised_role_is_not_refused(self, client: TestClient) -> None:
        """A gate that refuses everyone would pass every test above."""
        client.app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="tenant_admin", email="admin@example.com"
        )
        response = client.put("/api/v1/branding", json={})
        assert response.status_code != 403, "tenant_admin holds settings:write and must not be refused"
