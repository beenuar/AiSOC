"""The SCIM surface has to be reachable on the real application.

Five things in this program shipped with a passing test suite and no caller
on the path that needed them, so a module-level test of a router proves very
little. This builds the application the service actually serves and asks it
what it exposes.

``include_router`` does not populate ``app.routes`` usefully on the pinned
FastAPI, and a route inventory read from there can silently measure nothing
and report success. So this reads ``app.openapi()``, which is generated from
what was mounted, and it asserts the inventory is non-empty before asserting
anything about its contents.
"""

from __future__ import annotations

from app.main import create_application
from app.services.scim.resources import SCIM_BASE

#: Every path an identity provider reaches during a sync. A provider is
#: configured with the base URL only and appends these itself, so a missing
#: one surfaces to an administrator as a failed sync rather than as a 404
#: they can attribute.
REQUIRED_PATHS: dict[str, set[str]] = {
    f"{SCIM_BASE}/ServiceProviderConfig": {"get"},
    f"{SCIM_BASE}/ResourceTypes": {"get"},
    f"{SCIM_BASE}/Schemas": {"get"},
    f"{SCIM_BASE}/Users": {"get", "post"},
    f"{SCIM_BASE}/Users/{{user_id}}": {"get", "put", "patch", "delete"},
    f"{SCIM_BASE}/Groups": {"get", "post"},
    f"{SCIM_BASE}/Groups/{{group_id}}": {"get", "put", "patch", "delete"},
}


def test_the_scim_surface_is_mounted_on_the_real_application() -> None:
    paths = create_application().openapi()["paths"]

    # Before asserting what is there, assert that anything is. An empty
    # inventory makes every membership check below vacuously unrunnable and
    # a naive version of this test would pass over it.
    assert paths, "the OpenAPI document exposes no paths at all; this test would otherwise measure nothing"
    scim_paths = {path for path in paths if path.startswith(SCIM_BASE)}
    assert scim_paths, f"no path under {SCIM_BASE} is mounted; the SCIM router is defined and never included"

    for path, methods in REQUIRED_PATHS.items():
        assert path in paths, f"{path} is not mounted"
        assert methods <= set(paths[path]), f"{path} is missing {sorted(methods - set(paths[path]))}"


def test_the_console_facing_token_routes_are_mounted() -> None:
    """The credential the SCIM surface accepts has to be mintable.

    A SCIM surface with no way to issue a token for it is unreachable in
    practice however correct the handlers are.
    """
    paths = create_application().openapi()["paths"]
    assert paths, "the OpenAPI document exposes no paths at all"

    assert "/api/v1/scim-tokens" in paths
    assert {"get", "post"} <= set(paths["/api/v1/scim-tokens"])
    assert "/api/v1/scim-tokens/{token_id}/rotate" in paths
    assert "post" in paths["/api/v1/scim-tokens/{token_id}/rotate"]
    assert "delete" in paths["/api/v1/scim-tokens/{token_id}"]
