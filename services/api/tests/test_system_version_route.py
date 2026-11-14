"""``GET /api/v1/system/version`` — promised to operators, never built.

``apps/docs/docs/operations/upgrades.md`` tells an operator to "check
``/api/v1/system/version`` and see the same number" after an upgrade. The
route did not exist, so the documented way to confirm an upgrade landed
returned 404 — and the number it would have shown was the hardcoded
``0.1.0`` anyway.

What is asserted here
---------------------
* the route exists and answers,
* it reports the version in the tree, the applied-migration high-water mark
  and the schema-skew verdict,
* it is authenticated **and** authorized, with the authorization actually
  running rather than merely being written down.

That last one has its own test because of a defect this repository has
shipped eleven times: ``Annotated[Any, require_permission("x:write")]``
*without* ``Depends()`` reads as a permission check and is silently dropped
by FastAPI, which then reinterprets the parameter as a required **query
parameter**. The published spec is where that shows up, so the spec is where
it is checked — a route that authorizes correctly declares no query
parameters at all.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.main import app
from fastapi.testclient import TestClient

ROUTE = "/api/v1/system/version"
TREE_VERSION = (Path(__file__).resolve().parents[3] / "VERSION").read_text(encoding="utf-8").strip()


def _principal(role: str) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role=role,
        email=f"{role}@example.invalid",
    )


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_current_user, None)


class TestAuthorization:
    def test_unauthenticated_is_refused(self, client: TestClient) -> None:
        app.dependency_overrides.pop(get_current_user, None)
        assert client.get(ROUTE).status_code == 401

    def test_a_role_without_settings_read_is_refused(self, client: TestClient) -> None:
        app.dependency_overrides[get_current_user] = lambda: _principal("viewer")
        response = client.get(ROUTE)
        assert response.status_code == 403, response.text

    def test_an_admin_is_admitted(self, client: TestClient) -> None:
        app.dependency_overrides[get_current_user] = lambda: _principal("tenant_admin")
        assert client.get(ROUTE).status_code == 200

    def test_the_route_declares_no_query_parameters(self) -> None:
        """Pins the spec shape — but it is NOT the guard against a dropped
        permission, and the difference was measured rather than assumed.

        The known form of that defect is ``Annotated[Any, require_permission(
        "x:write")]`` with no ``Depends()``: FastAPI honours only ``Depends``/
        ``FieldInfo`` metadata, drops the rest, and reinterprets the parameter
        as a required query parameter — which is how eleven routes were found,
        by reading the published spec.

        That symptom does not appear here. ``AuthUser`` is itself
        ``Annotated[CurrentUser, Depends(get_current_user)]``, so the broken
        form flattens to ``Annotated[CurrentUser, Depends(get_current_user),
        require_permission(...)]``; FastAPI resolves the first ``Depends`` and
        silently discards the bare callable. Authentication still happens,
        authorization vanishes, and **the spec is byte-identical**. Removing
        ``Depends()`` here was executed as a negative control: this assertion
        passed and ``test_a_role_without_settings_read_is_refused`` returned
        200 instead of 403.

        So the behavioural test above is the load-bearing one. This stays
        because no-query-parameters is still a property worth pinning, and
        because a reader who knows only the spec-shaped symptom needs to be
        told it cannot see this variant.
        """
        operation = app.openapi()["paths"][ROUTE]["get"]
        query_params = [p for p in operation.get("parameters", []) if p.get("in") == "query"]
        assert query_params == [], f"unexpected query parameters: {query_params}"


class TestPayload:
    @pytest.fixture
    def body(self, client: TestClient) -> dict:
        app.dependency_overrides[get_current_user] = lambda: _principal("tenant_admin")
        response = client.get(ROUTE)
        assert response.status_code == 200, response.text
        return response.json()

    def test_reports_the_version_in_the_tree(self, body: dict) -> None:
        assert body["version"] == TREE_VERSION

    def test_agrees_with_health(self, body: dict, client: TestClient) -> None:
        """Two surfaces, one fact. They disagreed for twenty-two majors."""
        assert body["version"] == client.get("/health").json()["version"]

    def test_revision_is_absent_rather_than_invented_when_unstamped(self, body: dict) -> None:
        assert "revision" in body
        assert body["revision"] is None or isinstance(body["revision"], str)

    def test_carries_the_migration_high_water_mark_and_the_skew_verdict(self, body: dict) -> None:
        schema = body["schema_migrations"]
        assert schema["state"] in {"current", "skewed", "unknown"}
        assert "latest_applied" in schema
        assert schema["migrations_on_disk"] > 0, "the service ships migrations; the route should count them"

    def test_an_unreachable_database_reports_unknown_and_still_answers(self, body: dict) -> None:
        """Reporting loudly is not the same as refusing to serve.

        These tests run with no database, which is exactly the condition
        under which an operator most needs the route to answer. The verdict
        must be ``unknown`` — never ``current`` — and the response must still
        be a 200 carrying the version.
        """
        assert body["schema_migrations"]["state"] == "unknown"
        assert body["version"] == TREE_VERSION
