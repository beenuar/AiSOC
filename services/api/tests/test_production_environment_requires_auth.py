"""An unauthenticated request must not be admin outside development.

This is the assertion discussion #629 was really about. `docker-compose.yml`
defaults `ENVIRONMENT` to `development`, `development` is in
`AUTH_BYPASS_ENVIRONMENTS`, and `app/api/v1/dev_auth.py` then resolves a
request carrying no bearer token to a demo user whose role is `admin`. The
documented production compose file did not exist, so that was the only stack an
operator could start.

The bypass itself is intentional and stays: a contributor running the stack on
a laptop should not have to seed a user and log in. What was missing is
anything asserting the other half — that naming a non-development environment
actually turns it off at the point a request is served, rather than only in the
module's docstring.

Both directions are asserted. A test that only checked production would pass
against a build where the shim had been deleted, which would be a different
product and a silently broken developer experience.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient


def _probe_app(get_current_user) -> FastAPI:  # noqa: ANN001 - dependency callable
    """A one-route app whose only job is to resolve the current user.

    The dependency is a default value rather than `Annotated[..., Depends(...)]`
    because this module uses postponed annotations: the annotation would be a
    string, FastAPI would resolve it against this module's globals where the
    dependency is a local, and `user` would degrade to a query parameter —
    giving 422 on every request and testing nothing about authentication.
    """
    app = FastAPI()

    @app.get("/probe")
    async def probe(user=Depends(get_current_user)):  # noqa: ANN001, B008
        return {"user_id": str(getattr(user, "user_id", None)), "role": getattr(user, "role", None)}

    return app


@pytest.fixture
def client_in(monkeypatch: pytest.MonkeyPatch):
    def _build(environment: str) -> TestClient:
        # `current_env_from_os` reads ENV first, so both are set; a stale ENV
        # is precisely what shadowed an operator's ENVIRONMENT on ingest.
        monkeypatch.setenv("ENVIRONMENT", environment)
        monkeypatch.delenv("ENV", raising=False)
        from app.api.v1 import deps, dev_auth

        # Both, and in this order. Reloading `dev_auth` alone leaves
        # `deps.get_current_user` closed over the previous module, and the
        # route then rejects on validation (422) instead of exercising the
        # authentication path this test is about.
        importlib.reload(dev_auth)
        importlib.reload(deps)
        return TestClient(_probe_app(deps.get_current_user), raise_server_exceptions=False)

    return _build


class TestTheBypassIsEnvironmentGated:
    def test_production_refuses_an_unauthenticated_request(self, client_in) -> None:
        response = client_in("production").get("/probe")
        assert response.status_code == 401, (
            "an unauthenticated request was served outside development — this is the state "
            "every stock `docker compose up` ran in, because the production compose file "
            "the docs pointed at did not exist (discussion #629)"
        )

    @pytest.mark.parametrize("environment", ["staging", "prod", "production"])
    def test_no_non_development_environment_hands_back_a_user(self, client_in, environment: str) -> None:
        """`staging` included deliberately: it is not in the allow-list, and a
        reader could reasonably assume any named environment is safe."""
        assert client_in(environment).get("/probe").status_code == 401

    def test_development_still_resolves_a_user(self, client_in) -> None:
        """The other direction, so this cannot pass on a build with no shim."""
        response = client_in("development").get("/probe")
        assert response.status_code == 200
        assert response.json()["role"] == "admin"
