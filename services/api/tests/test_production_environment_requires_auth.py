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
    def _build(environment: str, *, bypass: str | None = None) -> TestClient:
        # `current_env_from_os` reads ENV first, so both are set; a stale ENV
        # is precisely what shadowed an operator's ENVIRONMENT on ingest.
        monkeypatch.setenv("ENVIRONMENT", environment)
        monkeypatch.delenv("ENV", raising=False)
        monkeypatch.delenv("AISOC_PUBLISHED_BIND_ADDRS", raising=False)
        if bypass is None:
            monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
        else:
            monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", bypass)

        from app.api.v1 import deps, dev_auth

        # This fixture used to `importlib.reload` both modules. It does not
        # any more, and neither should anything else here: a reload rebinds
        # every function object in `deps`, so the `dependency_overrides` that
        # other modules keyed on the old objects stop matching and their
        # routes fall through to real authentication. It went unnoticed
        # because this filename sorts near the end of the suite; a new file
        # doing the same thing took 146 unrelated tests down with it. The
        # shim reads `os.environ` at call time, so setting the variables is
        # sufficient and always was.
        dev_auth._REFUSALS_LOGGED.clear()
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

    def test_development_alone_is_no_longer_enough(self, client_in) -> None:
        """Naming the environment stopped being sufficient.

        This assertion used to read the other way, and that is the defect:
        `ENVIRONMENT` defaulted to `development` in `docker-compose.yml` and
        in the `.env` the setup script writes, so the only thing between an
        uncredentialed request and an administrator was a string nobody had
        chosen deliberately. The shim now needs `AISOC_DEV_AUTH_BYPASS`,
        which no compose file or template sets.
        """
        assert client_in("development").get("/probe").status_code == 401

    def test_development_with_the_explicit_optin_still_resolves_a_user(self, client_in) -> None:
        """The other direction, so this cannot pass on a build with no shim."""
        response = client_in("development", bypass="1").get("/probe")
        assert response.status_code == 200
        assert response.json()["role"] == "admin"
