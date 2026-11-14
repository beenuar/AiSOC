"""Naming a development environment does not make a host anonymous.

The defect this pins was not that the bypass existed. It was that the only
thing standing between an uncredentialed request and an administrator was the
string `development`, which:

* `docker-compose.yml` set as the default for `ENVIRONMENT`;
* `.env.example` wrote into `.env`, which `scripts/ensure_env.py` copies
  verbatim on first run;
* the single-host guide never mentioned, while telling operators to publish
  the console on `0.0.0.0`.

So every stock `docker compose up` served a credential-free request as
`admin`, and the tenant that admin belonged to was byte-identical to the one
`bootstrap_admin` had just put the operator's real account into.

Three conditions now gate the shim, and each is asserted in both directions.
One-directional coverage is what let this ship: the existing suite asserted
that `production` refuses, and nothing asserted that `development` alone
should not be enough.
"""

from __future__ import annotations

import uuid

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
        return {
            "user_id": str(getattr(user, "user_id", None)),
            "tenant_id": str(getattr(user, "tenant_id", None)),
            "role": getattr(user, "role", None),
        }

    return app


@pytest.fixture
def client_with(monkeypatch: pytest.MonkeyPatch):
    """Build a probe client under a named environment, flag and bind address.

    Deliberately does **not** `importlib.reload` anything. The shim reads
    `os.environ` at call time precisely so that it does not need to, and a
    reload here is actively harmful: it rebinds every function object in
    `deps`, so the `dependency_overrides` other test modules keyed on the old
    objects stop matching and their routes fall through to real authentication.

    That is not hypothetical. The first draft of this file reloaded both
    modules, copying an older test that does the same, and took 146 unrelated
    tests down with it across `test_content_route_permissions`,
    `test_discarded_permission_dependencies` and `test_platform_route_permissions`
    — every one of which passes in isolation. The older test got away with it
    only because its filename sorts near the end of the suite.
    """

    def _build(
        environment: str = "development",
        *,
        bypass: str | None = None,
        published: str | None = None,
    ) -> TestClient:
        # `current_env_from_os` reads ENV first, so both are set; a stale ENV
        # is precisely what shadowed an operator's ENVIRONMENT on ingest.
        monkeypatch.setenv("ENVIRONMENT", environment)
        monkeypatch.delenv("ENV", raising=False)
        for var, value in (
            ("AISOC_DEV_AUTH_BYPASS", bypass),
            ("AISOC_PUBLISHED_BIND_ADDRS", published),
        ):
            if value is None:
                monkeypatch.delenv(var, raising=False)
            else:
                monkeypatch.setenv(var, value)

        from app.api.v1 import deps, dev_auth

        # The refusal log is deduplicated per reason for the life of the
        # process, and each case wants its own reason recorded.
        dev_auth._REFUSALS_LOGGED.clear()
        return TestClient(_probe_app(deps.get_current_user), raise_server_exceptions=False)

    return _build


class TestTheEnvironmentNameIsNotEnough:
    def test_development_alone_refuses_an_unauthenticated_request(self, client_with) -> None:
        """The defect, stated as a test.

        This is the exact configuration every documented deployment produced:
        `ENVIRONMENT=development` from the compose default, no explicit
        opt-in anywhere, and an administrator handed to anyone who asked.
        """
        response = client_with("development").get("/probe")
        assert response.status_code == 401, (
            "an uncredentialed request was served under ENVIRONMENT=development "
            "with no explicit opt-in. That is the default every `docker compose "
            "up` and every `.env` written by ensure_env.py produced"
        )

    @pytest.mark.parametrize("environment", ["development", "dev", "local", "demo"])
    def test_no_bypass_environment_is_sufficient_on_its_own(self, client_with, environment: str) -> None:
        """All four names in AUTH_BYPASS_ENVIRONMENTS, not just the default one."""
        assert client_with(environment).get("/probe").status_code == 401

    def test_the_explicit_flag_enables_it(self, client_with) -> None:
        """The other direction, so this cannot pass on a build with no shim."""
        response = client_with("development", bypass="1").get("/probe")
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

    @pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
    def test_the_flag_accepts_the_documented_spellings(self, client_with, truthy: str) -> None:
        assert client_with("development", bypass=truthy).get("/probe").status_code == 200

    @pytest.mark.parametrize("falsy", ["0", "false", "no", "off", ""])
    def test_the_flag_is_not_enabled_by_any_other_value(self, client_with, falsy: str) -> None:
        """`AISOC_DEV_MODE=0` style values must read as off, not as "set"."""
        assert client_with("development", bypass=falsy).get("/probe").status_code == 401

    @pytest.mark.parametrize("environment", ["production", "staging", "prod"])
    def test_the_flag_does_not_re_enable_it_outside_a_dev_environment(self, client_with, environment: str) -> None:
        """Belt and braces: the flag narrows, it never widens.

        `staging` is included deliberately. It is not in the allow-list, and a
        reader could reasonably assume any named environment is safe.
        """
        assert client_with(environment, bypass="1").get("/probe").status_code == 401


class TestTheBypassIsRefusedOnAReachableAddress:
    """An anonymous administrator is a developer convenience only on loopback.

    The API cannot work this out for itself: it binds inside a container and
    sees `0.0.0.0` regardless of what the host published. So compose passes
    the published addresses in, and the shim refuses when any of them is
    reachable from somewhere else. That is the half the single-host guide
    needed, since it instructs `AISOC_CONSOLE_BIND_ADDR=0.0.0.0`.
    """

    @pytest.mark.parametrize("address", ["0.0.0.0", "192.168.1.10", "10.0.0.4", "[::]", "aisoc.example.com"])
    def test_a_reachable_published_address_refuses_the_bypass(self, client_with, address: str) -> None:
        response = client_with("development", bypass="1", published=address).get("/probe")
        assert response.status_code == 401, f"the bypass served a request while the deployment published {address}"

    @pytest.mark.parametrize("address", ["127.0.0.1", "localhost", "::1", "127.0.0.1:3000", "[::1]:8000"])
    def test_a_loopback_published_address_still_permits_it(self, client_with, address: str) -> None:
        assert client_with("development", bypass="1", published=address).get("/probe").status_code == 200

    def test_one_reachable_address_among_several_is_enough_to_refuse(self, client_with) -> None:
        """The console on loopback and the API published is still published."""
        response = client_with("development", bypass="1", published="127.0.0.1:3000,0.0.0.0:8000").get("/probe")
        assert response.status_code == 401

    def test_an_unset_bind_list_does_not_refuse(self, client_with) -> None:
        """A deployment that tells us nothing is treated as a local run.

        Refusing on an empty list would break `python -m uvicorn app.main:app`
        for contributors, which is the case the shim exists for. The
        deployment-path gate is what stops a published stack leaving it
        unset.
        """
        assert client_with("development", bypass="1", published=None).get("/probe").status_code == 200


class TestTheDemoIdentityHasItsOwnTenant:
    def test_the_demo_tenant_is_not_the_bootstrap_tenant(self) -> None:
        """The crux of the finding, and it was byte-identical.

        `dev_auth.DEMO_TENANT_ID` and `bootstrap_admin.DEFAULT_TENANT_ID` were
        both `…0001`, so the anonymous administrator operated inside the
        tenant holding the operator's real alerts and vault-encrypted
        connector credentials.
        """
        from app.api.v1.dev_auth import DEMO_TENANT_ID
        from app.scripts.bootstrap_admin import DEFAULT_TENANT_ID

        assert DEMO_TENANT_ID != DEFAULT_TENANT_ID, (
            "the anonymous demo principal shares a tenant with the real administrator this deployment bootstraps"
        )

    def test_the_canonical_tenant_id_did_not_move(self) -> None:
        """It is the demo identity that moved, and it had to be.

        Ten modules pin `…0001` as the canonical tenant, including the
        ingest-token minter, the agents ledger, and the dev principal in nine
        vendored `tenant_scope` copies. Moving that instead would have
        orphaned every row migration 001 seeds.
        """
        from app.scripts.bootstrap_admin import DEFAULT_TENANT_ID

        assert DEFAULT_TENANT_ID == uuid.UUID("00000000-0000-0000-0000-000000000001")

    def test_the_bypass_serves_the_demo_tenant_not_the_operators(self, client_with) -> None:
        from app.api.v1.dev_auth import DEMO_TENANT_ID

        response = client_with("development", bypass="1").get("/probe")
        assert response.status_code == 200
        assert response.json()["tenant_id"] == str(DEMO_TENANT_ID)


class TestTheRefusalSaysWhy:
    """A 401 with no explanation is how this stayed invisible.

    An operator who expected the bypass, and a contributor who expected it,
    both see the same 401. The reason has to be available somewhere, and the
    one place both will look is the service log.
    """

    def test_each_refusal_names_the_condition_that_withheld_it(self, monkeypatch) -> None:
        from app.core.config import auth_bypass_refusal

        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("ENV", raising=False)
        assert "not one of" in (auth_bypass_refusal() or "")

        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
        assert "AISOC_DEV_AUTH_BYPASS is not set" in (auth_bypass_refusal() or "")

        monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "1")
        monkeypatch.setenv("AISOC_PUBLISHED_BIND_ADDRS", "0.0.0.0:3000")
        refusal = auth_bypass_refusal() or ""
        assert "not loopback" in refusal
        assert "0.0.0.0:3000" in refusal

        monkeypatch.setenv("AISOC_PUBLISHED_BIND_ADDRS", "127.0.0.1:3000")
        assert auth_bypass_refusal() is None

    def test_activation_is_logged_as_a_warning(self, client_with, caplog) -> None:
        with caplog.at_level("WARNING"):
            client_with("development", bypass="1").get("/probe")
        assert any("ANONYMOUS ACCESS IS ENABLED" in record.message for record in caplog.records), (
            "a deployment with anonymous access active must say so at startup"
        )
