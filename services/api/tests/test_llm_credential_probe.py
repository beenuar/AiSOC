"""A saved LLM credential can be tested, and the test cannot be used to reach inward.

What this closes
----------------
The three credential routes validate *shape* -- that the URL parses, that the
provider/key/base combination is internally consistent -- and none of them
talks to the provider. So an operator who pasted a revoked key found out when
triage silently fell back to the deterministic path, which is quiet by design
and therefore hard to attribute to the key.

The guard, and why the obvious one is wrong
-------------------------------------------
This endpoint dials a URL the tenant supplied. The API's existing
`destinations.py::_guard_url` rejects every private and loopback address, which
is right for a webhook and would refuse `local-ollama`, `local-vllm` and
`local-litellm` -- three of the seven providers migration 038 allows, and the
ones most likely to sit on a private address. Using it here would break the
feature for exactly the deployments it is for.

So the vendored `validate_outbound_url(..., allow_private=True)` is used
instead, and the tests below pin both halves of what that buys: a private host
is reachable, and the cloud-metadata address is still refused *even though*
private addresses are allowed. The second is the one that matters -- a guard
that allowed private and stopped there would read as working.
"""

from __future__ import annotations

import pytest


class TestTheGuardAllowsLocalProvidersAndStillBlocksMetadata:
    @pytest.mark.asyncio
    async def test_a_private_host_is_permitted(self) -> None:
        """`local-ollama` on a LAN address is the configuration this exists
        for. A probe that refused it would be refusing the common case."""
        from app._vendor.ssrf_guard import validate_outbound_url

        # Does not raise.
        validate_outbound_url("http://192.168.1.50:11434/v1", allow_private=True)

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/v1",
        ],
    )
    @pytest.mark.asyncio
    async def test_cloud_metadata_is_refused_even_with_private_allowed(self, url: str) -> None:
        """The half that makes `allow_private=True` safe. Link-local stays
        rejected, so the metadata endpoint is unreachable through this route."""
        from app._vendor.ssrf_guard import SSRFError, validate_outbound_url

        with pytest.raises(SSRFError):
            validate_outbound_url(url, allow_private=True)

    @pytest.mark.asyncio
    async def test_loopback_is_refused(self) -> None:
        """From inside the API container, loopback is the container itself."""
        from app._vendor.ssrf_guard import SSRFError, validate_outbound_url

        with pytest.raises(SSRFError):
            validate_outbound_url("http://127.0.0.1:11434/v1", allow_private=True)

    @pytest.mark.asyncio
    async def test_the_probe_reports_a_refusal_rather_than_raising(self) -> None:
        """A guard rejection must become a reported outcome. An exception here
        would surface as a 500 on a settings page, which tells the operator
        nothing about their own URL."""
        from app.services.llm_credential_probe import probe_credential

        result = await probe_credential(
            provider="custom",
            base_url="http://169.254.169.254/v1",
            model="m",
            api_key="k",
        )

        assert result.outcome == "refused"
        assert "refused" in result.detail.lower()


class TestAirGapIsNotAFailure:
    @pytest.mark.asyncio
    async def test_a_blocked_host_reports_unverified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An air-gapped deployment refusing egress is the posture working.
        Reporting it as `refused` would send an operator to debug a credential
        that is fine."""
        # Patched where it is read, at call time: a module-level settings
        # reference goes stale if anything reloads app.core.config, which is
        # how this test passed alone and failed in the suite.
        from app.core import airgap as airgap_mod
        from app.services.llm_credential_probe import probe_credential

        monkeypatch.setattr(airgap_mod.settings, "AISOC_AIRGAPPED", True, raising=False)

        result = await probe_credential(
            provider="openai",
            base_url=None,
            model="gpt-4o-mini",
            api_key="sk-test",
        )

        assert result.outcome == "unverified"
        assert "air-gapped" in result.detail.lower()
        assert "not attempted" in result.detail.lower()

    @pytest.mark.asyncio
    async def test_a_local_host_still_runs_under_airgap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The negative control. Air-gap permits a private model host -- that
        is the whole point of running one -- so the probe must not refuse
        every call just because the flag is set."""
        # Patched where it is read, at call time: a module-level settings
        # reference goes stale if anything reloads app.core.config, which is
        # how this test passed alone and failed in the suite.
        from app.core import airgap as airgap_mod
        from app.services.llm_credential_probe import probe_credential

        monkeypatch.setattr(airgap_mod.settings, "AISOC_AIRGAPPED", True, raising=False)

        # A bare hostname with no dots is a compose/k8s service name, which
        # `_is_private_address` treats as internal by definition -- and that is
        # exactly what `local-ollama` looks like on a real air-gapped stack.
        result = await probe_credential(
            provider="local-ollama",
            base_url="http://ollama:11434/v1",
            model="llama3.2:3b",
            api_key=None,
        )

        # It will not reach that host from a test runner, but it must have
        # *tried* -- an `unverified` here would mean air-gap blocked a local
        # provider, which would make air-gapped BYOK impossible.
        assert result.outcome != "unverified", result.detail


class TestItNamesWhatWentWrong:
    @pytest.mark.parametrize(
        ("status_code", "expected"),
        [(401, "refused"), (403, "refused"), (404, "refused"), (429, "ok"), (500, "refused")],
    )
    @pytest.mark.asyncio
    async def test_each_provider_answer_maps_to_an_outcome(self, status_code: int, expected: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """429 is `ok` deliberately: being rate-limited means the request
        reached the provider and was authenticated enough to be counted, which
        is the question being asked."""
        import httpx
        from app.services import llm_credential_probe as probe_mod

        class _Client:
            def __init__(self, *_: object, **__: object) -> None:
                """No setup; the stub exists to intercept the POST below."""

            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *_: object) -> bool:
                return False

            async def post(self, *_: object, **__: object) -> httpx.Response:
                return httpx.Response(status_code, text="detail", request=httpx.Request("POST", "http://x"))

        monkeypatch.setattr(probe_mod.httpx, "AsyncClient", _Client)

        result = await probe_mod.probe_credential(
            provider="custom",
            base_url="http://192.168.1.50:11434/v1",
            model="m",
            api_key="k",
        )

        assert result.outcome == expected, result.detail

    @pytest.mark.asyncio
    async def test_a_404_says_the_model_might_be_the_problem(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A key can be perfect and the model name wrong. Saying only
        "rejected" sends the operator to rotate a working key."""
        import httpx
        from app.services import llm_credential_probe as probe_mod

        class _Client:
            def __init__(self, *_: object, **__: object) -> None:
                """No setup; the stub exists to intercept the POST below."""

            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *_: object) -> bool:
                return False

            async def post(self, *_: object, **__: object) -> httpx.Response:
                return httpx.Response(404, text="no such model", request=httpx.Request("POST", "http://x"))

        monkeypatch.setattr(probe_mod.httpx, "AsyncClient", _Client)

        result = await probe_mod.probe_credential(
            provider="custom",
            base_url="http://192.168.1.50:11434/v1",
            model="typo-model",
            api_key="k",
        )

        assert "typo-model" in result.detail
        assert "model name" in result.detail.lower()


class TestTheRouteIsReachableAtTheUrlTheConsoleCalls:
    """Ask the app what it published, not what the decorator says.

    Every test above calls `probe_credential` directly, and all thirteen
    passed while the route was mounted at
    `/api/v1/llm/credentials/credentials/test` -- a doubled segment, because
    the decorator repeated a prefix the router already carried. The endpoint
    was reachable at no URL anything calls, and only
    `check_console_route_contract` noticed, by comparing the console's fetches
    against the real OpenAPI document.

    Read from `app.openapi()` rather than `app.routes`: on FastAPI 0.141.x
    `include_router` leaves an opaque object there and the `APIRoute` count is
    zero, so an enumeration silently compares nothing.
    """

    def test_it_is_published_where_the_client_asks_for_it(self) -> None:
        from app.main import app

        assert "/api/v1/llm/credentials/test" in app.openapi()["paths"]

    def test_no_segment_is_doubled(self) -> None:
        from app.main import app

        doubled = [p for p in app.openapi()["paths"] if "credentials/credentials" in p]

        assert not doubled, f"a router prefix is repeated in the decorator: {doubled}"

    def test_the_console_and_the_api_agree_on_the_url(self) -> None:
        """The two halves of the contract, compared directly. A client string
        and a server path that drift apart produce a 404 nobody owns."""
        from pathlib import Path

        from app.main import app

        client = (Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "lib" / "api.ts").read_text(encoding="utf-8")

        assert "/api/v1/llm/credentials/test" in client
        assert "/api/v1/llm/credentials/test" in app.openapi()["paths"]
