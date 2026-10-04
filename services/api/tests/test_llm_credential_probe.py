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
            def __init__(self, *_: object, **__: object) -> None: ...
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
            def __init__(self, *_: object, **__: object) -> None: ...
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
