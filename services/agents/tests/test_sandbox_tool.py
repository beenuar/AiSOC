"""The file-analysis tool cannot upload, and never hands the model a clean negative.

The wording assertions look fussy and are the point. A model that reads a
timeout as "no detections" writes a benign verdict on a file nobody analysed,
and the only thing standing between those two outcomes is the sentence this
tool returns.
"""

from __future__ import annotations

import httpx
import pytest
from app.tools.registry import default_registry
from app.tools.sandbox import TOOL_DESCRIPTION, TOOL_PARAMETERS, lookup_file_hash

DIGEST = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

pytestmark = pytest.mark.asyncio


TENANT = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(autouse=True)
def _credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "fixpass-service-token")
    monkeypatch.setenv("AISOC_API_URL", "http://api:8000")


def _api(status: int, body: dict | None = None) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, json=body or {}))


def _patch_client(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    real = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)


class TestFailuresNeverReadAsClean:
    async def test_an_unreachable_api_is_could_not_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        _patch_client(monkeypatch, httpx.MockTransport(boom))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["available"] is False
        assert result["outcome"] == "could_not_check"
        assert "NOT been assessed" in result["reason"]
        assert "do not treat this as evidence that the file is benign" in result["reason"].lower()

    async def test_a_server_error_is_could_not_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, _api(503))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["outcome"] == "could_not_check"

    async def test_air_gap_refusal_is_could_not_check_not_a_miss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, _api(403))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["outcome"] == "could_not_check"
        assert "air-gapped" in result["reason"].lower()

    async def test_a_missing_credential_is_a_loud_skip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
        monkeypatch.delenv("AISOC_API_SERVICE_TOKEN", raising=False)
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["outcome"] == "could_not_check"
        assert "credential" in result["reason"]

    async def test_the_providers_own_failure_is_passed_through_as_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, _api(200, {"outcome": "could_not_check", "provider": "capev2", "detail": "timed out"}))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["outcome"] == "could_not_check"
        assert "timed out" in result["reason"]


class TestOrdinaryAnswers:
    async def test_a_known_hash_returns_the_report_whole(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = {"verdict": "malicious", "score": 100, "attack": "unavailable"}
        _patch_client(monkeypatch, _api(200, {"outcome": "known", "provider": "mock", "report": report, "detail": "ok"}))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["available"] is True
        assert result["outcome"] == "known"
        # Unavailable fields survive the trip rather than being stripped, so
        # the model is never invited to infer one.
        assert result["report"]["attack"] == "unavailable"

    async def test_an_unknown_hash_is_not_presented_as_a_clean_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, _api(200, {"outcome": "not_seen", "provider": "mock", "detail": "no analysis"}))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["outcome"] == "not_seen"
        assert "not a verdict" in result["reason"]
        assert "targeted malware" in result["reason"]

    async def test_a_pending_analysis_is_not_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch, _api(200, {"outcome": "pending", "provider": "capev2"}))
        result = await lookup_file_hash(DIGEST, tenant_id=TENANT)
        assert result["available"] is False
        assert result["outcome"] == "pending"
        assert "not a clean result" in result["reason"]

    async def test_a_non_hash_is_rejected_before_any_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def unexpected(request: httpx.Request) -> httpx.Response:
            raise AssertionError("the tool must not call out for a malformed digest")

        _patch_client(monkeypatch, httpx.MockTransport(unexpected))
        result = await lookup_file_hash("not-a-hash", tenant_id=TENANT)
        assert result["outcome"] == "invalid_input"


class TestToolSurface:
    async def test_the_tool_is_registered_for_the_model(self) -> None:
        assert "lookup_file_hash" in default_registry().names()

    async def test_the_registry_advertises_no_upload_verb(self) -> None:
        """The model must have no way to cause a file to leave the deployment."""
        names = default_registry().names()
        for forbidden in ("submit_file", "upload_file", "detonate_file", "analyse_file"):
            assert forbidden not in names

    async def test_the_tool_takes_a_hash_and_nothing_else(self) -> None:
        assert list(TOOL_PARAMETERS["properties"]) == ["sha256"]
        assert TOOL_PARAMETERS["required"] == ["sha256"]

    async def test_the_description_warns_the_model_about_both_negatives(self) -> None:
        description = TOOL_DESCRIPTION.lower()
        assert "never uploads" in description
        assert "unknown hash is not a clean verdict" in description
