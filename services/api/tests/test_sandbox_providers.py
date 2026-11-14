"""Each adapter maps its own payload onto the interface, and says so honestly.

Driven against recorded and synthetic vendor payloads through
``httpx.MockTransport``. Nothing here makes a network call, and nothing here
uploads a file: the recorded fixture was obtained by a GET on the EICAR test
file's hash. See ``tests/fixtures/sandbox/README.md`` for which payloads are
captures and which are hand-written.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.services.sandbox.providers.capev2 import CapeV2Provider
from app.services.sandbox.providers.malwareanalyzer import MalwareAnalyzerProvider
from app.services.sandbox.types import UNAVAILABLE, AnalysisState, SandboxUnavailable, SandboxVerdict, Unavailable

FIXTURES = Path(__file__).parent / "fixtures" / "sandbox"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def transport(routes: dict[str, tuple[int, Any]]) -> httpx.MockTransport:
    """Answer by path suffix, so a changed base URL does not silently miss."""

    def handler(request: httpx.Request) -> httpx.Response:
        for suffix, (status, body) in routes.items():
            if request.url.path.endswith(suffix) or suffix in str(request.url):
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "no route"}})

    return httpx.MockTransport(handler)


def client_for(routes: dict[str, tuple[int, Any]]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport(routes))


# ---------------------------------------------------------------------------
# MalwareAnalyzer
# ---------------------------------------------------------------------------


class TestMalwareAnalyzerMapping:
    """The pure mapping, driven on the recorded EICAR report."""

    def test_verdict_score_and_signatures_come_across(self) -> None:
        report = MalwareAnalyzerProvider.to_report(load("malwareanalyzer_report_eicar.json"))
        assert report.state is AnalysisState.COMPLETED
        assert report.verdict is SandboxVerdict.MALICIOUS
        assert report.score == 100
        assert not isinstance(report.signatures, Unavailable)
        assert len(report.signatures) == 9
        assert any(s.identifier == "yara:EICAR_Test_File" for s in report.signatures)
        assert report.sha256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    def test_absent_behavioural_stage_makes_attack_unavailable_not_empty(self) -> None:
        """The case the whole sentinel exists for.

        The recorded report carries ``attackTechniques: []`` beside
        ``behavior.analyzed: false``. The techniques are missing because the
        stage never ran, so reporting "no ATT&CK techniques" would invent a
        negative about a sample nobody detonated.
        """
        payload = load("malwareanalyzer_report_eicar.json")
        assert payload["verdict"]["attackTechniques"] == []
        assert payload["behavior"]["analyzed"] is False

        report = MalwareAnalyzerProvider.to_report(payload)
        assert report.attack is UNAVAILABLE
        assert report.attack != []
        assert "behavioural analysis did not run" in report.unavailable_reasons["attack"]
        assert "unidentified_file_type" in report.unavailable_reasons["attack"]
        assert report.summary()["attack"] == "unavailable"

    def test_a_run_behavioural_stage_yields_a_real_empty_list(self) -> None:
        """Same empty array, opposite meaning, when the stage did run."""
        payload = load("malwareanalyzer_report_eicar.json")
        payload["behavior"] = {"analyzed": True}
        report = MalwareAnalyzerProvider.to_report(payload)
        assert report.attack == ()
        assert "attack" not in report.unavailable_reasons

    def test_present_but_empty_ioc_buckets_are_not_unavailable(self) -> None:
        report = MalwareAnalyzerProvider.to_report(load("malwareanalyzer_report_eicar.json"))
        # Every bucket is present in the payload and empty: the analysis looked
        # and found none, which is a result.
        assert report.iocs.urls == ()
        assert report.iocs.domains == ()

    def test_a_missing_ioc_section_is_unavailable(self) -> None:
        payload = load("malwareanalyzer_report_eicar.json")
        payload.pop("iocs")
        report = MalwareAnalyzerProvider.to_report(payload)
        assert report.iocs.urls is UNAVAILABLE
        assert "iocs" in report.unavailable_reasons

    def test_public_visibility_is_carried_through(self) -> None:
        """The fact the upload policy turns on, taken from the payload not a constant."""
        report = MalwareAnalyzerProvider.to_report(load("malwareanalyzer_report_eicar.json"))
        assert report.visibility == "public"

    def test_a_missing_score_reads_unavailable_never_zero(self) -> None:
        payload = load("malwareanalyzer_report_eicar.json")
        payload["verdict"].pop("score")
        report = MalwareAnalyzerProvider.to_report(payload)
        assert report.score is UNAVAILABLE
        assert report.score != 0
        assert report.summary()["score"] == "unavailable"


@pytest.mark.asyncio
class TestMalwareAnalyzerTransport:
    async def test_hash_hit_returns_a_report(self) -> None:
        provider = MalwareAnalyzerProvider(client=client_for({"/v1/reports/": (200, load("malwareanalyzer_report_eicar.json"))}))
        report = await provider.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        assert report is not None
        assert report.verdict is SandboxVerdict.MALICIOUS

    async def test_hash_miss_is_none_not_an_exception(self) -> None:
        """A miss is an ordinary answer, so it must not look like a failure."""
        provider = MalwareAnalyzerProvider(client=client_for({"/v1/reports/": (404, load("malwareanalyzer_error_not_found.json"))}))
        assert await provider.lookup_hash("0" * 64) is None

    async def test_poll_reads_status_from_data_not_from_state(self) -> None:
        """The trap. The submit response uses ``state``; the poll response does not.

        A loop reading ``state`` here finds nothing and reports no progress
        while the scan runs perfectly normally.
        """
        payload = load("malwareanalyzer_poll_partial.json")
        assert "state" not in payload["data"]
        assert payload["data"]["status"] == "partial"

        provider = MalwareAnalyzerProvider(client=client_for({"/v1/result/": (200, payload)}))
        report = await provider.poll("scan_0f1e2d3c4b5a6978")
        assert report.state is AnalysisState.RUNNING
        assert not report.state.terminal
        assert report.verdict is UNAVAILABLE

    async def test_a_partial_flag_holds_back_a_completed_status(self) -> None:
        payload = load("malwareanalyzer_poll_partial.json")
        payload["data"]["status"] = "completed"
        payload["data"]["partial"] = True
        provider = MalwareAnalyzerProvider(client=client_for({"/v1/result/": (200, payload)}))
        assert not (await provider.poll("scan_x")).state.terminal

    async def test_url_submission_returns_the_scan_uuid_as_the_handle(self) -> None:
        provider = MalwareAnalyzerProvider(client=client_for({"/v1/submit": (202, load("malwareanalyzer_submit_url.json"))}))
        receipt = await provider.submit_url("https://example.com/")
        assert receipt.handle == "scan_0f1e2d3c4b5a6978"
        assert receipt.state is AnalysisState.PENDING

    async def test_an_unreachable_service_raises_rather_than_returning_a_report(self) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        provider = MalwareAnalyzerProvider(client=httpx.AsyncClient(transport=httpx.MockTransport(boom)))
        with pytest.raises(SandboxUnavailable) as caught:
            await provider.lookup_hash("a" * 64)
        assert caught.value.kind == "network"

    async def test_a_401_is_reported_as_auth_not_as_a_miss(self) -> None:
        provider = MalwareAnalyzerProvider(client=client_for({"/v1/reports/": (401, {"error": {"code": "unauthorized"}})}))
        with pytest.raises(SandboxUnavailable) as caught:
            await provider.lookup_hash("a" * 64)
        assert caught.value.kind == "auth"


class TestMalwareAnalyzerAuthentication:
    """The header is undetermined, so it is configurable and never invented."""

    def test_no_key_configured_sends_no_auth_header(self) -> None:
        provider = MalwareAnalyzerProvider(api_key="")
        assert "Authorization" not in provider._headers()

    def test_the_default_scheme_is_the_one_the_vendor_client_uses(self) -> None:
        provider = MalwareAnalyzerProvider(api_key="k-123")
        assert provider._headers()["Authorization"] == "Bearer k-123"

    def test_an_operator_can_name_a_different_header_without_a_code_change(self) -> None:
        provider = MalwareAnalyzerProvider(api_key="k-123", api_key_header="X-Api-Key")
        headers = provider._headers()
        assert headers["X-Api-Key"] == "k-123"
        assert "Authorization" not in headers

    def test_authentication_is_never_reported_as_verified(self) -> None:
        """Nobody in this repository has confirmed the scheme against a real key."""
        assert MalwareAnalyzerProvider(api_key="k-123").authentication_is_verified is False

    def test_a_key_alone_does_not_make_submissions_private(self) -> None:
        """Presence of a key is not evidence that `visibility: private` is honoured.

        Letting a key silently flip this would rewrite the sentence an
        operator agrees to before disclosing a customer file.
        """
        assert MalwareAnalyzerProvider(api_key="k").capabilities.submissions_are_public_by_default is True
        confirmed = MalwareAnalyzerProvider(api_key="k", private_submissions_confirmed=True)
        assert confirmed.capabilities.submissions_are_public_by_default is False

    def test_the_provider_is_never_local(self) -> None:
        assert MalwareAnalyzerProvider().capabilities.local is False


# ---------------------------------------------------------------------------
# CAPEv2
# ---------------------------------------------------------------------------


class TestCapeV2Mapping:
    """The pure mapping, on a documented CAPEv2 report schema."""

    def test_malscore_is_normalised_into_the_interface_range(self) -> None:
        """CAPE publishes 0-10. The interface publishes 0-100 and owns the range."""
        report = CapeV2Provider.to_report(load("capev2_report_completed.json"))
        assert report.score == 84
        assert report.verdict is SandboxVerdict.MALICIOUS

    def test_techniques_are_lifted_out_of_the_signatures(self) -> None:
        report = CapeV2Provider.to_report(load("capev2_report_completed.json"))
        assert not isinstance(report.attack, Unavailable)
        assert {t.technique_id for t in report.attack} == {"T1204.002", "T1055"}

    def test_a_report_with_no_malscore_has_no_derived_verdict(self) -> None:
        payload = load("capev2_report_completed.json")
        payload.pop("malscore")
        report = CapeV2Provider.to_report(payload)
        assert report.score is UNAVAILABLE
        assert report.verdict is UNAVAILABLE
        assert "publishes no verdict" in report.unavailable_reasons["verdict"]

    def test_iocs_are_mapped_from_the_network_section(self) -> None:
        report = CapeV2Provider.to_report(load("capev2_report_completed.json"))
        assert report.iocs.domains == ("payload.example.net",)
        assert report.iocs.urls == ("http://payload.example.net/stage2.bin",)


@pytest.mark.asyncio
class TestCapeV2Transport:
    async def test_a_hash_miss_is_none(self) -> None:
        """CAPE answers a miss with HTTP 200 and ``error: true``."""
        provider = CapeV2Provider("http://127.0.0.1:8090", client=client_for({"/search/": (200, load("capev2_search_miss.json"))}))
        assert await provider.lookup_hash("b" * 64) is None

    async def test_a_hash_hit_resolves_through_to_the_report(self) -> None:
        provider = CapeV2Provider(
            "http://127.0.0.1:8090",
            client=client_for(
                {
                    "/search/": (200, load("capev2_search_hit.json")),
                    "/view/": (200, {"error": False, "data": {"task": {"id": 4211, "status": "reported"}}}),
                    "/report/": (200, load("capev2_report_completed.json")),
                }
            ),
        )
        report = await provider.lookup_hash("9" * 64)
        assert report is not None
        assert report.state is AnalysisState.COMPLETED
        assert report.verdict is SandboxVerdict.MALICIOUS

    async def test_a_running_task_carries_no_verdict(self) -> None:
        provider = CapeV2Provider("http://127.0.0.1:8090", client=client_for({"/view/": (200, load("capev2_task_running.json"))}))
        report = await provider.poll("4212")
        assert report.state is AnalysisState.RUNNING
        assert report.verdict is UNAVAILABLE

    async def test_an_unrecognised_state_is_running_not_failed(self) -> None:
        """A new CAPE release adding a state must not become a fabricated failure."""
        provider = CapeV2Provider(
            "http://127.0.0.1:8090",
            client=client_for({"/view/": (200, {"error": False, "data": {"task": {"status": "distributed"}}})}),
        )
        assert (await provider.poll("1")).state is AnalysisState.RUNNING

    async def test_a_failed_analysis_is_failed_and_still_carries_no_verdict(self) -> None:
        provider = CapeV2Provider(
            "http://127.0.0.1:8090",
            client=client_for({"/view/": (200, {"error": False, "data": {"task": {"status": "failed_analysis"}}})}),
        )
        report = await provider.poll("1")
        assert report.state is AnalysisState.FAILED
        assert report.verdict is UNAVAILABLE
