"""The upload policy, the hash-first sequencing, and what a failure reaches a caller as.

The three properties the plan's definition of done names are asserted by name
at the bottom of this file:

* a phishing attachment hash is looked up through the mock provider
* an upload is refused unless tenant policy allows it
* air-gap mode refuses non-local providers

Nothing here makes a network call, and nothing here uploads a file. The mock
provider records every byte handed to it, so "no upload happened" is asserted
against what the provider received rather than inferred from a return value.
"""

from __future__ import annotations

import pytest
from app.services.sandbox import (
    CONSENT_TEXT_VERSION,
    SandboxRegistry,
    analyse_file,
    analyse_url,
    consent_text_for,
    evaluate_upload,
    lookup_hash,
    sha256_of,
)
from app.services.sandbox.enrichment import enrich_file_hash
from app.services.sandbox.policy import UploadRefusal
from app.services.sandbox.providers.capev2 import CapeV2Provider
from app.services.sandbox.providers.malwareanalyzer import MalwareAnalyzerProvider
from app.services.sandbox.providers.mock import MockSandboxProvider
from app.services.sandbox.types import (
    AnalysisState,
    ProviderCapabilities,
    SandboxReport,
    SandboxUnavailable,
    SandboxVerdict,
)

SAMPLE = b"not a real sample, just bytes for a digest"
SAMPLE_SHA256 = sha256_of(SAMPLE)

HOSTED = ProviderCapabilities(name="hosted", local=False, supports_file_submission=True, submissions_are_public_by_default=True)
LOCAL = ProviderCapabilities(name="local", local=True, supports_file_submission=True)


def registry(*providers, airgapped: bool = False) -> SandboxRegistry:
    return SandboxRegistry(list(providers), airgapped=airgapped)


class ExplodingProvider(MockSandboxProvider):
    """A provider that is reachable for nothing, to drive the failure paths."""

    async def lookup_hash(self, sha256: str) -> SandboxReport | None:
        raise SandboxUnavailable("mock", "connection timed out", kind="network")


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


class TestUploadDecision:
    def test_uploads_are_off_until_a_tenant_consents(self) -> None:
        decision = evaluate_upload(capabilities=HOSTED, airgapped=False, tenant_uploads_enabled=False, hash_already_known=False)
        assert decision.allowed is False
        assert decision.refusal is UploadRefusal.TENANT_NOT_CONSENTED

    def test_consent_alone_is_enough_once_given(self) -> None:
        decision = evaluate_upload(capabilities=HOSTED, airgapped=False, tenant_uploads_enabled=True, hash_already_known=False)
        assert decision.allowed is True

    def test_consent_is_per_provider_not_per_tenant(self) -> None:
        """Agreeing to a sandbox in your own rack is not agreeing to a hosted one.

        Driven here as two independent evaluations, which is the shape the
        store's ``(tenant, provider)`` primary key enforces.
        """
        local_ok = evaluate_upload(capabilities=LOCAL, airgapped=False, tenant_uploads_enabled=True, hash_already_known=False)
        hosted_not = evaluate_upload(capabilities=HOSTED, airgapped=False, tenant_uploads_enabled=False, hash_already_known=False)
        assert local_ok.allowed is True
        assert hosted_not.allowed is False

    def test_air_gap_outranks_tenant_consent(self) -> None:
        decision = evaluate_upload(capabilities=HOSTED, airgapped=True, tenant_uploads_enabled=True, hash_already_known=False)
        assert decision.allowed is False
        assert decision.refusal is UploadRefusal.AIRGAPPED

    def test_air_gap_leaves_a_local_provider_usable(self) -> None:
        decision = evaluate_upload(capabilities=LOCAL, airgapped=True, tenant_uploads_enabled=True, hash_already_known=False)
        assert decision.allowed is True

    def test_a_known_hash_short_circuits_even_a_consenting_tenant(self) -> None:
        decision = evaluate_upload(capabilities=HOSTED, airgapped=False, tenant_uploads_enabled=True, hash_already_known=True)
        assert decision.allowed is False
        assert decision.refusal is UploadRefusal.ALREADY_KNOWN
        assert decision.satisfied_by_hash_lookup is True

    def test_every_refusal_names_its_reason(self) -> None:
        for airgapped, consented, known in ((True, True, False), (False, False, False), (False, True, True)):
            decision = evaluate_upload(capabilities=HOSTED, airgapped=airgapped, tenant_uploads_enabled=consented, hash_already_known=known)
            assert decision.refusal is not None
            assert decision.reason


class TestConsentText:
    def test_a_publishing_provider_says_public_and_says_anyone(self) -> None:
        """The operator-facing sentence, for the provider that publishes samples."""
        text = consent_text_for(HOSTED)
        assert "public disclosure" in text
        assert "readable by anyone on the internet" in text
        assert "cannot be recalled" in text

    def test_the_live_provider_declares_itself_publishing(self) -> None:
        """Not a constant in the text: read off the adapter's own capabilities.

        The recorded report from that service carries ``visibility: "public"``
        and ``tlp: "clear"``.
        """
        caps = MalwareAnalyzerProvider().capabilities
        assert caps.submissions_are_public_by_default is True
        assert "readable by anyone on the internet" in consent_text_for(caps)

    def test_a_local_provider_is_not_described_as_publishing(self) -> None:
        text = consent_text_for(CapeV2Provider("http://127.0.0.1:8090").capabilities)
        assert "readable by anyone" not in text
        assert "does not leave your infrastructure" in text

    def test_every_text_says_the_hash_is_tried_first(self) -> None:
        for caps in (HOSTED, LOCAL):
            assert "looks a file's SHA-256 up first" in consent_text_for(caps)

    def test_the_version_is_a_constant_the_store_can_record(self) -> None:
        assert CONSENT_TEXT_VERSION


# ---------------------------------------------------------------------------
# Sequencing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHashFirst:
    async def test_a_known_hash_is_answered_without_uploading(self) -> None:
        provider = MockSandboxProvider()
        provider.seed(SAMPLE_SHA256, verdict=SandboxVerdict.MALICIOUS, score=95)
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
        )
        assert result.outcome == "known"
        assert result.uploaded is False
        assert provider.uploaded == []

    async def test_an_unknown_hash_without_consent_refuses_and_uploads_nothing(self) -> None:
        provider = MockSandboxProvider()
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=False,
        )
        assert result.outcome == "upload_refused"
        assert result.decision is not None
        assert result.decision.refusal is UploadRefusal.TENANT_NOT_CONSENTED
        assert result.uploaded is False
        assert provider.uploaded == []

    async def test_an_unknown_hash_with_consent_uploads_once(self) -> None:
        provider = MockSandboxProvider()
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
        )
        assert result.outcome == "pending"
        assert result.uploaded is True
        assert provider.uploaded == [("sample.bin", len(SAMPLE))]

    async def test_a_caller_may_decline_to_upload_without_blaming_the_tenant(self) -> None:
        """``allow_upload=False`` is the enrichment path: lookup only."""
        provider = MockSandboxProvider()
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
            allow_upload=False,
        )
        assert result.outcome == "upload_refused"
        assert "hash lookups only" in result.detail
        assert provider.uploaded == []

    async def test_an_upload_to_a_publishing_provider_carries_a_warning(self) -> None:
        class Publishing(MockSandboxProvider):
            @property
            def capabilities(self) -> ProviderCapabilities:
                return ProviderCapabilities(name="mock", local=False, supports_file_submission=True, submissions_are_public_by_default=True)

        provider = Publishing()
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
        )
        assert result.uploaded is True
        assert any("readable by anyone" in w for w in result.warnings)


@pytest.mark.asyncio
class TestFailureIsNotACleanResult:
    async def test_a_lookup_failure_is_could_not_check_not_not_seen(self) -> None:
        result = await lookup_hash(ExplodingProvider(), SAMPLE_SHA256)
        assert result.outcome == "could_not_check"
        assert result.report is None
        assert "not a verdict" in result.detail

    async def test_a_lookup_failure_never_becomes_an_upload(self) -> None:
        """A provider that could not answer a lookup must not then receive the file."""
        provider = ExplodingProvider()
        result = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
        )
        assert result.outcome == "could_not_check"
        assert provider.uploaded == []

    async def test_a_miss_and_a_failure_do_not_read_the_same(self) -> None:
        miss = await lookup_hash(MockSandboxProvider(), SAMPLE_SHA256)
        failure = await lookup_hash(ExplodingProvider(), SAMPLE_SHA256)
        assert miss.outcome == "not_seen"
        assert failure.outcome == "could_not_check"
        assert miss.detail != failure.detail

    async def test_enrichment_reports_an_unreachable_provider_separately(self) -> None:
        """An alert whose file could not be checked must not render as clean."""
        block = (await enrich_file_hash(SAMPLE_SHA256, registry=registry(ExplodingProvider())))["file_analysis"]
        assert block["hit"] is False
        assert block["findings"] == []
        assert block["could_not_check"]
        assert block["max_score"] is None

    async def test_enrichment_publishes_no_score_rather_than_a_zero(self) -> None:
        provider = MockSandboxProvider()
        provider.seed(SAMPLE_SHA256, verdict=SandboxVerdict.BENIGN, score=0)
        block = (await enrich_file_hash(SAMPLE_SHA256, registry=registry(provider)))["file_analysis"]
        # A measured zero is a fact and survives; an absent one would be None.
        assert block["max_score"] == 0
        assert block["hit"] is False


# ---------------------------------------------------------------------------
# The plan's definition of done
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPhaseElevenDoneWhen:
    async def test_a_phishing_attachment_hash_is_looked_up_through_the_mock_provider(self) -> None:
        provider = MockSandboxProvider()
        attachment = b"attachment bytes"
        digest = sha256_of(attachment)
        provider.seed(digest, verdict=SandboxVerdict.MALICIOUS, score=88, file_name="invoice.doc")

        block = (await enrich_file_hash(digest, registry=registry(provider)))["file_analysis"]
        assert block["hit"] is True
        assert block["findings"][0]["provider"] == "mock"
        assert block["findings"][0]["verdict"] == "malicious"
        # The whole point of the lookup: the attachment itself never moved.
        assert provider.uploaded == []

    async def test_an_upload_is_refused_unless_tenant_policy_allows_it(self) -> None:
        provider = MockSandboxProvider()
        refused = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=False,
        )
        assert refused.outcome == "upload_refused"
        assert provider.uploaded == []

        allowed = await analyse_file(
            provider,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(provider),
            tenant_uploads_enabled=True,
        )
        assert allowed.outcome == "pending"
        assert provider.uploaded == [("sample.bin", len(SAMPLE))]

    async def test_air_gap_mode_refuses_non_local_providers(self) -> None:
        hosted = MalwareAnalyzerProvider()
        local = CapeV2Provider("http://127.0.0.1:8090")
        airgapped = registry(hosted, local, airgapped=True)

        assert airgapped.is_usable(hosted) is False
        assert airgapped.is_usable(local) is True
        assert airgapped.usable_names() == ["capev2"]
        # Present but excluded, with the reason, rather than silently absent.
        assert "malwareanalyzer" in airgapped.names()
        assert airgapped.default() is local

        result = await analyse_url(hosted, "https://example.com/", registry=airgapped)
        assert result.outcome == "upload_refused"
        assert result.decision is not None
        assert result.decision.refusal is UploadRefusal.AIRGAPPED

    async def test_air_gap_refuses_a_hosted_upload_even_with_consent(self) -> None:
        hosted = MalwareAnalyzerProvider()
        result = await analyse_file(
            hosted,
            content=SAMPLE,
            file_name="sample.bin",
            registry=registry(hosted, airgapped=True),
            tenant_uploads_enabled=True,
        )
        # The lookup itself is refused first, because the outbound guard
        # enforces air-gap at the transport. Either way no file moves.
        assert result.outcome in ("could_not_check", "upload_refused")
        assert result.uploaded is False


class TestRegistryDefaults:
    def test_a_local_provider_wins_the_default_over_a_hosted_one(self) -> None:
        hosted = MalwareAnalyzerProvider()
        local = CapeV2Provider("http://127.0.0.1:8090")
        assert SandboxRegistry([hosted, local]).default() is local

    def test_the_mock_is_only_the_default_when_nothing_else_is_configured(self) -> None:
        mock = MockSandboxProvider()
        assert SandboxRegistry([mock]).default() is mock
        cape = CapeV2Provider("http://127.0.0.1:8090")
        assert SandboxRegistry([mock, cape]).default() is cape

    def test_the_mock_knows_nothing_until_a_test_seeds_it(self) -> None:
        """A first run must report "not seen", never a fabricated clean verdict."""
        assert MockSandboxProvider()._known == {}

    def test_a_mock_report_is_labelled_synthetic(self) -> None:
        report = MockSandboxProvider().seed(SAMPLE_SHA256)
        assert report.unavailable_reasons["is_synthetic"]
        assert report.state is AnalysisState.COMPLETED
