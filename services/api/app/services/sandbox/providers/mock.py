"""An in-memory provider, for tests and for a deployment with no sandbox wired.

Two jobs. It is what the test suite drives so no test needs a network, and it
is the provider a CORE deployment gets by default so the wiring is exercised on
a first run rather than lying dormant until someone configures CAPEv2.

Everything it returns is labelled synthetic. ``is_synthetic`` rides on the
report's :attr:`~app.services.sandbox.types.SandboxReport.unavailable_reasons`
and on every API response built from it, so a fabricated verdict can never be
mistaken for a measured one, and the corpus is empty unless a caller seeds it.
An empty corpus means a first run reports "not seen" rather than inventing a
clean bill of health for a file nobody analysed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.services.sandbox.base import SandboxProvider
from app.services.sandbox.types import (
    AnalysisState,
    AttackTechnique,
    ProviderCapabilities,
    SandboxIocs,
    SandboxReport,
    SandboxUnavailable,
    SandboxVerdict,
    Signature,
    SubmissionReceipt,
)

__all__ = ["MockSandboxProvider"]

#: Marks every report this provider produces. Read by
#: ``check_mock_data_gated.py``'s sibling rule in the API layer and asserted by
#: the tests: a synthetic verdict that reaches a surface without this key is
#: the failure the flag exists to make impossible.
SYNTHETIC_MARKER = "is_synthetic"


class MockSandboxProvider(SandboxProvider):
    """A sandbox that analyses nothing and says so.

    ``seed`` is how a test gives it something to find. Nothing is seeded by
    default, deliberately: a provider that answers "malicious" for an
    unseeded hash would make every test that forgets to seed pass for the
    wrong reason.
    """

    def __init__(self, *, accepts_uploads: bool = True) -> None:
        self._known: dict[str, SandboxReport] = {}
        self._submissions: dict[str, SandboxReport] = {}
        self._accepts_uploads = accepts_uploads
        #: Every file handed to :meth:`submit_file`, so a test can assert that
        #: a refused upload really did not transfer any bytes.
        self.uploaded: list[tuple[str, int]] = []

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            name="mock",
            local=True,
            supports_hash_lookup=True,
            supports_file_submission=self._accepts_uploads,
            supports_url_submission=True,
            submissions_are_public_by_default=False,
            description="In-process provider for tests and unconfigured deployments. Analyses nothing.",
        )

    def seed(
        self,
        sha256: str,
        *,
        verdict: SandboxVerdict = SandboxVerdict.MALICIOUS,
        score: int = 90,
        signatures: tuple[Signature, ...] = (),
        attack: tuple[AttackTechnique, ...] = (),
        file_name: str | None = None,
    ) -> SandboxReport:
        """Register a hash so :meth:`lookup_hash` finds it."""
        report = SandboxReport(
            provider="mock",
            state=AnalysisState.COMPLETED,
            verdict=verdict,
            score=score,
            signatures=signatures,
            attack=attack,
            iocs=SandboxIocs(),
            sha256=sha256.lower(),
            file_name=file_name,
            visibility="private",
            analyzed_at=datetime.now(UTC),
            unavailable_reasons={SYNTHETIC_MARKER: "synthetic fixture from the mock provider, not a real analysis"},
        )
        self._known[sha256.lower()] = report
        return report

    async def lookup_hash(self, sha256: str) -> SandboxReport | None:
        return self._known.get((sha256 or "").strip().lower())

    async def submit_file(self, content: bytes, file_name: str, *, visibility: str | None = None) -> SubmissionReceipt:
        if not self._accepts_uploads:
            raise SandboxUnavailable("mock", "this provider does not accept file submissions", kind="bad_response")
        self.uploaded.append((file_name, len(content)))
        return self._accept(kind="file")

    async def submit_url(self, url: str) -> SubmissionReceipt:
        return self._accept(kind="url")

    def _accept(self, *, kind: str) -> SubmissionReceipt:
        handle = f"mock_{kind}_{uuid.uuid4().hex[:12]}"
        self._submissions[handle] = SandboxReport(
            provider="mock",
            state=AnalysisState.PENDING,
            unavailable_reasons={
                "verdict": "analysis has not finished",
                SYNTHETIC_MARKER: "synthetic fixture from the mock provider, not a real analysis",
            },
        )
        return SubmissionReceipt(
            provider="mock",
            handle=handle,
            state=AnalysisState.PENDING,
            visibility="private",
            poll_after_seconds=1,
            submitted_at=datetime.now(UTC),
        )

    def complete(self, handle: str, report: SandboxReport) -> None:
        """Move a pending submission to a finished report, for a test's timeline."""
        self._submissions[handle] = report

    async def poll(self, handle: str) -> SandboxReport:
        report = self._submissions.get(handle)
        if report is None:
            return SandboxReport(
                provider="mock",
                state=AnalysisState.NOT_FOUND,
                unavailable_reasons={"verdict": f"no submission with handle {handle}"},
            )
        return report
