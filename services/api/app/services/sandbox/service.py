"""The one place hash-first is enforced and a failure becomes "could not check".

Two rules live here rather than in the routes, because there is more than one
caller (enrichment, phishing, the agent tool, the console) and a rule
re-implemented per caller is a rule that holds in three places and not the
fourth.

**Hash first.** :func:`analyse_file` looks the digest up before it will even
evaluate whether an upload is permitted, so the sequence cannot be skipped by a
caller passing the wrong argument. The policy function takes
``hash_already_known`` as data, and this is the only code that computes it.

**A failure is not a negative.** A provider that times out, refuses
authentication or returns something unparseable produces
``outcome="could_not_check"`` with the reason attached. It never produces a
report, and never an absent verdict that reads like a clean one. This is the
same rule the plan states for read tools generally, and a sandbox is the read
tool most likely to be slow or down.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

from app.services.sandbox.base import SandboxProvider
from app.services.sandbox.policy import UploadDecision, UploadRefusal, evaluate_upload
from app.services.sandbox.registry import SandboxRegistry
from app.services.sandbox.types import (
    AnalysisState,
    SandboxReport,
    SandboxUnavailable,
    SubmissionReceipt,
)

log = structlog.get_logger(__name__)

__all__ = ["SandboxOutcome", "SandboxResult", "analyse_file", "analyse_url", "lookup_hash", "poll", "sha256_of"]

#: What happened, as one word a caller can branch on.
#:
#: ``known``            a report exists and is attached.
#: ``pending``          an analysis is running; come back with ``handle``.
#: ``not_seen``         no provider has analysed this, and nothing was uploaded.
#: ``upload_refused``   an upload would have been needed and policy said no.
#: ``could_not_check``  the provider could not be asked. Not a verdict.
SandboxOutcome = Literal["known", "pending", "not_seen", "upload_refused", "could_not_check"]


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """What a caller gets back, whatever happened.

    One type for all five outcomes on purpose: a caller that forgets to handle
    ``could_not_check`` gets a result whose ``report`` is ``None``, rather than
    an exception it can swallow into a clean answer.
    """

    outcome: SandboxOutcome
    provider: str
    #: Present only when ``outcome == "known"``.
    report: SandboxReport | None = None
    #: Present when ``outcome == "pending"``.
    receipt: SubmissionReceipt | None = None
    #: Present when ``outcome == "upload_refused"``.
    decision: UploadDecision | None = None
    #: Human-readable, and safe to show an analyst or send to a model.
    detail: str = ""
    sha256: str | None = None
    #: True when bytes left this deployment as part of producing this result.
    uploaded: bool = False
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "provider": self.provider,
            "detail": self.detail,
            "sha256": self.sha256,
            "uploaded": self.uploaded,
            "report": self.report.summary() if self.report else None,
            "handle": self.receipt.handle if self.receipt else None,
            "poll_after_seconds": self.receipt.poll_after_seconds if self.receipt else None,
            "decision": self.decision.as_dict() if self.decision else None,
            "warnings": list(self.warnings),
        }


def sha256_of(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


async def lookup_hash(provider: SandboxProvider, sha256: str) -> SandboxResult:
    """Ask one provider whether it has already analysed this digest.

    The only verb that is always allowed: a SHA-256 discloses nothing about the
    file it names, so no tenant has to consent to it and air-gap mode only
    restricts which providers exist to ask.
    """
    digest = (sha256 or "").strip().lower()
    try:
        report = await provider.lookup_hash(digest)
    except SandboxUnavailable as exc:
        log.warning("sandbox.lookup_failed", provider=provider.name, kind=exc.kind, reason=exc.reason)
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            sha256=digest,
            detail=f"Could not check {provider.name}: {exc.reason}. This is not a verdict; the file was not assessed.",
        )
    if report is None:
        return SandboxResult(
            outcome="not_seen",
            provider=provider.name,
            sha256=digest,
            detail=f"{provider.name} has no analysis on file for this hash.",
        )
    if not report.state.terminal:
        return SandboxResult(
            outcome="pending",
            provider=provider.name,
            report=None,
            sha256=digest,
            detail=f"{provider.name} is still analysing this file.",
        )
    return SandboxResult(
        outcome="known",
        provider=provider.name,
        report=report,
        sha256=digest,
        detail=f"{provider.name} has an existing report for this hash. Nothing was uploaded.",
    )


async def analyse_file(
    provider: SandboxProvider,
    *,
    content: bytes,
    file_name: str,
    registry: SandboxRegistry,
    tenant_uploads_enabled: bool,
    allow_upload: bool = True,
    requested_visibility: str | None = None,
) -> SandboxResult:
    """Hash-lookup first, then upload only if policy allows it.

    ``allow_upload=False`` is how a caller that only wants a lookup says so
    without pretending the tenant has not consented: the refusal it produces
    names the caller, not the tenant's setting.
    """
    digest = sha256_of(content)
    looked_up = await lookup_hash(provider, digest)
    if looked_up.outcome in ("known", "pending", "could_not_check"):
        # A provider that could not be reached for the lookup will not be
        # reached for an upload either, and trying anyway would disclose the
        # file to find that out.
        return looked_up

    decision = evaluate_upload(
        capabilities=provider.capabilities,
        airgapped=registry.airgapped,
        tenant_uploads_enabled=tenant_uploads_enabled and allow_upload,
        hash_already_known=False,
    )
    if not decision.allowed:
        detail = decision.reason
        if not allow_upload and decision.refusal is UploadRefusal.TENANT_NOT_CONSENTED:
            detail = f"{provider.name} has not seen this file. This caller performs hash lookups only and did not upload it."
        return SandboxResult(
            outcome="upload_refused",
            provider=provider.name,
            decision=decision,
            sha256=digest,
            detail=detail,
        )

    visibility = requested_visibility or ("private" if provider.capabilities.local else "private")
    try:
        receipt = await provider.submit_file(content, file_name, visibility=visibility)
    except SandboxUnavailable as exc:
        log.warning("sandbox.submit_failed", provider=provider.name, kind=exc.kind, reason=exc.reason)
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            sha256=digest,
            detail=f"Could not submit to {provider.name}: {exc.reason}. This is not a verdict.",
        )

    warnings: list[str] = []
    if provider.capabilities.submissions_are_public_by_default:
        warnings.append(f"{provider.name} publishes submitted samples: this file and its report are now readable by anyone.")
    return SandboxResult(
        outcome="pending",
        provider=provider.name,
        receipt=receipt,
        sha256=digest,
        uploaded=True,
        detail=f"Uploaded to {provider.name} for analysis. Poll {receipt.handle} for the result.",
        warnings=warnings,
    )


async def analyse_url(provider: SandboxProvider, url: str, *, registry: SandboxRegistry) -> SandboxResult:
    """Submit a URL.

    Not governed by the upload policy, which is about customer *files*. It is
    still governed by air-gap mode, because a hosted provider is unreachable
    there whatever the artefact.
    """
    if not registry.is_usable(provider):
        decision = evaluate_upload(
            capabilities=provider.capabilities,
            airgapped=True,
            tenant_uploads_enabled=True,
            hash_already_known=False,
        )
        return SandboxResult(outcome="upload_refused", provider=provider.name, decision=decision, detail=decision.reason)
    if not provider.capabilities.supports_url_submission:
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            detail=f"{provider.name} does not accept URL submissions.",
        )
    try:
        receipt = await provider.submit_url(url)
    except SandboxUnavailable as exc:
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            detail=f"Could not submit to {provider.name}: {exc.reason}. This is not a verdict.",
        )
    return SandboxResult(
        outcome="pending",
        provider=provider.name,
        receipt=receipt,
        detail=f"Submitted to {provider.name}. Poll {receipt.handle} for the result.",
    )


async def poll(provider: SandboxProvider, handle: str) -> SandboxResult:
    """Check on a submission."""
    try:
        report = await provider.poll(handle)
    except SandboxUnavailable as exc:
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            detail=f"Could not reach {provider.name}: {exc.reason}. This is not a verdict.",
        )
    if report.state is AnalysisState.NOT_FOUND:
        return SandboxResult(outcome="not_seen", provider=provider.name, detail=f"{provider.name} has no analysis {handle}.")
    if report.state is AnalysisState.FAILED:
        return SandboxResult(
            outcome="could_not_check",
            provider=provider.name,
            detail=f"{provider.name} failed to analyse {handle}. No verdict was reached.",
        )
    if not report.state.terminal:
        return SandboxResult(outcome="pending", provider=provider.name, detail=f"{provider.name} is still analysing {handle}.")
    return SandboxResult(
        outcome="known",
        provider=provider.name,
        report=report,
        sha256=report.sha256,
        detail=f"{provider.name} finished analysing {handle}.",
    )
