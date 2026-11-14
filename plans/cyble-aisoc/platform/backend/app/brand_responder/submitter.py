"""Takedown submitter — fans out a request to its abuse channel.

In production each :class:`TakedownChannel` resolves to a real
provider integration:

- ``REGISTRAR_ABUSE`` → registrar's abuse@ email or RDAP-based
  abuse contact (per the IANA Registrar Accreditation Agreement).
- ``HOST_ABUSE`` → the hosting provider's abuse channel resolved
  from the candidate's IP / ASN.
- ``REGISTRY_ABUSE`` → escalation path when registrar declines
  (e.g. .com → Verisign abuse channel).
- ``SAFE_BROWSING`` → Google Safe Browsing / Microsoft SmartScreen
  reporting endpoints.
- ``BRAND_PROTECTION_VENDOR`` → third-party takedown SaaS (e.g.
  MarkMonitor / Group-IB) used by larger enterprises.

We mock those at the transport boundary so the rest of the
pipeline (detector → evidence → submitter → status update) works
end-to-end in tests. Swapping in a real provider is a one-file
change in :func:`_dispatch`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.models.brand import TakedownChannel, TakedownStatus


@dataclass(frozen=True)
class SubmissionResult:
    """Provider-agnostic outcome of one takedown filing.

    Mirrors the subset of fields the Brand Responder needs to
    record in :class:`~app.models.brand.TakedownRequest`. We don't
    leak the raw provider payload upward — providers differ wildly
    and we want a stable internal shape.
    """

    status: TakedownStatus
    provider_ticket: str | None
    recipient: str
    note: str

    @property
    def is_terminal_success(self) -> bool:
        """True if the channel confirmed the takedown landed."""
        return self.status == TakedownStatus.ACTIONED

    @property
    def is_failure(self) -> bool:
        return self.status == TakedownStatus.FAILED


_RECIPIENTS: dict[TakedownChannel, str] = {
    TakedownChannel.REGISTRAR_ABUSE: "abuse@registrar.example",
    TakedownChannel.HOST_ABUSE: "abuse@host.example",
    TakedownChannel.REGISTRY_ABUSE: "abuse@registry.example",
    TakedownChannel.SAFE_BROWSING: "safebrowsing-reports@google.com",
    TakedownChannel.BRAND_PROTECTION_VENDOR: "intake@brandvendor.example",
}
"""Mock recipient per channel.

In production these come from RDAP, ASN-to-abuse lookups, or
configured vendor endpoints — never from a static table. The map
exists so tests have a stable surface to assert against.
"""


def _resolve_recipient(channel: TakedownChannel, evidence: dict[str, Any]) -> str:
    """Pick the abuse-contact endpoint for ``channel``.

    Stub today; left as a function so the real RDAP / ASN-lookup
    logic plugs in without changing the call site.
    """
    candidate_domain = (
        evidence.get("candidate", {}).get("domain", "unknown") or "unknown"
    )
    base = _RECIPIENTS[channel]
    if channel == TakedownChannel.BRAND_PROTECTION_VENDOR:
        return base
    return f"{base}?domain={candidate_domain}"


def _dispatch(
    channel: TakedownChannel,
    evidence: dict[str, Any],
    *,
    dry_run: bool,
) -> SubmissionResult:
    """Mock provider-call boundary.

    A real implementation would issue an HTTP request / SMTP send
    here and parse the provider's response. The mock returns a
    deterministic acknowledged-with-ticket result for any non-
    dry-run submission, and a no-op SUBMITTED result when ``dry_run``
    is True (tests rely on this distinction).
    """
    recipient = _resolve_recipient(channel, evidence)
    evidence_id = evidence.get("evidence_id", "ev-unknown")

    if dry_run:
        return SubmissionResult(
            status=TakedownStatus.SUBMITTED,
            provider_ticket=None,
            recipient=recipient,
            note=f"dry-run: would submit {evidence_id} to {channel.value}",
        )

    ticket = f"{channel.value}-{evidence_id}"
    return SubmissionResult(
        status=TakedownStatus.ACKNOWLEDGED,
        provider_ticket=ticket,
        recipient=recipient,
        note=f"provider acknowledged ticket {ticket}",
    )


def submit_takedown_request(
    *,
    channel: TakedownChannel,
    evidence: dict[str, Any],
    dry_run: bool = False,
) -> SubmissionResult:
    """Submit one takedown filing on the given channel.

    Args:
        channel: Which abuse pipe to use.
        evidence: Frozen evidence packet (see
            :func:`app.brand_responder.evidence.build_evidence_packet`).
        dry_run: If True, do not actually push to the provider —
            used by HITL preview and by tests.

    Returns:
        :class:`SubmissionResult` describing the outcome.
    """
    if not evidence:
        return SubmissionResult(
            status=TakedownStatus.FAILED,
            provider_ticket=None,
            recipient="",
            note="evidence packet missing",
        )
    return _dispatch(channel, evidence, dry_run=dry_run)


def status_history_entry(
    status: TakedownStatus, note: str
) -> dict[str, Any]:
    """Build one row for :attr:`TakedownRequest.status_history`.

    Centralized so every status transition records the same shape:
    ``{at, status, note}``. Keeps the JSON column auditable.
    """
    return {
        "at": datetime.now(timezone.utc).isoformat(),
        "status": status.value,
        "note": note,
    }


__all__ = [
    "SubmissionResult",
    "status_history_entry",
    "submit_takedown_request",
]
