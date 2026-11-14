"""Evidence packet builder for brand takedowns.

A takedown is only as credible as the evidence shipped with it.
Registrars, hosts, and safe-browsing teams will reject filings that
don't show:

- Why we believe the candidate domain impersonates the brand.
- That the brand actually exists (trademark, canonical domain).
- A timestamped, frozen snapshot of the offending content
  (so the abuse team can verify it even after the attacker takes
  the page down between our filing and their review).

This module produces a single dict (``evidence`` field of
:class:`~app.models.brand.TakedownRequest`) that captures all of
the above in a provider-agnostic shape. The submitter layer is
responsible for projecting it into whichever schema a registrar
actually wants.

We deliberately keep the evidence packet as a plain ``dict`` (not
a Pydantic model) for two reasons:

1. It's stored in a JSON column — round-tripping through Pydantic
   adds zero value.
2. New providers periodically demand new fields; a dict lets us
   add them without a migration.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from app.brand_responder.detector import DetectorMatch
from app.models.brand import BrandAsset, TyposquatCandidate


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: str) -> str:
    """Stable short hash used as evidence-packet identifier.

    Not security-sensitive — just gives us a deterministic id we
    can echo back to the provider and reference in audit logs.
    """
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def build_evidence_packet(
    *,
    asset: BrandAsset,
    candidate: TyposquatCandidate,
    detector_match: DetectorMatch | None = None,
    content_sample: str | None = None,
) -> dict[str, Any]:
    """Assemble a frozen evidence packet for a takedown filing.

    Args:
        asset: The brand surface being defended (provides the
            trademark / canonical-domain claim).
        candidate: The typosquat candidate we want taken down.
        detector_match: Optional detector output. If supplied we
            include the score + reasons verbatim; this is the
            "explainability" the abuse team will read.
        content_sample: Optional already-fetched page sample.
            We DON'T fetch live here — the detector / sweep is
            responsible for crawling, and we just record what it
            saw. Keeping the fetch upstream means the same packet
            is reproducible in tests.

    Returns:
        A dict suitable for storing in
        :attr:`TakedownRequest.evidence` and for shipping to a
        provider.
    """
    now = _utc_now_iso()
    enrichment = dict(candidate.enrichment or {})

    detector_block: dict[str, Any]
    if detector_match is not None:
        detector_block = {
            "score": detector_match.score,
            "severity": detector_match.severity,
            "reasons": list(detector_match.reasons),
        }
    else:
        detector_block = {
            "score": candidate.score,
            "severity": candidate.severity,
            "reasons": list(candidate.reasons),
        }

    content_block: dict[str, Any] = {}
    if content_sample is not None:
        content_block = {
            "sha256": _digest(content_sample),
            "length_bytes": len(content_sample.encode("utf-8")),
            "captured_at": now,
        }

    packet: dict[str, Any] = {
        "schema_version": "1",
        "generated_at": now,
        "brand": {
            "name": asset.name,
            "root_domain": asset.root_domain,
            "aliases": list(asset.aliases),
            "monitored_terms": list(asset.monitored_terms),
            "tenant_id": asset.tenant_id,
        },
        "candidate": {
            "domain": candidate.candidate_domain,
            "first_seen": candidate.first_seen.isoformat(),
            "last_seen": candidate.last_seen.isoformat(),
            "enrichment": enrichment,
        },
        "detector": detector_block,
        "content": content_block,
        "claim": (
            f"The domain {candidate.candidate_domain} appears to "
            f"impersonate the brand {asset.name} "
            f"({asset.root_domain}). Detector reasons: "
            f"{', '.join(detector_block['reasons']) or 'n/a'}."
        ),
    }
    packet["evidence_id"] = _digest(
        f"{asset.tenant_id}:{candidate.candidate_domain}:{now}"
    )
    return packet


__all__ = ["build_evidence_packet"]
