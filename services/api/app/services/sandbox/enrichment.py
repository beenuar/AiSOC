"""File-hash enrichment: what a sandbox adds to an alert or a submission.

This is the hash-lookup half of the provider contract, shaped for the callers
that have a digest and want to know whether it is worth caring about. It never
uploads: enrichment runs unattended on whatever arrives, and an unattended path
that could upload is one misconfiguration away from disclosing every attachment
a tenant receives.

The output shape mirrors the enrichment service's, so a caller merging this
into an alert's ``enrichments`` does not learn a second schema. The key is
``file_analysis`` rather than a provider name, for the same reason the
interface owns the vocabulary: the reader should not have to know which sandbox
answered.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from app.services.sandbox.registry import SandboxRegistry, build_registry
from app.services.sandbox.service import lookup_hash
from app.services.sandbox.types import SandboxVerdict, Unavailable, is_available

log = structlog.get_logger(__name__)

__all__ = ["enrich_file_hash", "enrich_file_hashes"]

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

#: Verdicts that should raise an analyst's attention. ``UNKNOWN`` is not one:
#: a provider saying "I looked and cannot tell" is not a signal.
_NOTABLE = {SandboxVerdict.MALICIOUS, SandboxVerdict.SUSPICIOUS}


async def enrich_file_hash(sha256: str, *, registry: SandboxRegistry | None = None) -> dict[str, Any]:
    """Look one digest up across every usable provider.

    Returns ``{}`` when nothing is known, so a caller merging this into an
    alert adds nothing rather than adding an empty section. A provider that
    could not be reached is reported under ``could_not_check`` and is
    deliberately *not* folded into "no result": an alert whose file could not
    be checked and one whose file is clean must not render the same.
    """
    digest = (sha256 or "").strip().lower()
    if not _SHA256.match(digest):
        return {}
    registry = registry or build_registry()

    findings: list[dict[str, Any]] = []
    unchecked: list[dict[str, str]] = []
    for name in registry.usable_names():
        provider = registry.get(name)
        if provider is None:  # pragma: no cover
            continue
        result = await lookup_hash(provider, digest)
        if result.outcome == "could_not_check":
            unchecked.append({"provider": name, "reason": result.detail})
            continue
        if result.outcome != "known" or result.report is None:
            continue
        report = result.report
        findings.append(
            {
                "provider": name,
                "verdict": report.verdict.value if is_available(report.verdict) else "unavailable",
                "score": report.score if is_available(report.score) else None,
                "signature_count": 0 if isinstance(report.signatures, Unavailable) else len(report.signatures),
                "attack_techniques": (None if isinstance(report.attack, Unavailable) else [t.technique_id for t in report.attack]),
                "report_url": report.report_url,
                "analyzed_at": report.analyzed_at.isoformat() if report.analyzed_at else None,
                "unavailable": dict(report.unavailable_reasons),
            }
        )

    if not findings and not unchecked:
        return {}

    malicious = [f for f in findings if f["verdict"] in {v.value for v in _NOTABLE}]
    scores = [f["score"] for f in findings if isinstance(f["score"], int)]
    return {
        "file_analysis": {
            "sha256": digest,
            "hit": bool(malicious),
            "findings": findings,
            # Named so it cannot be read as a zero. A caller that only checks
            # `max_score` gets None, not 0, when nothing published one.
            "max_score": max(scores) if scores else None,
            "could_not_check": unchecked,
        }
    }


async def enrich_file_hashes(hashes: list[str], *, registry: SandboxRegistry | None = None, limit: int = 10) -> dict[str, Any]:
    """Enrich several digests, capped so one alert cannot fan out unboundedly."""
    registry = registry or build_registry()
    seen: list[str] = []
    for value in hashes:
        digest = (value or "").strip().lower()
        if _SHA256.match(digest) and digest not in seen:
            seen.append(digest)
        if len(seen) >= limit:
            break
    merged: list[dict[str, Any]] = []
    for digest in seen:
        block = (await enrich_file_hash(digest, registry=registry)).get("file_analysis")
        if block:
            merged.append(block)
    return {"file_analysis": merged} if merged else {}
