"""Brand Responder — closed-loop autonomous takedown for typosquats.

The Brand Responder is the §3d "Exposure-to-Response Loop" specialized
to the **brand surface**. It runs a continuous four-step pipeline per
registered :class:`~app.models.brand.BrandAsset`:

1. **Discover** — :mod:`detector` generates lookalike domain
   candidates (Levenshtein, homoglyph, brand-affix, IDN/punycode,
   lookalike-TLD). Detection is deterministic + cheap so we can run
   it inline against any candidate pool (Cyble brand-intel feed,
   newly-registered zone files, certificate transparency).

2. **Score** — each candidate gets a 0-100 risk score and a severity
   bucket. We expose the reasons that contributed so a human can
   tell why the score landed where it did.

3. **Evidence** — :mod:`evidence` assembles a frozen, shippable
   packet (WHOIS-style summary, DNS posture, content sample,
   trademark touch-point). Frozen = the evidence we ship to a
   registrar is the evidence we keep in the audit log.

4. **Submit** — :mod:`submitter` fans out per-:class:`~app.models.brand.TakedownChannel`
   (registrar, host, registry, safe-browsing, brand-vendor) and
   records the per-channel status returned by the provider.

Design rules:

- The pipeline NEVER auto-submits if the candidate score is below
  the configured ``brand_auto_takedown_threshold``. Lower-scored
  candidates surface as :class:`~app.models.brand.TyposquatCandidate`
  rows for human triage.

- All submissions are mocked at the provider boundary so this
  module works against the existing test harness; switching to a
  real registrar/host abuse API only requires replacing the
  provider stubs in :mod:`submitter`.

- The Responder Agent (:class:`BrandResponderAgent`) is a thin
  orchestrator over these modules. It owns the lifecycle
  transitions and the trace + case-publication wiring; it does
  not itself score domains.
"""
from __future__ import annotations

from app.brand_responder.detector import DetectorMatch, detect_typosquats
from app.brand_responder.evidence import build_evidence_packet
from app.brand_responder.submitter import (
    SubmissionResult,
    submit_takedown_request,
)
from app.brand_responder.responder import (
    BrandResponderAgent,
    BrandSweepReport,
)

__all__ = [
    "BrandResponderAgent",
    "BrandSweepReport",
    "DetectorMatch",
    "SubmissionResult",
    "build_evidence_packet",
    "detect_typosquats",
    "submit_takedown_request",
]
