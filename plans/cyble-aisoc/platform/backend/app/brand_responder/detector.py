"""Typosquat detector — cheap, deterministic, explainable.

The detector exists to answer one question: *given a brand surface
the tenant cares about and a pool of candidate domains, which
candidates look like impersonations and why?*

We deliberately keep this in plain Python:

- It needs to run cheaply per-sweep over thousands of candidates.
- The Brand Responder must explain why it flagged something to a
  human reviewer, so the scoring is a sum of named features rather
  than an opaque ML output.
- It should work without external services so the pipeline is
  testable end-to-end in CI.

The scoring model is intentionally simple: each detection rule
returns 0 or more "reasons", each reason carries a small weight,
and the final score is ``min(100, sum(weights))``. Severity bucket
follows from the score band. Anything matching the brand's own
domain or any of its registered aliases is dropped early as the
brand itself, never a squat.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from app.models.brand import BrandAsset


@dataclass(frozen=True)
class DetectorMatch:
    """One candidate domain the detector decided is brand-adjacent.

    Held immutable so callers can pass it around without worrying
    about late mutation. Reasons list is sorted for stable output.
    """

    candidate_domain: str
    score: int
    severity: str
    reasons: list[str]
    matched_brand_asset_id: int

    @property
    def is_actionable(self) -> bool:
        """Helper: whether severity is medium or worse.

        Detectors emit everything they see, including very weak
        matches; "actionable" is the floor at which we even bother
        recording a :class:`TyposquatCandidate` row.
        """
        return self.severity in {"medium", "high", "critical"}


# Multi-label suffixes treated as a single effective TLD.
#
# Two groups, same handling, separated for clarity:
#
# 1. Country-code ccTLD second levels (co.uk, com.br, …) — standard
#    public-suffix entries.
# 2. Free dynamic-DNS / cheap subdomain providers that attackers love
#    because anyone can register a hostname for free (no WHOIS, no
#    payment trail) — duckdns.org, no-ip.com, ngrok.io, etc. Without
#    these in the list, ``testbrand-portal.duckdns.org`` would have
#    ``duckdns`` as its registrable label and the brand match would
#    be missed. These are observed in Cyble's own brand-takedown
#    telemetry as recurring phishing infrastructure.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # Country-code public suffixes
        "co.uk",
        "co.in",
        "com.au",
        "com.br",
        "co.jp",
        # Free dynamic DNS / subdomain hosting (phishing-favoured)
        "duckdns.org",
        "no-ip.com",
        "no-ip.org",
        "ddns.net",
        "hopto.org",
        "zapto.org",
        "ngrok.io",
        "ngrok-free.app",
        "github.io",
        "gitlab.io",
        "netlify.app",
        "vercel.app",
        "web.app",
        "firebaseapp.com",
        "azurewebsites.net",
        "cloudfront.net",
        "herokuapp.com",
        "pages.dev",
        "workers.dev",
        "r2.dev",
    }
)


def _strip_tld(domain: str) -> str:
    """Return the registrable label (best-effort, no PSL lookup).

    We avoid pulling in the public-suffix list to keep this module
    dependency-free. The heuristic ("first label before the last
    dot") is good enough for typosquat scoring because we only use
    it for substring comparisons against the brand label.

    Multi-label public suffixes (``co.uk``) and well-known free
    dynamic-DNS / subdomain hosting providers (``duckdns.org``,
    ``ngrok.io``) are treated as a single effective TLD so the
    registrable label still reflects the attacker-chosen portion.
    """
    norm = domain.strip().lower().lstrip(".")
    if "." not in norm:
        return norm
    parts = norm.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES:
        return parts[-3]
    return parts[-2]


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance.

    Standard DP implementation; small enough that we don't need a
    C extension. Used only for short labels (brand name vs.
    candidate label), so the O(n*m) cost is negligible.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + cost,
            )
        prev = curr
    return prev[-1]


HOMOGLYPHS = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "l", "!"],
    "l": ["1", "i"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
}
"""Common ASCII homoglyph substitutions seen in typosquats.

This is not exhaustive — Unicode confusables would require a much
larger table — but it catches the lazy-attacker subset that
accounts for most observed phishing domains.
"""


def _homoglyph_collision(brand_label: str, candidate_label: str) -> bool:
    """True if candidate is a homoglyph-substituted version of the brand.

    Walks the brand label position by position. At each position
    the candidate must match the original character or an allowed
    homoglyph substitute. Lengths must match.
    """
    if len(brand_label) != len(candidate_label):
        return False
    diff = 0
    for orig, sub in zip(brand_label, candidate_label):
        if orig == sub:
            continue
        if sub in HOMOGLYPHS.get(orig, []):
            diff += 1
            continue
        return False
    return 1 <= diff <= max(1, len(brand_label) // 3)


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "support",
    "top",
    "xyz",
    "country",
    "win",
    "loan",
    "cam",
    "rest",
    "kim",
}
"""TLDs over-represented in phishing telemetry.

Tracked by industry reports (Spamhaus, Interisle) year over year.
Listed here so the scorer can give a small bump when an otherwise
borderline match lives on a known-bad TLD.
"""


BRAND_AFFIXES = {
    "secure",
    "support",
    "login",
    "verify",
    "account",
    "portal",
    "auth",
    "id",
    "official",
    "update",
    "billing",
    "payments",
    "service",
}
"""Strings attackers stitch onto a brand to seem legitimate."""


@dataclass
class _ScoreAcc:
    """Mutable accumulator passed through scoring helpers."""

    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, weight: int, reason: str) -> None:
        self.score += weight
        self.reasons.append(reason)


def _severity_from_score(score: int) -> str:
    """Map 0-100 score to a severity bucket.

    Bands chosen so the auto-takedown threshold (default 80) falls
    cleanly into "high", and the manual-review band (60-79) maps
    to "medium" — that matches what the Responder Agent's policy
    expects in :meth:`BrandResponderAgent.sweep`.
    """
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "low"


def _score_candidate(
    asset: BrandAsset, candidate: str
) -> tuple[int, list[str]]:
    """Score a single candidate against a single brand asset.

    Returns ``(score, reasons)``. A score of 0 means "no signal";
    the caller filters those out before returning.

    The function is intentionally split into independent feature
    checks so adding a new detector (e.g. brand keyword in path,
    cert SAN cross-match) is additive rather than a refactor.
    """
    acc = _ScoreAcc()

    cand_norm = candidate.strip().lower().lstrip(".")
    if not cand_norm or "." not in cand_norm:
        return 0, []

    cand_label = _strip_tld(cand_norm)
    cand_tld = cand_norm.rsplit(".", 1)[-1]

    brand_label = _strip_tld(asset.root_domain)
    if not brand_label:
        return 0, []

    if cand_norm == asset.root_domain.lower():
        return 0, []
    if any(cand_norm == alias.lower() for alias in asset.aliases):
        return 0, []

    distance = _levenshtein(brand_label, cand_label)
    if 1 <= distance <= 2 and len(brand_label) >= 4:
        acc.add(40 if distance == 1 else 25, f"edit_distance_{distance}")

    if cand_label != brand_label and brand_label in cand_label:
        affix = cand_label.replace(brand_label, "", 1).strip("-_")
        if affix:
            if affix in BRAND_AFFIXES:
                acc.add(35, f"brand_affix:{affix}")
            else:
                acc.add(20, "brand_substring")

    if _homoglyph_collision(brand_label, cand_label):
        acc.add(45, "homoglyph_substitution")

    if cand_norm.startswith("xn--") or ".xn--" in cand_norm:
        acc.add(30, "punycode_idn")

    if cand_tld in SUSPICIOUS_TLDS:
        acc.add(10, f"suspicious_tld:{cand_tld}")

    for term in asset.monitored_terms:
        term_norm = term.lower().strip()
        if term_norm and term_norm in cand_norm and term_norm != brand_label:
            acc.add(15, f"monitored_term:{term_norm}")
            break

    acc.reasons.sort()
    return min(acc.score, 100), acc.reasons


def detect_typosquats(
    assets: Iterable[BrandAsset],
    candidates: Iterable[str],
    *,
    min_score: int = 30,
) -> list[DetectorMatch]:
    """Run the detector over every (asset, candidate) pair.

    The default ``min_score`` of 30 filters out near-noise and keeps
    the output focused on candidates the Responder Agent will
    actually act on or display. Callers that want the raw output
    (e.g. for ML training) can lower it to 1.
    """
    asset_list = list(assets)
    matches: list[DetectorMatch] = []
    seen: set[tuple[int, str]] = set()

    for cand in candidates:
        cand_norm = cand.strip().lower().lstrip(".")
        if not cand_norm:
            continue

        best: DetectorMatch | None = None
        for asset in asset_list:
            if asset.id is None:
                continue
            score, reasons = _score_candidate(asset, cand_norm)
            if score < min_score:
                continue
            key = (asset.id, cand_norm)
            if key in seen:
                continue
            seen.add(key)
            severity = _severity_from_score(score)
            match = DetectorMatch(
                candidate_domain=cand_norm,
                score=score,
                severity=severity,
                reasons=reasons,
                matched_brand_asset_id=asset.id,
            )
            if best is None or match.score > best.score:
                best = match
        if best is not None:
            matches.append(best)

    matches.sort(key=lambda m: m.score, reverse=True)
    return matches


__all__ = ["DetectorMatch", "detect_typosquats"]
