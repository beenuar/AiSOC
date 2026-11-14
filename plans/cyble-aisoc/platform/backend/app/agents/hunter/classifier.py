"""Deterministic hypothesis classifier for the Hunter explorer.

The classifier is *intentionally* a pure function (statement → category +
suggested tools + seed params). The LLM is great at producing natural-
language hypotheses, but the explorer needs a closed, testable mapping
from "what we suspect" to "which tools we should pivot through". Keeping
that mapping deterministic means:

- Tests can pin behavior with string fixtures, no model required.
- A given hypothesis always classifies the same way across runs, which
  matters for replay and for the iterative explorer's idempotence.
- The explorer can be substituted into an LLM-driven outer loop later
  without rewriting the routing.

Classification is keyword/regex based and explicitly biased toward
*recall* over precision: every hypothesis ends up bucketed, defaulting
to ``HypothesisCategory.OTHER`` when nothing matches so the explorer can
still record the intent (and the analyst can refine it).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.agents.hunter.models import HypothesisCategory


# ── Entity / IOC extraction ─────────────────────────────────────────────


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# Domain regex requires at least one dot and a 2+ letter TLD. We
# deliberately keep it strict so usernames like "alice.bob" do not
# masquerade as domains.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Hosts: bare tokens like HOST-123, WIN-DC01, web-prod-3, ip-10-0-1-5
_HOSTNAME_HINT_RE = re.compile(
    r"\b(?:[A-Z]{2,}-\w+|[a-z]+-[a-z0-9-]{2,}|ip-\d+-\d+-\d+-\d+)\b"
)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Pull IOC-like tokens out of free-form text.

    Used both by the classifier (to seed root parameters) and by the
    explorer (to spawn IOC pivot children from tool evidence). Returned
    lists are deduplicated but order-preserving so the explorer fans out
    in a stable order.
    """
    if not text:
        return {"ips": [], "domains": [], "hashes": [], "cves": []}
    seen: dict[str, list[str]] = {
        "ips": [],
        "domains": [],
        "hashes": [],
        "cves": [],
    }
    for match in _IPV4_RE.findall(text):
        if match not in seen["ips"]:
            seen["ips"].append(match)
    for match in _DOMAIN_RE.findall(text):
        lower = match.lower()
        # Skip anything that's also a CVE — CVE-2024-12345 looks like a
        # domain only if you squint, but it's worth being explicit.
        if lower.startswith("cve-"):
            continue
        if lower not in seen["domains"]:
            seen["domains"].append(lower)
    for match in _SHA256_RE.findall(text):
        if match.lower() not in (h.lower() for h in seen["hashes"]):
            seen["hashes"].append(match)
    for match in _MD5_RE.findall(text):
        # SHA256 also matches the 32-char prefix of itself? No — \b boundaries
        # prevent it. But guard against duplicate listing if the same token
        # is already in hashes.
        if match.lower() not in (h.lower() for h in seen["hashes"]):
            seen["hashes"].append(match)
    for match in _CVE_RE.findall(text):
        upper = match.upper()
        if upper not in seen["cves"]:
            seen["cves"].append(upper)
    return seen


def extract_hostnames(text: str) -> list[str]:
    """Best-effort extraction of hostname-like tokens.

    These feed ``edr.get_process_tree`` and host pivot children. Kept
    separate from ``extract_iocs`` because a hostname is not an IOC — it's
    an asset reference.
    """
    if not text:
        return []
    seen: list[str] = []
    for match in _HOSTNAME_HINT_RE.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


# ── Category routing ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Classification:
    """Result of classifying one hypothesis statement."""

    category: HypothesisCategory
    suggested_tools: tuple[str, ...]
    seed_params: dict[str, Any]
    # Keywords that triggered the classification — surfaced on the node's
    # ``notes`` so the analyst can see *why* the explorer picked this lane.
    rationale: tuple[str, ...] = ()


# Order matters: the first rule that matches wins. Rules earlier in the
# list are more specific (e.g. "darkweb credential leak" outranks the
# generic "external exposure" rule). This keeps classification cheap and
# debuggable — no scoring, no ties.
_RULES: tuple[tuple[HypothesisCategory, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        HypothesisCategory.CREDENTIAL_LEAK,
        ("credential", "password", "leak", "stealer", "infostealer", "cookie",
         "session token", "darkweb", "dark web", "combolist"),
        ("cti.darkweb_search",),
    ),
    (
        HypothesisCategory.BRAND_IMPERSONATION,
        ("typosquat", "impersonation", "phishing kit", "brand abuse",
         "lookalike domain", "fake login"),
        ("cti.brand_intel",),
    ),
    (
        HypothesisCategory.VULNERABILITY,
        ("vulnerability", "vulnerable", "cve-", "exploit", "patch",
         "outdated", "unpatched"),
        ("cti.vuln_intel",),
    ),
    (
        HypothesisCategory.EXTERNAL_EXPOSURE,
        ("exposed", "exposure", "open port", "internet-facing",
         "external attack surface", "asm", "shodan"),
        ("cti.asm_lookup",),
    ),
    (
        HypothesisCategory.PROCESS_BEHAVIOR,
        ("process tree", "child process", "spawned", "powershell",
         "lolbin", "cmd.exe", "encoded command", "living off the land",
         "execution chain"),
        ("edr.get_process_tree", "siem.search_events"),
    ),
    (
        HypothesisCategory.NETWORK_BEHAVIOR,
        ("beacon", "c2", "callback", "dns tunneling", "exfil", "egress",
         "outbound", "command and control"),
        ("siem.search_events",),
    ),
)


def classify_hypothesis(statement: str) -> Classification:
    """Bucket ``statement`` into a category + suggested tools + seed params.

    The function is pure and total: every input produces a
    ``Classification``. Empty / whitespace strings fall through to
    ``HypothesisCategory.OTHER`` with no tools, so the explorer records the
    placeholder and skips exploration cleanly.
    """
    text = (statement or "").strip()
    if not text:
        return Classification(
            category=HypothesisCategory.OTHER,
            suggested_tools=(),
            seed_params={},
            rationale=("empty hypothesis",),
        )

    lowered = text.lower()

    # First, look for IOC tokens — if the hypothesis is *itself* an IOC
    # pivot, route it that way regardless of keyword matches. This is
    # what lets the iterative explorer spawn child hypotheses that look
    # like "investigate 198.51.100.7" and have them dispatched into the
    # CTI enrichment tool.
    iocs = extract_iocs(text)
    if iocs["ips"] or iocs["domains"] or iocs["hashes"]:
        first_ioc = (
            iocs["ips"][0]
            if iocs["ips"]
            else (iocs["domains"][0] if iocs["domains"] else iocs["hashes"][0])
        )
        return Classification(
            category=HypothesisCategory.IOC_PIVOT,
            suggested_tools=("cti.enrich_ioc",),
            seed_params={"ioc": first_ioc, "iocs": iocs},
            rationale=("IOC detected in hypothesis statement",),
        )

    hostnames = extract_hostnames(text)
    if hostnames and any(
        kw in lowered
        for kw in ("host", "endpoint", "workstation", "server", "device")
    ):
        return Classification(
            category=HypothesisCategory.HOST_PIVOT,
            suggested_tools=("edr.get_process_tree", "siem.get_related_alerts"),
            seed_params={"host_id": hostnames[0], "entity": hostnames[0]},
            rationale=(f"hostname-like token '{hostnames[0]}' detected",),
        )

    for category, keywords, tools in _RULES:
        for kw in keywords:
            if kw in lowered:
                seed: dict[str, Any] = {}
                if iocs["cves"]:
                    seed["cve"] = iocs["cves"][0]
                if hostnames and category == HypothesisCategory.PROCESS_BEHAVIOR:
                    seed["host_id"] = hostnames[0]
                # ``query`` is a safe fallback for SIEM-style tools.
                seed.setdefault("query", text)
                return Classification(
                    category=category,
                    suggested_tools=tools,
                    seed_params=seed,
                    rationale=(f"matched keyword '{kw}'",),
                )

    return Classification(
        category=HypothesisCategory.OTHER,
        suggested_tools=(),
        seed_params={"query": text},
        rationale=("no rule matched",),
    )


__all__ = [
    "Classification",
    "classify_hypothesis",
    "extract_hostnames",
    "extract_iocs",
]
