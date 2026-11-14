"""Phishing triage tools — deep, in-process analyses for the Phishing Triage agent.

Where ``email.analyze_message`` is a thin wrapper around the per-tenant email
connector (Proofpoint / M365 / mock), these tools layer Cyble-native deep
analysis on top of that raw signal:

* ``phishing.deep_header_analysis`` — SPF/DKIM/DMARC verdict + ARC chain +
  routing-path / From-vs-Return-Path-vs-Reply-To consistency + suspicious
  X-headers + hop timing anomalies.
* ``phishing.unwrap_url_chain`` — follow redirects through SafeLinks /
  ProofpointURL / url-shorteners until the terminal URL is reached, return
  the chain + terminal landing host.
* ``phishing.detonate_url`` — sandbox the landing page: surface forms,
  brand-mimicry signals (favicon, logos, brand text), JS obfuscation,
  cred-harvest patterns. Returns a structured detonation report.
* ``phishing.brand_impersonation`` — score a sender + URL chain against
  the tenant's brand list and Cyble brand-intel feed: lookalike domains,
  homoglyphs, recently-registered domains, known phish kits.

All four tools are ``RiskClass.READ`` (no writes). Containment lives in
``email_tool.py`` (``email.clawback_message``, ``email.block_sender``).

These tools are intentionally in-process and deterministic. Detonation /
URL-chain follow is mocked here to keep the demo hermetic — production
swaps the implementations behind feature flags without changing the tool
schema, so the agent's plan stays portable.

Tenancy
-------
Tools tagged ``needs:tenant`` receive ``tenant_id`` from the agent base.
The LLM never sees ``tenant_id``.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.tools.registry import RiskClass, tool

_NEEDS_TENANT = "needs:tenant"

# ── Demo data: tenant brand registry (production = per-tenant config + Cyble feed) ──
# A tenant's brand registry tells us which sending domains / display names
# are legitimately ours, so we can flag impersonation. Production reads this
# from the tenant config service; for the demo we keep a deterministic table
# keyed by tenant_id, with a generic fallback.
_TENANT_BRANDS: dict[str, dict[str, Any]] = {
    "default": {
        "display_names": ["IT Help Desk", "Payroll", "Finance", "HR"],
        "domains": ["example.com", "corp.example.com", "mail.example.com"],
        "brand_keywords": ["acme", "example corp"],
    },
}

# Known phishing kits + recently-registered phishing infra (Cyble brand intel feed).
# In production this is hydrated from the Cyble brand-intel API. For the demo
# we ship a deterministic mini-feed so the agent's reasoning is reproducible.
_CYBLE_BRAND_INTEL: dict[str, dict[str, Any]] = {
    "examp1e.com": {
        "kind": "homoglyph",
        "target_brand": "example.com",
        "registered_days_ago": 4,
        "kit": "evilginx2",
        "confidence": 0.92,
    },
    "example-secure-login.com": {
        "kind": "lookalike",
        "target_brand": "example.com",
        "registered_days_ago": 11,
        "kit": "16shop",
        "confidence": 0.87,
    },
    "examp1e-payroll.co": {
        "kind": "lookalike",
        "target_brand": "example.com",
        "registered_days_ago": 2,
        "kit": "unknown",
        "confidence": 0.78,
    },
}

# Mock URL chain: shortener / SafeLinks → terminal landing.
# Production resolves chains live (with a timeout + redirect cap). Keep this
# deterministic for the demo so agent traces are reproducible.
_URL_CHAINS: dict[str, list[str]] = {
    "https://safelinks.proofpoint.com/?u=https%3A//bit.ly/3zXq9": [
        "https://safelinks.proofpoint.com/?u=https%3A//bit.ly/3zXq9",
        "https://bit.ly/3zXq9",
        "https://examp1e.com/login",
    ],
    "https://t.co/abc123": [
        "https://t.co/abc123",
        "https://example-secure-login.com/auth",
    ],
    "https://bit.ly/safe1": [
        "https://bit.ly/safe1",
        "https://example.com/help",
    ],
}

# Mock detonation reports for landing pages.
_DETONATION_REPORTS: dict[str, dict[str, Any]] = {
    "examp1e.com": {
        "screenshot": "phish-001.png",
        "title": "Example Corp — Sign In",
        "forms": [
            {
                "action": "https://examp1e.com/harvest.php",
                "method": "POST",
                "fields": ["email", "password", "mfa_code"],
            }
        ],
        "brand_mimicry": {
            "logo_hash_match": "example.com",
            "favicon_match": True,
            "title_match": True,
        },
        "js_obfuscated": True,
        "credential_harvest": True,
        "verdict": "phishing",
        "kit": "evilginx2",
    },
    "example-secure-login.com": {
        "screenshot": "phish-002.png",
        "title": "Example Corp Secure Login",
        "forms": [
            {
                "action": "https://example-secure-login.com/post",
                "method": "POST",
                "fields": ["username", "password"],
            }
        ],
        "brand_mimicry": {
            "logo_hash_match": "example.com",
            "favicon_match": True,
            "title_match": True,
        },
        "js_obfuscated": False,
        "credential_harvest": True,
        "verdict": "phishing",
        "kit": "16shop",
    },
    "example.com": {
        "screenshot": None,
        "title": "Example Corp — Help",
        "forms": [],
        "brand_mimicry": {
            "logo_hash_match": "example.com",
            "favicon_match": True,
            "title_match": True,
        },
        "js_obfuscated": False,
        "credential_harvest": False,
        "verdict": "benign",
        "kit": None,
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────


def _tenant_brand(tenant_id: str) -> dict[str, Any]:
    """Return the tenant's brand registry, falling back to ``default``."""
    return _TENANT_BRANDS.get(tenant_id) or _TENANT_BRANDS["default"]


def _domain_of(value: str | None) -> str:
    """Extract a bare domain from an email address or URL.

    Strips angle brackets, lowercases, and returns the registrable
    portion only down to two labels (we don't need a full PSL parse for
    the demo). Returns empty string on bad input.
    """
    if not value:
        return ""
    v = value.strip().lower().strip("<>")
    if "@" in v:
        v = v.split("@", 1)[1].split(">", 1)[0]
    if "://" in v:
        try:
            v = urlparse(v).hostname or ""
        except Exception:
            return ""
    return v.strip().strip(".")


def _homoglyph_distance(a: str, b: str) -> int:
    """Cheap homoglyph-aware distance.

    Normalizes common phish-kit substitutions ('1' for 'l', '0' for 'o',
    'rn' for 'm') then computes a Levenshtein-style distance on the
    normalized strings. Lower = more visually similar.
    """
    sub = {"1": "l", "0": "o", "rn": "m", "vv": "w"}
    na, nb = a.lower(), b.lower()
    for k, v in sub.items():
        na = na.replace(k, v)
        nb = nb.replace(k, v)
    if na == nb:
        return 0
    # Tiny Levenshtein implementation — fine for short domain strings.
    if not na:
        return len(nb)
    if not nb:
        return len(na)
    prev = list(range(len(nb) + 1))
    for i, ca in enumerate(na, 1):
        cur = [i]
        for j, cb in enumerate(nb, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


# ── Tools ──────────────────────────────────────────────────────────────────


@tool(
    name="phishing.deep_header_analysis",
    integration="cyble-phishing",
    risk=RiskClass.READ,
    description=(
        "Deep email header analysis: SPF/DKIM/DMARC verdict + ARC chain + "
        "From/Reply-To/Return-Path alignment + suspicious X-headers + "
        "Received-hop routing anomalies. Returns structured findings."
    ),
    params={
        "type": "object",
        "properties": {
            "message_id": {"type": "string"},
            "headers": {
                "type": "object",
                "description": (
                    "Optional pre-fetched headers map; if omitted, analysis "
                    "operates on whatever the agent has already loaded via "
                    "email.analyze_message in scratchpad."
                ),
                "additionalProperties": True,
            },
        },
        "required": ["message_id"],
    },
    result={
        "type": "object",
        "properties": {
            "message_id": {"type": "string"},
            "auth": {
                "type": "object",
                "properties": {
                    "spf": {"type": "string"},
                    "dkim": {"type": "string"},
                    "dmarc": {"type": "string"},
                    "arc": {"type": "string"},
                },
                "additionalProperties": True,
            },
            "alignment": {
                "type": "object",
                "properties": {
                    "from_vs_return_path": {"type": "boolean"},
                    "from_vs_reply_to": {"type": "boolean"},
                    "envelope_from_match": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
            "routing": {
                "type": "object",
                "properties": {
                    "hop_count": {"type": "integer"},
                    "originating_country": {"type": "string"},
                    "suspicious_hops": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "additionalProperties": True,
            },
            "x_headers": {
                "type": "array",
                "items": {"type": "string"},
            },
            "findings": {
                "type": "array",
                "items": {"type": "string"},
            },
            "suspicion_score": {"type": "number"},
        },
        "required": ["message_id", "auth", "suspicion_score"],
        "additionalProperties": True,
    },
    cyble_native=True,
    tags=[_NEEDS_TENANT, "phishing", "moat"],
)
async def phishing_deep_header_analysis(
    *, tenant_id: str, message_id: str, headers: dict[str, Any] | None = None
) -> dict[str, Any]:
    """In-process deep header analysis.

    The analysis is intentionally deterministic given the same headers,
    so the case trace is reproducible. When ``headers`` is omitted we
    return a default profile — production wires this to a header store
    fronted by the email connector.
    """
    h = headers or {}

    from_addr = str(h.get("from", "")).lower()
    reply_to = str(h.get("reply_to", from_addr)).lower()
    return_path = str(h.get("return_path", from_addr)).lower()
    envelope_from = str(h.get("envelope_from", return_path)).lower()

    from_dom = _domain_of(from_addr) or "unknown"
    reply_dom = _domain_of(reply_to) or from_dom
    rp_dom = _domain_of(return_path) or from_dom
    env_dom = _domain_of(envelope_from) or rp_dom

    spf = str(h.get("spf", "fail")).lower()
    dkim = str(h.get("dkim", "fail")).lower()
    dmarc = str(h.get("dmarc", "fail")).lower()
    arc = str(h.get("arc", "none")).lower()

    received = h.get("received") or []
    if not isinstance(received, list):
        received = [str(received)]
    hop_count = len(received)
    originating = "unknown"
    suspicious_hops: list[str] = []
    for hop in received:
        s = str(hop).lower()
        if "from" in s:
            if ".ru" in s or ".cn" in s or ".tk" in s:
                originating = "high-risk-geo"
                suspicious_hops.append(s[:120])
            if re.search(r"\b(unknown|localhost|127\.0\.0\.1)\b", s):
                suspicious_hops.append(f"unknown-origin: {s[:120]}")

    x_headers = [str(k) for k in h.keys() if str(k).lower().startswith("x-")]

    findings: list[str] = []
    if spf not in {"pass"}:
        findings.append(f"SPF={spf}")
    if dkim not in {"pass"}:
        findings.append(f"DKIM={dkim}")
    if dmarc not in {"pass"}:
        findings.append(f"DMARC={dmarc}")
    if arc not in {"pass", "none"}:
        findings.append(f"ARC={arc}")

    from_vs_rp = from_dom == rp_dom
    from_vs_reply = from_dom == reply_dom
    env_match = env_dom == rp_dom
    if not from_vs_rp:
        findings.append(f"From/Return-Path mismatch: {from_dom} vs {rp_dom}")
    if not from_vs_reply:
        findings.append(f"From/Reply-To mismatch: {from_dom} vs {reply_dom}")
    if not env_match:
        findings.append(f"Envelope/Return-Path mismatch: {env_dom} vs {rp_dom}")
    if hop_count > 8:
        findings.append(f"Long hop chain: {hop_count} hops")
    if suspicious_hops:
        findings.append(f"Suspicious hops: {len(suspicious_hops)}")

    # Suspicion score: 0.0 (clean) → 1.0 (definitely phish).
    score = 0.0
    score += 0.20 if spf != "pass" else 0.0
    score += 0.25 if dkim != "pass" else 0.0
    score += 0.25 if dmarc != "pass" else 0.0
    score += 0.10 if not from_vs_rp else 0.0
    score += 0.10 if not from_vs_reply else 0.0
    score += 0.10 if not env_match else 0.0
    score += 0.05 * min(len(suspicious_hops), 4)
    score = round(min(score, 1.0), 3)

    return {
        "message_id": message_id,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc, "arc": arc},
        "alignment": {
            "from_vs_return_path": from_vs_rp,
            "from_vs_reply_to": from_vs_reply,
            "envelope_from_match": env_match,
        },
        "routing": {
            "hop_count": hop_count,
            "originating_country": originating,
            "suspicious_hops": suspicious_hops,
        },
        "x_headers": x_headers,
        "findings": findings,
        "suspicion_score": score,
    }


@tool(
    name="phishing.unwrap_url_chain",
    integration="cyble-phishing",
    risk=RiskClass.READ,
    description=(
        "Unwrap a URL chain by following redirects, SafeLinks, and "
        "url-shorteners until the terminal landing page is reached. "
        "Returns the full chain + terminal host."
    ),
    params={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "max_hops": {"type": "integer", "default": 10},
        },
        "required": ["url"],
    },
    result={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "chain": {"type": "array", "items": {"type": "string"}},
            "terminal_url": {"type": "string"},
            "terminal_host": {"type": "string"},
            "hop_count": {"type": "integer"},
            "shortener_used": {"type": "boolean"},
            "safelinks_used": {"type": "boolean"},
            "truncated": {"type": "boolean"},
        },
        "required": ["url", "chain", "terminal_url"],
        "additionalProperties": True,
    },
    cyble_native=True,
    tags=["phishing", "moat"],
)
async def phishing_unwrap_url_chain(
    *, url: str, max_hops: int = 10
) -> dict[str, Any]:
    """Follow the redirect chain to its terminal URL.

    Deterministic over the demo URL table; in production this calls a
    sandboxed crawler with per-hop TLS inspection and a hard timeout.
    """
    chain = list(_URL_CHAINS.get(url, [url]))
    if len(chain) > max_hops:
        chain = chain[:max_hops]
        truncated = True
    else:
        truncated = False
    terminal = chain[-1]
    terminal_host = _domain_of(terminal)
    shorteners = ("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd")
    safelinks = ("safelinks.protection.outlook.com", "safelinks.proofpoint.com", "urldefense.com")
    shortener_used = any(s in hop for hop in chain for s in shorteners)
    safelinks_used = any(s in hop for hop in chain for s in safelinks)
    return {
        "url": url,
        "chain": chain,
        "terminal_url": terminal,
        "terminal_host": terminal_host,
        "hop_count": len(chain),
        "shortener_used": shortener_used,
        "safelinks_used": safelinks_used,
        "truncated": truncated,
    }


@tool(
    name="phishing.detonate_url",
    integration="cyble-phishing",
    risk=RiskClass.READ,
    description=(
        "Sandbox a URL: render the landing page, capture forms, brand "
        "mimicry signals (logo / favicon / title), JS obfuscation, and "
        "credential-harvest patterns. Returns a structured detonation report."
    ),
    params={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "render_timeout_s": {"type": "integer", "default": 15},
        },
        "required": ["url"],
    },
    result={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "host": {"type": "string"},
            "screenshot": {"type": "string"},
            "title": {"type": "string"},
            "forms": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "method": {"type": "string"},
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "brand_mimicry": {
                "type": "object",
                "properties": {
                    "logo_hash_match": {"type": "string"},
                    "favicon_match": {"type": "boolean"},
                    "title_match": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
            "js_obfuscated": {"type": "boolean"},
            "credential_harvest": {"type": "boolean"},
            "kit": {"type": "string"},
            "verdict": {"type": "string"},
        },
        "required": ["url", "host", "verdict"],
        "additionalProperties": True,
    },
    cyble_native=True,
    tags=["phishing", "moat"],
)
async def phishing_detonate_url(
    *, url: str, render_timeout_s: int = 15
) -> dict[str, Any]:
    """Sandbox detonation of a URL.

    Deterministic over the demo table keyed by terminal host. Production
    routes through a Cyble-managed detonation farm with screenshot capture
    and DOM-level cred-harvest detection.
    """
    host = _domain_of(url)
    report = _DETONATION_REPORTS.get(host)
    if not report:
        # Default: treat as benign-unknown so an unfamiliar URL doesn't
        # auto-escalate. The agent should combine this with brand-impersonation
        # signals before deciding.
        return {
            "url": url,
            "host": host,
            "screenshot": None,
            "title": "",
            "forms": [],
            "brand_mimicry": {
                "logo_hash_match": "",
                "favicon_match": False,
                "title_match": False,
            },
            "js_obfuscated": False,
            "credential_harvest": False,
            "kit": "",
            "verdict": "unknown",
        }
    out = {"url": url, "host": host, **report}
    return out


@tool(
    name="phishing.brand_impersonation",
    integration="cyble-brand",
    risk=RiskClass.READ,
    description=(
        "Score sender / URL host for brand impersonation against the "
        "tenant brand registry + Cyble brand-intel feed. Detects "
        "lookalike domains, homoglyphs, recently-registered phishing "
        "infra, and known kits."
    ),
    params={
        "type": "object",
        "properties": {
            "candidate": {
                "type": "string",
                "description": "Sender email or URL/host to evaluate.",
            },
        },
        "required": ["candidate"],
    },
    result={
        "type": "object",
        "properties": {
            "candidate": {"type": "string"},
            "candidate_domain": {"type": "string"},
            "matched_brand": {"type": "string"},
            "kind": {"type": "string"},
            "homoglyph_distance": {"type": "integer"},
            "registered_days_ago": {"type": "integer"},
            "known_kit": {"type": "string"},
            "in_cyble_feed": {"type": "boolean"},
            "is_legitimate": {"type": "boolean"},
            "confidence": {"type": "number"},
            "verdict": {"type": "string"},
        },
        "required": ["candidate", "candidate_domain", "verdict"],
        "additionalProperties": True,
    },
    cyble_native=True,
    tags=[_NEEDS_TENANT, "phishing", "brand", "moat"],
)
async def phishing_brand_impersonation(
    *, tenant_id: str, candidate: str
) -> dict[str, Any]:
    """Score a sender or URL host against tenant brand + Cyble feed."""
    cand_dom = _domain_of(candidate)
    brand_cfg = _tenant_brand(tenant_id)
    tenant_doms = [d.lower() for d in brand_cfg.get("domains", [])]

    # 1. Legitimate? If the candidate matches a tenant-owned domain it's
    #    benign by definition. We still compute homoglyph distance against
    #    the canonical brand so the operator can see the alignment.
    if cand_dom and cand_dom in tenant_doms:
        return {
            "candidate": candidate,
            "candidate_domain": cand_dom,
            "matched_brand": cand_dom,
            "kind": "legitimate",
            "homoglyph_distance": 0,
            "registered_days_ago": -1,
            "known_kit": "",
            "in_cyble_feed": False,
            "is_legitimate": True,
            "confidence": 1.0,
            "verdict": "benign",
        }

    # 2. Cyble brand-intel feed hit?
    feed = _CYBLE_BRAND_INTEL.get(cand_dom)
    if feed:
        target = feed["target_brand"]
        distance = _homoglyph_distance(cand_dom, target)
        return {
            "candidate": candidate,
            "candidate_domain": cand_dom,
            "matched_brand": target,
            "kind": feed["kind"],
            "homoglyph_distance": distance,
            "registered_days_ago": feed["registered_days_ago"],
            "known_kit": feed.get("kit", ""),
            "in_cyble_feed": True,
            "is_legitimate": False,
            "confidence": float(feed["confidence"]),
            "verdict": "phishing",
        }

    # 3. Homoglyph proximity against tenant brand domains.
    best_brand = ""
    best_distance = 99
    for brand_dom in tenant_doms:
        d = _homoglyph_distance(cand_dom, brand_dom)
        if d < best_distance:
            best_distance = d
            best_brand = brand_dom

    if best_brand and 1 <= best_distance <= 2:
        # Visually close to a tenant brand — likely impersonation.
        return {
            "candidate": candidate,
            "candidate_domain": cand_dom,
            "matched_brand": best_brand,
            "kind": "homoglyph",
            "homoglyph_distance": best_distance,
            "registered_days_ago": -1,
            "known_kit": "",
            "in_cyble_feed": False,
            "is_legitimate": False,
            "confidence": 0.70,
            "verdict": "suspicious",
        }

    return {
        "candidate": candidate,
        "candidate_domain": cand_dom,
        "matched_brand": best_brand,
        "kind": "unrelated",
        "homoglyph_distance": best_distance,
        "registered_days_ago": -1,
        "known_kit": "",
        "in_cyble_feed": False,
        "is_legitimate": False,
        "confidence": 0.20,
        "verdict": "unknown",
    }


# Re-export for tests / orchestration helpers that want to seed the
# tenant brand registry or the Cyble feed deterministically.
def register_tenant_brand(
    tenant_id: str,
    *,
    domains: list[str],
    display_names: list[str] | None = None,
    brand_keywords: list[str] | None = None,
) -> None:
    """Register / overwrite a tenant brand profile (test + bootstrap helper)."""
    _TENANT_BRANDS[tenant_id] = {
        "display_names": display_names or [],
        "domains": [d.lower() for d in domains],
        "brand_keywords": brand_keywords or [],
    }


def register_cyble_brand_hit(
    domain: str,
    *,
    target_brand: str,
    kind: str,
    registered_days_ago: int,
    kit: str = "",
    confidence: float = 0.85,
) -> None:
    """Inject a synthetic Cyble brand-intel feed hit (test helper)."""
    _CYBLE_BRAND_INTEL[domain.lower()] = {
        "kind": kind,
        "target_brand": target_brand,
        "registered_days_ago": registered_days_ago,
        "kit": kit,
        "confidence": confidence,
    }


def register_url_chain(url: str, chain: list[str]) -> None:
    """Seed a URL chain for the unwrapper (test + bootstrap helper)."""
    _URL_CHAINS[url] = list(chain)


def register_detonation_report(host: str, report: dict[str, Any]) -> None:
    """Seed a detonation report keyed by terminal host (test helper)."""
    _DETONATION_REPORTS[host.lower()] = dict(report)


__all__ = [
    "phishing_deep_header_analysis",
    "phishing_unwrap_url_chain",
    "phishing_detonate_url",
    "phishing_brand_impersonation",
    "register_tenant_brand",
    "register_cyble_brand_hit",
    "register_url_chain",
    "register_detonation_report",
]
