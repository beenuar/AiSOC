"""Cyble-native CTI tools — the moat from the plan.

Dark-web mention checks, brand intel, ASM, vuln intel.
These are flagged cyble_native=True so the UI can highlight them.
"""
from __future__ import annotations

from typing import Any

from app.tools.registry import RiskClass, tool

# Mock IOC enrichment database (in real life this hits Cyble's CTI APIs).
#
# Several entries are intentionally attributed to named actors so the
# Threat Actor Profiling Agent (t3e-actor-profiling) has a real signal
# to materialise into ThreatActor / ActorIOCLink rows. Anything without
# an ``actor`` field is an orphan IOC the profiler will skip.
_IOC_DB: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "type": "ip",
        "threat_score": 92,
        "tags": ["tor_exit_node", "c2_infrastructure", "fin7_associated"],
        "first_seen": "2024-08-12",
        "actor": "FIN7",
        "campaigns": ["Carbanak Q3"],
        "darkweb_mentions": 14,
    },
    "evil-update.duckdns.org": {
        "type": "domain",
        "threat_score": 88,
        "tags": ["typosquat", "phishing", "credential_harvester"],
        "registered": "2026-04-18",
        "darkweb_mentions": 3,
    },
    "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f": {
        "type": "sha256",
        "threat_score": 96,
        "malware_family": "Cobalt Strike Beacon",
        "first_seen": "2025-11-04",
        "yara_hits": ["cobaltstrike_x64", "shellcode_loader"],
        "actor": "FIN7",
        "campaigns": ["Carbanak Q3"],
    },
    # APT29 (Cozy Bear, Nobelium) — espionage cluster.
    "104.21.55.211": {
        "type": "ip",
        "threat_score": 90,
        "tags": ["c2_infrastructure", "cloud_proxy"],
        "first_seen": "2024-03-04",
        "actor": "APT29",
        "campaigns": ["MidnightBlizzard 2024"],
        "darkweb_mentions": 5,
    },
    "msftauth-update.com": {
        "type": "domain",
        "threat_score": 87,
        "tags": ["spear_phishing", "credential_harvester", "m365_lure"],
        "registered": "2024-01-22",
        "actor": "APT29",
        "campaigns": ["MidnightBlizzard 2024"],
        "darkweb_mentions": 2,
    },
    # Lazarus — DPRK financial / supply-chain crew.
    "45.61.184.77": {
        "type": "ip",
        "threat_score": 94,
        "tags": ["c2_infrastructure", "north_korea"],
        "first_seen": "2025-06-09",
        "actor": "Lazarus",
        "campaigns": ["AppleJeus Refresh"],
        "darkweb_mentions": 9,
    },
    "trader-secure-app.io": {
        "type": "domain",
        "threat_score": 91,
        "tags": ["fake_app", "crypto_theft"],
        "registered": "2025-05-14",
        "actor": "Lazarus",
        "campaigns": ["AppleJeus Refresh"],
        "darkweb_mentions": 4,
    },
    # CL0P — ransomware crew that abuses managed-file-transfer 0-days.
    "ttps-clop.onion": {
        "type": "domain",
        "threat_score": 95,
        "tags": ["leak_site", "ransomware"],
        "first_seen": "2023-06-01",
        "actor": "CL0P",
        "campaigns": ["MOVEit 2023", "GoAnywhere 2023"],
        "darkweb_mentions": 28,
    },
}


@tool(
    name="cti.enrich_ioc",
    integration="cyble-cti",
    risk=RiskClass.READ,
    description="Enrich an IOC with Cyble threat intelligence: actor, campaign, dark-web mentions.",
    params={
        "type": "object",
        "properties": {"ioc": {"type": "string"}, "ioc_type": {"type": "string"}},
        "required": ["ioc"],
    },
    result={
        "type": "object",
        "properties": {
            "ioc": {"type": "string"},
            "found": {"type": "boolean"},
            "threat_score": {"type": "integer"},
            "type": {"type": "string"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "actor": {"type": "string"},
            "campaigns": {"type": "array", "items": {"type": "string"}},
            "darkweb_mentions": {"type": "integer"},
            "first_seen": {"type": "string"},
            "malware_family": {"type": "string"},
            "yara_hits": {"type": "array", "items": {"type": "string"}},
            "registered": {"type": "string"},
        },
        "required": ["ioc", "found"],
    },
    cyble_native=True,
    tags=["enrichment", "moat"],
)
async def cti_enrich_ioc(ioc: str, ioc_type: str = "auto") -> dict[str, Any]:
    record = _IOC_DB.get(ioc)
    if record:
        return {"ioc": ioc, "found": True, **record}
    return {"ioc": ioc, "found": False, "threat_score": 0}


@tool(
    name="cti.darkweb_search",
    integration="cyble-darkweb",
    risk=RiskClass.READ,
    description="Search Cyble's dark-web crawl index for mentions of an entity (domain, email, brand).",
    params={
        "type": "object",
        "properties": {"query": {"type": "string"}, "days": {"type": "integer", "default": 30}},
        "required": ["query"],
    },
    cyble_native=True,
    tags=["moat"],
)
async def cti_darkweb_search(query: str, days: int = 30) -> dict[str, Any]:
    return {
        "query": query,
        "days": days,
        "hits": [
            {
                "forum": "exploit.in",
                "ts": "2026-04-26T03:14:00Z",
                "snippet": f"Selling fresh access to *{query}* corporate VPN — $4,500 BTC",
                "actor_handle": "ghostvendor",
                "confidence": "high",
            },
            {
                "forum": "telegram:leakroom",
                "ts": "2026-04-22T19:08:00Z",
                "snippet": f"Database leak referencing {query} employee credentials, 1.2k rows",
                "confidence": "medium",
            },
        ],
    }


@tool(
    name="cti.brand_intel",
    integration="cyble-brand",
    risk=RiskClass.READ,
    description="Brand intelligence: typosquats, phishing kits, fake apps, executive impersonation.",
    params={
        "type": "object",
        "properties": {"brand": {"type": "string"}},
        "required": ["brand"],
    },
    cyble_native=True,
    tags=["moat"],
)
async def cti_brand_intel(brand: str) -> dict[str, Any]:
    return {
        "brand": brand,
        "active_typosquats": 7,
        "phishing_kits_observed": 2,
        "examples": [
            f"{brand}-secure.com",
            f"{brand}-portal.duckdns.org",
        ],
    }


@tool(
    name="cti.asm_lookup",
    integration="cyble-asm",
    risk=RiskClass.READ,
    description="Attack-surface management: external assets, exposed services, certs for a domain.",
    params={
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"],
    },
    cyble_native=True,
    tags=["moat"],
)
async def cti_asm_lookup(domain: str) -> dict[str, Any]:
    return {
        "domain": domain,
        "external_assets": 412,
        "high_risk_findings": [
            {"asset": f"vpn.{domain}", "issue": "Pulse Secure VPN — known CVE-2024-21887 exposed", "severity": "critical"},
            {"asset": f"api-staging.{domain}", "issue": "Swagger UI exposed without auth", "severity": "high"},
        ],
    }


# Canonical actor profile catalogue. The Threat Actor Profiling agent
# fuses these "vendor facts" with whatever it observes in IOCs that
# carry an ``actor`` field, so the per-tenant profile is always a
# superset of the global catalogue.
_ACTOR_CATALOGUE: dict[str, dict[str, Any]] = {
    "FIN7": {
        "aliases": ["Carbanak", "Carbon Spider"],
        "description": (
            "Financially motivated cybercrime crew active since ~2013; "
            "long history of POS-malware and ransomware affiliations "
            "(including Darkside and BlackMatter)."
        ),
        "motivation": "financial",
        "sophistication": "advanced",
        "origin_country": "RU",
        "target_sectors": ["retail", "hospitality", "financial_services"],
        "target_regions": ["US", "EU"],
        "techniques": ["T1566.001", "T1059.001", "T1055", "T1486"],
        "tools": ["Carbanak", "Griffon", "POWERPLANT", "Cobalt Strike"],
        "campaigns": ["Carbanak Q3", "BadUSB drops"],
        "references": [
            "https://attack.mitre.org/groups/G0046/",
            "https://www.mandiant.com/resources/blog/fin7-carbanak-cycle",
        ],
        "first_observed": "2013-06-01",
        "confidence": 0.92,
    },
    "APT29": {
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"],
        "description": (
            "Russian state-sponsored espionage cluster attributed to the "
            "SVR. Heavy focus on M365 / cloud identity, supply chain, and "
            "long-dwell intelligence collection."
        ),
        "motivation": "espionage",
        "sophistication": "advanced",
        "origin_country": "RU",
        "target_sectors": [
            "government",
            "diplomatic",
            "technology",
            "thinktanks",
        ],
        "target_regions": ["US", "EU", "UK"],
        "techniques": ["T1078.004", "T1606", "T1199", "T1098.005"],
        "tools": ["WellMess", "WellMail", "FoggyWeb", "MagicWeb"],
        "campaigns": ["SolarWinds 2020", "MidnightBlizzard 2024"],
        "references": [
            "https://attack.mitre.org/groups/G0016/",
            "https://www.microsoft.com/security/blog/midnight-blizzard/",
        ],
        "first_observed": "2008-01-01",
        "confidence": 0.95,
    },
    "Lazarus": {
        "aliases": ["Hidden Cobra", "ZINC", "Diamond Sleet"],
        "description": (
            "DPRK state-sponsored crew with both espionage and financial "
            "lines (cryptocurrency theft, SWIFT fraud)."
        ),
        "motivation": "financial",
        "sophistication": "advanced",
        "origin_country": "KP",
        "target_sectors": [
            "financial_services",
            "cryptocurrency",
            "defense",
            "technology",
        ],
        "target_regions": ["US", "EU", "APAC"],
        "techniques": ["T1566.002", "T1027", "T1059.007", "T1055.012"],
        "tools": ["AppleJeus", "BLINDINGCAN", "ELECTRICFISH"],
        "campaigns": ["AppleJeus Refresh", "Operation Dream Job"],
        "references": [
            "https://attack.mitre.org/groups/G0032/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a",
        ],
        "first_observed": "2009-01-01",
        "confidence": 0.93,
    },
    "CL0P": {
        "aliases": ["Cl0p", "TA505 affiliate"],
        "description": (
            "Ransomware-as-a-service operator specialising in mass "
            "exploitation of managed-file-transfer 0-days (MOVEit, "
            "GoAnywhere, Accellion FTA) followed by leak-site extortion."
        ),
        "motivation": "financial",
        "sophistication": "intermediate",
        "origin_country": "RU",
        "target_sectors": ["healthcare", "financial_services", "manufacturing"],
        "target_regions": ["US", "EU"],
        "techniques": ["T1190", "T1486", "T1567.002"],
        "tools": ["Cl0p ransomware", "FlawedAmmyy", "TrueBot"],
        "campaigns": ["MOVEit 2023", "GoAnywhere 2023", "Accellion 2021"],
        "references": [
            "https://attack.mitre.org/groups/G0092/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
        ],
        "first_observed": "2019-02-01",
        "confidence": 0.9,
    },
}


@tool(
    name="cti.actor_lookup",
    integration="cyble-cti",
    risk=RiskClass.READ,
    description=(
        "Look up a canonical threat-actor profile by handle (e.g. 'FIN7', "
        "'APT29') and return aliases, motivation, sophistication, origin, "
        "target sectors/regions, MITRE techniques, tooling, campaigns, and "
        "reference URLs from Cyble's actor catalogue."
    ),
    params={
        "type": "object",
        "properties": {"actor": {"type": "string"}},
        "required": ["actor"],
    },
    result={
        "type": "object",
        "properties": {
            "actor": {"type": "string"},
            "found": {"type": "boolean"},
            "aliases": {"type": "array", "items": {"type": "string"}},
            "description": {"type": "string"},
            "motivation": {"type": "string"},
            "sophistication": {"type": "string"},
            "origin_country": {"type": "string"},
            "target_sectors": {"type": "array", "items": {"type": "string"}},
            "target_regions": {"type": "array", "items": {"type": "string"}},
            "techniques": {"type": "array", "items": {"type": "string"}},
            "tools": {"type": "array", "items": {"type": "string"}},
            "campaigns": {"type": "array", "items": {"type": "string"}},
            "references": {"type": "array", "items": {"type": "string"}},
            "first_observed": {"type": "string"},
            "confidence": {"type": "number"},
        },
        "required": ["actor", "found"],
    },
    cyble_native=True,
    tags=["enrichment", "moat", "actor"],
)
async def cti_actor_lookup(actor: str) -> dict[str, Any]:
    """Resolve a threat-actor handle (case-insensitive on alias match)."""
    handle = (actor or "").strip()
    if not handle:
        return {"actor": actor, "found": False}
    record = _ACTOR_CATALOGUE.get(handle)
    if record is None:
        # Best-effort alias resolution so analysts pivoting on
        # "Cozy Bear" or "Nobelium" still hit the APT29 record.
        lc = handle.lower()
        for canonical, profile in _ACTOR_CATALOGUE.items():
            if canonical.lower() == lc:
                record = profile
                handle = canonical
                break
            if any(a.lower() == lc for a in profile.get("aliases", []) or []):
                record = profile
                handle = canonical
                break
    if record is None:
        return {"actor": actor, "found": False}
    return {"actor": handle, "found": True, **record}


@tool(
    name="cti.vuln_intel",
    integration="cyble-vuln",
    risk=RiskClass.READ,
    description="Vulnerability intelligence: CVE exploitation status, ITW evidence, patch priority.",
    params={
        "type": "object",
        "properties": {"cve": {"type": "string"}},
        "required": ["cve"],
    },
    cyble_native=True,
    tags=["moat"],
)
async def cti_vuln_intel(cve: str) -> dict[str, Any]:
    return {
        "cve": cve,
        "exploited_in_wild": True,
        "first_itw": "2024-02-14",
        "exploit_kits": ["Metasploit", "PoC on Github"],
        "ransomware_use": ["CL0P", "Akira"],
        "patch_priority": "P0",
    }
