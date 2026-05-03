"""
Tool wrappers used by every investigator agent.
Each tool is a plain async callable that can be registered with LangChain/LangGraph
tool-calling or invoked directly.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_ENRICHMENT_URL = os.getenv("ENRICHMENT_SERVICE_URL", "http://enrichment:8080")
_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Enrichment tool
# ---------------------------------------------------------------------------

async def enrich_ioc(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    """
    Call the AiSOC enrichment micro-service for a single IOC.
    Returns the enrichment result or an error dict.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_ENRICHMENT_URL}/enrich",
                json={"value": ioc_value, "type": ioc_type},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrich_ioc failed", ioc=ioc_value, error=str(exc))
        return {"error": str(exc), "ioc": ioc_value}


# ---------------------------------------------------------------------------
# Case / alert lookup
# ---------------------------------------------------------------------------

async def fetch_case(case_id: str, api_token: str = "") -> dict[str, Any]:
    """Fetch full case details from the AiSOC API."""
    headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_API_URL}/api/v1/cases/{case_id}", headers=headers)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("fetch_case failed", case_id=case_id, error=str(exc))
        return {"error": str(exc)}


async def fetch_related_alerts(
    case_id: str,
    limit: int = 20,
    api_token: str = "",
) -> list[dict[str, Any]]:
    """Fetch alerts related to a case."""
    headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/cases/{case_id}/alerts",
                params={"limit": limit},
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json().get("alerts", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("fetch_related_alerts failed", case_id=case_id, error=str(exc))
        return []


# ---------------------------------------------------------------------------
# MITRE ATT&CK lookup (local data, no network)
# ---------------------------------------------------------------------------

_MITRE_KEYWORDS: dict[str, str] = {
    "phishing": "T1566",
    "lateral movement": "T1021",
    "credential dumping": "T1003",
    "c2": "T1071",
    "exfiltration": "T1041",
    "ransomware": "T1486",
    "privilege escalation": "T1068",
    "persistence": "T1547",
    "reconnaissance": "T1592",
    "discovery": "T1083",
    "execution": "T1059",
    "defence evasion": "T1027",
    "collection": "T1119",
    "impact": "T1485",
}


def map_to_mitre(text: str) -> list[str]:
    """Heuristic keyword-to-technique mapper (extend with ATT&CK dataset)."""
    hits: list[str] = []
    lower = text.lower()
    for keyword, technique_id in _MITRE_KEYWORDS.items():
        if keyword in lower and technique_id not in hits:
            hits.append(technique_id)
    return hits


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def sha256_of(obj: Any) -> str:
    serialised = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def extract_iocs(text: str) -> list[dict[str, str]]:
    """
    Naive regex-free IOC extractor (replace with proper library such as
    iocextract in production). Returns list of {type, value} dicts.
    """
    import re

    iocs: list[dict[str, str]] = []

    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    sha256_pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")

    for m in sha256_pattern.finditer(text):
        iocs.append({"type": "hash", "value": m.group()})
    for m in url_pattern.finditer(text):
        iocs.append({"type": "url", "value": m.group()})
    for m in ip_pattern.finditer(text):
        iocs.append({"type": "ip", "value": m.group()})
    for m in domain_pattern.finditer(text):
        val = m.group()
        if "." in val and not any(d["value"] == val for d in iocs):
            iocs.append({"type": "domain", "value": val})

    return iocs
