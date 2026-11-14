"""
Tool: IOC enrichment via the enrichment microservice.

The enrichment service authenticates its callers (GHSA-qf6m-hgwv-65f9): a
service call presents the shared service token and declares the tenant it
acts for on ``X-AiSOC-Tenant-ID``. Callers here thread the investigation's
own tenant through — it is never an LLM-visible argument.
"""

import os

import httpx
import structlog

logger = structlog.get_logger()

_ENRICHMENT_URL = os.getenv("ENRICHMENT_SERVICE_URL", "http://enrichment:8082")


def service_headers(tenant_id: str = "") -> dict[str, str]:
    """Headers for a service-to-service call to the enrichment service.

    Client-side mirror of the server's token resolution (per-service override
    first, then the platform token) — the same pattern as the API's DLQ
    gateway uses toward fusion. With no token configured the headers are
    empty and the server refuses; the callers here are best-effort and
    surface that as a logged failure rather than a crash.
    """
    headers: dict[str, str] = {}
    token = (os.getenv("AISOC_ENRICHMENT_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tenant_id.strip():
        headers["X-AiSOC-Tenant-ID"] = tenant_id.strip()
    return headers


async def enrich_ioc(ioc_value: str, ioc_type: str, *, tenant_id: str = "") -> dict:
    """Call the enrichment service to get threat intel for an IOC."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{_ENRICHMENT_URL}/enrich",
                json={"value": ioc_value, "ioc_type": ioc_type, "tenant_id": tenant_id},
                headers=service_headers(tenant_id),
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("IOC enrichment failed", ioc=ioc_value, error=str(exc))
        return {"error": str(exc), "value": ioc_value, "ioc_type": ioc_type}


async def bulk_enrich_iocs(items: list[dict], *, tenant_id: str = "") -> list[dict]:
    """Bulk enrich up to 100 IOCs for one tenant."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{_ENRICHMENT_URL}/enrich/bulk",
                json={"items": items},
                headers=service_headers(tenant_id),
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("results", [])
    except Exception as exc:
        logger.warning("Bulk IOC enrichment failed", error=str(exc))
        return []
