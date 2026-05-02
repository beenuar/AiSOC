"""
Tool: IOC enrichment via the enrichment microservice.
"""
import httpx
import structlog

logger = structlog.get_logger()

_ENRICHMENT_URL = "http://enrichment:8082"


async def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
    """Call the enrichment service to get threat intel for an IOC."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{_ENRICHMENT_URL}/enrich",
                json={"value": ioc_value, "ioc_type": ioc_type},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("IOC enrichment failed", ioc=ioc_value, error=str(exc))
        return {"error": str(exc), "value": ioc_value, "ioc_type": ioc_type}


async def bulk_enrich_iocs(items: list[dict]) -> list[dict]:
    """Bulk enrich up to 100 IOCs."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{_ENRICHMENT_URL}/enrich/bulk",
                json={"items": items},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("results", [])
    except Exception as exc:
        logger.warning("Bulk IOC enrichment failed", error=str(exc))
        return []
