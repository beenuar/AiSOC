"""Scheduled refresh of the SIEM content inventory (WS1.2).

One tick: every tenant with an enabled content-capable SIEM connector gets
its inventory refreshed through `siem_content.sweep_tenant` — the same
decrypt-and-forward transport federated search uses, one SIEM's failure a
per-source verdict. The interval is deliberately hours, not minutes: an
inventory is a snapshot discipline, and the vendor APIs this reads are
admin surfaces with rate limits.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.connector import Connector
from app.services import siem_content
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.siem_content_sweep")


async def run_once() -> dict[str, int]:
    summary = {"tenants": 0, "sources_ok": 0, "sources_error": 0}
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Connector).where(
                Connector.enabled.is_(True),
                Connector.connector_type.in_(siem_content.CONTENT_SOURCES),
            )
        )
        by_tenant: dict[str, list[Connector]] = {}
        for connector in result.scalars().all():
            by_tenant.setdefault(str(connector.tenant_id), []).append(connector)
        summary["tenants"] = len(by_tenant)
        for tenant_id, connectors in by_tenant.items():
            try:
                report = await siem_content.sweep_tenant(db, tenant_id=connectors[0].tenant_id, connectors=connectors)
                for source in report["sources"]:
                    if source.get("status") == "ok":
                        summary["sources_ok"] += 1
                    else:
                        summary["sources_error"] += 1
            except Exception as exc:  # noqa: BLE001 — one tenant must not stop the fleet
                summary["sources_error"] += 1
                logger.warning("siem_content_sweep.tenant_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
        await db.commit()
    if summary["tenants"]:
        logger.info("siem_content_sweep %s", summary)
    return summary


async def run_forever() -> None:
    interval = max(int(getattr(settings, "SIEM_CONTENT_SWEEP_INTERVAL_SECONDS", 21600)), 3600)
    logger.info("siem_content_sweep started interval=%ds", interval)
    failures = TickFailures("siem_content_sweep", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover — defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("siem_content_sweep stopped")
        raise
