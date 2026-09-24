"""Reconcile an AiSOC alert with the vendor finding that produced it.

Ingest knows the vendor's identifier for a finding — the normalizer maps
``external_id`` onto OCSF ``finding.uid`` — and until migration 057 nothing
downstream kept it, so by the time a row reached ``alerts`` there was no way
to answer "which Splunk notable was this?" and therefore no way to write a
verdict back to it.

This module is the read/write path for that link. Every query filters by
``tenant_id`` in the ``WHERE`` clause. Row-level security is enabled on the
table as well, but the query-layer filter is the control being relied on here
— RLS depends on the session GUC being set, and a code path that forgets it
would read across tenants with the policy still enabled.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

#: Live-actions vendor ids this platform can write a disposition back to.
#: A link row naming anything else is stored (the connector may legitimately
#: know an id AiSOC cannot act on) but never dispatched.
WRITEBACK_VENDORS: frozenset[str] = frozenset({"splunk", "elastic", "sentinel", "qradar", "defender"})

#: connector_type -> live-actions vendor id. Mirrors the actions service's own
#: alias map; kept here because the API resolves the vendor before it ever
#: talks to the actions service.
CONNECTOR_TYPE_TO_VENDOR: dict[str, str] = {
    "splunk": "splunk",
    "splunk_enterprise": "splunk",
    "elastic": "elastic",
    "elasticsearch": "elastic",
    "elastic_security": "elastic",
    "microsoft_sentinel": "sentinel",
    "azure_sentinel": "sentinel",
    "sentinel": "sentinel",
    "qradar": "qradar",
    "ibm_qradar": "qradar",
    "defender": "defender",
    "microsoft_defender": "defender",
    "azure_defender": "defender",
}


def vendor_for_connector_type(connector_type: str | None) -> str | None:
    """Map a connector type onto the vendor id the dispatcher routes on."""
    if not connector_type:
        return None
    return CONNECTOR_TYPE_TO_VENDOR.get(connector_type.strip().lower())


@dataclass(frozen=True)
class AlertSourceLink:
    """One (alert, vendor, finding) link and its last writeback attempt."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    alert_id: uuid.UUID
    vendor: str
    external_id: str
    connector_instance_id: uuid.UUID | None = None
    external_url: str | None = None
    last_disposition: str | None = None
    last_writeback_action: str | None = None
    last_writeback_status: str | None = None
    last_writeback_detail: str | None = None
    executed: bool = False

    @property
    def dispatchable(self) -> bool:
        return self.vendor in WRITEBACK_VENDORS and bool(self.external_id)


def _row_to_link(row: Any) -> AlertSourceLink:
    return AlertSourceLink(
        id=row.id,
        tenant_id=row.tenant_id,
        alert_id=row.alert_id,
        vendor=row.vendor,
        external_id=row.external_id,
        connector_instance_id=row.connector_instance_id,
        external_url=row.external_url,
        last_disposition=row.last_disposition,
        last_writeback_action=row.last_writeback_action,
        last_writeback_status=row.last_writeback_status,
        last_writeback_detail=row.last_writeback_detail,
        executed=bool(row.executed),
    )


_SELECT = """
    SELECT id, tenant_id, alert_id, vendor, external_id, connector_instance_id,
           external_url, last_disposition, last_writeback_action,
           last_writeback_status, last_writeback_detail, executed
      FROM alert_source_links
"""


async def links_for_alert(db: AsyncSession, *, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> list[AlertSourceLink]:
    """Every source finding linked to one alert, scoped to the tenant."""
    result = await db.execute(
        text(f"{_SELECT} WHERE tenant_id = :tenant_id AND alert_id = :alert_id ORDER BY created_at"),
        {"tenant_id": str(tenant_id), "alert_id": str(alert_id)},
    )
    return [_row_to_link(row) for row in result.fetchall()]


async def link_for_external_id(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    vendor: str,
    external_id: str,
) -> AlertSourceLink | None:
    """The reverse lookup: which alert did this vendor finding produce?"""
    result = await db.execute(
        text(f"{_SELECT} WHERE tenant_id = :tenant_id AND vendor = :vendor AND external_id = :external_id LIMIT 1"),
        {"tenant_id": str(tenant_id), "vendor": vendor, "external_id": external_id},
    )
    row = result.fetchone()
    return _row_to_link(row) if row else None


async def upsert_link(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    vendor: str,
    external_id: str,
    connector_instance_id: uuid.UUID | None = None,
    external_url: str | None = None,
) -> AlertSourceLink | None:
    """Record that ``alert_id`` came from ``external_id`` in ``vendor``.

    Idempotent on ``(alert_id, vendor, external_id)``. Returns ``None`` rather
    than raising if the write fails: losing a link costs a writeback, while
    failing the caller would cost the alert.
    """
    if not external_id.strip():
        return None
    try:
        result = await db.execute(
            text(
                """
                INSERT INTO alert_source_links (
                    tenant_id, alert_id, vendor, external_id,
                    connector_instance_id, external_url, executed
                ) VALUES (
                    :tenant_id, :alert_id, :vendor, :external_id,
                    :connector_instance_id, :external_url, FALSE
                )
                ON CONFLICT (alert_id, vendor, external_id) DO UPDATE SET
                    connector_instance_id = COALESCE(EXCLUDED.connector_instance_id,
                                                     alert_source_links.connector_instance_id),
                    external_url          = COALESCE(EXCLUDED.external_url, alert_source_links.external_url),
                    updated_at            = NOW()
                RETURNING id, tenant_id, alert_id, vendor, external_id, connector_instance_id,
                          external_url, last_disposition, last_writeback_action,
                          last_writeback_status, last_writeback_detail, executed
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "alert_id": str(alert_id),
                "vendor": vendor,
                "external_id": external_id.strip(),
                "connector_instance_id": str(connector_instance_id) if connector_instance_id else None,
                "external_url": external_url,
            },
        )
        row = result.fetchone()
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — a missing link must not fail the alert
        await db.rollback()
        logger.warning(
            "alert_source_link.upsert_failed",
            alert_id=str(alert_id),
            vendor=vendor,
            error=str(exc).replace("\r", "").replace("\n", " ")[:300],
        )
        return None
    return _row_to_link(row) if row else None


async def record_writeback(
    db: AsyncSession,
    *,
    link_id: uuid.UUID,
    tenant_id: uuid.UUID,
    disposition: str,
    writeback_action: str,
    status: str,
    executed: bool,
    detail: str = "",
) -> None:
    """Persist the outcome of one writeback attempt.

    ``executed`` is the field that carries the honesty requirement: a dry run
    and a live call write the same row apart from this flag, so it is passed
    explicitly by the caller rather than inferred from the status. A refusal
    and a simulation both record ``executed=False`` with the reason in
    ``detail``, so nothing downstream can read either as a vendor write that
    happened.
    """
    try:
        await db.execute(
            text(
                """
                UPDATE alert_source_links
                   SET last_disposition      = :disposition,
                       last_writeback_action = :writeback_action,
                       last_writeback_status = :status,
                       last_writeback_detail = :detail,
                       last_writeback_at     = NOW(),
                       executed              = :executed,
                       updated_at            = NOW()
                 WHERE id = :link_id AND tenant_id = :tenant_id
                """
            ),
            {
                "link_id": str(link_id),
                "tenant_id": str(tenant_id),
                "disposition": disposition,
                "writeback_action": writeback_action,
                "status": status,
                "detail": detail[:2000],
                "executed": executed,
            },
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — audit write must not fail the action
        await db.rollback()
        logger.warning(
            "alert_source_link.record_failed",
            link_id=str(link_id),
            error=str(exc).replace("\r", "").replace("\n", " ")[:300],
        )
