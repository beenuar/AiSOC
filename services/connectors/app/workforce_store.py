"""Where the scheduler puts workforce and device context.

Depth plan wave 2, item 1.3. The record shapes live in `app/workforce.py`,
which deliberately carries no database dependency so a connector importing
them does not pull SQLAlchemy into its import graph. This half does the
writing and may.

**Upsert, never replace.** An import runs on a schedule against a source of
record that may be partial or briefly unavailable. Replacing a tenant's
context with whatever one run produced would delete a department because an
HR export timed out.

**Departure is recorded, not deleted.** A terminated employee whose
accounts still authenticate is the highest-signal row this table can hold,
and removing it on offboarding destroys exactly that signal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from app.workforce import (
    COMPLIANCE_STATES,
    WORKER_STATUSES,
    WORKER_TYPES,
    DeviceRecord,
    WorkforceRecord,
)

logger = logging.getLogger(__name__)

_UPSERT_WORKER = text(
    """
    INSERT INTO workforce_members (
        tenant_id, connector_type, external_id, email, display_name,
        status, start_date, end_date, manager_external_id, department,
        worker_type, title, last_synced_at
    ) VALUES (
        CAST(:tenant_id AS uuid), :connector_type, :external_id, :email, :display_name,
        :status, CAST(:start_date AS date), CAST(:end_date AS date),
        :manager_external_id, :department, :worker_type, :title, NOW()
    )
    ON CONFLICT (tenant_id, connector_type, external_id) DO UPDATE SET
        email = EXCLUDED.email,
        display_name = EXCLUDED.display_name,
        status = EXCLUDED.status,
        start_date = EXCLUDED.start_date,
        end_date = EXCLUDED.end_date,
        manager_external_id = EXCLUDED.manager_external_id,
        department = EXCLUDED.department,
        worker_type = EXCLUDED.worker_type,
        title = EXCLUDED.title,
        last_synced_at = NOW()
    """
)

_UPSERT_DEVICE = text(
    """
    INSERT INTO workforce_devices (
        tenant_id, connector_type, external_id, hostname, owner_email,
        owner_external_id, compliance_state, os_name, os_version,
        encrypted, edr_agent_health, serial_number, last_seen, last_synced_at
    ) VALUES (
        CAST(:tenant_id AS uuid), :connector_type, :external_id, :hostname, :owner_email,
        :owner_external_id, :compliance_state, :os_name, :os_version,
        :encrypted, :edr_agent_health, :serial_number,
        CAST(:last_seen AS timestamptz), NOW()
    )
    ON CONFLICT (tenant_id, connector_type, external_id) DO UPDATE SET
        hostname = EXCLUDED.hostname,
        owner_email = EXCLUDED.owner_email,
        owner_external_id = EXCLUDED.owner_external_id,
        compliance_state = EXCLUDED.compliance_state,
        os_name = EXCLUDED.os_name,
        os_version = EXCLUDED.os_version,
        encrypted = EXCLUDED.encrypted,
        edr_agent_health = EXCLUDED.edr_agent_health,
        serial_number = EXCLUDED.serial_number,
        last_seen = EXCLUDED.last_seen,
        last_synced_at = NOW()
    """
)


@dataclass
class SyncReport:
    """Per-record outcome, named.

    Modelled on `ImportReport` in `context_import.py` and for the same
    reason its docstring gives: "imported 900 of 1000" does not say whether
    the missing hundred are one malformed department or every contractor.
    """

    workers: int = 0
    devices: int = 0
    rejected: list[dict[str, str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.rejected is None:
            self.rejected = []

    def reject(self, kind: str, identifier: str, reason: str) -> None:
        self.rejected.append({"kind": kind, "id": identifier[:80], "reason": reason})


async def sync_workforce(
    engine: Any,
    *,
    tenant_id: Any,
    connector_type: str,
    workers: list[WorkforceRecord] | None = None,
    devices: list[DeviceRecord] | None = None,
) -> SyncReport:
    """Upsert workforce and device context for one tenant.

    Upsert and never replace, the same rule `context_import.py` states:
    an import runs on a schedule against a source that may be partial or
    briefly unavailable, and replacing a tenant's context with whatever one
    run produced would delete a department because an HR export timed out.

    A departure is recorded, not deleted. A terminated employee whose
    accounts still authenticate is the highest-signal row this table can
    hold, and removing it on offboarding destroys exactly that signal.
    """
    report = SyncReport()
    scoped_workers = workers or []
    scoped_devices = devices or []
    if not scoped_workers and not scoped_devices:
        return report

    async with engine.begin() as conn:
        for worker in scoped_workers:
            if not worker.external_id:
                report.reject("worker", "<missing>", "no external id")
                continue
            if worker.status not in WORKER_STATUSES:
                report.reject("worker", worker.external_id, f"status {worker.status!r} is not one of {WORKER_STATUSES}")
                continue
            if worker.worker_type not in WORKER_TYPES:
                report.reject("worker", worker.external_id, f"worker_type {worker.worker_type!r} is not one of {WORKER_TYPES}")
                continue
            await conn.execute(
                _UPSERT_WORKER,
                {
                    "tenant_id": str(tenant_id),
                    "connector_type": connector_type,
                    "external_id": worker.external_id,
                    "email": (worker.email or None),
                    "display_name": worker.display_name,
                    "status": worker.status,
                    "start_date": worker.start_date,
                    "end_date": worker.end_date,
                    "manager_external_id": worker.manager_external_id,
                    "department": worker.department,
                    "worker_type": worker.worker_type,
                    "title": worker.title,
                },
            )
            report.workers += 1

        for device in scoped_devices:
            if not device.external_id:
                report.reject("device", "<missing>", "no external id")
                continue
            if device.compliance_state not in COMPLIANCE_STATES:
                report.reject(
                    "device",
                    device.external_id,
                    f"compliance_state {device.compliance_state!r} is not one of {COMPLIANCE_STATES}",
                )
                continue
            await conn.execute(
                _UPSERT_DEVICE,
                {
                    "tenant_id": str(tenant_id),
                    "connector_type": connector_type,
                    "external_id": device.external_id,
                    "hostname": device.hostname,
                    "owner_email": (device.owner_email or None),
                    "owner_external_id": device.owner_external_id,
                    "compliance_state": device.compliance_state,
                    "os_name": device.os_name,
                    "os_version": device.os_version,
                    "encrypted": device.encrypted,
                    "edr_agent_health": device.edr_agent_health,
                    "serial_number": device.serial_number,
                    "last_seen": device.last_seen,
                },
            )
            report.devices += 1

    return report
