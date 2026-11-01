"""Workforce and device context: the shapes, and where the scheduler puts them.

Depth plan wave 2, item 1.3.

Why this is a store and not an event stream
-------------------------------------------
An employee's last day and a laptop's compliance state are not events. They
are current facts that change slowly and are read at triage time, which is
the opposite of the alert pipeline's shape. Pushing them through ingest
would make "is this person leaving" a question answered by searching the
lake for the most recent HR event, which is both slower and wrong whenever
the last poll failed.

Why a Postgres table and not only the graph
--------------------------------------------
`services/api/app/services/context_import.py` already imports exactly this
context, and writes it to Neo4j. Neo4j is in the `full` profile. A CORE
install -- the one `make up` gives you -- has no graph, so on CORE the HR
dimension would not exist at all and every detection and triage input that
reads it would be silently dead. ADR 0010 put the entity store in CORE for
this reason; this is the same decision applied to the same data.

Both paths stay. The graph import is richer (it links employees to
identities and applications through relationships), the table is the one
that is always there, and the scheduler writes the table because the
connectors service has a Postgres engine and no Neo4j driver.

Personal data minimisation
--------------------------
Only the fields item 1.3 lists are stored: employment status, start date,
termination or last-day date, manager, department and worker type for a
person; owner, compliance state, OS version, encryption and EDR agent
health for a device. No compensation, no personal contact details, no date
of birth, no national identifier -- several of which the vendor APIs return
and this module drops on the floor rather than persisting. Rows are
tenant-scoped under RLS and are covered by the tenant-erasure path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)

#: Employment status, normalised. `unknown` is a real member and is what an
#: unrecognised vendor value becomes: deciding somebody still works here on
#: a value we do not recognise is the wrong direction to be wrong in.
WORKER_STATUSES = ("active", "leave", "terminated", "pending", "unknown")

#: Worker type. The distinction 1.3 asks for is employee versus contractor,
#: and a source that does not say stays `unknown` rather than defaulting to
#: employee -- a contractor misread as staff loses exactly the signal the
#: field exists for.
WORKER_TYPES = ("employee", "contractor", "unknown")

#: Device compliance, normalised across vendors. `unknown` covers both "the
#: MDM has not evaluated this device" and "the vendor reported a state we do
#: not recognise", and must never render as compliant.
COMPLIANCE_STATES = ("compliant", "noncompliant", "in_grace_period", "not_enrolled", "unknown")


@dataclass(frozen=True)
class WorkforceRecord:
    """One person, as an HR system reports them.

    Dates are kept as the vendor's own ISO-8601 date strings rather than
    parsed: a termination date is a calendar date in a jurisdiction, not an
    instant, and parsing it into a UTC datetime here would move somebody's
    last day by a day for half the world.
    """

    external_id: str
    email: str | None = None
    display_name: str | None = None
    status: str = "unknown"
    start_date: str | None = None
    end_date: str | None = None
    manager_external_id: str | None = None
    department: str | None = None
    worker_type: str = "unknown"
    title: str | None = None


@dataclass(frozen=True)
class DeviceRecord:
    """One managed device, as an MDM reports it.

    `encrypted` is a tri-state on purpose. `False` means the MDM evaluated
    the device and found no encryption, which is a finding; `None` means
    nobody said, which is not. Collapsing them would put every
    unenrolled-but-known device into the finding.
    """

    external_id: str
    hostname: str | None = None
    owner_email: str | None = None
    owner_external_id: str | None = None
    compliance_state: str = "unknown"
    os_name: str | None = None
    os_version: str | None = None
    encrypted: bool | None = None
    edr_agent_health: str | None = None
    serial_number: str | None = None
    last_seen: str | None = None


def normalise_status(raw: Any, mapping: dict[str, str]) -> str:
    """Map a vendor status onto the closed set, or `unknown`."""
    if not isinstance(raw, str):
        return "unknown"
    return mapping.get(raw.strip().lower(), "unknown")


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
