"""Workforce and device context: the record shapes.

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

No database dependency, on purpose
-----------------------------------
This module holds the shapes and nothing else; the store that writes them
is `app/workforce_store.py`. The split is not tidiness: the detection
replay worker imports the whole connector registry with a minimal
dependency set, so a `from sqlalchemy import text` reachable from a
connector's import graph takes the entire validation job down with
`ModuleNotFoundError: No module named 'sqlalchemy'`. A connector must not
pull a database driver in behind it.

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
