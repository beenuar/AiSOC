"""HR and device context from the CORE entity store.

Depth plan wave 2, item 1.3.

`incident_context.get_identity_context_for_accounts` answers the same
question from Neo4j. Neo4j is a `full`-profile service, so on a CORE
install -- the one `make up` gives you -- it answers nothing, and every
triage input reading HR context is silently dead there.

This is the CORE half: the same question against `workforce_members` and
`workforce_devices`, which migration 131 puts in Postgres. The route merges
the two, graph rows first, because the graph import carries relationships
this table does not (an employee linked to an application they own) and the
connector sync carries freshness the graph import does not.

Why the join is on the email address
-------------------------------------
An HR system knows a work email; an authentication event names an account.
They are the same string often enough to be useful and not always, which is
why this returns `match: "email"` on every row it produces. A caller that
cannot see how a link was made will treat a coincidence as an identity, and
Phase 3.1 is the item that will do this properly with confidence and
evidence. Until then the link is stated rather than implied.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text

logger = logging.getLogger("aisoc.workforce_context")

#: Bounded for the same reason the graph query is: this reaches a prompt,
#: and the prompt budget is shared with the evidence.
MAX_ROWS = 25

_BY_ACCOUNT = text(
    """
    SELECT m.external_id,
           m.email,
           m.display_name,
           m.status,
           m.start_date,
           m.end_date,
           m.department,
           m.worker_type,
           m.title,
           m.manager_external_id,
           m.connector_type,
           m.last_synced_at,
           mgr.display_name AS manager_display_name,
           mgr.email        AS manager_email
      FROM workforce_members m
      LEFT JOIN workforce_members mgr
             ON mgr.tenant_id = m.tenant_id
            AND mgr.connector_type = m.connector_type
            AND mgr.external_id = m.manager_external_id
     WHERE m.tenant_id = CAST(:tenant_id AS uuid)
       AND lower(m.email) = ANY(CAST(:accounts AS text[]))
     ORDER BY m.last_synced_at DESC
     LIMIT :limit
    """
)

_DEVICES_FOR_OWNERS = text(
    """
    SELECT owner_email,
           hostname,
           compliance_state,
           os_name,
           os_version,
           encrypted,
           edr_agent_health,
           connector_type,
           last_seen
      FROM workforce_devices
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND lower(owner_email) = ANY(CAST(:accounts AS text[]))
     ORDER BY last_seen DESC NULLS LAST
     LIMIT :limit
    """
)


async def get_workforce_context_for_accounts(
    session: Any,
    tenant_id: str,
    accounts: list[str],
    *,
    limit: int = MAX_ROWS,
) -> list[dict[str, Any]]:
    """Rows in the same shape the graph reader produces, plus device state.

    Fail-soft, like every other context read on the triage path: an
    investigation without HR context is degraded, and one that dies because
    a table was unreadable is worse than the gap it was closing.
    """
    normalised = sorted({a.strip().lower() for a in accounts if isinstance(a, str) and a.strip()})
    if not normalised:
        return []

    try:
        result = await session.execute(
            _BY_ACCOUNT,
            {"tenant_id": tenant_id, "accounts": normalised, "limit": max(1, limit)},
        )
        members = [dict(row) for row in result.mappings()]

        device_result = await session.execute(
            _DEVICES_FOR_OWNERS,
            {"tenant_id": tenant_id, "accounts": normalised, "limit": max(1, limit)},
        )
        devices = [dict(row) for row in device_result.mappings()]
    except Exception as exc:  # noqa: BLE001 - workforce context is advisory
        logger.warning(
            "workforce_context.unavailable error=%s",
            str(exc).replace("\r", "").replace("\n", " ")[:300],
        )
        return []

    by_owner: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        owner = str(device.get("owner_email") or "").lower()
        if owner:
            by_owner.setdefault(owner, []).append(device)

    rows: list[dict[str, Any]] = []
    for member in members:
        email = str(member.get("email") or "").lower()
        rows.append(
            {
                "account": email,
                "provider": member.get("connector_type"),
                "employee": member.get("display_name"),
                "title": member.get("title"),
                # The graph reader's field is a boolean, so the same key is
                # produced here rather than a second vocabulary the prompt
                # renderer would have to learn.
                "is_active": member.get("status") == "active",
                "status": member.get("status"),
                "employment_type": member.get("worker_type"),
                "start_date": _as_date_string(member.get("start_date")),
                "end_date": _as_date_string(member.get("end_date")),
                "department": member.get("department"),
                "manager": member.get("manager_display_name"),
                "manager_email": member.get("manager_email"),
                # The freshness of the fact, not an effective date. A row
                # nobody has refreshed in a month is not the same fact as one
                # refreshed this morning, and the caller applies the cutoff.
                "imported_at": _as_iso(member.get("last_synced_at")),
                # Stated rather than implied: this link was made on an email
                # string match and nothing stronger. Phase 3.1 is where it
                # gains a confidence and its evidence.
                "match": "email",
                "source": "entity_store",
                "devices": [
                    {
                        "hostname": device.get("hostname"),
                        "compliance_state": device.get("compliance_state"),
                        "os_name": device.get("os_name"),
                        "os_version": device.get("os_version"),
                        "encrypted": device.get("encrypted"),
                        "edr_agent_health": device.get("edr_agent_health"),
                        "provider": device.get("connector_type"),
                        "last_seen": _as_iso(device.get("last_seen")),
                    }
                    for device in by_owner.get(email, [])[:5]
                ],
            }
        )
    return rows


def _as_date_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)[:10] or None


def _as_iso(value: Any) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if callable(isoformat) else str(value)
