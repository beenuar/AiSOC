"""Normalise an osquery result row into an AiSOC event dict.

Mirrors the severity heuristics used by the osctrl and FleetDM connectors
(PR1) so that direct-TLS agents produce identically shaped events.

Schema reference: services/connectors/app/connectors/osctrl.py
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

_HIGH_PATTERNS = [
    re.compile(r"process_events", re.IGNORECASE),
    re.compile(r"socket_events", re.IGNORECASE),
    re.compile(r"file_events", re.IGNORECASE),
    re.compile(r"user_events", re.IGNORECASE),
    re.compile(r"suid_bin", re.IGNORECASE),
]
_MEDIUM_PATTERNS = [
    re.compile(r"logged_in_users", re.IGNORECASE),
    re.compile(r"listening_ports", re.IGNORECASE),
]


def _infer_severity(query_name: str, row: dict) -> str:
    for pat in _HIGH_PATTERNS:
        if pat.search(query_name):
            return "high"
    for pat in _MEDIUM_PATTERNS:
        if pat.search(query_name):
            return "medium"
    return "info"


def normalize_row(
    row: dict,
    *,
    host_identifier: str,
    tenant_id: str,
    query_name: str,
    log_type: str = "result",
) -> dict:
    """Convert a single osquery result row into an AiSOC normalised event.

    Parameters
    ----------
    row:
        A single osquery result dict (column→value mapping).
    host_identifier:
        The node's stable host_identifier (UUID or hostname).
    tenant_id:
        AiSOC tenant this node belongs to.
    query_name:
        The name of the scheduled or distributed query that produced the row.
    log_type:
        ``"result"`` for schedule rows, ``"snapshot"`` for snapshot logs,
        ``"status"`` for osquery status messages.
    """
    severity = _infer_severity(query_name, row)
    return {
        "event_type": "osquery_query_row",
        "source": "aisoc_direct",
        "tenant_id": tenant_id,
        "host_identifier": host_identifier,
        "query_name": query_name,
        "log_type": log_type,
        "severity": severity,
        "raw": row,
        "timestamp": row.get("unixTime") or datetime.now(UTC).isoformat(),
    }
