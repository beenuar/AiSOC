"""
/v1/osquery/extensions/* — data endpoints consumed by the aisoc-extension
Go binary (the five osquery virtual tables).

All three routes are read-only and accept an optional ?host_identifier=
query parameter so multi-tenant operators can scope responses to a single
host.  Authentication uses the same Bearer-token check as the rest of the
osquery-tls service.

Endpoints
---------
GET /v1/osquery/extensions/pending-actions
    Returns HITL response actions that are queued and not yet expired.
    The Go extension surfaces these via `aisoc_pending_actions`.

GET /v1/osquery/extensions/alert-cache
    Returns recent alerts for the given host (default: last 24 h).
    The Go extension surfaces these via `aisoc_alert_cache`.

GET /v1/osquery/extensions/persistence-baseline
    Returns the approved persistence-mechanism baseline used to diff
    against what osquery actually finds on the host.
    The Go extension surfaces these via `aisoc_attck_persistence`.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query

log = logging.getLogger(__name__)

router = APIRouter(prefix="/extensions", tags=["extensions"])

# ---------------------------------------------------------------------------
# Stub data factories
# ---------------------------------------------------------------------------
# These stubs return representative data so the virtual tables are useful
# immediately after deployment, before a full case/alert integration is wired.
# In production the data should be pulled from the main aisoc_cases and
# aisoc_alerts tables (or via the ingest service); that join is left as a
# follow-up task (see ROADMAP).
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _pending_actions_stub(host: str) -> list[dict[str, Any]]:
    return [
        {
            "action_id": "act-stub-001",
            "case_id": "case-stub-042",
            "action_type": "isolate",
            "target": host,
            "requested_by": "aisoc-playbook",
            "requested_at": (_now() - timedelta(minutes=10)).isoformat(),
            "expires_at": (_now() + timedelta(hours=23, minutes=50)).isoformat(),
            "description": "Isolate host pending malware triage",
        }
    ]


def _alert_cache_stub(host: str, since: datetime) -> list[dict[str, Any]]:
    fired = _now() - timedelta(hours=2)
    if fired < since:
        return []
    return [
        {
            "alert_id": "alr-stub-999",
            "rule_id": "det-endpoint-201",
            "severity": "high",
            "fired_at": fired.isoformat(),
            "summary": f"Suspicious process execution on {host}",
            "case_id": "case-stub-042",
        }
    ]


def _persistence_baseline_stub(host: str) -> list[dict[str, Any]]:
    return [
        {
            "entry_id": "pe-stub-001",
            "mechanism": "cron",
            "path": "/etc/cron.d/sysmon-exporter",
            "arguments": "* * * * * root /usr/bin/sysmon-exporter",
            "approved": True,
            "mitre_technique": "T1053.003",
        },
        {
            "entry_id": "pe-stub-002",
            "mechanism": "systemd",
            "path": "/etc/systemd/system/aisoc-agent.service",
            "arguments": "",
            "approved": True,
            "mitre_technique": "T1543.002",
        },
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/pending-actions")
async def get_pending_actions(
    host_identifier: Annotated[str | None, Query(description="Host identifier")] = None,
) -> list[dict[str, Any]]:
    """Return pending HITL response actions for the given host."""
    host = host_identifier or "unknown"
    return _pending_actions_stub(host)


@router.get("/alert-cache")
async def get_alert_cache(
    host_identifier: Annotated[str | None, Query()] = None,
    since: Annotated[
        str | None,
        Query(description="ISO-8601 lower bound for alert fired_at"),
    ] = None,
) -> list[dict[str, Any]]:
    """Return recent alerts fired for the given host."""
    host = host_identifier or "unknown"
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            since_dt = _now() - timedelta(hours=24)
    else:
        since_dt = _now() - timedelta(hours=24)
    return _alert_cache_stub(host, since_dt)


@router.get("/persistence-baseline")
async def get_persistence_baseline(
    host_identifier: Annotated[str | None, Query()] = None,
) -> list[dict[str, Any]]:
    """Return the approved persistence-mechanism baseline for this host."""
    host = host_identifier or "unknown"
    return _persistence_baseline_stub(host)
