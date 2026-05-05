"""
Alert correlation engine: groups related alerts into incidents using entity and
MITRE ATT&CK context stored in Redis.
"""

from datetime import datetime
from uuid import uuid4

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import AlertSeverity, IncidentSummary, RawAlert

logger = structlog.get_logger()

_CORRELATION_PREFIX = "aisoc:fusion:correlation:"
_INCIDENT_PREFIX = "aisoc:fusion:incident:"

_SEVERITY_ORDER = {
    AlertSeverity.CRITICAL: 5,
    AlertSeverity.HIGH: 4,
    AlertSeverity.MEDIUM: 3,
    AlertSeverity.LOW: 2,
    AlertSeverity.INFO: 1,
}


def _max_severity(a: AlertSeverity, b: AlertSeverity) -> AlertSeverity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


class Correlator:
    """Correlates alerts into incidents using entity-based grouping."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._window = settings.correlation_window_seconds
        self._max_alerts = settings.max_alerts_per_incident

    async def correlate(self, alert: RawAlert) -> tuple[bool, IncidentSummary]:
        """
        Attempt to correlate an alert to an existing incident.

        Returns:
            (is_correlated_to_existing, incident_summary)
        """
        corr_key = alert.correlation_key()
        index_key = f"{_CORRELATION_PREFIX}{corr_key}"

        # Look up existing incident ID for this correlation key
        incident_id_bytes = await self._redis.get(index_key)

        if incident_id_bytes:
            incident_id = incident_id_bytes.decode()
            incident = await self._load_incident(incident_id)
            if incident and incident.alert_count < self._max_alerts:
                # Update existing incident
                incident = await self._merge_alert(incident, alert)
                await self._save_incident(incident)
                logger.info(
                    "Alert correlated to existing incident",
                    incident_id=incident_id,
                    alert_id=str(alert.id),
                    alert_count=incident.alert_count,
                )
                return True, incident

        # Create a new incident
        incident = self._create_incident(alert)
        await self._save_incident(incident)
        # Map correlation key -> incident ID
        await self._redis.set(index_key, str(incident.id), ex=self._window)
        logger.info(
            "New incident created from alert",
            incident_id=str(incident.id),
            alert_id=str(alert.id),
            correlation_key=corr_key,
        )
        return False, incident

    def _create_incident(self, alert: RawAlert) -> IncidentSummary:
        incident = IncidentSummary(
            id=uuid4(),
            tenant_id=alert.tenant_id,
            title=f"Incident: {alert.title}",
            severity=alert.severity,
            alert_count=1,
            alert_ids=[str(alert.id)],
            src_ips=[alert.src_ip] if alert.src_ip else [],
            hostnames=[alert.hostname] if alert.hostname else [],
            usernames=[alert.username] if alert.username else [],
            mitre_tactics=list(set(alert.mitre_tactics)),
            mitre_techniques=list(set(alert.mitre_techniques)),
            correlation_keys=[alert.correlation_key()],
            first_seen=alert.created_at,
            last_seen=alert.created_at,
        )
        return incident

    async def _merge_alert(self, incident: IncidentSummary, alert: RawAlert) -> IncidentSummary:
        incident.alert_count += 1
        incident.alert_ids.append(str(alert.id))
        incident.severity = _max_severity(incident.severity, alert.severity)
        incident.last_seen = datetime.utcnow()

        if alert.src_ip and alert.src_ip not in incident.src_ips:
            incident.src_ips.append(alert.src_ip)
        if alert.hostname and alert.hostname not in incident.hostnames:
            incident.hostnames.append(alert.hostname)
        if alert.username and alert.username not in incident.usernames:
            incident.usernames.append(alert.username)

        for tactic in alert.mitre_tactics:
            if tactic not in incident.mitre_tactics:
                incident.mitre_tactics.append(tactic)
        for technique in alert.mitre_techniques:
            if technique not in incident.mitre_techniques:
                incident.mitre_techniques.append(technique)

        corr_key = alert.correlation_key()
        if corr_key not in incident.correlation_keys:
            incident.correlation_keys.append(corr_key)

        return incident

    async def _save_incident(self, incident: IncidentSummary) -> None:
        key = f"{_INCIDENT_PREFIX}{incident.id}"
        await self._redis.set(
            key,
            incident.model_dump_json(),
            ex=self._window,
        )

    async def _load_incident(self, incident_id: str) -> IncidentSummary | None:
        key = f"{_INCIDENT_PREFIX}{incident_id}"
        data = await self._redis.get(key)
        if not data:
            return None
        return IncidentSummary.model_validate_json(data)
