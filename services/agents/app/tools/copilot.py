"""Read-only console tools, using the caller's credential rather than a service grant.

The core API remains the authority for tenant and resource permissions. Neither
an LLM argument nor page context can choose a URL, credential or tenant. Results
are bounded before becoming both model context and citable evidence.
"""

from __future__ import annotations

import json
import math
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.api.copilot_grounding import EvidenceSource
from app.prompting.tool_results import MAX_TOOL_MESSAGE_CHARS
from app.tools.registry import Tool, ToolRegistry

MAX_RESPONSE_BYTES = 256_000
MAX_EVIDENCE_BYTES = 24_000
MAX_RECORDS = 20
_RECORD_KEYS = (
    "id",
    "title",
    "description",
    "severity",
    "status",
    "priority",
    "created_at",
    "event_time",
    "first_seen",
    "last_seen",
    "rule_id",
    "rule_name",
    "connector_type",
    "ai_summary",
    "summary",
    "entity_type",
    "entity_value",
    "score",
    "alert_count",
)
_LIST_KEYS = ("affected_hosts", "affected_ips", "affected_users", "mitre_techniques", "contributing_alerts")
_OBJECT_LIST_KEYS = {
    "entities": ("type", "value"),
    "contributors": ("alert_id", "severity", "detection", "points", "at", "host"),
}
# Keep useful normalized facts from detail responses. Arbitrary vendor data,
# raw logs, request bodies and headers are not model evidence. A key denylist
# or a different string format would still forward those opaque payloads.
_EVENT_FIELDS = (
    "device.name",
    "device.hostname",
    "device.ip",
    "src_endpoint.ip",
    "src_endpoint.hostname",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.hostname",
    "dst_endpoint.port",
    "actor.user.name",
    "actor.user.uid",
    "finding.uid",
    "finding.title",
    "finding.desc",
    "rule.id",
    "rule.description",
    "activity.action",
    "activity.outcome",
    "activity.actor.kind",
    "activity.actor.name",
    "activity.actor.id",
    "activity.actor.on_behalf_of",
    "activity.resource.type",
    "activity.resource.id",
    "activity.resource.name",
    "activity.resource.owner",
    "activity.location.ip",
    "activity.location.country",
    "activity.location.country_code",
    "activity.location.city",
    "activity.location.asn",
    "activity.location.as_org",
    "activity.location.ip_class",
    "activity.location.device",
)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | bool | int) or (isinstance(value, float) and math.isfinite(value))


def _project_record(row: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted summaries; never stringify an unexpected nested object."""
    selected = {key: row[key] for key in _RECORD_KEYS if key in row and _is_scalar(row[key])}
    for key in _LIST_KEYS:
        if isinstance(row.get(key), list):
            selected[key] = [value for value in row[key] if _is_scalar(value)]
    for key, fields in _OBJECT_LIST_KEYS.items():
        if isinstance(row.get(key), list):
            selected[key] = [
                {field: item[field] for field in fields if field in item and _is_scalar(item[field])}
                for item in row[key]
                if isinstance(item, dict)
            ]
    severities = row.get("severities")
    if isinstance(severities, dict):
        selected["severities"] = {
            key: severities[key]
            for key in ("info", "low", "medium", "high", "critical")
            if isinstance(severities.get(key), int | float) and math.isfinite(severities[key])
        }
    raw_event = row.get("raw_event")
    if isinstance(raw_event, dict):
        facts: dict[str, Any] = {}
        for path in _EVENT_FIELDS:
            value: Any = raw_event
            for part in path.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if value is not None and _is_scalar(value):
                facts[path] = value
        if facts:
            selected["event_summary"] = facts
    return selected


def _bounded(value: Any, depth: int = 0, *, max_chars: int = 2000, max_items: int = MAX_RECORDS) -> Any:
    if depth >= 5:
        return "[truncated]"
    if isinstance(value, str):
        return value[:max_chars] + (" [truncated]" if len(value) > max_chars else "")
    if isinstance(value, list):
        return [_bounded(v, depth + 1, max_chars=max_chars, max_items=max_items) for v in value[:max_items]]
    if isinstance(value, dict):
        return {str(k): _bounded(v, depth + 1, max_chars=max_chars, max_items=max_items) for k, v in list(value.items())[:40]}
    return value


class CopilotReads:
    """A single request's HTTP reads, evidence and provenance; never shared state."""

    def __init__(self, authorization: str | None = None, tenant_id: uuid.UUID | None = None) -> None:
        self._authorization = authorization
        self._tenant_id = tenant_id
        self._now = datetime.now(UTC)
        self._evidence_bytes = 0
        self.sources: list[EvidenceSource] = []
        self.calls: list[dict[str, Any]] = []

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self._tenant_id

    def registry(self) -> ToolRegistry:
        return ToolRegistry(
            [
                Tool(
                    name="copilot_alerts",
                    description=(
                        "Read alerts already ingested into AiSOC from any connected source. Filter by event-time window, "
                        "severity or exact hostname. Results are one bounded page, not the complete estate. "
                        "Use next_page when supplied. This does not query the upstream SIEM or EDR."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "hours": {"type": "integer", "minimum": 1, "maximum": 168},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "hostname": {"type": "string", "minLength": 1, "maxLength": 255},
                            "page": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                    },
                    fn=self.alerts,
                ),
                Tool(
                    name="copilot_record",
                    description=(
                        "Read one tenant-authorized alert or case by its UUID. Cite the returned ref, not a client-supplied snapshot."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "kind": {"type": "string", "enum": ["alert", "case"]},
                            "record_id": {"type": "string", "format": "uuid", "maxLength": 36},
                        },
                        "required": ["kind", "record_id"],
                    },
                    fn=self.record,
                ),
                Tool(
                    name="copilot_entity_risk",
                    description=(
                        "Read Fusion risk for an entity, or the highest-scored observed entities of a type (host by default). "
                        "Queue coverage is bounded to Fusion's top 200 entities, not all assets. Risk is not proof of compromise. "
                        "Use contributing_alerts with copilot_record to investigate the evidence."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "entity_type": {"type": "string", "enum": ["host", "user", "src_ip", "domain"]},
                            "entity_value": {"type": "string", "minLength": 1, "maxLength": 255},
                        },
                    },
                    fn=self.entity_risk,
                ),
            ]
        )

    def _unavailable(self, operation: str, reason: str) -> dict[str, Any]:
        self.calls.append({"tool": operation, "status": "could_not_check", "reason": reason})
        return {
            "available": False,
            "outcome": "could_not_check",
            "reason": reason,
            "notice": "This lookup did not complete. It is not evidence of no alerts or no risk.",
        }

    async def _get(self, operation: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self._authorization or not self._tenant_id:
            return self._unavailable(operation, "No caller credential is available for this read.")
        headers = {"Authorization": self._authorization, "X-AiSOC-Tenant-ID": str(self._tenant_id)}
        # A fixed deployment target and fixed route families. Never follow a
        # redirect with the console bearer, or substitute a stronger credential.
        url = os.getenv("AISOC_API_URL", "http://api:8000").rstrip("/") + path
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                async with client.stream("GET", url, params=params, headers=headers) as response:
                    if response.status_code != 200:
                        return self._unavailable(operation, f"The core API returned HTTP {response.status_code}.")
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_RESPONSE_BYTES:
                            return self._unavailable(operation, "The API response exceeded the safe read limit.")
            body = json.loads(data)
            if not isinstance(body, dict):
                raise ValueError("expected object")
            return body
        except (httpx.HTTPError, ValueError):
            # Do not put upstream bodies, URLs with credentials, or exception
            # strings into the prompt. The HTTP status is enough to diagnose.
            return self._unavailable(operation, "The core API did not return a readable response.")

    def _records(self, operation: str, kind: str, rows: list[dict[str, Any]], **coverage: Any) -> dict[str, Any]:
        result: list[dict[str, Any]] = []
        sources: list[EvidenceSource] = []
        payload: dict[str, Any] = {
            "available": True,
            "outcome": "ok",
            "records": result,
            "truncated": len(rows) > MAX_RECORDS,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "evidence_scope": "Allowlisted record summaries and event facts only; raw payloads are omitted.",
            **coverage,
        }
        for row in rows[:MAX_RECORDS]:
            selected = _project_record(row)
            identifier = row.get("id") if kind != "entity_risk" else f"{row.get('entity_type')}:{row.get('entity_value')}"
            if not isinstance(identifier, str) or not identifier:
                return self._unavailable(operation, "The API returned a record without an identifier.")
            ref = f"{kind}:{identifier}"
            max_chars, max_items = 2000, MAX_RECORDS
            while True:
                projected = _bounded(selected, max_chars=max_chars, max_items=max_items)
                if "id" in selected:
                    projected["id"] = selected["id"]
                entry: dict[str, Any] | None = {"ref": ref, **projected}
                candidate = {**payload, "records": [*result, entry]}
                if len(json.dumps(candidate, default=str)) <= MAX_TOOL_MESSAGE_CHARS:
                    break
                # Compact a large first record instead of returning no facts.
                # Subsequent records are omitted whole, with an explicit limit.
                if result or max_chars <= 32:
                    entry = None
                    break
                max_chars = max(32, max_chars // 2)
                max_items = max(1, max_items // 2)
            if entry is None:
                payload["truncated"] = True
                break
            payload["truncated"] |= projected != selected
            entry_bytes = len(json.dumps(entry, ensure_ascii=False).encode())
            if self._evidence_bytes + entry_bytes > MAX_EVIDENCE_BYTES:
                payload["truncated"] = True
                break
            self._evidence_bytes += entry_bytes
            result.append(entry)
            sources.append(EvidenceSource(ref=ref, kind=kind, text=json.dumps(projected), label=str(projected.get("title") or identifier)))
        # The shared renderer slices at MAX_TOOL_MESSAGE_CHARS. Fit the entire
        # envelope before recording sources so coverage and citations describe
        # exactly the evidence that survives that boundary, including Unicode.
        self.sources.extend(sources)
        self.calls.append({"tool": operation, "status": "ok", "records": len(result), "truncated": payload["truncated"]})
        return payload

    async def alerts(self, hours: int = 24, severity: str | None = None, hostname: str | None = None, page: int = 1) -> dict[str, Any]:
        now = self._now
        params: dict[str, Any] = {
            "page": page,
            "page_size": MAX_RECORDS,
            "sort": "priority",
            "event_since": (now - timedelta(hours=hours)).isoformat(),
            "event_until": now.isoformat(),
        }
        if severity:
            params["severity"] = severity
        if hostname:
            params["hostname"] = hostname
        body = await self._get("copilot_alerts", "/api/v1/alerts", params)
        if body.get("available") is False:
            return body
        rows, total = body.get("items"), body.get("total")
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows) or not isinstance(total, int):
            return self._unavailable("copilot_alerts", "The alert list response did not match its contract.")
        return self._records(
            "copilot_alerts",
            "alert",
            rows,
            total=total,
            page=page,
            next_page=page + 1 if page * MAX_RECORDS < total and page < 10 else None,
            window={"field": "event_time", "since": params["event_since"], "until": params["event_until"]},
            coverage="Ingested AiSOC alerts only; missing upstream telemetry was not searched.",
        )

    async def record(self, kind: str, record_id: str) -> dict[str, Any]:
        if kind not in {"alert", "case"}:
            return self._unavailable("copilot_record", "Unsupported record type.")
        try:
            identifier = str(uuid.UUID(record_id))
        except ValueError:
            return self._unavailable("copilot_record", "A record UUID is required.")
        body = await self._get("copilot_record", f"/api/v1/{kind}s/{identifier}")
        if body.get("available") is False:
            return body
        if str(body.get("id")) != identifier:
            return self._unavailable("copilot_record", "The returned record did not match the requested UUID.")
        return self._records("copilot_record", kind, [body])

    async def entity_risk(self, entity_type: str = "host", entity_value: str | None = None) -> dict[str, Any]:
        if entity_value is not None:
            path = f"/api/v1/fusion/entity-risk/{quote(entity_type, safe='')}/{quote(entity_value, safe='')}"
            body = await self._get("copilot_entity_risk", path)
            if body.get("available") is False:
                return body
            rows = [body]
        else:
            body = await self._get("copilot_entity_risk", "/api/v1/fusion/entity-risk/queue", {"limit": 200})
            if body.get("available") is False:
                return body
            if not isinstance(body.get("entities"), list) or not all(isinstance(r, dict) for r in body["entities"]):
                return self._unavailable("copilot_entity_risk", "The risk queue response did not match its contract.")
            rows = [r for r in body["entities"] if r.get("entity_type") == entity_type]
        if not all(
            r.get("entity_type") == entity_type
            and isinstance(r.get("entity_value"), str)
            and isinstance(r.get("score"), int | float)
            and math.isfinite(r["score"])
            and (entity_value is None or r["entity_value"] == entity_value)
            for r in rows
        ):
            return self._unavailable("copilot_entity_risk", "The risk records did not match their contract.")
        rows.sort(key=lambda r: r["score"], reverse=True)
        return self._records(
            "copilot_entity_risk",
            "entity_risk",
            rows,
            coverage="Fusion's observed risk records; queue reads cover at most its top 200 entities, not the whole estate.",
        )
