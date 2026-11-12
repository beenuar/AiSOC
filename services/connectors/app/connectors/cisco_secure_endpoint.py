"""Cisco Secure Endpoint (formerly AMP for Endpoints) detections, read through the v1 events API.

Vendor reference, from Cisco's Secure Endpoint API documentation
(`https://developer.cisco.com/docs/secure-endpoint/`) and its API FAQ:

* **Where.** Each Secure Endpoint cloud is its own API host, and a
  credential exists in exactly one of them:

      North America                  https://api.amp.cisco.com
      Europe                         https://api.eu.amp.cisco.com
      Asia Pacific, Japan and China  https://api.apjc.amp.cisco.com

  The region is a fixed choice of three, not a URL, so the credential can only ever
  be sent to one of Cisco's three hosts.

* **Authentication.** HTTP Basic, with the API client ID as the user name
  and the API key as the password. The credential is created in the
  Secure Endpoint console under Accounts → API Credentials, and the
  read-only scope is enough for everything here.

* **Events.** `GET /v1/events` with `start_date` (ISO 8601), `limit` and
  `offset`. "A maximum of 500 results will be returned"; the rest of the
  collection is paged by `offset`, which is what `metadata.links.next`
  carries. The response is `{version, metadata: {links, results}, data}`,
  newest first.

Reading the window to the end
-----------------------------
The read goes through `read_offset_pages`, building each following request
from the configured region rather than requesting `metadata.links.next`. The
link only ever differs from the first request by its `offset`, and building
it here means a host named in a response body is never sent the credential.
A page shorter than the 500 asked for ends the collection.

The list is newest first, so an event recorded while the window is being read
pushes every row down by one and the row at a page boundary is returned
twice. That costs a duplicate, never a lost row, and the duplicate is dropped
by its `id` before the batch leaves the connector.

What is read, and what is not
-----------------------------
The events stream is every event the console records: detections and
quarantines, but also policy updates, scan starts and completions, file
fetches and installs. Cisco rates the first kind with a `severity` and leaves
the second unrated. Only rated events are returned, because this connector's
events are filed as OCSF 2001 Security Findings, which fusion promotes
unconditionally — an unrated policy update would otherwise reach the alert
queue as an alert. How many unrated events a poll skipped is logged as
`cisco_secure_endpoint.unrated_events_skipped`.

The severity ladder
-------------------
Cisco publishes Low, Medium, High and Critical. Each maps to its own tier;
`Critical` stays `critical` and is never collapsed into `high`. A value
outside the four carries no `severity` key rather than a guessed one.

Read-only
---------
Nothing here isolates a computer, changes a policy or acknowledges an event.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_offset_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

#: One host per Secure Endpoint cloud. A credential works in one of them only.
_REGION_HOSTS = {
    "nam": "https://api.amp.cisco.com",
    "eu": "https://api.eu.amp.cisco.com",
    "apjc": "https://api.apjc.amp.cisco.com",
}

_EVENTS_PATH = "/v1/events"

#: The documented maximum. It is also the page size `read_offset_pages`
#: compares against to tell the last page, so it is the value sent as `limit`.
_PAGE_SIZE = 500

#: The vendor's published ladder, four entries because it publishes four.
_SEVERITIES = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}


class CiscoSecureEndpointError(RuntimeError):
    """Cisco Secure Endpoint refused a request, with a message written for the operator."""


class CiscoSecureEndpointConnector(BaseConnector):
    connector_id = "cisco_secure_endpoint"
    connector_name = "Cisco Secure Endpoint"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Cisco Secure Endpoint (formerly AMP for Endpoints) detections — threats, quarantines, "
                "exploit prevention, behavioural protection, indicators of compromise and threat hunting "
                "incidents — via the v1 events API. Read-only."
            ),
            docs_url="/docs/connectors/cisco-secure-endpoint",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "nam", "label": "North America (api.amp.cisco.com)"},
                        {"value": "eu", "label": "Europe (api.eu.amp.cisco.com)"},
                        {"value": "apjc", "label": "Asia Pacific, Japan and China (api.apjc.amp.cisco.com)"},
                    ],
                    help_text="The Secure Endpoint cloud the console and the API credential live in.",
                ),
                Field("client_id", "string", "API client ID"),
                Field(
                    "api_key",
                    "secret",
                    "API key",
                    help_text="Created in the Secure Endpoint console under Accounts → API Credentials. Read-only scope is enough.",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        region: str,
        client_id: str,
        api_key: str,
        transport: Any | None = None,
    ) -> None:
        region_key = (region or "").strip().lower()
        if region_key not in _REGION_HOSTS:
            raise ValueError(f"region {region!r} is not a Cisco Secure Endpoint region; expected one of {', '.join(_REGION_HOSTS)}")
        self._region = region_key
        self._host = _REGION_HOSTS[region_key]
        self._auth = httpx.BasicAuth((client_id or "").strip(), api_key)
        self._transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._host,
            auth=self._auth,
            headers={"Accept": "application/json"},
            timeout=timeout,
            transport=self._transport,
        )

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client(30.0) as client:
                response = await client.get(_EVENTS_PATH, params={"limit": 1})
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": self._refusal(response)}
            return {"success": True, "connector": self.connector_id, "region": self._region, "api_host": self._host}
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        start_date = (datetime.now(UTC) - timedelta(seconds=max(1, int(since_seconds)))).isoformat(timespec="seconds")

        async with self._client(60.0) as client:

            async def page(offset: int) -> httpx.Response:
                return await client.get(
                    _EVENTS_PATH,
                    params={"start_date": start_date, "limit": _PAGE_SIZE, "offset": offset},
                )

            # Raised, not returned: an empty list would read as a quiet
            # estate, and the scheduler records an exception as the failed
            # poll it is. A later page failing is left to the reader, which
            # keeps the pages already read.
            first = await page(0)
            if first.status_code != 200:
                raise CiscoSecureEndpointError(self._refusal(first))
            events = await read_offset_pages(
                first,
                request=page,
                items_field="data",
                page_size=_PAGE_SIZE,
                feed="cisco_secure_endpoint.events",
            )

        rated: list[dict[str, Any]] = []
        seen: set[str] = set()
        unrated = 0
        for event in events:
            event_id = _identifier(event.get("id"))
            if event_id:
                # Newest first: a row shifted across a page boundary by an
                # event recorded mid-read comes back twice.
                if event_id in seen:
                    continue
                seen.add(event_id)
            if _severity(event) is None:
                unrated += 1
                continue
            rated.append(event)
        if unrated:
            logger.info(
                "cisco_secure_endpoint.unrated_events_skipped",
                skipped=unrated,
                returned=len(rated),
                detail="events Cisco does not rate (policy updates, scans, installs) are operational records, not detections",
            )
        return [self.normalize(event) for event in rated]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        computer = _object(raw.get("computer"))
        file_info = _object(raw.get("file"))
        identity = _object(file_info.get("identity"))
        network = _object(raw.get("network_info"))
        cloud_ioc = _object(raw.get("cloud_ioc"))
        hunting = _object(raw.get("threat_hunting"))

        event_type = _text(raw.get("event_type"))
        # The most specific name the event carries: a detection's signature,
        # an indicator's short name, or a threat hunting incident's title.
        name = _text(raw.get("detection")) or _text(cloud_ioc.get("short_description")) or _text(hunting.get("incident_title"))
        if event_type and name:
            title = f"{event_type}: {name}"
        else:
            title = event_type or name or "Cisco Secure Endpoint event"

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _identifier(raw.get("id")),
            "title": title,
            "description": _text(cloud_ioc.get("description")) or _text(hunting.get("incident_summary")),
            "event_type": event_type,
            "detection": _text(raw.get("detection")),
            "created_at": _text(raw.get("date")),
            "hostname": _text(computer.get("hostname")),
            "actor": _text(computer.get("user")),
            "src_ip": _text(network.get("local_ip")) or _first_address(computer.get("network_addresses")),
            # Only a network event names the peer it connected to.
            "dst_ip": _text(network.get("remote_ip")),
            "external_ip": _text(computer.get("external_ip")),
            "endpoint_id": _text(raw.get("connector_guid")) or _text(computer.get("connector_guid")),
            "file_name": _text(file_info.get("file_name")),
            "file_path": _text(file_info.get("file_path")),
            "sha256": _text(identity.get("sha256")),
            "disposition": _text(file_info.get("disposition")),
            "mitre_techniques": _techniques(raw, hunting),
            "raw_event": raw,
        }
        severity = _severity(raw)
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "", [])}

    @staticmethod
    def _refusal(response: httpx.Response) -> str:
        message = f"Cisco Secure Endpoint answered HTTP {response.status_code} to GET {_EVENTS_PATH}: {response.text[:300]}"
        if response.status_code == 401:
            message += (
                " Check the API client ID and key, and that the region matches the console the credential was "
                "created in: a credential from one region is refused by the others."
            )
        elif response.status_code == 429:
            message += " The API rate limit for this organisation is exhausted; the next poll retries."
        return message


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _object(value: Any) -> dict[str, Any]:
    """``value`` when it is a JSON object, otherwise an empty one."""
    return value if isinstance(value, dict) else {}


def _identifier(value: Any) -> str:
    """An event id as text. Cisco sends it as a JSON integer wider than 53 bits."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return _text(value)


def _severity(raw: dict[str, Any]) -> str | None:
    value = raw.get("severity")
    return _SEVERITIES.get(value.strip().lower()) if isinstance(value, str) else None


def _first_address(value: Any) -> str:
    """The first internal address the computer reports, if any."""
    if not isinstance(value, list):
        return ""
    for entry in value:
        address = _text(_object(entry).get("ip"))
        if address:
            return address
    return ""


def _techniques(raw: dict[str, Any], hunting: dict[str, Any]) -> list[str]:
    """ATT&CK technique ids, from the event and from a threat hunting incident."""
    ids: list[str] = []
    for source in (raw.get("techniques"), hunting.get("techniques")):
        if not isinstance(source, list):
            continue
        for technique in source:
            technique_id = _text(_object(technique).get("external_id"))
            if technique_id and technique_id not in ids:
                ids.append(technique_id)
    return ids
