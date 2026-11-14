"""ESET PROTECT detections, read through the ESET Connect API.

Vendor reference, from the ESET Connect documentation
(`https://help.eset.com/eset_connect/en-US/`):

* **Where.** ESET Connect is served per data region, and an API user exists
  in exactly one of them. Each region has one host per service:

      Region          Token                                        Detections and devices
      Europe          eu.business-account.iam.eset.systems         eu.incident-management / eu.device-management
      Germany         de.business-account.iam.eset.systems         de.incident-management / de.device-management
      United States   us.business-account.iam.eset.systems         us.incident-management / us.device-management
      Canada          ca.business-account.iam.eset.systems         ca.incident-management / ca.device-management
      Japan           jpn.business-account.iam.eset.systems        jpn.incident-management / jpn.device-management

  (every host under `.eset.systems`). The region is a fixed choice of five,
  not a URL, so the credential can only ever be sent to ESET.

* **Authentication.** An OAuth2 password grant for a dedicated API user,
  created in ESET PROTECT Hub (or ESET Business Account / ESET MSP
  Administrator 2) with the **Integrations** toggle on:

      POST https://<region>.business-account.iam.eset.systems/oauth/token
      Content-Type: application/x-www-form-urlencoded
      grant_type=password&username=<email>&password=<password>

  answers `{access_token, refresh_token, token_type, expires_in}`, and the
  access token is sent as `Authorization: Bearer <token>`.

* **Detections.** `GET /v1/detections` on the incident-management host,
  with `startTime` (inclusive) and `endTime` (exclusive) bounding
  `occurTime`, `pageSize` (at most 1000) and `pageToken`. The response is
  `{detections, nextPageToken, totalSize}`; `nextPageToken` is empty on the
  last page.

* **Devices.** `GET /v1/devices:batchGet` on the device-management host,
  with `devicesUuids` repeated per device, answers `{devices}`. A detection
  names its device only by `context.deviceUuid`.

* **Slow responses.** A request ESET cannot answer within 30 seconds answers
  `202 Accepted` with a `response-id` header and is cached. Re-sending the
  identical request with that header returns the result once it is ready,
  or another 202 while it is not; after 120 seconds ESET answers 504.

Reading the window
------------------
The read asks for the window by `startTime` and `endTime` and follows
`nextPageToken` through `read_token_pages` until ESET returns an empty one.
The following request is built here from the configured region with the
token, so a host named in a response never receives the bearer token. A 202
is waited out by re-sending the same request with its `response-id`, every
few seconds up to ESET's own 120-second limit. A refused or unreachable
opening request raises, so the scheduler records a failed poll rather than a
quiet window; a later page failing keeps the pages already read.

The request is made at second precision, which is what ESET stamps, and the
exact window is applied to `occurTime` here. The window is closed at the
moment the read began: a detection stamped later belongs to the next poll's
window, which opens there, and is raised then rather than twice.

ESET filters on `occurTime`, the moment the detection happened on the
endpoint. An endpoint that was offline uploads its detections when it
reconnects, stamped with the time they happened, and a detection uploaded
after its window was read is not requested again. That is a property of the
vendor's filter, not of this reader, and the connector page says so.

The host behind a detection
---------------------------
Each distinct device in a poll's detections is looked up through
`devices:batchGet`, `_DEVICE_BATCH` at a time and at most
`_MAX_DEVICE_LOOKUPS` per poll. The device record is carried on the
detection under `device`, a key the vendor's detection does not use, so a
replay of the stored record normalizes to the same host. ESET documents the
batch as atomic, so a failed batch costs the hosts of the detections in it,
never the detections themselves. A 429, or a batch still pending after
ESET's 120 seconds, stops the lookups for the poll. Only a well-formed UUID
is put into a request.

The severity ladder
-------------------
ESET publishes five levels: `SEVERITY_LEVEL_DIAGNOSTIC`, `_INFORMATIONAL`,
`_LOW`, `_MEDIUM` and `_HIGH`. Diagnostic and informational map to `info`,
and low, medium and high each map to their own tier. ESET's ladder stops at
high, so no detection is raised as `critical`. `SEVERITY_LEVEL_UNSPECIFIED`,
or anything else, carries no `severity` key rather than a guessed one.

Read-only
---------
Nothing here isolates a device, resolves a detection or runs a task.
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_token_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

#: The ESET Connect data regions, each with its own set of hosts.
_REGIONS: dict[str, str] = {
    "eu": "Europe",
    "de": "Germany",
    "us": "United States",
    "ca": "Canada",
    "jpn": "Japan",
}

_TOKEN_URL = "https://{region}.business-account.iam.eset.systems/oauth/token"
_DETECTIONS_URL = "https://{region}.incident-management.eset.systems/v1/detections"
_DEVICES_URL = "https://{region}.device-management.eset.systems/v1/devices:batchGet"

_DETECTIONS_PATH = "/v1/detections"
_TOKEN_PATH = "/oauth/token"

#: The documented maximum for `pageSize`.
_PAGE_SIZE = 1000

#: Seconds of headroom before a cached token's expiry. A token that expires
#: between the check and the call answers 401, which reads as a bad credential.
_TOKEN_HEADROOM_SECONDS = 60

#: How many times a 202 is re-sent with its `response-id`, and how long to
#: wait before each. Together they cover ESET's own 120 seconds, after which
#: it answers 504 instead.
_PENDING_ATTEMPTS = 24
_PENDING_WAIT_SECONDS = 5.0

#: Devices per `devices:batchGet` request. Each UUID adds about fifty
#: characters to the query string, so this keeps the URL well short of the
#: lengths proxies refuse.
_DEVICE_BATCH = 50

#: Devices one poll may look up. A window with more than this many distinct
#: devices is an outbreak, and its detections still arrive, without a host.
_MAX_DEVICE_LOOKUPS = 500

#: The vendor's published ladder. It has no critical level.
_SEVERITIES = {
    "SEVERITY_LEVEL_DIAGNOSTIC": "info",
    "SEVERITY_LEVEL_INFORMATIONAL": "info",
    "SEVERITY_LEVEL_LOW": "low",
    "SEVERITY_LEVEL_MEDIUM": "medium",
    "SEVERITY_LEVEL_HIGH": "high",
}

_INBOUND = "NETWORK_COMMUNICATION_DIRECTION_INBOUND"
_OUTBOUND = "NETWORK_COMMUNICATION_DIRECTION_OUTBOUND"

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class ESETProtectError(RuntimeError):
    """ESET refused a request, with a message written for the operator."""


class ESETProtectConnector(BaseConnector):
    connector_id = "eset_protect"
    connector_name = "ESET PROTECT"
    connector_category = "edr"

    #: Seconds between re-sends of a 202. An attribute so a test can set it to zero.
    pending_wait_seconds = _PENDING_WAIT_SECONDS

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "ESET PROTECT detections — antivirus, HIPS, firewall, network intrusion, web access and "
                "ESET Inspect rule hits — via the ESET Connect API, with the affected device resolved for "
                "its hostname, addresses and operating system. Read-only."
            ),
            docs_url="/docs/connectors/eset-protect",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[{"value": key, "label": f"{label} ({key})"} for key, label in _REGIONS.items()],
                    help_text="The ESET data region your ESET PROTECT Hub or ESET Business Account lives in.",
                ),
                Field(
                    "username",
                    "string",
                    "API user email",
                    help_text="A dedicated user with the Integrations toggle on. It must have signed in once before the API accepts it.",
                ),
                Field(
                    "password",
                    "secret",
                    "API user password",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(self, region: str, username: str, password: str, transport: Any | None = None) -> None:
        region_key = (region or "").strip().lower()
        if region_key not in _REGIONS:
            raise ValueError(f"region {region!r} is not an ESET Connect region; expected one of {', '.join(_REGIONS)}")
        self._region = region_key
        self._username = (username or "").strip()
        self._password = password or ""
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers={"Accept": "application/json"}, timeout=timeout, transport=self._transport)

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._token_expires_at - _TOKEN_HEADROOM_SECONDS:
            return self._token
        url = _TOKEN_URL.format(region=self._region)
        try:
            response = await client.post(
                url,
                data={"grant_type": "password", "username": self._username, "password": self._password},
            )
        except httpx.HTTPError as exc:
            raise ESETProtectError(f"ESET could not be reached at {httpx.URL(url).host}: {exc}") from exc
        if response.status_code != 200:
            raise ESETProtectError(_refusal(response, "POST", _TOKEN_PATH))
        body = _json(response)
        token = _text(body.get("access_token"))
        if not token:
            raise ESETProtectError(f"ESET answered POST {_TOKEN_PATH} without an access_token.")
        expires_in = body.get("expires_in")
        lifetime = float(expires_in) if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else 3600.0
        self._token = token
        self._token_expires_at = time.time() + lifetime
        return token

    async def _get(self, client: httpx.AsyncClient, url: str, params: dict[str, Any]) -> httpx.Response:
        """One GET, fetching the token again once if a cached one is refused."""
        previous = self._token
        token = await self._access_token(client)
        response = await self._send(client, url, params, token)
        # Only a token reused from an earlier request is retried. A token
        # issued for this request and refused is a refusal of the credential,
        # and exchanging it again would loop.
        if response.status_code == 401 and token == previous:
            self._token = None
            token = await self._access_token(client)
            response = await self._send(client, url, params, token)
        return response

    async def _send(self, client: httpx.AsyncClient, url: str, params: dict[str, Any], token: str) -> httpx.Response:
        """One GET, waiting out ESET's 202 by re-sending the identical request with its `response-id`."""
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(url, params=params, headers=headers)
        for _ in range(_PENDING_ATTEMPTS):
            if response.status_code != 202:
                return response
            response_id = response.headers.get("response-id", "").strip()
            if not response_id:
                return response
            await asyncio.sleep(self.pending_wait_seconds)
            response = await client.get(url, params=params, headers={**headers, "response-id": response_id})
        return response

    async def test_connection(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        params = {"startTime": _second(now - timedelta(hours=1)), "endTime": _second(now + timedelta(seconds=1)), "pageSize": 1}
        try:
            async with self._client(60.0) as client:
                response = await self._get(client, _DETECTIONS_URL.format(region=self._region), params)
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": _refusal(response, "GET", _DETECTIONS_PATH)}
            return {"success": True, "connector": self.connector_id, "region": self._region}
        except ESETProtectError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        window_start = window_end - timedelta(seconds=max(1, int(since_seconds)))
        # Second precision is what the vendor stamps, so the request covers
        # every second the window touches and the exact edges are applied
        # below. `endTime` is exclusive, hence the second added.
        params: dict[str, Any] = {
            "startTime": _second(window_start),
            "endTime": _second(window_end + timedelta(seconds=1)),
            "pageSize": _PAGE_SIZE,
        }
        url = _DETECTIONS_URL.format(region=self._region)

        async with self._client(60.0) as client:

            async def page(token: str | None) -> httpx.Response:
                # Raised, not returned: on the opening page an empty list
                # would read as a quiet estate, and the scheduler records an
                # exception as the failed poll it is. A later page failing is
                # left to the reader, which keeps the pages already read.
                try:
                    response = await self._get(client, url, {**params, "pageToken": token} if token else params)
                except httpx.HTTPError as exc:
                    if token is None:
                        raise ESETProtectError(f"ESET could not be reached at {httpx.URL(url).host}: {exc}") from exc
                    raise
                except ESETProtectError as exc:
                    # A refused token exchange part-way through is a failed
                    # later page like any other. The reader keeps the pages
                    # it has on a request error, so it is handed one.
                    if token is None:
                        raise
                    raise httpx.RequestError(str(exc)) from exc
                if token is None and response.status_code != 200:
                    raise ESETProtectError(_refusal(response, "GET", _DETECTIONS_PATH))
                return response

            detections = await read_token_pages(
                request=page,
                items_field="detections",
                token_field="nextPageToken",
                feed="eset_protect.detections",
            )

            inside: list[dict[str, Any]] = []
            seen: set[str] = set()
            for detection in detections:
                detection_id = _text(detection.get("uuid"))
                if detection_id:
                    if detection_id in seen:
                        continue
                    seen.add(detection_id)
                occurred = _timestamp(detection.get("occurTime"))
                if occurred is not None and not window_start <= occurred < window_end:
                    continue
                inside.append(detection)

            devices = await self._devices(client, inside)

        out: list[dict[str, Any]] = []
        for detection in inside:
            device = devices.get(_device_uuid(detection))
            out.append(self.normalize({**detection, "device": device} if device else detection))
        return out

    async def _devices(self, client: httpx.AsyncClient, detections: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """The device record behind each distinct `context.deviceUuid`, within the lookup budget."""
        wanted = list(dict.fromkeys(uuid for uuid in (_device_uuid(d) for d in detections) if uuid))
        if len(wanted) > _MAX_DEVICE_LOOKUPS:
            logger.warning(
                "eset_protect.device_lookups_capped",
                devices=len(wanted),
                looked_up=_MAX_DEVICE_LOOKUPS,
                detail="detections on the devices beyond the bound are returned without a host",
            )
            wanted = wanted[:_MAX_DEVICE_LOOKUPS]

        url = _DEVICES_URL.format(region=self._region)
        devices: dict[str, dict[str, Any]] = {}
        for start in range(0, len(wanted), _DEVICE_BATCH):
            batch = wanted[start : start + _DEVICE_BATCH]
            try:
                response = await self._get(client, url, {"devicesUuids": batch})
            except (httpx.HTTPError, ESETProtectError) as exc:
                logger.warning("eset_protect.device_lookup_failed", devices=len(batch), error=str(exc))
                continue
            if response.status_code in (202, 429):
                # Rate-limited, or still pending after ESET's own 120 seconds:
                # the next batch would meet the same, and each pending one
                # holds the poll for another two minutes.
                logger.warning(
                    "eset_protect.device_lookups_stopped",
                    status=response.status_code,
                    looked_up=len(devices),
                    detail="ESET is rate-limiting or not answering in time; the remaining detections are returned without a host",
                )
                break
            if response.status_code != 200:
                logger.warning("eset_protect.device_lookup_failed", devices=len(batch), status=response.status_code)
                continue
            records = _json(response).get("devices")
            for record in records if isinstance(records, list) else []:
                if isinstance(record, dict) and _text(record.get("uuid")).lower() in batch:
                    devices[_text(record.get("uuid")).lower()] = record
        return devices

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        context = _object(raw.get("context"))
        process = _object(context.get("process"))
        network = _object(raw.get("networkCommunication"))
        device = _object(raw.get("device"))
        operating_system = _object(device.get("operatingSystem"))

        title = _text(raw.get("displayName")) or _text(raw.get("typeName"))
        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _text(raw.get("uuid")),
            "title": title or "ESET PROTECT detection",
            "description": _text(context.get("circumstances")),
            "created_at": _text(raw.get("occurTime")),
            "category": _enum(raw.get("category"), "DETECTION_CATEGORY_"),
            "object_type": _text(raw.get("objectTypeName")),
            "object_name": _text(raw.get("objectName")),
            "object_url": _text(raw.get("objectUrl")),
            "sha1": _text(raw.get("objectHashSha1")),
            "sha256": _text(raw.get("objectHashSha256")),
            "process_path": _text(process.get("path")),
            "actor": _text(context.get("userName")),
            "endpoint_id": _text(context.get("deviceUuid")),
            "hostname": _text(device.get("systemHostname")) or _text(device.get("displayName")),
            "os": _text(operating_system.get("displayName")),
            "external_ip": _text(device.get("publicIpAddress")),
            "protocol": _text(network.get("protocolName")),
            "responses": _response_names(raw.get("responses")),
            "raw_event": raw,
        }
        event.update(_endpoints(network, _text(device.get("primaryLocalIpAddress"))))
        severity = _SEVERITIES.get(_text(raw.get("severityLevel")).upper())
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "", [])}


def _endpoints(network: dict[str, Any], device_ip: str) -> dict[str, Any]:
    """Source and destination, oriented by the direction ESET recorded.

    An inbound connection's source is the remote peer. Without a recorded
    direction the host's own address fills `src_ip` and the peer is kept as
    `remote_ip`, so neither is presented as the side that opened the
    connection.
    """
    direction = _text(network.get("direction")).upper()
    local_ip = _text(network.get("localIpAddress")) or device_ip
    remote_ip = _text(network.get("remoteIpAddress"))
    local_port = _port(network.get("localPort"))
    remote_port = _port(network.get("remotePort"))
    if direction == _INBOUND:
        return {"src_ip": remote_ip, "src_port": remote_port, "dst_ip": local_ip, "dst_port": local_port}
    if direction == _OUTBOUND:
        return {"src_ip": local_ip, "src_port": local_port, "dst_ip": remote_ip, "dst_port": remote_port}
    return {"src_ip": local_ip, "remote_ip": remote_ip}


def _refusal(response: httpx.Response, method: str, path: str) -> str:
    message = f"ESET answered HTTP {response.status_code} to {method} {path}: {response.text[:300]}"
    if response.status_code in (400, 401) and path == _TOKEN_PATH:
        message += (
            " Check the API user's email and password, that the region is the one its account was created in, "
            "and that the user has signed in to ESET PROTECT Hub once."
        )
    elif response.status_code == 401:
        message += " The access token was refused; check that the API user still exists and has the Integrations toggle on."
    elif response.status_code == 403:
        message += (
            " The API user is valid but its permissions do not allow reading detections;"
            " turn on its Integrations toggle and grant read access."
        )
    elif response.status_code == 429:
        message += " The API rate limit is reached; the next poll retries."
    elif response.status_code == 202:
        message += " ESET was still preparing the result after its own 120-second limit; the next poll retries."
    return message


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        return _object(response.json())
    except ValueError:
        return {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _object(value: Any) -> dict[str, Any]:
    """``value`` when it is a JSON object, otherwise an empty one."""
    return value if isinstance(value, dict) else {}


def _enum(value: Any, prefix: str) -> str:
    """An ESET enum value without its prefix, lower-cased; the unspecified fallback is no value."""
    text = _text(value).upper()
    if not text.startswith(prefix):
        return ""
    name = text[len(prefix) :].lower()
    return "" if name == "unspecified" else name


def _response_names(value: Any) -> list[str]:
    """The names of the actions ESET took on the detection, such as `cleaned by deleting`."""
    if not isinstance(value, list):
        return []
    return [name for name in (_text(_object(entry).get("displayName")) for entry in value) if name]


def _port(value: Any) -> int | None:
    """A port number, which ESET sends as an int64 and proto3 JSON may render as a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    return value if isinstance(value, int) and 0 < value < 65536 else None


def _device_uuid(detection: dict[str, Any]) -> str:
    """The detection's device UUID, lower-cased, or empty unless it is a well-formed UUID."""
    value = _text(_object(detection.get("context")).get("deviceUuid"))
    return value.lower() if _UUID.match(value) else ""


def _second(moment: datetime) -> str:
    """An RFC 3339 UTC timestamp at second precision, the form ESET's filters accept."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value: Any) -> datetime | None:
    """An RFC 3339 timestamp as an aware datetime, or None."""
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
