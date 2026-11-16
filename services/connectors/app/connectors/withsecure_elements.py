"""WithSecure Elements Broad Context Detections, read through the Elements API.

Vendor reference, from the WithSecure Elements API reference
(`https://connect.withsecure.com/api-reference/elements`) and the OpenAPI
document behind it (`https://connect.withsecure.com/specs/elements/rendered/api-spec.yaml`):

* **Where.** One production host, `https://api.connect.withsecure.com`, for
  every organization. It is fixed here rather than configurable, so the
  credential can only ever be sent to WithSecure. Every request must carry a
  `User-Agent` header; WithSecure rejects one without it.

* **Authentication.** OAuth2 client credentials. The client id and secret
  are created in Elements Security Center under Management > Organization
  Settings > API clients, and exchanged with HTTP Basic at:

      POST https://api.connect.withsecure.com/as/token.oauth2
      Content-Type: application/x-www-form-urlencoded
      grant_type=client_credentials&scope=connect.api.read

  which answers `{access_token, token_type, expires_in}`. The access token is
  sent as `Authorization: Bearer <token>`. A read-only client can only be
  granted `connect.api.read`, which is the only scope asked for here.

* **Broad Context Detections.** Elements EDR groups related detections into
  a Broad Context Detection (BCD), which the API calls an incident.
  `GET /incidents/v1/incidents` takes `organizationId`, `createdTimestampStart`
  (inclusive) and `createdTimestampEnd` (exclusive), `archived`, `limit` (at
  most 50), `order` and `anchor`. The response is `{items, nextAnchor}`, and
  `nextAnchor` is absent on the last page. Each BCD carries a five-level
  `severity` (`info` to `critical`) and a five-level `riskLevel` (`info` to
  `severe`).

* **Detections.** `GET /incidents/v1/detections` with `incidentId` lists the
  detections in one BCD, newest first, at most 100 a page and paged the same
  way. Each names its device by `deviceId` and carries the process, its
  command line and hash, the user, and the MITRE ATT&CK ids in `mitre`.

* **Devices.** `GET /devices/v1/devices` with `deviceId` answers the device
  record, with its `name`, comma-separated `ipAddresses`, `publicIpAddress`
  and `os`.

* **Rate limit.** "For EDR endpoints, the rate limit is 300 requests per
  minute per unique IP address", which covers the BCD, detection and device
  reads alike.

Reading the window
------------------
The read asks for the window by `createdTimestampStart` and
`createdTimestampEnd`, oldest first, and follows `nextAnchor` through
`read_token_pages` until WithSecure leaves it out. The following request is
built here from the fixed host with the token, so a host named in a response
never receives the bearer token. A refused or unreachable opening request
raises, so the scheduler records a failed poll rather than a quiet window; a
later page failing keeps the pages already read.

A BCD is updated every time a detection joins it or an analyst touches it,
so windowing on `updatedTimestamp` would raise the same BCD once per update.
The window is on `createdTimestamp` instead, which raises each BCD once, in
the poll whose window contains its creation. The window is closed at the
moment the read began: a BCD created later belongs to the next poll's window
and is raised there, not twice.

The window opens at the persisted event-time cursor rather than the clock,
as `eset_protect` does: ``checkpointed_since_seconds`` widens the lookback
to the newest `createdTimestamp` ingest has accepted, so a poll cut short by
the page bound, or a run of polls that failed, is caught up on the next
successful one, and ``apply_checkpoint`` drops what the overlap re-reads.

`archived` is not filtered on. WithSecure suggests `archived=false` to speed
up a query, but it does not document when a BCD is archived, and a filter
that could drop a BCD created inside the window costs more than a narrow
query saves.

A BCD that WithSecure closed by itself as a duplicate or a suppression —
resolution `merged`, `autoFalsePositive` or `autoAcceptedBehavior` — is not
raised. A merged BCD's detections belong to the BCD it was merged into, and
the other two were closed by a false-positive mark or a suppression rule the
organization set. Every other BCD is raised, closed or not, with its status
and resolution.

What a BCD is made of
---------------------
A BCD has a name, a severity and categories, but no host, user or process.
For each BCD in the poll, up to `_MAX_INCIDENT_LOOKUPS` of them and the most
severe first, the newest `_DETECTION_PAGE_SIZE` detections are read, and
each distinct device they name is looked up, up to `_MAX_DEVICE_LOOKUPS` a
poll. The detections and device records ride on the BCD under `detections`
and `devices`, keys the vendor's BCD does not use, so a replay of the stored
record normalizes to the same alert. Each detection is stored without its
`activityContext`: WithSecure documents it as open-ended and nothing here
reads it. The one page and that omission keep a BCD's event bounded, which
matters because the cursor only moves past what ingest accepts, so an event
ingest refuses is read again on every poll.

A failed lookup costs the context, never the BCD. A 429, or a credential
WithSecure stops accepting part-way through, stops the lookups of that kind
for the poll.

The bounds keep a whole poll inside the rate limit: at most 25 BCD pages,
one detection page for each of 50 BCDs, and 50 devices is 125 requests, well
under the 300 a minute WithSecure allows one address.

The alert's process comes from the BCD's most severe detection, the newest
one first among equals. Its user and host come from that detection too, or,
when it names none, from the first detection that does; the host's name and
addresses are always those of the device `endpoint_id` names. Every host and
ATT&CK id across the detections is kept too.

The severity ladder
-------------------
WithSecure publishes five severity levels, `info`, `low`, `medium`, `high`
and `critical`, and each maps to its own tier; `critical` stays `critical`.
A BCD without a published severity falls back to its `riskLevel`, whose top
level `severe` maps to `critical`. Anything else carries no `severity` key
rather than a guessed one.

Read-only
---------
Only `connect.api.read` is requested. Nothing here isolates a device, runs a
response action or changes a BCD.
"""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_token_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_BASE_URL = "https://api.connect.withsecure.com"

_TOKEN_PATH = "/as/token.oauth2"
_INCIDENTS_PATH = "/incidents/v1/incidents"
_DETECTIONS_PATH = "/incidents/v1/detections"
_DEVICES_PATH = "/devices/v1/devices"

#: WithSecure refuses a request without a `User-Agent`.
_USER_AGENT = "AiSOC/connectors-withsecure-elements"

#: Read-only. A read-only API client can be granted nothing else.
_SCOPE = "connect.api.read"

#: The documented maxima for `limit` on the BCD and detection lists.
_INCIDENT_PAGE_SIZE = 50
_DETECTION_PAGE_SIZE = 100

#: Seconds of headroom before a cached token's expiry. A token that expires
#: between the check and the call answers 401, which reads as a bad credential.
_TOKEN_HEADROOM_SECONDS = 60

#: BCDs one poll reads the detections of. A window with more than this many
#: new BCDs is an outbreak, and the BCDs beyond it still arrive, without
#: their host, user or process.
_MAX_INCIDENT_LOOKUPS = 50

#: Pages of detections read for one BCD, newest first. A BCD with more
#: detections than fit keeps its newest ones, which also bounds the size of
#: the event it becomes.
_DETECTION_PAGES = 1

#: The detection field left out of the stored record: open-ended per
#: WithSecure's schema, and read by nothing here.
_UNSTORED_DETECTION_FIELDS = frozenset({"activityContext"})

#: Devices one poll looks up. Each is one request, because the device list
#: filters on a single `deviceId`.
_MAX_DEVICE_LOOKUPS = 50

#: Resolutions WithSecure sets on a BCD it closed by itself, as a duplicate of
#: another BCD or by a false-positive mark or suppression rule the
#: organization made.
_SUPPRESSED_RESOLUTIONS = frozenset({"merged", "autoFalsePositive", "autoAcceptedBehavior"})

#: The vendor's published ladders. `severity` reaches `critical`; `riskLevel`
#: names its top level `severe`.
_SEVERITIES = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_RISK_LEVELS = {"info": "info", "low": "low", "medium": "medium", "high": "high", "severe": "critical"}

#: Answers that stop a poll's lookups of one kind: a rate limit, or a token
#: WithSecure refused even after it was exchanged again.
_STOP_LOOKUPS = frozenset({401, 429})

#: Rank of each tier, to order BCDs and pick a BCD's most severe detection.
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class WithSecureElementsError(RuntimeError):
    """WithSecure refused a request, with a message written for the operator."""


class WithSecureElementsConnector(BaseConnector):
    connector_id = "withsecure_elements"
    connector_name = "WithSecure Elements"
    connector_category = "edr"

    #: Event-time watermark, as in `eset_protect`: the window opens at the
    #: newest `createdTimestamp` ingest accepted, so a poll cut short or a
    #: run of failed polls is caught up rather than slid past. Both values
    #: sit at the top level of every BCD, so the base accessors read them
    #: without overrides.
    checkpoint_time_field = ("createdTimestamp",)
    checkpoint_id_field = ("incidentId",)

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "WithSecure Elements EDR Broad Context Detections via the Elements API, each raised once with "
                "the host, user, process and MITRE ATT&CK techniques of its detections. Read-only."
            ),
            docs_url="/docs/connectors/withsecure-elements",
            fields=[
                Field(
                    "client_id",
                    "string",
                    "Client ID",
                    help_text=(
                        "From an API client created in Elements Security Center under Management > Organization Settings > API clients."
                    ),
                ),
                Field(
                    "client_secret",
                    "secret",
                    "Client secret",
                ),
                Field(
                    "organization_id",
                    "string",
                    "Organization ID",
                    required=False,
                    placeholder="ec8a0100-d313-4896-b3cb-02188e060bf3",
                    help_text=(
                        "The UUID of the organization to read. Leave empty to read the API client's own organization; "
                        "a partner account sets the customer organization here."
                    ),
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        organization_id: str = "",
        transport: Any | None = None,
    ) -> None:
        organization = (organization_id or "").strip()
        if organization and not _UUID.match(organization):
            raise ValueError(f"organization_id {organization_id!r} is not a UUID; copy it from Elements Security Center")
        self._organization = organization.lower()
        self._auth = httpx.BasicAuth((client_id or "").strip(), client_secret or "")
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            timeout=timeout,
            transport=self._transport,
        )

    def _scoped(self, params: dict[str, Any]) -> dict[str, Any]:
        """``params`` with the configured organization, when there is one."""
        return {"organizationId": self._organization, **params} if self._organization else params

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._token_expires_at - _TOKEN_HEADROOM_SECONDS:
            return self._token
        try:
            response = await client.post(
                _TOKEN_PATH,
                data={"grant_type": "client_credentials", "scope": _SCOPE},
                auth=self._auth,
            )
        except httpx.HTTPError as exc:
            raise WithSecureElementsError(f"WithSecure could not be reached at {httpx.URL(_BASE_URL).host}: {exc}") from exc
        if response.status_code != 200:
            raise WithSecureElementsError(_refusal(response, "POST", _TOKEN_PATH))
        body = _json(response)
        token = _text(body.get("access_token"))
        if not token:
            raise WithSecureElementsError(f"WithSecure answered POST {_TOKEN_PATH} without an access_token.")
        expires_in = body.get("expires_in")
        lifetime = float(expires_in) if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else 1800.0
        self._token = token
        self._token_expires_at = time.time() + lifetime
        return token

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any]) -> httpx.Response:
        """One GET, fetching the token again once if a cached one is refused."""
        previous = self._token
        token = await self._access_token(client)
        response = await client.get(path, params=params, headers={"Authorization": f"Bearer {token}"})
        # Only a token reused from an earlier request is retried. A token
        # issued for this request and refused is a refusal of the credential,
        # and exchanging it again would loop.
        if response.status_code == 401 and token == previous:
            self._token = None
            token = await self._access_token(client)
            response = await client.get(path, params=params, headers={"Authorization": f"Bearer {token}"})
        return response

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client(30.0) as client:
                response = await self._get(client, _INCIDENTS_PATH, self._scoped({"limit": 1}))
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": _refusal(response, "GET", _INCIDENTS_PATH)}
            result: dict[str, Any] = {"success": True, "connector": self.connector_id}
            if self._organization:
                result["organization_id"] = self._organization
            return result
        except WithSecureElementsError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        # Open at the persisted createdTimestamp cursor rather than the clock,
        # so a poll the page bound cut short, or polls that failed, are caught
        # up. First poll, or no usable cursor, is since_seconds unchanged.
        effective_since = self.checkpointed_since_seconds(since_seconds)
        window_start = window_end - timedelta(seconds=max(1, int(effective_since)))
        params = self._scoped(
            {
                "createdTimestampStart": _millisecond(window_start),
                "createdTimestampEnd": _millisecond(window_end),
                "limit": _INCIDENT_PAGE_SIZE,
                "order": "asc",
            }
        )

        async with self._client(60.0) as client:

            async def page(anchor: str | None) -> httpx.Response:
                # Raised, not returned: on the opening page an empty list
                # would read as a quiet estate, and the scheduler records an
                # exception as the failed poll it is. A later page failing is
                # left to the reader, which keeps the pages already read.
                try:
                    response = await self._get(client, _INCIDENTS_PATH, {**params, "anchor": anchor} if anchor else params)
                except httpx.HTTPError as exc:
                    if anchor is None:
                        raise WithSecureElementsError(f"WithSecure could not be reached at {httpx.URL(_BASE_URL).host}: {exc}") from exc
                    raise
                except WithSecureElementsError as exc:
                    # A refused token exchange part-way through is a failed
                    # later page like any other. The reader keeps the pages
                    # it has on a request error, so it is handed one.
                    if anchor is None:
                        raise
                    raise httpx.RequestError(str(exc)) from exc
                if anchor is None and response.status_code != 200:
                    raise WithSecureElementsError(_refusal(response, "GET", _INCIDENTS_PATH))
                return response

            incidents = await read_token_pages(
                request=page,
                items_field="items",
                token_field="nextAnchor",
                feed="withsecure_elements.incidents",
            )

            inside: list[dict[str, Any]] = []
            seen: set[str] = set()
            suppressed = 0
            for incident in incidents:
                incident_id = _text(incident.get("incidentId"))
                if incident_id:
                    if incident_id in seen:
                        continue
                    seen.add(incident_id)
                created = _timestamp(incident.get("createdTimestamp"))
                if created is not None and not window_start <= created < window_end:
                    continue
                if _text(incident.get("resolution")) in _SUPPRESSED_RESOLUTIONS:
                    suppressed += 1
                    continue
                inside.append(incident)
            if suppressed:
                logger.info(
                    "withsecure_elements.incidents_suppressed",
                    incidents=suppressed,
                    detail="closed by WithSecure as merged, an automatic false positive or accepted behaviour",
                )

            # Dedup against the cursor and stage its advance. The advance is
            # persisted only after ingest accepts the batch (scheduler
            # ordering), so a failed hand-off re-reads rather than loses.
            fresh = self.apply_checkpoint(inside)

            detections = await self._detections(client, fresh)
            # The device each BCD is filed on first, then the other hosts its
            # detections name, so a bound that binds costs a BCD its list of
            # other hosts before it costs the host it is filed on.
            endpoints = [_endpoint_id(found) for found in detections.values()]
            others = [_device_id(d) for found in detections.values() for d in found]
            devices = await self._devices(client, [device_id for device_id in endpoints + others if device_id])

        out: list[dict[str, Any]] = []
        for incident in fresh:
            found = detections.get(_text(incident.get("incidentId")), [])
            if not found:
                out.append(self.normalize(incident))
                continue
            named = list(dict.fromkeys(_device_id(d) for d in found if _device_id(d)))
            records = [devices[device_id] for device_id in named if device_id in devices]
            enriched: dict[str, Any] = {**incident, "detections": found}
            if records:
                enriched["devices"] = records
            out.append(self.normalize(enriched))
        return out

    async def _detections(self, client: httpx.AsyncClient, incidents: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """The detections in each BCD, newest first, within the lookup budget."""
        # Most severe first, so a bound that binds costs the least severe
        # BCDs their context. The sort is stable, so equals keep their order.
        ranked = sorted(incidents, key=lambda incident: -_RANK.get(_tier(incident) or "", -1))
        wanted = list(dict.fromkeys(_text(i.get("incidentId")) for i in ranked if _UUID.match(_text(i.get("incidentId")))))
        if len(wanted) > _MAX_INCIDENT_LOOKUPS:
            logger.warning(
                "withsecure_elements.detection_lookups_capped",
                incidents=len(wanted),
                looked_up=_MAX_INCIDENT_LOOKUPS,
                detail="the BCDs beyond the bound are returned without their host, user or process",
            )
            wanted = wanted[:_MAX_INCIDENT_LOOKUPS]

        found: dict[str, list[dict[str, Any]]] = {}
        for incident_id in wanted:
            params = self._scoped({"incidentId": incident_id, "limit": _DETECTION_PAGE_SIZE})
            stopped: list[str] = []

            async def page(anchor: str | None, params: dict[str, Any] = params, stopped: list[str] = stopped) -> httpx.Response:
                try:
                    response = await self._get(client, _DETECTIONS_PATH, {**params, "anchor": anchor} if anchor else params)
                except WithSecureElementsError as exc:
                    # The token exchange was refused; every later lookup would
                    # be refused the same way.
                    stopped.append(str(exc))
                    raise httpx.RequestError(str(exc)) from exc
                if response.status_code in _STOP_LOOKUPS:
                    stopped.append(_refusal(response, "GET", _DETECTIONS_PATH))
                return response

            rows = await read_token_pages(
                request=page,
                items_field="items",
                token_field="nextAnchor",
                feed="withsecure_elements.detections",
                max_pages=_DETECTION_PAGES,
            )
            rows = [{key: value for key, value in row.items() if key not in _UNSTORED_DETECTION_FIELDS} for row in rows]
            if rows:
                found[incident_id] = rows
            if stopped:
                # The next BCD would meet the same limit or refusal.
                logger.warning(
                    "withsecure_elements.detection_lookups_stopped",
                    looked_up=len(found),
                    error=stopped[0],
                    detail="the remaining BCDs are returned without their host, user or process",
                )
                break
        return found

    async def _devices(self, client: httpx.AsyncClient, device_ids: list[str]) -> dict[str, dict[str, Any]]:
        """The record of each distinct device, in the order given, within the lookup budget."""
        wanted = list(dict.fromkeys(device_ids))
        if len(wanted) > _MAX_DEVICE_LOOKUPS:
            logger.warning(
                "withsecure_elements.device_lookups_capped",
                devices=len(wanted),
                looked_up=_MAX_DEVICE_LOOKUPS,
                detail="BCDs on the devices beyond the bound are returned without a host name",
            )
            wanted = wanted[:_MAX_DEVICE_LOOKUPS]

        devices: dict[str, dict[str, Any]] = {}
        for device_id in wanted:
            try:
                response = await self._get(client, _DEVICES_PATH, self._scoped({"deviceId": device_id}))
            except httpx.HTTPError as exc:
                logger.warning("withsecure_elements.device_lookup_failed", error=str(exc))
                continue
            except WithSecureElementsError as exc:
                stop = str(exc)
            else:
                stop = _refusal(response, "GET", _DEVICES_PATH) if response.status_code in _STOP_LOOKUPS else ""
            if stop:
                # Rate-limited, or the credential is no longer accepted: every
                # later lookup would meet the same.
                logger.warning(
                    "withsecure_elements.device_lookups_stopped",
                    looked_up=len(devices),
                    error=stop,
                    detail="the remaining BCDs are returned without a host name",
                )
                break
            if response.status_code != 200:
                logger.warning("withsecure_elements.device_lookup_failed", status=response.status_code)
                continue
            items = _json(response).get("items")
            for record in items if isinstance(items, list) else []:
                if isinstance(record, dict) and _text(record.get("id")).lower() == device_id:
                    devices[device_id] = record
                    break
        return devices

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        detections = [d for d in raw.get("detections") or [] if isinstance(d, dict)]
        devices = {_text(d.get("id")).lower(): d for d in raw.get("devices") or [] if isinstance(d, dict) and _text(d.get("id"))}
        primary = _most_severe(detections)
        endpoint_id = _endpoint_id(detections)
        # Only the device endpoint_id names, so the host columns never
        # describe a different machine from the one the alert is filed on.
        device = devices.get(endpoint_id, {})
        operating_system = _object(device.get("os"))

        mitre = [value for d in detections for value in _strings(d.get("mitre"))]
        exe_hash = _text(primary.get("exeHash"))
        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _text(raw.get("incidentId")),
            "title": _text(raw.get("name")) or "WithSecure Elements Broad Context Detection",
            "description": _text(raw.get("description")) or _text(primary.get("description")),
            "created_at": _text(raw.get("createdTimestamp")),
            "incident_public_id": _text(raw.get("incidentPublicId")),
            "status": _text(raw.get("status")),
            "resolution": _text(raw.get("resolution")),
            "risk_score": _number(raw.get("riskScore")),
            "categories": _strings(raw.get("categories")),
            "sources": _strings(raw.get("sources")),
            "detection_count": len(detections) or None,
            "detection_names": list(dict.fromkeys(_text(d.get("name")) for d in detections if _text(d.get("name")))),
            "mitre_techniques": list(dict.fromkeys(v for v in mitre if _TECHNIQUE.match(v))),
            "mitre_tactics": list(dict.fromkeys(v for v in mitre if _TACTIC.match(v))),
            "process_name": _text(primary.get("exeName")),
            "process_path": _text(primary.get("exePath")),
            "command_line": _text(primary.get("cmdl")),
            "sha1": exe_hash.lower() if _SHA1.match(exe_hash) else "",
            "sha256": exe_hash.lower() if _SHA256.match(exe_hash) else "",
            "actor": _text(primary.get("username")) or next((_text(d.get("username")) for d in detections if _text(d.get("username"))), ""),
            "endpoint_id": endpoint_id,
            "hostname": _text(device.get("name")),
            "hostnames": list(dict.fromkeys(_text(d.get("name")) for d in devices.values() if _text(d.get("name")))),
            "src_ip": _first_address(device.get("ipAddresses")),
            "external_ip": _address(device.get("publicIpAddress")),
            "os": " ".join(part for part in (_text(operating_system.get("name")), _text(operating_system.get("version"))) if part),
            "raw_event": raw,
        }
        severity = _tier(raw)
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "", [])}


def _most_severe(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """The detection with the highest severity, the newest first among equals; empty when there are none."""
    best: dict[str, Any] = {}
    best_key: tuple[int, str] | None = None
    for detection in detections:
        key = (_RANK.get(_tier(detection) or "", -1), _text(detection.get("createdTimestamp")))
        if best_key is None or key > best_key:
            best, best_key = detection, key
    return best


def _endpoint_id(detections: list[dict[str, Any]]) -> str:
    """The device a BCD is filed on: its most severe detection's, else the first one named."""
    return _device_id(_most_severe(detections)) or next((_device_id(d) for d in detections if _device_id(d)), "")


def _tier(record: dict[str, Any]) -> str | None:
    """The tier of a BCD or detection: its `severity`, else its `riskLevel`, else none."""
    return _SEVERITIES.get(_text(record.get("severity")).lower()) or _RISK_LEVELS.get(_text(record.get("riskLevel")).lower())


def _refusal(response: httpx.Response, method: str, path: str) -> str:
    message = f"WithSecure answered HTTP {response.status_code} to {method} {path}: {response.text[:300]}"
    if response.status_code in (400, 401) and path == _TOKEN_PATH:
        message += (
            " Check the client ID and secret, and that the API client was created in Elements Security Center"
            " under Management > Organization Settings > API clients."
        )
    elif response.status_code == 401:
        message += " The access token was refused; check that the API client still exists."
    elif response.status_code == 403:
        message += " The API client is valid but may not read this organization; check its scope and the organization ID."
    elif response.status_code == 404:
        message += " The organization was not found, or is outside this API client's scope; check the organization ID."
    elif response.status_code == 429:
        message += " The API rate limit is reached; the next poll retries."
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


def _strings(value: Any) -> list[str]:
    """The non-empty strings of a JSON array, in order."""
    if not isinstance(value, list):
        return []
    return [text for text in (_text(item) for item in value) if text]


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _first_address(value: Any) -> str:
    """The first well-formed address in WithSecure's comma-separated list, without a prefix length."""
    for piece in _text(value).split(","):
        address = _address(piece.split("/", 1)[0])
        if address:
            return address
    return ""


def _address(value: Any) -> str:
    """``value`` as a canonical IP address, or empty when it is not one."""
    try:
        return str(ipaddress.ip_address(_text(value)))
    except ValueError:
        return ""


def _device_id(detection: dict[str, Any]) -> str:
    """The detection's device id, lower-cased, or empty unless it is a well-formed UUID."""
    value = _text(detection.get("deviceId"))
    return value.lower() if _UUID.match(value) else ""


def _millisecond(moment: datetime) -> str:
    """An RFC 3339 UTC timestamp at millisecond precision, the form WithSecure stamps."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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
