"""Vectra AI Platform network detections, read through the v3.4 REST API.

Vendor reference: the Vectra AI Platform (Respond UX) API guide
(`https://docs.vectra.ai/configuration/access/api-rux/v34-api-guide-rux`) and
the API reference at `https://apidocs.vectra.ai/`.

* **Where.** Each tenant has its own portal, `https://<id>.<region>.portal.vectra.ai`,
  shown in the console's address bar. Every request goes to that host, and
  only over HTTPS.

* **Authentication.** OAuth2 client credentials. An API client created under
  Configuration > Access > API Clients has a client ID and a secret key; the
  exchange is

      POST {portal}/oauth2/token
      Authorization: Basic base64(client_id:secret_key)
      Content-Type: application/x-www-form-urlencoded
      grant_type=client_credentials

  and answers `{access_token, expires_in, ...}`. The access token is sent as
  `Authorization: Bearer <token>`.

* **Detection events.** `GET /api/v3.4/events/detections` with
  `event_timestamp_gte`, `limit` and `from`. The response is
  `{events, next_checkpoint, remaining_count}`: while `remaining_count` is
  above zero there is more, and the next page is requested with
  `from=<next_checkpoint>`. Each event carries `id`, `detection_id`,
  `detection_type`, `d_type_vname`, `category`, `detection_href`, `url`,
  `entity_id`, `entity_uid`, `src_entity`, `type` (`host` or `account`),
  `event_timestamp`, `mitre`, `triaged`, `threat`, `certainty` and `severity`.
  Detections in the `info` category are left out unless the request asks for
  them, and this one does not.

Reading the window
------------------
The read opens at the window's start, through `event_timestamp_gte`, and
follows `next_checkpoint` until `remaining_count` reaches zero. Every request
is built here from the configured portal, so the credential is never sent to
a host named in a response. The window is closed at the moment the read
began: an event stamped later belongs to the next poll's window, which opens
there, and is raised then rather than twice. A refused or unreachable opening
request raises, so the scheduler records a failed poll rather than a quiet
window; a later page failing keeps the pages already read.

One alert per detection
-----------------------
The events stream emits a detection again each time Vectra updates it. The
vendor's finding is the detection, so `detection_id` is the `external_id`,
and a poll that reads several events for one detection returns only the
newest of them. A detection a customer triage rule has already marked
(`triaged: true`) is expected behaviour by the customer's own rule and is not
raised.

Why there is no severity
------------------------
Vectra does not publish a severity tier for an individual detection on this
platform. Its own guidance is that "individual detections are no longer
scored": prioritisation happens on the host or account entity. The event's
`threat` and `certainty` are legacy scores that are often zero, and its
integer `severity` is not documented. Mapping any of them onto a tier would
put a guess in the vendor's name, so no `severity` key is emitted, the same
as an unscored ExtraHop detection. The ingest profile files `vectra_ai` at
`class_uid: 2001`, which the fusion promoter promotes regardless of severity,
and all three numbers stay in `raw_event` as the vendor sent them.

Read-only
---------
Nothing here closes, tags, assigns or triages a detection.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_TOKEN_PATH = "/oauth2/token"
_EVENTS_PATH = "/api/v3.4/events/detections"

#: Events per page. Vectra's own integrations read the stream 500 at a time.
_PAGE_SIZE = 500

#: Seconds of headroom before a cached token's expiry. A token that expires
#: between the check and the call answers 401, which reads as a bad credential.
_TOKEN_HEADROOM_SECONDS = 60

#: A MITRE ATT&CK technique or sub-technique id.
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class VectraAIError(RuntimeError):
    """Vectra refused a request, with a message written for the operator."""


class VectraAIConnector(BaseConnector):
    connector_id = "vectra_ai"
    connector_name = "Vectra AI Platform"
    connector_category = "ndr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Network, identity and cloud detections from the Vectra AI Platform via the v3.4 detection "
                "events API, one alert per detection with its host or account. Read-only: nothing here "
                "closes, tags or triages a detection."
            ),
            docs_url="/docs/connectors/vectra-ai",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Portal URL",
                    placeholder="https://123456789012.uw2.portal.vectra.ai",
                    help_text="The address of your Vectra AI Platform console. HTTPS only.",
                ),
                Field(
                    "client_id",
                    "string",
                    "API client ID",
                    help_text="Created under Configuration > Access > API Clients, with a role that can read detections.",
                ),
                Field(
                    "client_secret",
                    "secret",
                    "API client secret key",
                    help_text="Shown once, when the API client is created.",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(self, base_url: str, client_id: str, client_secret: str, transport: Any | None = None) -> None:
        self._base_url = _portal(base_url)
        self._auth = httpx.BasicAuth((client_id or "").strip(), (client_secret or "").strip())
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _client(self, timeout: float) -> httpx.AsyncClient:
        if not self._base_url.startswith("https://"):
            raise VectraAIError(f"The portal URL must use HTTPS, so the API client secret is never sent in clear; got {self._base_url!r}.")
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Accept": "application/json"},
            timeout=timeout,
            transport=self._transport,
        )

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._token_expires_at - _TOKEN_HEADROOM_SECONDS:
            return self._token
        try:
            response = await client.post(_TOKEN_PATH, auth=self._auth, data={"grant_type": "client_credentials"})
        except httpx.HTTPError as exc:
            raise VectraAIError(f"Vectra could not be reached at {self._base_url}: {exc}") from exc
        if response.status_code != 200:
            raise VectraAIError(_refusal(response, "POST", _TOKEN_PATH))
        body = _json(response)
        token = _text(body.get("access_token"))
        if not token:
            raise VectraAIError(f"Vectra answered POST {_TOKEN_PATH} without an access_token.")
        expires_in = body.get("expires_in")
        lifetime = float(expires_in) if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else 3600.0
        self._token = token
        self._token_expires_at = time.time() + lifetime
        return token

    async def _get_events(self, client: httpx.AsyncClient, params: dict[str, Any]) -> httpx.Response:
        """One events request, fetching the token again once if a cached one is refused."""
        cached = self._token is not None
        token = await self._access_token(client)
        response = await client.get(_EVENTS_PATH, params=params, headers={"Authorization": f"Bearer {token}"})
        if response.status_code == 401 and cached:
            self._token = None
            token = await self._access_token(client)
            response = await client.get(_EVENTS_PATH, params=params, headers={"Authorization": f"Bearer {token}"})
        return response

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client(30.0) as client:
                response = await self._get_events(client, {"limit": 1})
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": _refusal(response, "GET", _EVENTS_PATH)}
            return {"success": True, "connector": self.connector_id}
        except VectraAIError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        window_start = window_end - timedelta(seconds=max(1, int(since_seconds)))
        # Second precision is what the vendor stamps, so the request opens at
        # the start of the window's first second and the exact edge is
        # applied below.
        opens = window_start.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

        async with self._client(60.0) as client:
            events = await self._read(client, opens)

        newest: dict[str, dict[str, Any]] = {}
        unidentified: list[dict[str, Any]] = []
        for event in events:
            stamped = _timestamp(event.get("event_timestamp"))
            if stamped is not None and not window_start <= stamped < window_end:
                continue
            if event.get("triaged") is True:
                continue
            detection_id = _identifier(event.get("detection_id"))
            if not detection_id:
                unidentified.append(event)
                continue
            if _sequence(event) >= _sequence(newest.get(detection_id)):
                newest[detection_id] = event

        return [self.normalize(event) for event in [*newest.values(), *unidentified]]

    async def _read(self, client: httpx.AsyncClient, opens: str) -> list[dict[str, Any]]:
        """Every event from ``opens`` onward, following ``next_checkpoint``."""
        params: dict[str, Any] = {"event_timestamp_gte": opens, "limit": _PAGE_SIZE}
        # Raised, not returned: on the opening page an empty list would read
        # as a quiet network, and the scheduler records an exception as the
        # failed poll it is.
        try:
            response = await self._get_events(client, params)
        except httpx.HTTPError as exc:
            raise VectraAIError(f"Vectra could not be reached at {self._base_url}: {exc}") from exc
        if response.status_code != 200:
            raise VectraAIError(_refusal(response, "GET", _EVENTS_PATH))

        body = _json(response)
        events = _rows(body)
        for page in range(1, DEFAULT_MAX_PAGES):
            checkpoint = _more(body)
            if checkpoint is None:
                return events
            try:
                response = await self._get_events(client, {**params, "from": checkpoint})
            except (httpx.HTTPError, VectraAIError) as exc:
                # Keep what was read. A failure on page four is not a reason
                # to discard pages one to three.
                logger.warning(
                    "connector.paging.token_page_error", feed="vectra_ai.detections", page=page, rows=len(events), error=str(exc)
                )
                return events
            if response.status_code != 200:
                logger.warning(
                    "connector.paging.token_page_failed",
                    feed="vectra_ai.detections",
                    page=page,
                    status=response.status_code,
                    rows=len(events),
                    body=response.text[:300],
                )
                return events
            body = _json(response)
            events.extend(_rows(body))

        if _more(body) is not None:
            logger.warning(
                "connector.paging.page_cap_reached",
                feed="vectra_ai.detections",
                pages=DEFAULT_MAX_PAGES,
                rows=len(events),
                detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
            )
        return events

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        entity_type = _text(raw.get("type")).lower()
        entity = _text(raw.get("entity_name")) or _text(raw.get("src_entity")) or _text(raw.get("entity_uid"))
        detection = _text(raw.get("d_type_vname")) or _text(raw.get("detection_type"))
        category = _text(raw.get("category"))

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _identifier(raw.get("detection_id")),
            "event_id": _identifier(raw.get("id")),
            "title": detection or "Vectra AI detection",
            "description": _description(detection, category, entity_type, entity),
            "created_at": _text(raw.get("event_timestamp")),
            "event_type": _text(raw.get("detection_type")),
            "category": category,
            "url": _text(raw.get("detection_href")) or _text(raw.get("url")),
            "entity_type": entity_type,
            "entity_id": _identifier(raw.get("entity_id")),
            "mitre_techniques": _techniques(raw.get("mitre")),
            "raw_event": raw,
        }
        # A host detection names a machine and an account detection names a
        # principal. Putting either in the other's column would give fusion a
        # wrong correlation key, so an entity of any other type fills neither.
        if entity_type == "host":
            event["hostname"] = entity
        elif entity_type == "account":
            event["actor"] = entity
        return {key: value for key, value in event.items() if value not in (None, "", [])}


def _portal(value: str) -> str:
    """The portal origin, with `https://` assumed when no scheme is given."""
    text = (value or "").strip().rstrip("/")
    if text and "://" not in text:
        text = f"https://{text}"
    return text


def _refusal(response: httpx.Response, method: str, path: str) -> str:
    message = f"Vectra answered HTTP {response.status_code} to {method} {path}: {response.text[:300]}"
    if response.status_code == 401:
        message += " Check the API client ID and secret key; the secret is shown once, when the client is created."
    elif response.status_code == 403:
        message += " The API client is valid but its role does not allow reading detections."
    elif response.status_code == 429:
        message += " The tenant's API rate limit is exhausted; the next poll retries."
    return message


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    events = body.get("events")
    return [event for event in events if isinstance(event, dict)] if isinstance(events, list) else []


def _more(body: dict[str, Any]) -> int | None:
    """The checkpoint to read from next, or None when the stream has been read to the end.

    Only a positive `remaining_count` is a promise of more events, and only an
    integer checkpoint is put into a request.
    """
    remaining = body.get("remaining_count")
    checkpoint = body.get("next_checkpoint")
    if isinstance(remaining, bool) or not isinstance(remaining, int) or remaining <= 0:
        return None
    if isinstance(checkpoint, bool) or not isinstance(checkpoint, int):
        return None
    return checkpoint


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _identifier(value: Any) -> str:
    """A numeric id as text."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return _text(value)


def _sequence(event: dict[str, Any] | None) -> int:
    """Where an event sits in the stream: its integer `id`, which `next_checkpoint` counts in.

    Compared rather than trusting arrival order, so the newest event of a
    detection wins however a page happens to be ordered. An event without an
    integer id sorts first, and a tie goes to the event read later.
    """
    value = (event or {}).get("id")
    return value if isinstance(value, int) and not isinstance(value, bool) else -1


def _timestamp(value: Any) -> datetime | None:
    """An ISO 8601 timestamp as an aware datetime, or None."""
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _techniques(value: Any) -> list[str]:
    """The ATT&CK technique ids, shape-checked and de-duplicated in order."""
    if not isinstance(value, list):
        return []
    ids = (entry.strip().upper() for entry in value if isinstance(entry, str))
    return list(dict.fromkeys(i for i in ids if _TECHNIQUE.match(i)))


def _description(detection: str, category: str, entity_type: str, entity: str) -> str:
    if not detection:
        return ""
    sentence = f"Vectra AI detected {detection}"
    if category:
        sentence += f" ({category.replace('_', ' ')})"
    if entity and entity_type in ("host", "account"):
        sentence += f" on {entity_type} {entity}"
    return sentence + "."
