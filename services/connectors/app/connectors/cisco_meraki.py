"""Cisco Meraki MX security events, read through the Dashboard API v1.

Vendor reference, from the Meraki Dashboard API documentation
(`https://developer.cisco.com/meraki/api-v1/`) and the OpenAPI document it is
generated from (`https://github.com/meraki/openapi`):

* **Where.** Each Meraki dashboard is its own API host, and an organization
  lives in exactly one of them:

      Most of the world    https://api.meraki.com/api/v1
      Canada               https://api.meraki.ca/api/v1
      China                https://api.meraki.cn/api/v1
      India                https://api.meraki.in/api/v1
      US FedRAMP           https://api.gov-meraki.com/api/v1

  The region is a fixed choice of five, not a URL, so the API key can only
  ever be sent to a Meraki host.

* **Authentication.** A dashboard API key, sent as
  `Authorization: Bearer <key>`. A key carries the permissions of the
  administrator who generated it, so a read-only organization administrator
  is enough for everything here.

* **Security events.** `GET /organizations/{organizationId}/appliance/security/events`
  lists the MX security appliance's intrusion detection alerts (`IDS Alert`),
  the Advanced Malware Protection verdicts on downloaded files
  (`File Scanned`) and TLS decryption failures (`TLS Decrypt Alert`) across
  every network in the organization. It takes `t0` and `t1` for the window,
  `perPage` (3 to 1000), and `sortOrder` (`ascending` by detection time, the
  default). The body is a JSON array; further pages are named by the
  response's RFC 8288 `Link` header, whose `next` link carries the
  server-defined `startingAfter` token.

* **Redirects.** The dashboard may answer with a redirect to the shard host
  that serves the organization (`n123.meraki.com`), and Meraki's own SDK
  follows it. A redirect, like a `next` link, is followed only to an HTTPS
  host inside the configured region's domain, so the API key never leaves
  Meraki. One outside it is refused and reported.

Reading the window to the end
-----------------------------
The read follows the `next` link until it is absent or a page comes back
empty, within the shared 25-page bound, which is logged when it binds. A
refused or unreachable opening request raises, so a failure is not read as a
quiet network. A later page failing keeps the pages already read.

The events are read oldest first, so a read cut short by the page bound, a
429 or a failed page always stops at a point in time: the cursor rests on the
newest event kept, and the next window opens there (#1860), so whatever came
after it is requested again rather than slid past.

The window overlaps the previous poll by one interval as well (#1971). The
scheduler drops a run when the previous poll is still active, and without
the overlap the interval in between would never be requested.

The identity of an event
------------------------
Meraki gives a security event no id. The cursor's tie-breaker, and the
alert's `external_id`, is `row_id`: a digest of the whole event as Meraki
sent it, added to the record before it is checkpointed. The same event
re-read by an overlapping window digests to the same value and is dropped
against the cursor.

What is read, and what is not
-----------------------------
This connector's events are filed as OCSF 2001 Security Findings, which
fusion promotes unconditionally, so only events that rate as a threat are
returned:

* an `IDS Alert` is rated by its Snort `priority` — Meraki's IDS runs Snort
  rules, and its `ruleId` says so (`meraki:intrusion/snort/GID/1/SID/...`);
* a `File Scanned` event is rated when its `disposition` is `Malicious`.

A TLS decryption failure, a file scanned clean, and any event type Meraki
adds later carry no rating; they are skipped, and how many a poll skipped is
logged as `cisco_meraki.unrated_events_skipped`.

The severity ladder
-------------------
Snort's priorities run from 1, the most severe, to 4: `1` → `high`,
`2` → `medium`, `3` → `low`, `4` → `info`. Snort publishes no level above
its first, so nothing is raised as `critical`. A file AMP judged malicious
is `high`. Any other value carries no `severity` key rather than a guessed
one.

Read-only
---------
Nothing here changes a rule, a policy or a client.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

#: One dashboard per region: its API base, and the domain every host the key
#: is sent to must sit inside. An organization exists in one of them only.
_REGIONS: dict[str, tuple[str, str]] = {
    "global": ("https://api.meraki.com/api/v1", "meraki.com"),
    "canada": ("https://api.meraki.ca/api/v1", "meraki.ca"),
    "china": ("https://api.meraki.cn/api/v1", "meraki.cn"),
    "india": ("https://api.meraki.in/api/v1", "meraki.in"),
    "fedramp": ("https://api.gov-meraki.com/api/v1", "gov-meraki.com"),
}

#: The documented maximum for `perPage`.
_PAGE_SIZE = 1000

#: Redirects followed for one request. The dashboard sends at most one, to
#: the organization's shard; this only bounds a server that keeps going.
_MAX_REDIRECTS = 3

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: Meraki organization ids are numeric; letters, `_` and `-` are allowed so a
#: format change is not refused, but nothing that could leave the path is.
_ORGANIZATION_ID = re.compile(r"[A-Za-z0-9_-]+")

#: Snort's priorities, as Meraki reports them on an IDS alert. Four entries
#: because Snort defines four.
_IDS_PRIORITIES = {"1": "high", "2": "medium", "3": "low", "4": "info"}


class CiscoMerakiError(RuntimeError):
    """The Meraki dashboard refused a request, with a message written for the operator."""


class CiscoMerakiConnector(BaseConnector):
    connector_id = "cisco_meraki"
    connector_name = "Cisco Meraki"
    connector_category = "network"

    #: The cursor resumes on the detection time, with the event digest
    #: breaking ties within one instant (#1860, #1971).
    checkpoint_time_field = ("ts",)
    checkpoint_id_field = ("row_id",)

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Cisco Meraki MX security appliance events — intrusion detection alerts and files Advanced "
                "Malware Protection judged malicious — across every network in an organization, via the "
                "Dashboard API v1. Read-only."
            ),
            docs_url="/docs/connectors/cisco-meraki",
            fields=[
                Field(
                    "region",
                    "select",
                    "Dashboard region",
                    options=[
                        {"value": "global", "label": "Most of the world (api.meraki.com)"},
                        {"value": "canada", "label": "Canada (api.meraki.ca)"},
                        {"value": "china", "label": "China (api.meraki.cn)"},
                        {"value": "india", "label": "India (api.meraki.in)"},
                        {"value": "fedramp", "label": "US FedRAMP (api.gov-meraki.com)"},
                    ],
                    help_text="The Meraki dashboard the organization lives in.",
                ),
                Field(
                    "organization_id",
                    "string",
                    "Organization ID",
                    help_text="Shown at the foot of every dashboard page, and returned by GET /organizations.",
                ),
                Field(
                    "api_key",
                    "secret",
                    "API key",
                    help_text=(
                        "Generated under My profile → API access by an administrator of the organization. "
                        "Read-only organization access is enough."
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
        region: str,
        organization_id: str,
        api_key: str,
        transport: Any | None = None,
    ) -> None:
        region_key = (region or "").strip().lower()
        if region_key not in _REGIONS:
            raise ValueError(f"region {region!r} is not a Meraki dashboard region; expected one of {', '.join(_REGIONS)}")
        organization = (organization_id or "").strip()
        if not _ORGANIZATION_ID.fullmatch(organization):
            raise ValueError(f"organization_id {organization_id!r} is not a Meraki organization id")
        self._region = region_key
        self._base, self._domain = _REGIONS[region_key]
        self._organization_id = organization
        self._events_url = f"{self._base}/organizations/{organization}/appliance/security/events"
        self._api_key = (api_key or "").strip()
        self._transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        # Redirects are followed by hand in `_get`, never by httpx, so the
        # key is only re-sent once the target has been checked.
        return httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"},
            timeout=timeout,
            follow_redirects=False,
            transport=self._transport,
        )

    def _permitted_target(self, base: httpx.URL, reference: str) -> httpx.URL | None:
        """``reference`` resolved against ``base``, or None unless it is an HTTPS address of this region's dashboard."""
        try:
            target = base.join(reference)
        except httpx.InvalidURL:
            return None
        host = (target.host or "").lower()
        permitted = target.scheme == "https" and target.port in (None, 443) and (host == self._domain or host.endswith("." + self._domain))
        return target if permitted else None

    async def _get(self, client: httpx.AsyncClient, url: str | httpx.URL, params: dict[str, Any] | None = None) -> httpx.Response:
        """GET ``url``, following redirects that stay inside the region's domain.

        A redirect anywhere else is returned unfollowed, and the caller
        reports it as the refusal it is.
        """
        response = await client.get(url, params=params)
        for _ in range(_MAX_REDIRECTS):
            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_STATUSES or not location:
                return response
            target = self._permitted_target(response.url, location)
            if target is None:
                return response
            # The location already carries the query string.
            response = await client.get(target)
        return response

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client(30.0) as client:
                response = await self._get(client, self._events_url, params={"perPage": 3, "timespan": 3600})
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": self._refusal(response)}
            return {
                "success": True,
                "connector": self.connector_id,
                "region": self._region,
                "organization_id": self._organization_id,
            }
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        # Two intervals of overlap plus the persisted cursor (#1971): the
        # scheduler drops a run when the previous poll is still active, and
        # without the overlap the interval between the two polls would never
        # be requested. The cursor covers anything longer than one skipped
        # run; apply_checkpoint below drops the rows the overlap re-reads.
        effective_since = self.contiguous_since_seconds(since_seconds, now=window_end)
        window_start = window_end - timedelta(seconds=max(1, int(effective_since)))
        params = {
            "t0": _stamp(window_start),
            "t1": _stamp(window_end),
            "perPage": _PAGE_SIZE,
            "sortOrder": "ascending",
        }

        async with self._client(60.0) as client:
            events = await self._read_events(client, params)

        rated: list[dict[str, Any]] = []
        unrated: Counter[str] = Counter()
        for event in events:
            if _severity(event) is None:
                unrated[_text(event.get("eventType")) or "(none)"] += 1
                continue
            rated.append({**event, "row_id": _digest(event)})
        if unrated:
            logger.info(
                "cisco_meraki.unrated_events_skipped",
                skipped=sum(unrated.values()),
                returned=len(rated),
                event_types=dict(unrated),
                detail="TLS decryption failures and files scanned clean are not threats; only rated events are raised",
            )
        # Dedup against the cursor and stage its advance. The overlapped
        # window deliberately re-reads the previous interval; this is what
        # drops those rows, and the advance is persisted only after ingest
        # accepts the batch (scheduler ordering).
        rated = self.apply_checkpoint(rated)
        return [self.normalize(event) for event in rated]

    async def _read_events(self, client: httpx.AsyncClient, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Every event in the window, following the `next` link to the end."""
        # Raised, not returned: an empty list would read as a quiet network,
        # and the scheduler records an exception as the failed poll it is.
        response = await self._get(client, self._events_url, params=params)
        if response.status_code != 200:
            raise CiscoMerakiError(self._refusal(response))
        page = _rows(response)
        if page is None:
            raise CiscoMerakiError(f"Meraki answered GET {self._path} with a body that is not a JSON array: {response.text[:300]}")

        events = list(page)
        for _ in range(DEFAULT_MAX_PAGES - 1):
            link = response.links.get("next", {}).get("url")
            # An empty page ends the read even beside a next link, as it
            # does for every Link-header collection read here.
            if not page or not link:
                return events
            target = self._permitted_target(response.url, link)
            if target is None:
                logger.warning("cisco_meraki.next_link_refused", link=link[:200], events=len(events))
                return events
            try:
                response = await self._get(client, target)
            except httpx.HTTPError as exc:
                # Keep what was read. Oldest first, so the cursor stops at
                # the last event kept and the next poll reads on from there.
                logger.warning("cisco_meraki.next_page_error", events=len(events), error=str(exc))
                return events
            if response.status_code != 200:
                logger.warning(
                    "cisco_meraki.next_page_failed",
                    status=response.status_code,
                    events=len(events),
                    body=response.text[:300],
                )
                return events
            page = _rows(response)
            if page is None:
                logger.warning("cisco_meraki.next_page_unparseable", events=len(events))
                return events
            events.extend(page)

        if page and response.links.get("next"):
            logger.warning(
                "connector.paging.page_cap_reached",
                feed="cisco_meraki.security_events",
                pages=DEFAULT_MAX_PAGES,
                rows=len(events),
                detail="the window was not read to the end; the next poll opens at the cursor and reads on",
            )
        return events

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        event_type = _text(raw.get("eventType"))
        # The most specific name the event carries: an IDS alert's rule
        # message, or the malware name AMP gave a file.
        name = _text(raw.get("message")) or _text(raw.get("canonicalName"))
        if event_type and name:
            title = f"{event_type}: {name}"
        else:
            title = event_type or name or "Cisco Meraki security event"

        src_ip, src_port = _endpoint(raw.get("srcIp"))
        dst_ip, dst_port = _endpoint(raw.get("destIp"))

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _text(raw.get("row_id")),
            "title": title,
            "event_type": event_type,
            "created_at": _text(raw.get("ts")),
            "hostname": _text(raw.get("clientName")),
            "src_ip": src_ip or _address(raw.get("clientIp")),
            "src_port": _port(raw.get("sourcePort")) or src_port,
            "dst_ip": dst_ip,
            "dst_port": _port(raw.get("destinationPort")) or dst_port,
            "protocol": _text(raw.get("protocol")),
            "client_mac": _text(raw.get("clientMac")),
            "appliance_mac": _text(raw.get("deviceMac")),
            "url": _text(raw.get("uri")),
            "signature": _text(raw.get("signature")),
            "rule_id": _text(raw.get("ruleId")),
            "malware_name": _text(raw.get("canonicalName")),
            "sha256": _text(raw.get("fileHash")),
            "file_type": _text(raw.get("fileType")),
            "disposition": _text(raw.get("disposition")),
            "action": _action(raw),
            "raw_event": raw,
        }
        severity = _severity(raw)
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "", [])}

    @property
    def _path(self) -> str:
        return f"/organizations/{self._organization_id}/appliance/security/events"

    def _refusal(self, response: httpx.Response) -> str:
        status = response.status_code
        if status in _REDIRECT_STATUSES:
            return (
                f"Meraki answered GET {self._path} with a redirect to {response.headers.get('location', '')[:200]!r}, "
                f"which is not an HTTPS host of the {self._domain} dashboard; the API key is not sent there."
            )
        message = f"Meraki answered HTTP {status} to GET {self._path}: {response.text[:300]}"
        if status == 401:
            message += " Check the API key, and that the region matches the dashboard the organization lives in."
        elif status == 403:
            message += " The key's administrator has no access to this organization."
        elif status == 404:
            message += (
                " Check the organization ID, and that API access is enabled under Organization → Settings; "
                "an organization in another region is not found here either."
            )
        elif status == 429:
            message += " The organization's API rate limit is exhausted, often by another integration; the next poll retries."
        return message


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _stamp(moment: datetime) -> str:
    """ISO 8601 in UTC, to the second, as `t0` and `t1` take it."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rows(response: httpx.Response) -> list[dict[str, Any]] | None:
    """The events on one page, or None when the body is not a JSON array."""
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, list):
        return None
    return [row for row in body if isinstance(row, dict)]


def _digest(event: dict[str, Any]) -> str:
    """A stable identity for an event Meraki gives no id: a digest of the whole record."""
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _severity(raw: dict[str, Any]) -> str | None:
    event_type = _text(raw.get("eventType")).lower()
    if event_type == "ids alert":
        priority = raw.get("priority")
        if isinstance(priority, bool):
            return None
        if isinstance(priority, int):
            priority = str(priority)
        return _IDS_PRIORITIES.get(_text(priority))
    if event_type == "file scanned" and _text(raw.get("disposition")).lower() == "malicious":
        return "high"
    return None


def _action(raw: dict[str, Any]) -> str:
    """What the appliance did: AMP's `action`, or an IDS alert's `blocked` flag."""
    action = _text(raw.get("action")).lower()
    if action:
        return action
    blocked = raw.get("blocked")
    if blocked is True:
        return "blocked"
    if blocked is False:
        return "allowed"
    return ""


def _address(value: Any) -> str:
    """``value`` when it is an IP address, otherwise an empty string."""
    text = _text(value)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    return value if isinstance(value, int) and 0 < value <= 65535 else None


def _endpoint(value: Any) -> tuple[str, int | None]:
    """Address and port from `srcIp` / `destIp`.

    Meraki writes an IDS alert's ends as `address:port` and a scanned file's
    as a bare address. An IPv6 end is bracketed when it carries a port.
    """
    text = _text(value)
    if not text:
        return "", None
    address = _address(text)
    if address:
        return address, None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return _address(host), _port(rest[1:]) if rest.startswith(":") else None
    host, _, port = text.rpartition(":")
    address = _address(host)
    return (address, _port(port)) if address else ("", None)
