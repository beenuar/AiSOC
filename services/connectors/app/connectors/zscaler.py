"""
Zscaler connector.

Reads ZIA **admin audit logs** — every policy change, sign-in and API call
recorded by the ZIA Admin Portal — through the documented report flow:
``POST /auditlogEntryReport`` for a window, poll the status until
``COMPLETE``, then download the CSV.

Why audit logs and not web traffic
----------------------------------
The previous implementation POSTed ``startTime/endTime/pageSize`` to
``/api/v1/webApplicationRules``. In Zscaler's published API,
``webApplicationRules`` is the Cloud App Control **policy** resource — its
routes are ``GET /webApplicationRules/{rule_type}`` and friends, and the only
POST it serves *creates a rule*. There is no bare-collection POST and no
event semantics, so that request has never returned an event on any
deployment; the stream was dead from the day it shipped. ZIA publishes **no
pull API for web transaction logs at all** — those leave via NSS/Cloud NSS
push — and Security & UEBA alert *events* leave via webhooks. The admin
audit log report is the one event feed ZIA documents for pulling, so it is
what this connector reads: an admin disabling a policy, a new API key, a
failed portal sign-in are exactly the control-plane changes a SOC wants from
its secure web gateway.

Vendor contract (help.zscaler.com, "Downloading Audit Logs … Using API"):
``POST /auditlogEntryReport`` with ``startTime``/``endTime`` in epoch
milliseconds (optionally ``page``/``pageSize``) answers ``{status,
statusId}``; ``GET /auditlogEntryReport?statusId=…`` is polled until a
terminal status (``COMPLETE``/``CANCELLED``/``ERRORED``/``STOP``); ``GET
/auditlogEntryReport/download?statusId=…`` returns the CSV. A report covers
at most 31 days or 1,000 records; a new POST overwrites the previous report.
The CSV opens with preamble rows (administrator, creation time, window) and
the column header starts at the ``Time`` column. Row timestamps are rendered
in the **admin account's configured timezone** with an abbreviation, e.g.
``"26 Mar 2026 00:30:19, PDT"``.

Severity: audit entries carry none, and none is invented — the rows ship
without a ``severity`` key for the same reason the Sophos connector never
emits a tier its vendor did not set.

The window overlaps the previous poll by one interval and the event-time
cursor drops the re-read rows (#1970/#1971), so a scheduler-skipped run is
covered without duplicates.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import time
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REPORT_PATH = "/api/v1/auditlogEntryReport"
_PAGE_SIZE = 1000  # the vendor's documented per-report maximum
_MAX_PAGES = 5  # continuation bound per poll; the cap is announced if it binds
_POLL_INTERVAL_S = 2.0
_POLL_BUDGET_S = 90.0
_TERMINAL = {"COMPLETE", "CANCELLED", "ERRORED", "STOP"}

# The report renders times in the admin's configured timezone as an
# abbreviation. Abbreviations are ambiguous in general; this maps the
# unambiguous and most common ones and leaves the rest unparsed — an
# unparseable time never drops a row, it only omits created_at (the
# cursor then orders that row by text, the documented degradation).
_TZ_OFFSETS_MIN = {
    "UTC": 0,
    "GMT": 0,
    "PST": -8 * 60,
    "PDT": -7 * 60,
    "MST": -7 * 60,
    "MDT": -6 * 60,
    "CST": -6 * 60,
    "CDT": -5 * 60,
    "EST": -5 * 60,
    "EDT": -4 * 60,
    "BST": 60,
    "CET": 60,
    "CEST": 120,
    "IST": 5 * 60 + 30,
    "JST": 9 * 60,
    "AEST": 10 * 60,
    "AEDT": 11 * 60,
}


class ZscalerError(RuntimeError):
    """A refusal or failure the ZIA API reported, with its reason."""


def _parse_report_time(raw: str) -> datetime | None:
    """``"26 Mar 2026 00:30:19, PDT"`` → aware UTC datetime, or ``None``."""
    text = (raw or "").strip().strip('"')
    if not text:
        return None
    # Split the timezone token off the tail: `26 Mar 2026 00:30:19, PDT`
    if "," in text:
        stamp, _, tz_token = text.rpartition(",")
        tz_token = tz_token.strip()
    else:
        stamp, tz_token = text, ""
    try:
        naive = datetime.strptime(stamp.strip(), "%d %b %Y %H:%M:%S")
    except ValueError:
        return None
    offset_min = _TZ_OFFSETS_MIN.get(tz_token)
    if offset_min is None:
        return None
    return naive.replace(tzinfo=timezone(timedelta(minutes=offset_min))).astimezone(UTC)


class ZscalerConnector(BaseConnector):
    connector_id = "zscaler"
    connector_name = "Zscaler Internet Access"
    connector_category = "network"

    #: Event-time cursor over the parsed row time, id breaking ties (#1970).
    checkpoint_time_field = ("event_time",)
    checkpoint_id_field = ("row_id",)

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Zscaler Internet Access admin audit logs — policy changes, "
                "portal sign-ins and API calls — via the ZIA audit log "
                "report API."
            ),
            docs_url="/docs/connectors/zscaler",
            fields=[
                Field("api_key", "secret", "API Key"),
                Field(
                    "cloud",
                    "string",
                    "ZIA Cloud",
                    required=False,
                    default="zscloud.net",
                    help_text="ZIA cloud domain (e.g. zscloud.net, zscaler.net).",
                ),
                Field("username", "string", "Admin Username"),
                Field("password", "secret", "Admin Password"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # ZIA admin audit log entries surfaced as events. Web transaction
        # logs have no pull API (NSS push only) and are deliberately absent.
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        api_key: str,
        username: str,
        password: str,
        cloud: str = "zscloud.net",
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._api_key = api_key
        self._cloud = cloud
        self._username = username
        self._password = password
        self._base_url = f"https://zsapi.{cloud}"
        self._jsessionid: str | None = None
        self._transport = transport

    def _http_client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self._transport)

    def _obfuscate_api_key(self) -> tuple[str, str]:
        """Zscaler's published key obfuscation.

        The previous implementation skipped the first loop (the timestamp
        digits) and the ``+ 2`` offset in the second, producing a key the
        API could never accept — authentication itself had never succeeded.
        This is the algorithm from Zscaler's own getting-started guide:
        the last six digits of the millisecond timestamp index the key
        directly, then the digits of ``n >> 1`` index it at ``digit + 2``.
        """
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for ch in n:
            key += self._api_key[int(ch)]
        for ch in r:
            key += self._api_key[int(ch) + 2]
        return key, now

    async def _authenticate(self, client: httpx.AsyncClient) -> None:
        obf_key, timestamp = self._obfuscate_api_key()
        payload = {
            "apiKey": obf_key,
            "username": self._username,
            "password": self._password,
            "timestamp": timestamp,
        }
        resp = await client.post(f"{self._base_url}/api/v1/authenticatedSession", json=payload)
        resp.raise_for_status()
        self._jsessionid = resp.cookies.get("JSESSIONID")
        if not self._jsessionid:
            for cookie in resp.cookies.jar:
                if cookie.name == "JSESSIONID":
                    self._jsessionid = cookie.value
                    break
        if not self._jsessionid:
            raise ZscalerError("authenticatedSession answered 200 without a JSESSIONID cookie")

    def _cookies(self) -> dict[str, str]:
        return {"JSESSIONID": self._jsessionid or ""}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._http_client(15.0) as client:
                await self._authenticate(client)
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("zscaler.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def _report_page(self, client: httpx.AsyncClient, start_ms: int, end_ms: int, page: int) -> list[dict[str, Any]]:
        """One audit-log report: create, poll to COMPLETE, download, parse."""
        body = {
            "startTime": start_ms,
            "endTime": end_ms,
            "page": page,
            "pageSize": _PAGE_SIZE,
        }
        resp = await client.post(f"{self._base_url}{_REPORT_PATH}", cookies=self._cookies(), json=body)
        if resp.status_code == 401:
            await self._authenticate(client)
            resp = await client.post(f"{self._base_url}{_REPORT_PATH}", cookies=self._cookies(), json=body)
        resp.raise_for_status()
        status_id = str((resp.json() or {}).get("statusId", ""))

        status = "EXECUTING"
        deadline = time.monotonic() + _POLL_BUDGET_S
        params = {"statusId": status_id} if status_id else {}
        while time.monotonic() < deadline:
            poll = await client.get(f"{self._base_url}{_REPORT_PATH}", cookies=self._cookies(), params=params)
            poll.raise_for_status()
            payload = poll.json() or {}
            status = str(payload.get("status", "")).upper()
            if status in _TERMINAL:
                if status != "COMPLETE":
                    raise ZscalerError(
                        f"audit log report ended {status}: {payload.get('errorMessage') or payload.get('errorCode') or 'no reason given'}"
                    )
                break
            await asyncio.sleep(_POLL_INTERVAL_S)
        else:
            raise ZscalerError(f"audit log report still {status} after {int(_POLL_BUDGET_S)}s; giving up this poll")

        download = await client.get(f"{self._base_url}{_REPORT_PATH}/download", cookies=self._cookies(), params=params)
        download.raise_for_status()
        return _parse_report_csv(download.text)

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        # One interval of overlap plus the persisted cursor (#1971): the
        # scheduler drops a run when the previous poll is still active, and
        # without the overlap the interval in between would never be
        # requested. apply_checkpoint drops the rows the overlap re-reads.
        effective_since = self.contiguous_since_seconds(since_seconds, now=window_end)
        window_start = window_end - timedelta(seconds=max(1, int(effective_since)))
        start_ms = int(window_start.timestamp() * 1000)
        end_ms = int(window_end.timestamp() * 1000)

        rows: list[dict[str, Any]] = []
        async with self._http_client(30.0) as client:
            if not self._jsessionid:
                await self._authenticate(client)
            for page in range(1, _MAX_PAGES + 1):
                page_rows = await self._report_page(client, start_ms, end_ms, page)
                rows.extend(page_rows)
                if len(page_rows) < _PAGE_SIZE:
                    break
            else:
                # The vendor caps a report at 1,000 records and every page
                # came back full: the window holds more than this poll read.
                logger.warning(
                    "zscaler.audit_report.page_cap",
                    pages=_MAX_PAGES,
                    rows=len(rows),
                    detail="window has more audit entries than one poll reads; the cursor resumes from the newest row read",
                )

        rows = self.apply_checkpoint(rows)
        return [self.normalize(row) for row in rows]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("Action", "") or "audit event"
        category = raw.get("Category", "") or "unknown"
        subcategory = raw.get("Subcategory", "")
        resource = raw.get("Resource", "")
        result = raw.get("Result", "")
        where = f"{category}/{subcategory}" if subcategory else category

        normalized: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": raw.get("row_id", ""),
            "title": f"Zscaler admin audit: {action} — {where}",
            "description": (
                f"{raw.get('User', 'unknown admin')} performed '{action}' "
                f"({where}{f', resource: {resource}' if resource else ''}) "
                f"via {raw.get('Interface', 'unknown interface')}"
                f"{f' — result: {result}' if result else ''}"
            ),
            # No severity key on purpose: ZIA audit entries publish no
            # severity tier, and inventing one is the defect the severity
            # ladder rules exist to refuse.
            "src_ip": raw.get("Client IP") or None,
            "actor": raw.get("User") or None,
            "raw_event": {k: v for k, v in raw.items() if k not in ("event_time",)},
        }
        if raw.get("event_time"):
            normalized["created_at"] = raw["event_time"]
        return normalized


def _parse_report_csv(text: str) -> list[dict[str, Any]]:
    """The report CSV → row dicts keyed by the vendor's column names.

    The file opens with preamble rows (administrator, report creation time,
    window) before the real header, which is recognised by its first cell
    being ``Time``. Each row additionally gets:

    * ``event_time`` — the row's time parsed to UTC ISO-8601 when the
      timezone abbreviation is unambiguous, else absent (the row is kept).
    * ``row_id`` — a stable digest of the identifying columns, because audit
      entries carry no vendor id; it de-duplicates overlap re-reads.
    """
    rows: list[dict[str, Any]] = []
    reader = csv.reader(io.StringIO(text))
    header: list[str] | None = None
    for cells in reader:
        if not cells:
            continue
        if header is None:
            if cells[0].strip() == "Time":
                header = [c.strip() for c in cells]
            continue
        row = {header[i]: (cells[i].strip() if i < len(cells) else "") for i in range(len(header))}
        parsed = _parse_report_time(row.get("Time", ""))
        if parsed is not None:
            row["event_time"] = parsed.isoformat()
        identity = "|".join(
            row.get(k, "") for k in ("Time", "User", "Action", "Category", "Subcategory", "Resource", "Result", "Client IP", "TraceId")
        )
        row["row_id"] = hashlib.sha256(identity.encode()).hexdigest()[:32]
        rows.append(row)
    return rows
