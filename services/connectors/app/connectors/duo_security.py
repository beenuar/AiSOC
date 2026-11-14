"""
Duo Security connector.
Fetches authentication logs from the Duo Admin API using HMAC-SHA1 signed requests.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Duo's documented delay before a new authentication is served by the logs API.
_AVAILABILITY_DELAY_S = 120

# Duo's documented maximum page size for the authentication log ("Default: 100;
# Max: 1000"). Asking for the maximum keeps a busy window to the fewest requests.
_PAGE_LIMIT = 1000

_FEED = "duo_security.authentication"


def _response(body: Any) -> dict[str, Any]:
    """The ``response`` object of a Duo reply, or an empty one if the reply has none."""
    response = body.get("response") if isinstance(body, dict) else None
    return response if isinstance(response, dict) else {}


def _authlogs(response: dict[str, Any]) -> list[dict[str, Any]]:
    entries = response.get("authlogs")
    return [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []


def _next_offset(response: dict[str, Any]) -> str | None:
    """The ``next_offset`` to send for the following page, or None when the log has ended.

    Duo returns it as a two-element array — a 13-character millisecond
    timestamp and the event txid — and takes it back as one parameter with
    "both of these values ... separated by a comma". Its absence is the end.
    """
    metadata = response.get("metadata")
    offset = metadata.get("next_offset") if isinstance(metadata, dict) else None
    if isinstance(offset, list) and offset and all(isinstance(part, str) and part for part in offset):
        return ",".join(offset)
    return None


class DuoSecurityConnector(BaseConnector):
    connector_id = "duo_security"
    connector_name = "Duo Security"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Duo Security authentication logs via the Admin API (HMAC-SHA1 signed).",
            docs_url="/docs/connectors/duo-security",
            fields=[
                Field("integration_key", "string", "Integration Key"),
                Field("secret_key", "secret", "Secret Key"),
                Field(
                    "api_hostname",
                    "string",
                    "API Hostname",
                    placeholder="api-XXXXXXXX.duosecurity.com",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Duo authentication logs are an audit feed (who logged in from where).
        return (Capability.PULL_AUDIT,)

    def __init__(self, integration_key: str, secret_key: str, api_hostname: str):
        self._ikey = integration_key
        self._skey = secret_key
        self._host = api_hostname.lower()

    def _sign(self, method: str, path: str, params: dict[str, str]) -> tuple[str, str]:
        now = email.utils.formatdate()
        canon_params = urllib.parse.urlencode(sorted(params.items()))
        canon = "\n".join([now, method.upper(), self._host, path, canon_params])
        sig = hmac.new(self._skey.encode(), canon.encode(), hashlib.sha1).hexdigest()
        auth = base64.b64encode(f"{self._ikey}:{sig}".encode()).decode()
        return now, f"Basic {auth}"

    async def test_connection(self) -> dict[str, Any]:
        try:
            path = "/admin/v1/info/summary"
            date_str, auth = self._sign("GET", path, {})
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://{self._host}{path}",
                    headers={"Date": date_str, "Authorization": auth},
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("duo_security.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Duo serves an authentication "up to as recently as two minutes
        # before the API request" and answers a newer range as empty. A window
        # ending at now therefore never held its last two minutes, and the
        # next poll's window starts at now, so those entries were never read.
        # Ending the window two minutes back keeps consecutive polls contiguous.
        maxtime = datetime.now(UTC) - timedelta(seconds=_AVAILABILITY_DELAY_S)
        mintime = maxtime - timedelta(seconds=since_seconds)
        path = "/admin/v2/logs/authentication"
        window = {
            "mintime": str(int(mintime.timestamp()) * 1000),
            "maxtime": str(int(maxtime.timestamp()) * 1000),
            "limit": str(_PAGE_LIMIT),
        }

        async with httpx.AsyncClient(timeout=30.0) as client:

            async def page(next_offset: str | None) -> httpx.Response:
                # Every page repeats the window and is signed afresh: the
                # signature covers the query string and the Date header, so a
                # page cannot reuse the opening request's.
                params = {**window, "next_offset": next_offset} if next_offset else dict(window)
                date_str, auth = self._sign("GET", path, params)
                return await client.get(
                    f"https://{self._host}{path}",
                    headers={"Date": date_str, "Authorization": auth},
                    params=params,
                )

            # The opening request still raises, so a refused credential is
            # recorded by the scheduler as a failed poll rather than a quiet one.
            resp = await page(None)
            resp.raise_for_status()
            body = _response(resp.json())
            logs = _authlogs(body)

            # Duo: "To fetch all results, call repeatedly with the next_offset
            # paging parameter as long as the result metadata has next_offset
            # values." The read ends on the offset, never on a short page.
            for _ in range(DEFAULT_MAX_PAGES - 1):
                next_offset = _next_offset(body)
                if next_offset is None:
                    break
                try:
                    resp = await page(next_offset)
                except httpx.HTTPError as exc:
                    # Keep what was read; a failure part-way is not a reason
                    # to discard the pages that succeeded.
                    logger.warning("connector.paging.next_page_error", feed=_FEED, rows=len(logs), error=str(exc))
                    break
                if resp.status_code != 200:
                    logger.warning(
                        "connector.paging.next_page_failed",
                        feed=_FEED,
                        status=resp.status_code,
                        rows=len(logs),
                        body=resp.text[:300],
                    )
                    break
                try:
                    body = _response(resp.json())
                except ValueError:
                    logger.warning("connector.paging.next_page_unparseable", feed=_FEED, rows=len(logs))
                    break
                logs.extend(_authlogs(body))
            else:
                if _next_offset(body) is not None:
                    logger.warning(
                        "connector.paging.page_cap_reached",
                        feed=_FEED,
                        pages=DEFAULT_MAX_PAGES,
                        rows=len(logs),
                        detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
                    )

        return [self.normalize(entry) for entry in logs]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        result = str(raw.get("result", "")).upper()
        reason = str(raw.get("reason", "")).lower()

        if "fraud" in reason:
            severity = "high"
        elif result == "FAILURE":
            severity = "medium"
        elif raw.get("access_device", {}).get("is_encryption_enabled") == "false":
            severity = "low"
        elif result == "SUCCESS" and "new" in reason:
            severity = "low"
        else:
            severity = "info"

        user = raw.get("user", {}).get("name", "unknown")
        auth_device = raw.get("auth_device", {})

        return {
            "source": self.connector_id,
            "external_id": raw.get("txid", ""),
            "title": f"Duo auth: {result.lower()} for {user}",
            "description": f"Result: {result}, Reason: {raw.get('reason', 'N/A')}, User: {user}",
            "severity": severity,
            "src_ip": raw.get("access_device", {}).get("ip"),
            "actor": user,
            "hostname": auth_device.get("name"),
            "raw_event": raw,
            "created_at": raw.get("isotimestamp"),
        }
