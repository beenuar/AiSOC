"""
Splunk connector.
Runs saved searches and fetches notable events from Splunk SIEM.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_spl

logger = structlog.get_logger()

# Page size for the results endpoint. ``head 100`` / ``count=100`` used to cap a
# poll at 100 notables and silently drop the rest (#529); we now page through
# every result. _MAX_PAGES bounds a single poll so a misconfigured saved search
# can't spin forever.
_DEFAULT_PAGE_SIZE = 500
_MAX_PAGES = 200
_JOB_POLL_ATTEMPTS = 30
_JOB_POLL_INTERVAL_S = 2.0
_SEVERITY_BY_URGENCY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _first(raw: dict[str, Any], *keys: str) -> Any:
    """The first key carrying a value, treating an empty string as absent.

    A search result carries only the columns its search named, and Splunk
    renders a column it has no value for as ``""`` rather than omitting it, so
    a plain ``or`` chain over ``.get()`` would stop at the empty one.
    """
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return None


class SplunkConnector(BaseConnector):
    connector_id = "splunk"
    connector_name = "Splunk SIEM"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Splunk Enterprise / Cloud notable events via the REST API.",
            docs_url="/docs/connectors/splunk",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Splunk URL",
                    placeholder="https://splunk.example.com:8089",
                    help_text="Management port (default 8089), not the web UI port.",
                ),
                Field("token", "secret", "HEC / API Token"),
                Field(
                    "saved_search",
                    "string",
                    "Saved Search Name",
                    required=False,
                    default="AiSOC_Alerts",
                    help_text="Dispatched via the saved-search endpoint. Leave blank to search index=notable.",
                ),
                Field(
                    "page_size",
                    "number",
                    "Results page size",
                    required=False,
                    default=_DEFAULT_PAGE_SIZE,
                    help_text="Number of results fetched per page. Polling pages through all results — there is no 100-event cap.",
                ),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for self-signed certificates in private deployments.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Splunk surfaces notable events (alerts) and supports federated SPL
        # search over indexes — the latter maps to QUERY_LOGS.
        # WS-E5: Live Splunk REST API response actions now wired
        # via services/actions/app/clients/splunk_client.py
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.CREATE_NOTABLE_EVENT,
        )

    #: Splunk stamps `_time` on every result and `_cd` is its stable
    #: per-event address; `event_id` wins when a saved search projects one.
    checkpoint_time_field = ("_time", "event_time")
    checkpoint_id_field = ("event_id", "_cd")

    def __init__(
        self,
        base_url: str,
        token: str,
        saved_search: str = "AiSOC_Alerts",
        ssl_verify: bool = True,
        page_size: int = _DEFAULT_PAGE_SIZE,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._saved_search = saved_search
        self._ssl_verify = ssl_verify
        try:
            self._page_size = max(1, int(page_size))
        except (TypeError, ValueError):
            self._page_size = _DEFAULT_PAGE_SIZE
        # Checkpoint plumbing (#529) lives on BaseConnector (10b); the two
        # cursor fields declared above are all this connector contributes.

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}/services/server/info",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                resp.raise_for_status()
                version = resp.json().get("entry", [{}])[0].get("content", {}).get("version")
                return {"success": True, "connector": self.connector_id, "version": version}
            except Exception as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        earliest = f"-{max(1, int(since_seconds))}s"
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            sid = await self._dispatch(client, earliest)
            if not sid:
                return []
            await self._await_job(client, sid)
            rows = await self._collect_results(client, sid)

        ordered = self._order_and_checkpoint(rows)
        return [self.normalize(r) for r in ordered]

    async def _dispatch(self, client: httpx.AsyncClient, earliest: str) -> str | None:
        """Kick off the search job and return its SID.

        Honors the configured saved search (#525): when ``saved_search`` names
        a real saved search we dispatch it via the dedicated endpoint with a
        URL-encoded name (never injecting the untrusted name into SPL) and
        override its time window. When it is empty or an ``index=`` expression
        we fall back to the original ad-hoc notable-index search.
        """
        ss = (self._saved_search or "").strip()
        if ss and not ss.startswith("index="):
            resp = await client.post(
                f"{self._base_url}/services/saved/searches/{quote(ss, safe='')}/dispatch",
                headers=self._headers(),
                data={
                    "output_mode": "json",
                    "dispatch.earliest_time": earliest,
                    "dispatch.latest_time": "now",
                    "trigger_actions": "0",
                },
            )
            resp.raise_for_status()
            return self._extract_sid(resp)

        index = ss[len("index=") :] if ss.startswith("index=") else "notable"
        resp = await client.post(
            f"{self._base_url}/services/search/jobs",
            headers=self._headers(),
            data={"search": f"search index={index} earliest={earliest}", "output_mode": "json"},
        )
        resp.raise_for_status()
        return self._extract_sid(resp)

    @staticmethod
    def _extract_sid(resp: httpx.Response) -> str | None:
        try:
            data = resp.json()
            if isinstance(data, dict) and data.get("sid"):
                return str(data["sid"])
        except (ValueError, KeyError):
            # Response wasn't JSON with a sid — fall through to the XML path below.
            pass
        # The dispatch endpoint may answer with XML (<sid>…</sid>) despite
        # output_mode=json depending on Splunk version.
        match = re.search(r"<sid>([^<]+)</sid>", resp.text)
        return match.group(1) if match else None

    async def _await_job(self, client: httpx.AsyncClient, sid: str) -> str:
        for _ in range(_JOB_POLL_ATTEMPTS):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}",
                headers=self._headers(),
                params={"output_mode": "json"},
            )
            state = resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED", "PAUSED"):
                return state
            await asyncio.sleep(_JOB_POLL_INTERVAL_S)
        return "TIMED_OUT"

    async def _collect_results(self, client: httpx.AsyncClient, sid: str) -> list[dict[str, Any]]:
        """Page through every result (#529) — no more silent ``head 100`` cap."""
        rows: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": self._page_size, "offset": offset},
            )
            resp.raise_for_status()
            page = resp.json().get("results", [])
            if not page:
                break
            rows.extend(page)
            if len(page) < self._page_size:
                break
            offset += len(page)
        return rows

    def _order_and_checkpoint(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Order, drop anything at or before the cursor, and stage the advance.

        The implementation moved to :meth:`BaseConnector.apply_checkpoint` in
        10b so the other eighty-three connectors can adopt it by declaring two
        field names; this connector kept the behaviour and the tests that pin
        it. Retained as a named method because those tests drive it directly.
        """
        return self.apply_checkpoint(rows)

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated SPL search and return raw rows.

        We deliberately do *not* call ``normalize`` here because federated
        search returns rows for analyst pivoting, not alerts that should
        flow into the fusion engine. The API layer wraps each row with
        connector identity so downstream consumers can tell sources apart.
        """
        index = self._saved_search if self._saved_search.startswith("index=") else "notable"
        spl = to_spl(unified, index=index)
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": spl, "output_mode": "json", "exec_mode": "oneshot"},
            )
            resp.raise_for_status()
            return list(resp.json().get("results", []))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Idempotency guard (#528): ``fetch_alerts`` already returns canonical
        # events, and the scheduler historically re-ran ``normalize`` on every
        # event. Re-normalizing a canonical envelope treated it as a raw Splunk
        # row (external_id -> "", title -> "splunk", severity -> medium,
        # nested raw_event). Detect the envelope and pass it straight through.
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw

        # Prefer a stable vendor identifier so replays map to the same canonical
        # event ID downstream (#529). Emit it under both keys the ingest
        # normalizer understands.
        external_id = str(raw.get("event_id") or raw.get("_cd") or "")
        return {
            "source": self.connector_id,
            "external_id": external_id,
            "event_id": external_id,
            # The correlation-search name is the notable's rule title; fall back
            # to source, then a generic label.
            "title": raw.get("search_name") or raw.get("source") or "Splunk Notable Event",
            "description": raw.get("description", ""),
            "severity": _SEVERITY_BY_URGENCY.get(str(raw.get("urgency", "medium")).lower(), "medium"),
            "src_ip": raw.get("src", raw.get("src_ip")),
            # `host` is Splunk's own indexed-source metadata — on a notable it
            # names the search head, not the machine the detection is about.
            # Enterprise Security correlates assets on src/dest/dvc and
            # identities on user/src_user, which is why those are read too.
            "hostname": _first(raw, "host", "dest", "dvc", "orig_host"),
            "username": _first(raw, "user", "src_user"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }
