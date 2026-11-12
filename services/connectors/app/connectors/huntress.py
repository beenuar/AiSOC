"""Huntress Managed EDR incident reports, read through the v1 REST API.

Vendor reference, from the Huntress API reference (`https://api.huntress.io/docs`)
and the OpenAPI document behind it (`https://api.huntress.io/v1/swagger_doc.json`):

* **Where.** One host, `https://api.huntress.io`, for every account. It is
  fixed here rather than configurable, so the credential can only ever be
  sent to Huntress.

* **Authentication.** HTTP Basic, with the API key as the user name and the
  API secret key as the password. Both are generated in the Huntress portal
  at `<account subdomain>.huntress.io` under API Credentials.

* **Rate limit.** "Every Huntress API account is rate limited to 60 requests
  per minute, on a sliding window"; the 61st request answers 429.

* **Incident reports.** `GET /v1/incident_reports` with `limit` (at most
  500), `page_token`, `sort_field` (`id`, `created_at` or `updated_at`) and
  `sort_direction`. The response is `{incident_reports, pagination}`, and the
  next page is named by `pagination.next_page_token`, which is absent on the
  last page. The list has **no time filter**.

Reading the window
------------------
With no time filter, the window is found by ordering. The list is read by
`updated_at`, newest first, through `read_token_pages`, and the read stops on
the first page whose oldest report was last updated before the window opened.

The window is then applied to `sent_at`, the moment a Huntress SOC analyst
delivered the report. A report is updated again when it is closed, commented
on or remediated, so windowing on `updated_at` would raise the same incident
once per update; windowing on `sent_at` raises it once, in the poll whose
window contains its delivery. Sending a report updates it, so a report sent
inside the window was last updated inside it too, and reading by `updated_at`
down to the window's start reaches every one of them. The window is closed at
the moment the read started: a report delivered while it runs belongs to the
next poll's window and is raised there, not twice.

A report without `sent_at` was never delivered — the SOC dismissed it before
sending, or it is still a draft — and is not returned.

The following request is built here with the token, never taken from
`pagination.next_page_url`, so a host named in a response body is never sent
the credential. A refused or unreachable opening request raises, so the
scheduler records a failed poll rather than a quiet window; a later page
failing keeps the pages already read.

The host behind a report
------------------------
A report names its host only by `agent_id`. Each distinct agent in a poll's
reports is looked up once through `GET /v1/agents/{id}` for its hostname,
internal and external address and operating system, and the agent record is
carried on the report under `agent` — a key the vendor's report does not
use — so a replay of the stored record normalizes to the same host.

The lookups share the account's 60-a-minute budget with the list read, so a
poll makes at most `_MAX_AGENT_LOOKUPS` of them and stops early on a 429. A
report whose agent was not looked up, or whose lookup failed, is still
returned, without a host. Reports from Microsoft 365, Google or email
security carry no agent at all.

The severity ladder
-------------------
Huntress publishes `low`, `high` and `critical`, and nothing in between. Each
maps to its own tier; `critical` stays `critical` and is never collapsed into
`high`. A value outside the three carries no `severity` key rather than a
guessed one.

Read-only
---------
Nothing here isolates an agent, approves a remediation or resolves a report.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_token_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_API_HOST = "https://api.huntress.io"
_REPORTS_PATH = "/v1/incident_reports"
_ACCOUNT_PATH = "/v1/account"
_AGENT_PATH = "/v1/agents/{agent_id}"

#: The documented maximum for `limit`.
_PAGE_SIZE = 500

#: Agent lookups one poll may spend out of the account's 60 requests a minute,
#: leaving the list read and the next poll room inside the same minute.
_MAX_AGENT_LOOKUPS = 20

#: The vendor's published ladder, three entries because it publishes three.
_SEVERITIES = {"low": "low", "high": "high", "critical": "critical"}


class HuntressError(RuntimeError):
    """Huntress refused a request, with a message written for the operator."""


class HuntressConnector(BaseConnector):
    connector_id = "huntress"
    connector_name = "Huntress"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Huntress Managed EDR incident reports — footholds, ransomware canaries, process, antivirus, "
                "identity and SIEM detections a Huntress SOC analyst has confirmed and delivered — via the "
                "v1 REST API, with the affected host resolved from its agent. Read-only."
            ),
            docs_url="/docs/connectors/huntress",
            fields=[
                Field(
                    "api_key",
                    "secret",
                    "API key",
                    help_text="The public half of a Huntress API credential. It is half of the credential, so the vault encrypts it too.",
                ),
                Field(
                    "api_secret",
                    "secret",
                    "API secret key",
                    help_text="Generated with the API key at <your subdomain>.huntress.io under API Credentials.",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(self, api_key: str, api_secret: str, transport: Any | None = None) -> None:
        self._auth = httpx.BasicAuth((api_key or "").strip(), (api_secret or "").strip())
        self._transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=_API_HOST,
            auth=self._auth,
            headers={"Accept": "application/json"},
            timeout=timeout,
            transport=self._transport,
        )

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client(30.0) as client:
                response = await client.get(_ACCOUNT_PATH)
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": _refusal(response, _ACCOUNT_PATH)}
            account = _object(_json(response).get("account"))
            result: dict[str, Any] = {"success": True, "connector": self.connector_id}
            name = _text(account.get("name"))
            if name:
                result["account"] = name
            return result
        except httpx.HTTPError as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        window_end = datetime.now(UTC)
        window_start = window_end - timedelta(seconds=max(1, int(since_seconds)))

        async with self._client(60.0) as client:

            async def page(token: str | None) -> httpx.Response:
                params: dict[str, Any] = {"limit": _PAGE_SIZE, "sort_field": "updated_at", "sort_direction": "desc"}
                if token:
                    params["page_token"] = token
                # Raised, not returned: on the opening page an empty list
                # would read as a quiet estate, and the scheduler records an
                # exception as the failed poll it is. A later page failing is
                # left to the reader, which keeps the pages already read. The
                # reader treats a transport error as a failed later page, so
                # the opening request's is converted here.
                try:
                    response = await client.get(_REPORTS_PATH, params=params)
                except httpx.HTTPError as exc:
                    if token is None:
                        raise HuntressError(f"Huntress could not be reached at {_API_HOST}: {exc}") from exc
                    raise
                if token is None and response.status_code != 200:
                    raise HuntressError(_refusal(response, _REPORTS_PATH))
                return response

            def passed_window_start(rows: list[dict[str, Any]]) -> bool:
                # Newest first, so the last row is the page's oldest. An
                # unreadable timestamp does not end the read.
                oldest = _timestamp(rows[-1].get("updated_at"))
                return oldest is not None and oldest < window_start

            reports = await read_token_pages(
                request=page,
                items_field="incident_reports",
                token_field="pagination.next_page_token",
                stop_when=passed_window_start,
                feed="huntress.incident_reports",
            )

            delivered: list[dict[str, Any]] = []
            seen: set[str] = set()
            for report in reports:
                report_id = _identifier(report.get("id"))
                if report_id:
                    # A report updated mid-read moves to the top of the list
                    # and can be returned on two pages.
                    if report_id in seen:
                        continue
                    seen.add(report_id)
                sent_at = _timestamp(report.get("sent_at"))
                if sent_at is not None and window_start <= sent_at < window_end:
                    delivered.append(report)

            agents = await self._agents(client, delivered)

        out: list[dict[str, Any]] = []
        for report in delivered:
            agent_id = _agent_id(report.get("agent_id"))
            agent = agents.get(agent_id) if agent_id is not None else None
            out.append(self.normalize({**report, "agent": agent} if agent else report))
        return out

    async def _agents(self, client: httpx.AsyncClient, reports: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
        """The agent record behind each distinct `agent_id`, within the lookup budget."""
        # dict.fromkeys de-duplicates and keeps first-seen order: the newest
        # reports' agents are looked up first when the bound binds.
        ids = (_agent_id(report.get("agent_id")) for report in reports)
        wanted = list(dict.fromkeys(agent_id for agent_id in ids if agent_id is not None))
        if len(wanted) > _MAX_AGENT_LOOKUPS:
            logger.warning(
                "huntress.agent_lookups_capped",
                agents=len(wanted),
                looked_up=_MAX_AGENT_LOOKUPS,
                detail="reports on the agents beyond the bound are returned without a host",
            )

        agents: dict[int, dict[str, Any]] = {}
        for agent_id in wanted[:_MAX_AGENT_LOOKUPS]:
            path = _AGENT_PATH.format(agent_id=agent_id)
            try:
                response = await client.get(path)
            except httpx.HTTPError as exc:
                logger.warning("huntress.agent_lookup_failed", agent_id=agent_id, error=str(exc))
                continue
            if response.status_code == 429:
                logger.warning(
                    "huntress.agent_lookups_rate_limited",
                    looked_up=len(agents),
                    detail="the account's 60 requests a minute are spent; the remaining reports are returned without a host",
                )
                break
            if response.status_code != 200:
                logger.warning("huntress.agent_lookup_failed", agent_id=agent_id, status=response.status_code)
                continue
            agent = _object(_json(response).get("agent"))
            if agent:
                agents[agent_id] = agent
        return agents

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        agent = _object(raw.get("agent"))
        indicator_types = raw.get("indicator_types")

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _identifier(raw.get("id")),
            "title": _text(raw.get("subject")) or "Huntress incident report",
            "description": _text(raw.get("summary")),
            "created_at": _text(raw.get("sent_at")),
            "status": _text(raw.get("status")),
            "platform": _text(raw.get("platform")),
            "indicator_types": [t for t in indicator_types if isinstance(t, str) and t] if isinstance(indicator_types, list) else [],
            "hostname": _text(agent.get("hostname")),
            "src_ip": _text(agent.get("ipv4_address")),
            "external_ip": _text(agent.get("external_ip")),
            "os": _text(agent.get("os")),
            "endpoint_id": _identifier(raw.get("agent_id")),
            "organization_id": _identifier(raw.get("organization_id")),
            "raw_event": raw,
        }
        severity = _severity(raw)
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "", [])}


def _refusal(response: httpx.Response, path: str) -> str:
    message = f"Huntress answered HTTP {response.status_code} to GET {path}: {response.text[:300]}"
    if response.status_code == 401:
        message += " Check the API key and API secret key; both are shown once, when the credential is generated."
    elif response.status_code == 403:
        message += " The credential is valid but its user's role does not allow reading this resource."
    elif response.status_code == 429:
        message += " The account's limit of 60 requests a minute is exhausted; the next poll retries."
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


def _identifier(value: Any) -> str:
    """A numeric id as text."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return _text(value)


def _agent_id(value: Any) -> int | None:
    """A positive integer agent id, or None. Only an integer is put into a request path."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


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


def _severity(raw: dict[str, Any]) -> str | None:
    value = raw.get("severity")
    return _SEVERITIES.get(value.strip().lower()) if isinstance(value, str) else None
