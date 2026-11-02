"""Rippling workforce context.

Depth plan wave 2, item 1.3.

Vendor reference, verified 2026-11-01 at developer.rippling.com:

* `GET https://rest.ripplingapis.com/workers/`
* OAuth scope `workers.read`, sent as a bearer token.
* Response is `{"results": [...], "next_link": "..."}`; paging follows
  `next_link` until it is absent.
* `expand` is a comma-separated list of relationship fields. Without it,
  `department` and `employment_type` arrive as bare `*_id` strings, which
  would make the department of every employee an opaque identifier.
* `status` is a closed vocabulary: `INIT`, `HIRED`, `ACCEPTED`, `ACTIVE`,
  `TERMINATED`.
* `employment_type.type` is `CONTRACTOR` or `EMPLOYEE`.

What is deliberately not read
------------------------------
The worker object also carries compensation, date of birth, gender, race,
ethnicity, citizenship, personal email and home address. None of it is
expanded, none of it is stored, and `expand` names only the two
relationships the plan's field list needs. The vendor's own
`__meta.redacted_fields` is logged rather than ignored, because a field the
tenant's own configuration redacts is a fact about their data and not an
error.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.workforce import WorkforceRecord, normalise_status

logger = structlog.get_logger()

_BASE_URL = "https://rest.ripplingapis.com"

#: Only the two relationships the plan's field list needs. Expanding
#: `compensation` here would pull a salary into a security product.
_EXPAND = "department,employment_type"

#: The vendor's documented vocabulary, mapped onto the closed set. `INIT`,
#: `HIRED` and `ACCEPTED` are all pre-start states, which is a real and
#: separate thing from employed: a worker who has accepted but not started
#: should not look like staff, and should not look terminated either.
_STATUS_MAP = {
    "active": "active",
    "terminated": "terminated",
    "init": "pending",
    "hired": "pending",
    "accepted": "pending",
}

_TYPE_MAP = {"employee": "employee", "contractor": "contractor"}

#: A ceiling on pages followed, so a paging bug upstream cannot turn one
#: scheduled sync into an unbounded walk. 100 results per page at the
#: documented maximum covers 20,000 workers.
_MAX_PAGES = 200


class RipplingConnector(BaseConnector):
    connector_id = "rippling"
    connector_name = "Rippling"
    connector_category = "hr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Employment status, start and end dates, manager, department and worker type from "
                "Rippling, as triage context. Read-only; compensation and personal data are never requested."
            ),
            docs_url="/docs/connectors/rippling",
            fields=[
                Field(
                    "api_token",
                    "secret",
                    "API token",
                    help_text="A Rippling API token or installed-app access token carrying the workers.read scope.",
                ),
                Field(
                    "base_url",
                    "string",
                    "API base URL",
                    required=False,
                    default=_BASE_URL,
                    help_text="Override only if Rippling has given you a different regional host.",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_WORKFORCE,)

    def __init__(self, api_token: str, base_url: str = _BASE_URL, transport: Any | None = None) -> None:
        self._token = api_token
        self._base_url = (base_url or _BASE_URL).rstrip("/")
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            timeout=30.0,
            transport=self._transport,
        )

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get("/workers/", params={"limit": 1})
                if response.status_code == 403:
                    return {
                        "ok": False,
                        "error": "Rippling answered 403. The token is valid but is missing the workers.read scope.",
                    }
                response.raise_for_status()
            return {"ok": True, "detail": "workers endpoint readable"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """No alerts. See the BambooHR connector for the reasoning."""
        return []

    async def fetch_workforce(self) -> list[WorkforceRecord]:
        records: list[WorkforceRecord] = []
        async with self._client() as client:
            url: str | None = "/workers/"
            params: dict[str, Any] | None = {"limit": 100, "expand": _EXPAND}
            for _ in range(_MAX_PAGES):
                if url is None:
                    break
                response = await client.get(url, params=params)
                response.raise_for_status()
                body = response.json()

                redacted = ((body.get("__meta") or {}).get("redacted_fields")) or []
                if redacted:
                    # A fact about the tenant's configuration, not an error.
                    # Logged so an operator can see why a column is empty
                    # rather than concluding the connector is broken.
                    logger.info(
                        "rippling.fields_redacted_by_tenant_policy",
                        fields=[str(entry.get("name")) for entry in redacted][:10],
                    )

                for worker in body.get("results") or []:
                    record = self._to_record(worker)
                    if record is not None:
                        records.append(record)

                url = body.get("next_link") or None
                # `next_link` is an absolute URL already carrying the
                # cursor; re-sending the first page's params would reset it.
                params = None
        return records

    @staticmethod
    def _to_record(worker: dict[str, Any]) -> WorkforceRecord | None:
        external_id = str(worker.get("id") or "").strip()
        if not external_id:
            return None

        department = worker.get("department")
        department_name = department.get("name") if isinstance(department, dict) else None

        employment_type = worker.get("employment_type")
        raw_type = employment_type.get("type") if isinstance(employment_type, dict) else None

        return WorkforceRecord(
            external_id=external_id,
            email=(worker.get("work_email") or "").strip() or None,
            display_name=None,
            status=normalise_status(worker.get("status"), _STATUS_MAP),
            start_date=(worker.get("start_date") or "").strip() or None,
            end_date=(worker.get("end_date") or "").strip() or None,
            manager_external_id=(str(worker.get("manager_id") or "").strip() or None),
            department=(department_name or "").strip() or None,
            worker_type=_TYPE_MAP.get(str(raw_type or "").strip().lower(), "unknown"),
            title=(worker.get("title") or "").strip() or None,
        )
