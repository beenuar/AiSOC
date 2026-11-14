"""BambooHR workforce context.

Depth plan wave 2, item 1.3.

Vendor reference, verified 2026-11-01 at documentation.bamboohr.com:

* `GET https://api.bamboohr.com/api/v1/{subdomain}/v1/employees/directory`
  lists the published directory.
* `GET https://api.bamboohr.com/api/v1/{subdomain}/v1/employees/{id}?fields=...`
  returns an explicit field list for one employee.
* Authentication is HTTP Basic with the API key as the username and any
  string as the password.
* `Accept: application/json` is required; without it the API answers XML.

Why both endpoints and not just the directory
----------------------------------------------
The directory is one request and would have been the obvious read. Its own
reference rules it out for this feature twice over: it "never includes
compensation, national identifiers such as SSN, birth date, home address,
home contact details, **or employment status and history, in any
configuration**", and "inactive and former employees are also excluded".

Those two sentences remove every field item 1.3 actually asks for -
employment status, start date, termination date - and remove the entire
population the feature exists to see, which is the person who left on
Friday and whose account authenticated on Saturday. So the directory is
used only to enumerate ids, and each employee's fields are read
individually with the field list named in the request.

That costs one request per employee. It is a scheduled background sync
reading a slowly-changing roster, not a hot path, and the alternative is a
feature that cannot see a departure.

What is deliberately not read
------------------------------
Everything else. The per-employee endpoint can return compensation, home
address, date of birth and national identifiers; this connector names
exactly the fields the plan lists and nothing more, so the data minimisation
is in the request rather than in a filter applied afterwards.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.workforce import WorkforceRecord, normalise_status

logger = structlog.get_logger()

#: Named in the request. A reader that does not ask for a column cannot
#: recover it with an adapter afterwards, which is how four of five vendor
#: readers in this tree came to return null hostnames.
_FIELDS = (
    "id",
    "displayName",
    "workEmail",
    "department",
    "jobTitle",
    "supervisorEid",
    "hireDate",
    "terminationDate",
    "status",
    "employmentHistoryStatus",
)

#: BambooHR's `status` field is `Active` or `Inactive`. It carries no
#: "on leave" member, so this map has none either rather than inventing one.
_STATUS_MAP = {"active": "active", "inactive": "terminated"}

#: `employmentHistoryStatus` is a free-text employment-type field whose
#: values a company configures. These are the shipped defaults; anything
#: else is `unknown`, because a bespoke value read as "employee" would lose
#: exactly the contractor signal the field is here for.
_TYPE_MAP = {
    "full-time": "employee",
    "part-time": "employee",
    "full time": "employee",
    "part time": "employee",
    "contractor": "contractor",
    "intern": "contractor",
    "temporary": "contractor",
    "temp": "contractor",
}


class BambooHRConnector(BaseConnector):
    connector_id = "bamboohr"
    connector_name = "BambooHR"
    connector_category = "hr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Employment status, start and last-day dates, manager, department and worker type "
                "from BambooHR, as triage context. Read-only; no personal or compensation data is stored."
            ),
            docs_url="/docs/connectors/bamboohr",
            fields=[
                Field(
                    "subdomain",
                    "string",
                    "Company subdomain",
                    placeholder="acme",
                    help_text="The first label of your BambooHR URL: acme.bamboohr.com -> acme.",
                ),
                Field(
                    "api_key",
                    "secret",
                    "API key",
                    help_text="Generated from your BambooHR profile under API Keys. Needs directory and employee read access.",
                ),
                Field(
                    "max_employees",
                    "number",
                    "Maximum employees per sync",
                    required=False,
                    default=5000,
                    help_text="A ceiling on the per-employee reads one sync will make.",
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_WORKFORCE,)

    def __init__(
        self,
        subdomain: str,
        api_key: str,
        max_employees: int = 5000,
        transport: Any | None = None,
    ) -> None:
        self._subdomain = subdomain.strip().strip("/")
        self._api_key = api_key
        self._max_employees = max(1, int(max_employees))
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=f"https://api.bamboohr.com/api/gateway.php/{self._subdomain}/v1",
            # Basic with the key as username and any password, per the
            # vendor's authentication page.
            auth=(self._api_key, "x"),
            headers={"Accept": "application/json"},
            timeout=30.0,
            transport=self._transport,
        )

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get("/employees/directory")
                if response.status_code == 403:
                    # Named rather than reported as a bad credential: the
                    # vendor returns 403 with an empty body when directory
                    # sharing is off company-wide, which is a setting the
                    # operator can fix and a wrong key is not.
                    return {
                        "ok": False,
                        "error": (
                            "BambooHR answered 403. The key may be valid but the company's directory "
                            "sharing is off (Settings > Company Directory), which every caller including "
                            "administrators hits."
                        ),
                    }
                response.raise_for_status()
                count = len(response.json().get("employees") or [])
            return {"ok": True, "detail": f"directory readable, {count} employee(s) published"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """No alerts. An HR system reports state, not security events.

        Returning an empty list rather than raising keeps the connector
        pollable by the ordinary scheduler loop; the workforce sync is a
        separate branch in the same poll.
        """
        return []

    async def fetch_workforce(self) -> list[WorkforceRecord]:
        records: list[WorkforceRecord] = []
        async with self._client() as client:
            directory = await client.get("/employees/directory")
            directory.raise_for_status()
            employees = directory.json().get("employees") or []

            for entry in employees[: self._max_employees]:
                employee_id = str(entry.get("id") or "").strip()
                if not employee_id:
                    continue
                detail = await client.get(
                    f"/employees/{employee_id}",
                    params={"fields": ",".join(_FIELDS)},
                )
                if detail.status_code != 200:
                    # One unreadable employee is not an unreadable roster.
                    logger.warning(
                        "bamboohr.employee_unreadable",
                        employee_id=employee_id,
                        status=detail.status_code,
                    )
                    continue
                records.append(self._to_record(detail.json()))
        return records

    @staticmethod
    def _to_record(payload: dict[str, Any]) -> WorkforceRecord:
        end_date = (payload.get("terminationDate") or "").strip() or None
        status = normalise_status(payload.get("status"), _STATUS_MAP)
        # A termination date in the record and a status of Active is the
        # normal state of a notice period, and it is the case this feature
        # exists for. The date wins nothing here: status stays what the
        # vendor said, and "departing within N days" is derived downstream
        # from the date, so both facts survive.
        return WorkforceRecord(
            external_id=str(payload.get("id") or "").strip(),
            email=(payload.get("workEmail") or "").strip() or None,
            display_name=(payload.get("displayName") or "").strip() or None,
            status=status,
            start_date=(payload.get("hireDate") or "").strip() or None,
            end_date=end_date,
            manager_external_id=(str(payload.get("supervisorEid") or "").strip() or None),
            department=(payload.get("department") or "").strip() or None,
            worker_type=_TYPE_MAP.get(str(payload.get("employmentHistoryStatus") or "").strip().lower(), "unknown"),
            title=(payload.get("jobTitle") or "").strip() or None,
        )
