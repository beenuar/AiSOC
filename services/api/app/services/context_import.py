"""Import the context that events cannot carry.

The v1.1 graph labels split cleanly by where the truth lives. An event can
tell you an account authenticated; it cannot tell you which person holds that
account, who they report to, whether they still work here, which business
application the host serves, how critical it is, or what an outage costs.
That is directory, HR and CMDB data, and it has to be imported.

This is the difference between an alert that says "unusual login for
svc_deploy" and one that says "unusual login for svc_deploy, owned by a
contractor whose last day was Friday, on the host running the tier-1 payments
service". Same event, different incident.

Design notes:

**Upsert, never replace.** An import runs on a schedule against a source of
record that may be partial or briefly unavailable. Replacing the tenant's
context with whatever one run produced would delete an entire department
because an HR export timed out. Records are merged, and removal is explicit.

**Departure is recorded, not deleted.** An employee with an end date whose
accounts still authenticate is one of the highest-signal findings the graph
can produce, and deleting the row on offboarding destroys exactly that
signal.

**Validation is strict and the report is per-record.** A partially-applied
import that reports success is worse than a rejected one, because the gaps
are invisible afterwards. Every rejected record is named with its reason.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.db.neo4j import get_session

logger = logging.getLogger("aisoc.context_import")

MAX_RECORDS_PER_KIND = 50_000
_ID_RE = re.compile(r"^[A-Za-z0-9._@:\-]{1,200}$")

CRITICALITY = ("tier-1", "tier-2", "tier-3", "tier-4", "unknown")
DATA_CLASSIFICATION = ("public", "internal", "confidential", "restricted", "pci", "phi", "pii")


@dataclass
class ImportReport:
    """Per-kind counts plus every rejection, named.

    A count alone hides the shape of a failure: "imported 900 of 1000" does
    not say whether the missing hundred are one malformed department or every
    contractor.
    """

    employees: int = 0
    departments: int = 0
    applications: int = 0
    cloud_accounts: int = 0
    edges: int = 0
    rejected: list[dict[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.employees + self.departments + self.applications + self.cloud_accounts

    def reject(self, kind: str, identifier: str, reason: str) -> None:
        self.rejected.append({"kind": kind, "id": identifier, "reason": reason})

    def as_dict(self) -> dict[str, Any]:
        return {
            "employees": self.employees,
            "departments": self.departments,
            "applications": self.applications,
            "cloud_accounts": self.cloud_accounts,
            "edges": self.edges,
            "imported": self.total,
            "rejected_count": len(self.rejected),
            # Bounded: a malformed export can reject every row, and a
            # 50,000-entry error list is not a usable response.
            "rejected": self.rejected[:100],
            "rejected_truncated": len(self.rejected) > 100,
        }


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value.strip()))


def _clean(value: Any, *, limit: int = 500) -> str | None:
    """Trim a free-text property, or None if it is not usable.

    Length-capped because these render in a UI and reach a prompt, and a
    CMDB description field is a common place to find an entire runbook.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:limit] if text else None


def _enum(value: Any, allowed: tuple[str, ...]) -> str | None:
    """Normalise an enum-ish field, rejecting rather than guessing.

    A criticality of "very important" must not silently become tier-1: the
    autonomy policy reads this field, so a wrong value is a wrong decision.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text if text in allowed else None


async def import_context(
    tenant_id: uuid.UUID | str,
    payload: dict[str, Any],
    *,
    session: Any | None = None,
) -> ImportReport:
    """Upsert employees, departments, applications and cloud accounts.

    ``payload`` accepts four optional lists. Relationships are expressed as
    fields on the records rather than as a separate edge list, because a
    separate list is one more thing an export can get out of step with.
    """
    report = ImportReport()
    tid = str(tenant_id)

    async def _apply(sess: Any) -> None:
        await _import_departments(sess, tid, payload.get("departments") or [], report)
        # Employees after departments so BELONGS_TO has a target; the MERGE
        # would create a bare Department node otherwise, with a name nobody
        # set.
        await _import_employees(sess, tid, payload.get("employees") or [], report)
        await _import_cloud_accounts(sess, tid, payload.get("cloud_accounts") or [], report)
        await _import_applications(sess, tid, payload.get("applications") or [], report)

    if session is not None:
        await _apply(session)
    else:
        async with get_session() as sess:
            await _apply(sess)

    logger.info(
        "context_import tenant=%s imported=%d rejected=%d",
        tid,
        report.total,
        len(report.rejected),
    )
    return report


async def _import_departments(session: Any, tenant_id: str, records: list[Any], report: ImportReport) -> None:
    for record in records[:MAX_RECORDS_PER_KIND]:
        if not isinstance(record, dict):
            report.reject("department", str(record)[:40], "not an object")
            continue
        dept_id = record.get("id")
        if not _valid_id(dept_id):
            report.reject("department", str(dept_id)[:40], "missing or malformed id")
            continue
        name = _clean(record.get("name"), limit=200)
        if not name:
            report.reject("department", str(dept_id), "missing name")
            continue

        await session.run(
            "MERGE (d:Department {id: $id}) "
            "SET d.tenant_id = $tenant_id, d.name = $name, "
            "    d.cost_centre = coalesce($cost_centre, d.cost_centre), "
            "    d.updated_at = datetime()",
            id=f"{tenant_id}:{dept_id}",
            tenant_id=tenant_id,
            name=name,
            cost_centre=_clean(record.get("cost_centre"), limit=100),
        )
        report.departments += 1


async def _import_employees(session: Any, tenant_id: str, records: list[Any], report: ImportReport) -> None:
    for record in records[:MAX_RECORDS_PER_KIND]:
        if not isinstance(record, dict):
            report.reject("employee", str(record)[:40], "not an object")
            continue
        emp_id = record.get("id")
        if not _valid_id(emp_id):
            report.reject("employee", str(emp_id)[:40], "missing or malformed id")
            continue

        # is_active is derived from end_date rather than trusted from the
        # payload: the two disagreeing is the exact case that matters, and an
        # export that sets is_active=true on a departed employee would erase
        # the finding.
        end_date = _clean(record.get("end_date"), limit=40)
        is_active = end_date is None

        await session.run(
            "MERGE (e:Employee {id: $id}) "
            "SET e.tenant_id = $tenant_id, "
            "    e.email = coalesce($email, e.email), "
            "    e.display_name = coalesce($display_name, e.display_name), "
            "    e.title = coalesce($title, e.title), "
            "    e.employment_type = coalesce($employment_type, e.employment_type), "
            "    e.location = coalesce($location, e.location), "
            "    e.start_date = coalesce($start_date, e.start_date), "
            "    e.end_date = $end_date, "
            "    e.is_active = $is_active, "
            "    e.updated_at = datetime()",
            id=f"{tenant_id}:{emp_id}",
            tenant_id=tenant_id,
            email=_clean(record.get("email"), limit=320),
            display_name=_clean(record.get("display_name"), limit=200),
            title=_clean(record.get("title"), limit=200),
            employment_type=_clean(record.get("employment_type"), limit=60),
            location=_clean(record.get("location"), limit=120),
            start_date=_clean(record.get("start_date"), limit=40),
            end_date=end_date,
            is_active=is_active,
        )
        report.employees += 1

        if _valid_id(record.get("department_id")):
            await session.run(
                "MATCH (e:Employee {id: $emp}), (d:Department {id: $dept}) "
                "WHERE e.tenant_id = $tenant_id AND d.tenant_id = $tenant_id "
                "MERGE (e)-[r:BELONGS_TO]->(d) SET r.snapshot_id = $snapshot",
                emp=f"{tenant_id}:{emp_id}",
                dept=f"{tenant_id}:{record['department_id']}",
                tenant_id=tenant_id,
                snapshot="import",
            )
            report.edges += 1

        if _valid_id(record.get("manager_id")):
            await session.run(
                "MATCH (m:Employee {id: $mgr}), (e:Employee {id: $emp}) "
                "WHERE m.tenant_id = $tenant_id AND e.tenant_id = $tenant_id "
                "MERGE (m)-[r:MANAGES]->(e) SET r.snapshot_id = $snapshot",
                mgr=f"{tenant_id}:{record['manager_id']}",
                emp=f"{tenant_id}:{emp_id}",
                tenant_id=tenant_id,
                snapshot="import",
            )
            report.edges += 1

        # The join that makes the whole identity dimension work: one person,
        # many accounts. Matched on the existing Identity nodes the event
        # pipeline already writes, so no account is invented here.
        for account in record.get("accounts") or []:
            if not isinstance(account, str) or not account.strip():
                continue
            result = await session.run(
                "MATCH (i:Identity) "
                "WHERE i.tenant_id = $tenant_id "
                "  AND (i.external_id = $account OR i.email = $account OR i.name = $account) "
                "MATCH (e:Employee {id: $emp}) WHERE e.tenant_id = $tenant_id "
                "MERGE (e)-[r:AUTHENTICATES_AS]->(i) SET r.snapshot_id = $snapshot "
                "RETURN count(r) AS linked",
                tenant_id=tenant_id,
                account=account.strip(),
                emp=f"{tenant_id}:{emp_id}",
                snapshot="import",
            )
            row = await result.single()
            linked = int(row["linked"]) if row else 0
            report.edges += linked
            if not linked:
                # Named rather than silently dropped: an account the graph
                # has never seen is either a typo or a system nothing
                # ingests, and both are worth knowing.
                report.reject(
                    "employee_account",
                    f"{emp_id}:{account}",
                    "no Identity node matches this account; it has not been seen in any ingested event",
                )


async def _import_cloud_accounts(session: Any, tenant_id: str, records: list[Any], report: ImportReport) -> None:
    for record in records[:MAX_RECORDS_PER_KIND]:
        if not isinstance(record, dict):
            report.reject("cloud_account", str(record)[:40], "not an object")
            continue
        account_id = record.get("account_id")
        provider = _clean(record.get("provider"), limit=40)
        if not _valid_id(account_id) or not provider:
            report.reject("cloud_account", str(account_id)[:40], "missing or malformed account_id/provider")
            continue

        await session.run(
            "MERGE (c:CloudAccount {id: $id}) "
            "SET c.tenant_id = $tenant_id, c.provider = $provider, "
            "    c.account_id = $account_id, "
            "    c.name = coalesce($name, c.name), "
            "    c.environment = coalesce($environment, c.environment), "
            "    c.updated_at = datetime()",
            id=f"{tenant_id}:{provider}:{account_id}",
            tenant_id=tenant_id,
            provider=provider.lower(),
            account_id=str(account_id),
            name=_clean(record.get("name"), limit=200),
            environment=_clean(record.get("environment"), limit=60),
        )
        report.cloud_accounts += 1


async def _import_applications(session: Any, tenant_id: str, records: list[Any], report: ImportReport) -> None:
    for record in records[:MAX_RECORDS_PER_KIND]:
        if not isinstance(record, dict):
            report.reject("application", str(record)[:40], "not an object")
            continue
        app_id = record.get("id")
        if not _valid_id(app_id):
            report.reject("application", str(app_id)[:40], "missing or malformed id")
            continue
        name = _clean(record.get("name"), limit=200)
        if not name:
            report.reject("application", str(app_id), "missing name")
            continue

        criticality = _enum(record.get("criticality"), CRITICALITY)
        if record.get("criticality") and criticality is None:
            # Rejected rather than coerced: the autonomy policy reads this
            # field, so "very important" silently becoming tier-1 is a wrong
            # decision, not a cosmetic one.
            report.reject(
                "application",
                str(app_id),
                f"criticality {record['criticality']!r} is not one of {CRITICALITY}",
            )
            continue

        classification = _enum(record.get("data_classification"), DATA_CLASSIFICATION)
        if record.get("data_classification") and classification is None:
            report.reject(
                "application",
                str(app_id),
                f"data_classification {record['data_classification']!r} is not one of {DATA_CLASSIFICATION}",
            )
            continue

        scope = [s.strip()[:60] for s in (record.get("compliance_scope") or []) if isinstance(s, str) and s.strip()][:20]

        await session.run(
            "MERGE (a:Application {id: $id}) "
            "SET a.tenant_id = $tenant_id, a.name = $name, "
            "    a.criticality = coalesce($criticality, a.criticality), "
            "    a.data_classification = coalesce($classification, a.data_classification), "
            "    a.revenue_impact = coalesce($revenue_impact, a.revenue_impact), "
            "    a.environment = coalesce($environment, a.environment), "
            "    a.internet_facing = coalesce($internet_facing, a.internet_facing), "
            "    a.compliance_scope = $scope, "
            "    a.updated_at = datetime()",
            id=f"{tenant_id}:{app_id}",
            tenant_id=tenant_id,
            name=name,
            criticality=criticality,
            classification=classification,
            revenue_impact=_clean(record.get("revenue_impact"), limit=100),
            environment=_clean(record.get("environment"), limit=60),
            internet_facing=(bool(record["internet_facing"]) if "internet_facing" in record else None),
            scope=scope,
        )
        report.applications += 1

        if _valid_id(record.get("owner_employee_id")):
            await session.run(
                "MATCH (a:Application {id: $app}), (e:Employee {id: $owner}) "
                "WHERE a.tenant_id = $tenant_id AND e.tenant_id = $tenant_id "
                "MERGE (a)-[r:OWNED_BY]->(e) SET r.snapshot_id = $snapshot, r.role = $role",
                app=f"{tenant_id}:{app_id}",
                owner=f"{tenant_id}:{record['owner_employee_id']}",
                tenant_id=tenant_id,
                snapshot="import",
                role=_clean(record.get("owner_role"), limit=60) or "business_owner",
            )
            report.edges += 1

        # Resources are matched, never created: a CMDB naming a host the
        # platform has never ingested should surface as a coverage gap, not
        # as a graph node that looks monitored.
        for host in record.get("hosts") or []:
            if not isinstance(host, str) or not host.strip():
                continue
            result = await session.run(
                "MATCH (r:Resource) "
                "WHERE r.tenant_id = $tenant_id "
                "  AND (r.name = $host OR r.hostname = $host OR r.id = $host) "
                "MATCH (a:Application {id: $app}) WHERE a.tenant_id = $tenant_id "
                "MERGE (r)-[rel:RUNS]->(a) SET rel.snapshot_id = $snapshot "
                "RETURN count(rel) AS linked",
                tenant_id=tenant_id,
                host=host.strip(),
                app=f"{tenant_id}:{app_id}",
                snapshot="import",
            )
            row = await result.single()
            linked = int(row["linked"]) if row else 0
            report.edges += linked
            if not linked:
                report.reject(
                    "application_host",
                    f"{app_id}:{host}",
                    "no Resource node matches this host; it is in the CMDB but has not been seen in any ingested event",
                )
