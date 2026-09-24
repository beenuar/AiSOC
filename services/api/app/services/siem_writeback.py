"""Close the loop: project an AiSOC verdict onto the finding that raised it.

Two-way integration has only ever run inbound. A Splunk notable becomes an
AiSOC alert, the agent triages it, and the notable sits in the Splunk queue
untouched — so an analyst re-reads a finding AiSOC already dismissed, and a
finding AiSOC confirmed waits its turn behind them. This service is the
return leg.

Why it lives in the API service
-------------------------------
The agents worker reaches it over HTTP rather than dispatching itself. The
API holds the credential vault, the tenant-scoped database session and the
actions-service token, and it is the single governed path a response action
takes. Duplicating that in the worker would mean two places that can execute
against a customer's SIEM, two audit trails, and two copies of the
credential-handling code — and the second copy is the one that goes stale.

Governance
----------
``AISOC_SIEM_WRITEBACK_ENABLED`` (default **on**) turns the feature off
entirely. ``AISOC_SIEM_WRITEBACK_EXECUTE`` (default **off**) is what decides
whether a vendor is actually called: with it off every attempt is dispatched
as a dry run, recorded with ``executed=False``, and reported as
``mode="dry_run"``. An operator opts in to writing into their own SIEM; they
do not opt out.

Nothing here raises. A writeback failure must never fail the triage that
produced the verdict — the verdict is the durable thing, and losing it
because Splunk was unreachable would be the wrong trade.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import actions_client
from app.services.alert_source_link import (
    AlertSourceLink,
    links_for_alert,
    record_writeback,
)

logger = structlog.get_logger(__name__)

CAPABILITY = "update_alert_disposition"

#: Dispositions the actions service will act on. Mirrored here only to skip a
#: pointless round trip for a verdict that would be refused anyway — the
#: authority is ``services/actions/app/services/disposition_writeback.py`` and
#: this service never widens it.
_ACTIONABLE: frozenset[str] = frozenset({"true_positive", "false_positive", "benign", "benign_true_positive", "escalate"})

#: The subset that may close something. A confirmed true positive is not
#: here, and that is the point: it escalates.
_CLOSING_DISPOSITIONS: frozenset[str] = frozenset({"false_positive", "benign", "benign_true_positive"})


def writeback_enabled() -> bool:
    """Master switch. On by default; the execute flag is the one that bites."""
    return os.getenv("AISOC_SIEM_WRITEBACK_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def writeback_executes() -> bool:
    """Whether a vendor is actually called. **Off by default.**

    Default-off because the failure mode is asymmetric: a writeback that did
    not happen costs an analyst one duplicated triage, and a writeback that
    happened when the operator did not expect it silently closed findings in
    their system of record.
    """
    return os.getenv("AISOC_SIEM_WRITEBACK_EXECUTE", "0").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class WritebackOutcome:
    """What happened to one source finding. Honest about what did not run."""

    vendor: str
    external_id: str
    #: ``executed`` | ``dry_run`` | ``refused`` | ``simulated`` | ``failed`` | ``skipped``
    status: str
    #: TRUE only when a vendor call actually ran.
    executed: bool
    writeback_action: str = "refuse"
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WritebackReport:
    """The whole attempt for one alert."""

    alert_id: str
    disposition: str
    #: ``live`` | ``dry_run`` | ``disabled``
    mode: str
    outcomes: list[WritebackOutcome] = field(default_factory=list)

    @property
    def executed_count(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.executed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "disposition": self.disposition,
            "mode": self.mode,
            # Named so no caller can mistake a dry run for a write. The UI and
            # the API response both key off this rather than off `status`.
            "executed": self.executed_count > 0,
            "executed_count": self.executed_count,
            "outcomes": [outcome.as_dict() for outcome in self.outcomes],
        }


async def write_back_disposition(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    disposition: str,
    confidence: float | None = None,
    rationale: str = "",
    requested_by: str = "aisoc-agents",
) -> WritebackReport:
    """Write ``disposition`` back to every source finding behind ``alert_id``.

    Never raises. Every branch that does not reach a vendor records
    ``executed=False`` both in the returned report and on the link row.
    """
    dry_run = not writeback_executes()
    report = WritebackReport(
        alert_id=str(alert_id),
        disposition=disposition,
        mode="dry_run" if dry_run else "live",
    )

    if not writeback_enabled():
        report.mode = "disabled"
        logger.info("siem_writeback.disabled", alert_id=str(alert_id))
        return report

    if disposition not in _ACTIONABLE:
        # Refused before it costs a round trip. The actions service refuses
        # the same set; this is an optimisation, not a second policy.
        logger.info("siem_writeback.not_actionable", alert_id=str(alert_id), disposition=disposition)
        return report

    links = await links_for_alert(db, tenant_id=tenant_id, alert_id=alert_id)
    if not links:
        logger.debug("siem_writeback.no_source_link", alert_id=str(alert_id))
        return report

    connectors = await _load_connectors(db, tenant_id=tenant_id, links=links)

    for link in links:
        report.outcomes.append(
            await _write_one(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                link=link,
                connector=connectors.get(link.connector_instance_id),
                disposition=disposition,
                confidence=confidence,
                rationale=rationale,
                requested_by=requested_by,
                dry_run=dry_run,
            )
        )

    report.outcomes.extend(
        await _project_onto_ticket(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            disposition=disposition,
            dry_run=dry_run,
        )
    )

    logger.info(
        "siem_writeback.complete",
        alert_id=str(alert_id),
        disposition=disposition,
        mode=report.mode,
        executed=report.executed_count,
        attempted=len(report.outcomes),
    )
    return report


def ticket_projection_enabled() -> bool:
    """Whether a closing verdict may resolve the linked case. **Off.**

    See :func:`_project_onto_ticket` for why this is a third flag rather than
    riding on the execute flag.
    """
    return os.getenv("AISOC_SIEM_WRITEBACK_CLOSE_CASE", "0").strip().lower() in {"1", "true", "yes", "on"}


async def _project_onto_ticket(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    disposition: str,
    dry_run: bool,
) -> list[WritebackOutcome]:
    """Carry a closing verdict onto the Jira / ServiceNow ticket, if any.

    The ITSM connectors project a *status transition*, not a comment: their
    ``push_status_change`` maps an AiSOC case status onto a vendor state. So
    the only honest way to reach a ticket is to make the transition real —
    move the case, then let the existing fan-out project the status the case
    actually has. Synthesising a transition the case never made would put a
    resolution on someone's ticket that no AiSOC record supports, which is the
    same defect as reporting a dry run as executed.

    That makes this a bigger action than closing a SIEM finding: a case is a
    unit of work with an owner. Hence its own flag, off by default, on top of
    the execute flag. With it off the linked ticket is reported ``skipped``
    with the reason, so the console shows an honest "not projected" rather
    than silence.
    """
    row = (
        await db.execute(
            text("SELECT case_id FROM alerts WHERE id = :alert_id AND tenant_id = :tenant_id"),
            {"alert_id": str(alert_id), "tenant_id": str(tenant_id)},
        )
    ).fetchone()
    case_id = row.case_id if row else None
    if not case_id:
        return []

    refs = (
        await db.execute(
            text(
                """
                SELECT vendor, external_id FROM case_external_refs
                 WHERE case_id = :case_id
                """
            ),
            {"case_id": str(case_id)},
        )
    ).fetchall()
    if not refs:
        return []

    if disposition not in _CLOSING_DISPOSITIONS:
        return [
            WritebackOutcome(
                vendor=str(ref.vendor),
                external_id=str(ref.external_id),
                status="skipped",
                executed=False,
                writeback_action="escalate",
                detail=(
                    f"Ticket left open: AiSOC reached {disposition}, and the ITSM connectors project a "
                    f"status transition rather than a note, so there is nothing truthful to write."
                ),
            )
            for ref in refs
        ]

    if dry_run or not ticket_projection_enabled():
        reason = "DRY RUN" if dry_run else "AISOC_SIEM_WRITEBACK_CLOSE_CASE is off"
        return [
            WritebackOutcome(
                vendor=str(ref.vendor),
                external_id=str(ref.external_id),
                status="dry_run" if dry_run else "skipped",
                executed=False,
                writeback_action="close",
                detail=(f"{reason} — the case was not resolved, so nothing was projected onto the ticket."),
            )
            for ref in refs
        ]

    return await _resolve_case_and_fan_out(db, tenant_id=tenant_id, case_id=case_id, disposition=disposition, refs=refs)


async def _resolve_case_and_fan_out(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: Any,
    disposition: str,
    refs: list[Any],
) -> list[WritebackOutcome]:
    """Move the case to resolved, then project the status it now has."""
    from app.models.case import Case  # noqa: PLC0415 — avoids a models import cycle at startup
    from app.services.case_fanout import fanout_status_change  # noqa: PLC0415 — same

    case_row = (await db.execute(select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id))).scalar_one_or_none()
    if case_row is None:
        return []

    old_status = str(getattr(case_row, "status", "") or "")
    if old_status in {"resolved", "closed"}:
        return [
            WritebackOutcome(
                vendor=str(ref.vendor),
                external_id=str(ref.external_id),
                status="skipped",
                executed=False,
                writeback_action="close",
                detail="Case was already resolved; no transition to project.",
            )
            for ref in refs
        ]

    case_row.status = "resolved"
    await db.commit()
    await db.refresh(case_row)

    results = await fanout_status_change(
        db,
        case_row=case_row,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="resolved",
        pushed_by="aisoc-writeback",
    )
    return [
        WritebackOutcome(
            vendor=result.connector_type,
            external_id=result.external_id or "",
            status="executed" if result.status == "ok" else "failed",
            executed=result.status == "ok",
            writeback_action="close",
            detail=(result.error or f"Case resolved after an AiSOC {disposition} verdict; ticket transitioned."),
        )
        for result in results
    ]


async def _load_connectors(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    links: list[AlertSourceLink],
) -> dict[uuid.UUID, Connector]:
    """Fetch the live connector rows the links point at, tenant-scoped.

    Read fresh rather than cached on the link: credentials rotate, and a
    writeback using the values that were current when the alert was ingested
    would start failing silently the first time someone rolls a token.
    """
    instance_ids = [link.connector_instance_id for link in links if link.connector_instance_id]
    if not instance_ids:
        return {}
    result = await db.execute(
        text("SELECT * FROM connectors WHERE tenant_id = :tenant_id AND id = ANY(:ids)"),
        {"tenant_id": str(tenant_id), "ids": [str(i) for i in instance_ids]},
    )
    rows = result.mappings().all()
    out: dict[uuid.UUID, Connector] = {}
    for row in rows:
        connector = Connector()
        for key, value in row.items():
            if hasattr(connector, key):
                setattr(connector, key, value)
        out[connector.id] = connector
    return out


async def _write_one(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    link: AlertSourceLink,
    connector: Connector | None,
    disposition: str,
    confidence: float | None,
    rationale: str,
    requested_by: str,
    dry_run: bool,
) -> WritebackOutcome:
    """One link, one dispatch. Records the outcome and returns it."""
    if not link.dispatchable:
        return await _record(
            db,
            tenant_id=tenant_id,
            link=link,
            disposition=disposition,
            outcome=WritebackOutcome(
                vendor=link.vendor,
                external_id=link.external_id,
                status="skipped",
                executed=False,
                detail=f"no disposition-writeback arm for vendor {link.vendor!r}",
            ),
        )

    auth_config: dict[str, Any] = {}
    if connector is not None:
        try:
            auth_config = get_vault().decrypt_dict(connector.auth_config or {})
        except CredentialVaultError as exc:
            return await _record(
                db,
                tenant_id=tenant_id,
                link=link,
                disposition=disposition,
                outcome=WritebackOutcome(
                    vendor=link.vendor,
                    external_id=link.external_id,
                    status="failed",
                    executed=False,
                    detail=f"credential decryption failed: {exc}",
                ),
            )
        auth_config.update(_operational_config(connector))

    params: dict[str, Any] = {
        "disposition": disposition,
        "rationale": rationale,
        "aisoc_alert_id": str(alert_id),
        # The vendor is pinned so credential ordering cannot decide it — and
        # the actions service checks the pin against the credentials before
        # honouring it, so pinning a vendor this tenant has not configured
        # simulates rather than claiming an arm ran.
        "alert_vendor": link.vendor,
    }
    if confidence is not None:
        params["confidence"] = confidence

    try:
        body = await actions_client.dispatch_live_action(
            capability=CAPABILITY,
            vendor_id=link.vendor,
            target=link.external_id,
            tenant_id=str(tenant_id),
            params=params,
            auth_config=auth_config or None,
            dry_run=dry_run,
            requested_by=requested_by,
        )
    except actions_client.ActionsServiceError as exc:
        return await _record(
            db,
            tenant_id=tenant_id,
            link=link,
            disposition=disposition,
            outcome=WritebackOutcome(
                vendor=link.vendor,
                external_id=link.external_id,
                status="failed",
                executed=False,
                detail=exc.upstream_detail,
            ),
        )

    return await _record(
        db,
        tenant_id=tenant_id,
        link=link,
        disposition=disposition,
        outcome=_interpret(link, body, dry_run=dry_run),
    )


def _operational_config(connector: Connector) -> dict[str, Any]:
    """Non-secret per-instance settings the writeback needs.

    Today that is QRadar's closing reason id, which is deployment-specific and
    which QRadar refuses a close without. Read from ``connector_config``
    rather than ``auth_config`` because it is configuration, not a secret, and
    it must not be encrypted at rest as though it were one.
    """
    config = connector.connector_config or {}
    out: dict[str, Any] = {}
    for key in ("closing_reason_id", "owner", "owner_upn"):
        if config.get(key) is not None:
            out[key] = config[key]
    return out


def _interpret(link: AlertSourceLink, body: dict[str, Any], *, dry_run: bool) -> WritebackOutcome:
    """Translate a live-action response into an honest outcome.

    The load-bearing line is ``executed``. The actions service returns
    ``written`` on the result details and that is the only thing trusted here:
    a SIMULATED status, a refusal and a dry run all produce ``written=False``,
    and none of them may be reported as a write that happened.
    """
    result = body.get("result") if isinstance(body.get("result"), dict) else {}
    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    status = str(result.get("status") or "")
    written = bool(details.get("written"))
    action = str(details.get("writeback_action") or "refuse")
    reason = str(details.get("reason") or result.get("summary") or "")

    if status == "failed":
        return WritebackOutcome(
            vendor=link.vendor,
            external_id=link.external_id,
            status="failed",
            executed=False,
            writeback_action=action,
            detail=str(result.get("error") or reason)[:2000],
        )

    if dry_run:
        return WritebackOutcome(
            vendor=link.vendor,
            external_id=link.external_id,
            status="dry_run",
            executed=False,
            writeback_action=action,
            detail=f"DRY RUN — nothing was written to {link.vendor}. {reason}".strip(),
        )

    if not written:
        # Either the disposition was refused or there were no usable
        # credentials. Both are real outcomes and neither is a write.
        return WritebackOutcome(
            vendor=link.vendor,
            external_id=link.external_id,
            status="simulated" if status == "simulated" else "refused",
            executed=False,
            writeback_action=action,
            detail=reason[:2000],
        )

    return WritebackOutcome(
        vendor=link.vendor,
        external_id=link.external_id,
        status="executed",
        executed=True,
        writeback_action=action,
        detail=reason[:2000],
    )


async def _record(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    link: AlertSourceLink,
    disposition: str,
    outcome: WritebackOutcome,
) -> WritebackOutcome:
    await record_writeback(
        db,
        link_id=link.id,
        tenant_id=tenant_id,
        disposition=disposition,
        writeback_action=outcome.writeback_action,
        status=outcome.status,
        executed=outcome.executed,
        detail=outcome.detail,
    )
    return outcome
