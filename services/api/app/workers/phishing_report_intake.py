"""Poll the tenant's phishing report mailbox and turn what is in it into reports.

Depth 7.1 names three intake doors. ``POST /phishing/reports`` is the door a
caller pushes through and the ``email_inbox`` connector is the door IMAP
pushes through; this worker is the third — the one that *pulls*, from a
Microsoft 365 report mailbox over Graph or a Google Workspace label.

Without it the intake adapters would be a mechanism with no production
caller: the exact "exists, is unit-tested, and nothing calls it on the path
that matters" shape this repository keeps rediscovering. The module
reachability gate would even have passed, because the route calls the
adapters; what it cannot see is that no code path reads a report mailbox.

How a tenant turns it on
------------------------
Two things, both deliberate:

1. ``PHISHING_INTAKE_WORKER_ENABLED`` on the deployment. Default off. Reading
   a mailbox on a schedule is a capability an upgrade must not acquire by
   itself, the same reasoning the mailbox arms ship disabled under.
2. ``connector_config.phishing_report_mailbox`` on an enabled ``m365_audit``,
   ``azure_entra`` or ``google_workspace`` connector. No mailbox, no polling:
   the worker never guesses an address, because a guess here reads somebody's
   mail.

A tenant that has done one and not the other is logged once per sweep at
``info`` with which half is missing. "Nothing is happening" with no reason is
the diagnostic failure that made a clean-room install take four attempts.

What a poll does and does not do
---------------------------------
It asks ``search_mailboxes`` for messages received since the last watermark,
normalises each through the same adapters the route uses, and writes a
submission plus a campaign membership. It does **not** mark the source
message read, move it, or delete it: this worker has a read verb and should
not acquire a write one to keep its own bookkeeping. De-duplication is by
``internet_message_id`` per tenant, which is the identity of the message
rather than of the copy, so the same phish reported twice joins one campaign
instead of creating two submissions.

The watermark lives in the connector row
-----------------------------------------
``connector_config.phishing_report_watermark``, with a deliberate overlap of
:data:`WATERMARK_OVERLAP_SECONDS` on each poll. Mail is indexed after it is
delivered, so a watermark with no overlap drops anything that landed in the
gap — the same lesson the Splunk connector's high-watermark carries, and the
same reason the overlap is paid for by de-duplication rather than avoided.
It is not held on an instance attribute: a worker object is rebuilt on
restart and there are several replicas, so in-process state would silently
re-read or skip.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services.phishing import campaigns as phishing_campaigns
from app.services.phishing import intake as phishing_intake
from app.services.playbook_step_dispatch import dispatch_step
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.phishing_report_intake")

#: Connector types that can hold a report mailbox, and the intake adapter
#: each one's payloads are parsed by. A dict rather than an ``if`` chain so
#: the two cannot disagree about which vendor a connector speaks.
MAILBOX_CONNECTORS: dict[str, str] = {
    "m365_audit": "m365_graph",
    "azure_entra": "m365_graph",
    "google_workspace": "google_workspace",
}

#: The key an operator sets on the connector to nominate a report mailbox.
MAILBOX_CONFIG_KEY = "phishing_report_mailbox"
WATERMARK_CONFIG_KEY = "phishing_report_watermark"

#: How far back a poll reaches beyond the last watermark. Mail is indexed
#: after it is delivered, so a watermark with no overlap drops whatever
#: landed in the gap. Paid for by de-duplication on the message id.
WATERMARK_OVERLAP_SECONDS = 120

#: How far back a *first* poll reaches. Bounded so enabling the worker on a
#: mailbox with four years of reports does not ingest four years of reports.
FIRST_POLL_LOOKBACK_HOURS = 24

#: Per poll, per mailbox. The vendor caps its own page at 100.
MAX_MESSAGES_PER_POLL = 50


@dataclass
class SweepReport:
    """What one sweep did, for the log line and for the tests."""

    tenants_considered: int = 0
    mailboxes_polled: int = 0
    messages_seen: int = 0
    reports_created: int = 0
    duplicates_skipped: int = 0
    campaigns_touched: set[uuid.UUID] = field(default_factory=set)
    #: Tenants that configured half of what the worker needs. Named rather
    #: than counted: "nothing is happening" with no reason is the diagnostic
    #: failure worth avoiding.
    incomplete: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def _mailbox_connectors(db: AsyncSession) -> list[Any]:
    """Enabled connectors across every tenant that nominate a report mailbox."""
    rows = (
        await db.execute(
            text("""
                SELECT id, tenant_id, connector_type, connector_config
                  FROM connectors
                 WHERE is_enabled = TRUE
                   AND connector_type = ANY(CAST(:types AS text[]))
                 ORDER BY tenant_id, connector_type
            """).bindparams(types=sorted(MAILBOX_CONNECTORS))
        )
    ).fetchall()
    return list(rows)


def _watermark(config: dict[str, Any]) -> datetime:
    raw = str((config or {}).get(WATERMARK_CONFIG_KEY) or "")
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed - timedelta(seconds=WATERMARK_OVERLAP_SECONDS)
        except ValueError:
            logger.warning("phishing_report_intake: unparseable watermark %r, falling back to the first-poll window", raw[:64])
    return datetime.now(UTC) - timedelta(hours=FIRST_POLL_LOOKBACK_HOURS)


async def _already_seen(db: AsyncSession, *, tenant_id: uuid.UUID, message_id: str) -> bool:
    if not message_id:
        # A message with no id cannot be de-duplicated, and ingesting it
        # anyway would create a new submission on every poll for as long as
        # it sits in the mailbox. Skipping is the lesser error and it is
        # counted, so a mailbox full of them is visible.
        return True
    found = (
        await db.execute(
            text("SELECT 1 FROM aisoc_phishing_submissions WHERE tenant_id = :tenant_id AND internet_message_id = :mid LIMIT 1").bindparams(
                tenant_id=tenant_id, mid=message_id
            )
        )
    ).fetchone()
    return found is not None


async def _record(db: AsyncSession, *, tenant_id: uuid.UUID, message: phishing_intake.ReportedMessage) -> uuid.UUID | None:
    """Write one submission and join it to its campaign.

    Triage is deliberately **not** run here. The worker ingests whatever is
    in a report mailbox, which on a busy tenant is hundreds of messages a
    day, and an LLM call per message is a cost nobody asked for on a path
    nobody is watching. ``POST /phishing/{id}/retriage`` is the door for
    that, and the verdict stays ``pending`` until somebody opens it — which
    is honest, where a heuristic verdict applied silently would not be.
    """
    submission_id = uuid.uuid4()
    now = datetime.now(UTC)
    await db.execute(
        text("""
            INSERT INTO aisoc_phishing_submissions (
                id, tenant_id, submitted_by, artifact_kind, raw_content, sender, subject,
                urls, verdict, confidence, indicators, mitre_technique,
                internet_message_id, recipients, reported_by, intake_source,
                submitted_at, triaged_at, created_at
            ) VALUES (
                :id, :tenant_id, 'phishing-report-intake', 'email', :content, :sender, :subject,
                CAST(:urls AS text[]), 'pending', NULL, CAST('[]' AS jsonb), NULL,
                :message_id, CAST(:recipients AS text[]), :reported_by, :source,
                :now, NULL, :now
            )
        """).bindparams(
            id=submission_id,
            tenant_id=tenant_id,
            content=message.body_text,
            sender=message.sender,
            subject=message.subject,
            urls=list(message.urls),
            message_id=message.internet_message_id,
            recipients=list(message.recipients),
            reported_by=message.reported_by,
            source=message.intake_source,
            now=now,
        )
    )
    campaign = await phishing_campaigns.record_report(db, tenant_id=tenant_id, message=message, submission_id=submission_id)
    return campaign.id if campaign else None


async def run_once() -> SweepReport:
    """One sweep across every tenant with a nominated report mailbox."""
    report = SweepReport()
    async with AsyncSessionLocal() as db:
        await assert_cross_tenant_session(db, "phishing report intake sweeps every tenant's nominated report mailbox")
        connectors = await _mailbox_connectors(db)
        report.tenants_considered = len({str(c.tenant_id) for c in connectors})

        for connector in connectors:
            config = dict(connector.connector_config or {})
            mailbox = str(config.get(MAILBOX_CONFIG_KEY) or "").strip()
            if not mailbox:
                report.incomplete.append(
                    f"tenant {connector.tenant_id} has an enabled {connector.connector_type} connector and no "
                    f"{MAILBOX_CONFIG_KEY} in its connector_config, so nothing is polled"
                )
                continue

            source = MAILBOX_CONNECTORS[connector.connector_type]
            since = _watermark(config)
            polled_at = datetime.now(UTC)

            step = await dispatch_step(
                db,
                tenant_id=connector.tenant_id,
                capability="search_mailboxes",
                target=mailbox,
                params={
                    "received_after": since.isoformat().replace("+00:00", "Z"),
                    "limit": MAX_MESSAGES_PER_POLL,
                },
                vendor_id="m365" if source == "m365_graph" else "google_workspace",
                dry_run=False,
                requested_by="aisoc-phishing-report-intake",
            )
            if not step.executed:
                # Reported with the step's own reason. "The report mailbox
                # has gone quiet" and "the capability is disabled on this
                # deployment" send an operator to different places, and the
                # step vocabulary already distinguishes them.
                report.errors.append(f"tenant {connector.tenant_id} {mailbox}: {step.status} — {step.summary}")
                continue

            report.mailboxes_polled += 1
            matches = list((step.details or {}).get("matches") or [])
            report.messages_seen += len(matches)

            for payload in matches:
                if not isinstance(payload, dict):
                    continue
                try:
                    message = phishing_intake.normalise(source, payload)
                except ValueError as exc:
                    report.errors.append(f"tenant {connector.tenant_id}: {exc}")
                    continue
                if await _already_seen(db, tenant_id=connector.tenant_id, message_id=message.internet_message_id):
                    report.duplicates_skipped += 1
                    continue
                campaign_id = await _record(db, tenant_id=connector.tenant_id, message=message)
                report.reports_created += 1
                if campaign_id:
                    report.campaigns_touched.add(campaign_id)

            # The watermark advances only on a poll that reached the vendor,
            # which is why it is set here and not before the dispatch: a
            # failed poll that moved the watermark would skip whatever
            # arrived during the outage.
            config[WATERMARK_CONFIG_KEY] = polled_at.isoformat().replace("+00:00", "Z")
            await db.execute(
                # Keyed by id *and* tenant. The id alone is unique and would
                # work; the predicate is here because `connectors` is a
                # tenant-scoped table and a cross-tenant sweep writing to one
                # without naming the tenant is the shape
                # `check_tenant_query_predicates.py` exists to refuse --
                # "how the row was addressed is irrelevant; naming another
                # tenant's id reaches it".
                text("UPDATE connectors SET connector_config = CAST(:cfg AS jsonb) WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                    cfg=json.dumps(config), id=connector.id, tenant_id=connector.tenant_id
                )
            )

        await db.commit()

    if report.incomplete:
        logger.info("phishing_report_intake: %s", "; ".join(report.incomplete[:5]))
    for problem in report.errors[:5]:
        logger.warning("phishing_report_intake: %s", problem)
    logger.info(
        "phishing_report_intake swept tenants=%d mailboxes=%d seen=%d created=%d duplicates=%d campaigns=%d",
        report.tenants_considered,
        report.mailboxes_polled,
        report.messages_seen,
        report.reports_created,
        report.duplicates_skipped,
        len(report.campaigns_touched),
    )
    return report


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the other workers."""
    interval = max(int(getattr(settings, "PHISHING_INTAKE_WORKER_INTERVAL_SECONDS", 300)), 60)
    logger.info("phishing_report_intake started interval=%ds", interval)
    failures = TickFailures("phishing_report_intake", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("phishing_report_intake stopped")
        raise
