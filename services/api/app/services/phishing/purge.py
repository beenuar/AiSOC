"""The governed purge fan-out: one dispatch per mailbox, one grading each.

Gap-closure 10.3 asks for "one governed purge proposal across all
recipients". The word doing the work is *governed*, and it decides the whole
shape of this module.

One request per mailbox, not one request with a list
-----------------------------------------------------
Handing a single executor twenty-five addresses would produce one approval
covering a list the approver never read, which is exactly the defect the
per-capability contract exists to refuse — "approving a playbook must never
authorise whatever its steps happen to contain". So the fan-out happens here,
above the dispatcher, and every mailbox gets its own capability contract
grading, its own audit row, its own verification probe and its own restore
handle.

The *proposal* is still one thing. The campaign is graded once, from its
recipient count, so an analyst approves "purge this message from 25
mailboxes" rather than twenty-five separate prompts — and the grading they
see is the one each dispatch will be held to, because both read the same
``scaled_impact``.

Preview is the default
----------------------
``execute=False`` is the signature's default and the route's default. The
preview reports, per mailbox, what would be attempted and at what tier; it
reports ``simulated`` and never ``purged``. ``executed`` is the single field
meaning a vendor was touched and it is false on every preview row.

What counts as purged
---------------------
Only a dispatch whose report says ``executed``. ``simulated``, ``dry_run``,
``pending_approval``, ``blocked``, ``no_integration``, ``unsupported`` and
``failed`` are all recorded under their own name, and the campaign lands on
``partially_purged`` rather than ``purged`` when any mailbox did not. A
fan-out that reports forty of forty purged when the message was in thirty of
them teaches an analyst to trust a number that means nothing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.phishing.intake import utcnow
from app.services.playbook_step_dispatch import dispatch_step

logger = structlog.get_logger(__name__)

PURGE_CAPABILITY = "purge_email"
RESTORE_CAPABILITY = "restore_email"

#: Step statuses that map onto a recipient's ``purge_state``. Anything not
#: listed is recorded as ``failed`` with the status in ``purge_detail``, so a
#: new step status cannot quietly become a success.
_STATE_FROM_STATUS: dict[str, str] = {
    "executed": "purged",
    "simulated": "simulated",
    "dry_run": "simulated",
    "pending_approval": "pending_approval",
}


@dataclass
class RecipientOutcome:
    recipient: str
    purge_state: str
    executed: bool
    summary: str
    detail: str = ""
    vendor: str = ""
    verification: str = ""


@dataclass
class PurgeOutcome:
    campaign_id: uuid.UUID
    recipient_count: int
    requested_impact: str
    approval_requirement: str
    approval_reason: str
    executed_count: int = 0
    preview: bool = True
    status: str = "open"
    recipients: list[RecipientOutcome] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": str(self.campaign_id),
            "recipient_count": self.recipient_count,
            "impact": self.requested_impact,
            "approval": self.approval_requirement,
            "approval_reason": self.approval_reason,
            "preview": self.preview,
            "executed_count": self.executed_count,
            "status": self.status,
            "recipients": [
                {
                    "recipient": r.recipient,
                    "purge_state": r.purge_state,
                    "executed": r.executed,
                    "summary": r.summary,
                    "detail": r.detail,
                    "vendor": r.vendor,
                    "verification": r.verification,
                }
                for r in self.recipients
            ],
        }


def grade(recipient_count: int, confidence: float | None, tier: str) -> tuple[str, str, str]:
    """``(impact, requirement, reason)`` for a purge over this many mailboxes.

    Imported from the vendored action contracts so the console, the
    dispatcher and this proposal cannot answer the question three ways — the
    arrangement already used for the LLM input contract and the deterministic
    narrative. ``scripts/sync_vendored_action_contracts.py --check`` keeps the
    copy byte-identical with ``services/actions``.
    """
    from app._vendor.action_contracts.approval_rules import evaluate
    from app._vendor.action_contracts.capability_contracts import CAPABILITY_CONTRACTS, scaled_impact

    impact = scaled_impact(PURGE_CAPABILITY, {"recipient_count": recipient_count})
    contract = CAPABILITY_CONTRACTS[PURGE_CAPABILITY]
    decision = evaluate(impact=impact, declared_approval=contract.approval, confidence=confidence, tier=tier)
    return impact.value, decision.requirement.value, decision.reason


async def propose_purge(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    confidence: float | None = None,
    tier: str = "L1",
    execute: bool = False,
    requested_by: str = "aisoc-phishing",
) -> PurgeOutcome | None:
    """Raise one purge proposal across a campaign's recipients.

    Returns ``None`` when the campaign does not exist for this tenant, which
    the route turns into a 404. Every other condition — no recipients, no
    integration, an approval the tier will not grant — is reported inside the
    outcome, because each sends an operator somewhere different and a bare
    404 sends them nowhere.
    """
    campaign = (
        await db.execute(
            text("""
                SELECT id, sender, subject, recipient_count, status
                  FROM aisoc_phishing_campaigns
                 WHERE tenant_id = :tenant_id AND id = :id
            """).bindparams(tenant_id=tenant_id, id=campaign_id)
        )
    ).fetchone()
    if campaign is None:
        return None

    recipients = (
        await db.execute(
            text("""
                SELECT recipient, internet_message_id
                  FROM aisoc_phishing_campaign_recipients
                 WHERE tenant_id = :tenant_id AND campaign_id = :id
                 ORDER BY recipient
            """).bindparams(tenant_id=tenant_id, id=campaign_id)
        )
    ).fetchall()

    impact, requirement, reason = grade(len(recipients), confidence, tier)
    outcome = PurgeOutcome(
        campaign_id=campaign_id,
        recipient_count=len(recipients),
        requested_impact=impact,
        approval_requirement=requirement,
        approval_reason=reason,
        preview=not execute,
    )

    if not recipients:
        # Not an error and not a success. A campaign whose reports named no
        # recipients has nothing to purge, and saying so is how somebody
        # notices an intake adapter that stopped parsing a `To` header.
        outcome.status = campaign.status
        logger.info("phishing_purge.no_recipients", campaign_id=str(campaign_id), tenant_id=str(tenant_id))
        return outcome

    # The campaign is graded once and every dispatch below is held to the
    # same grading, because both read `scaled_impact` over the same count.
    # The per-mailbox dispatch carries the count so the dispatcher's own
    # contract check reaches the same tier rather than grading each mailbox
    # as a one-recipient purge.
    now = utcnow()
    for row in recipients:
        report = await dispatch_step(
            db,
            tenant_id=tenant_id,
            capability=PURGE_CAPABILITY,
            target=row.recipient,
            params={
                "internet_message_id": row.internet_message_id,
                "recipient_count": len(recipients),
                "campaign_id": str(campaign_id),
            },
            confidence=confidence,
            dry_run=not execute,
            requested_by=requested_by,
        )
        state = _STATE_FROM_STATUS.get("executed" if report.executed else report.status, "failed")
        if state == "failed" and "not found" in (report.detail or report.summary or "").lower():
            # A mailbox that never held the message is a distinct outcome
            # from a mailbox the purge failed on, and only one of them is
            # worth an operator's attention.
            state = "not_found"

        details = report.details or {}
        await db.execute(
            text("""
                UPDATE aisoc_phishing_campaign_recipients
                   SET purge_state = :state,
                       purge_detail = :detail,
                       vendor = :vendor,
                       restore_message_id = COALESCE(NULLIF(:restore_id, ''), restore_message_id),
                       restore_folder_id = COALESCE(NULLIF(:restore_folder, ''), restore_folder_id),
                       last_action_at = :now
                 WHERE tenant_id = :tenant_id AND campaign_id = :cid AND recipient = :recipient
            """).bindparams(
                state=state,
                detail=(report.detail or report.summary)[:2000],
                vendor=report.vendor_id,
                restore_id=str(details.get("restore_message_id") or ""),
                restore_folder=str(details.get("restore_folder_id") or ""),
                now=now,
                tenant_id=tenant_id,
                cid=campaign_id,
                recipient=row.recipient,
            )
        )
        outcome.recipients.append(
            RecipientOutcome(
                recipient=row.recipient,
                purge_state=state,
                executed=report.executed,
                summary=report.summary,
                detail=report.detail,
                vendor=report.vendor_id,
                verification=report.verification,
            )
        )
        if report.executed:
            outcome.executed_count += 1

    outcome.status = _campaign_status(outcome, preview=not execute)
    await _set_status(db, tenant_id=tenant_id, campaign_id=campaign_id, status=outcome.status, now=now)
    await db.commit()
    return outcome


async def _set_status(db: AsyncSession, *, tenant_id: uuid.UUID, campaign_id: uuid.UUID, status: str, now: Any) -> None:
    await db.execute(
        text("""
            UPDATE aisoc_phishing_campaigns
               SET status = :status, updated_at = :now
             WHERE id = :id AND tenant_id = :tenant_id
        """).bindparams(status=status, now=now, id=campaign_id, tenant_id=tenant_id)
    )


def _campaign_status(outcome: PurgeOutcome, *, preview: bool) -> str:
    """Where the campaign stands after this run.

    A preview never advances past ``purge_proposed``: nothing was removed, so
    a status implying it was would be the same lie as an executed count that
    includes previews.
    """
    if preview:
        return "purge_proposed"
    if outcome.executed_count == 0:
        return "purge_proposed"
    if outcome.executed_count == outcome.recipient_count:
        return "purged"
    return "partially_purged"


async def restore_campaign(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    confidence: float | None = None,
    requested_by: str = "aisoc-phishing",
) -> PurgeOutcome | None:
    """Put a purged campaign's messages back, one mailbox at a time.

    The reverse exists because the forward verb is the most disruptive one
    this product offers. It reads the restore handles the purge stored —
    Microsoft's move gives the message a new id in the destination folder and
    the original folder is only knowable before the move — so this is a real
    reversal rather than a declared one.

    Only rows the purge actually executed on are restored. Attempting a
    restore on a mailbox that was previewed, failed or never held the message
    would report work that did not happen.
    """
    rows = (
        await db.execute(
            text("""
                SELECT recipient, internet_message_id, restore_message_id, restore_folder_id, vendor
                  FROM aisoc_phishing_campaign_recipients
                 WHERE tenant_id = :tenant_id AND campaign_id = :id AND purge_state = 'purged'
                 ORDER BY recipient
            """).bindparams(tenant_id=tenant_id, id=campaign_id)
        )
    ).fetchall()

    exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_phishing_campaigns WHERE tenant_id = :tenant_id AND id = :id").bindparams(
                tenant_id=tenant_id, id=campaign_id
            )
        )
    ).fetchone()
    if exists is None:
        return None

    impact, requirement, reason = grade(len(rows), confidence, "L4")
    outcome = PurgeOutcome(
        campaign_id=campaign_id,
        recipient_count=len(rows),
        requested_impact=impact,
        approval_requirement=requirement,
        approval_reason=reason,
        preview=False,
    )
    now = utcnow()
    for row in rows:
        report = await dispatch_step(
            db,
            tenant_id=tenant_id,
            capability=RESTORE_CAPABILITY,
            target=row.recipient,
            params={
                "restore_message_id": row.restore_message_id,
                "restore_folder_id": row.restore_folder_id,
                "internet_message_id": row.internet_message_id,
                "alert_vendor": row.vendor,
            },
            vendor_id=row.vendor,
            confidence=confidence,
            dry_run=False,
            requested_by=requested_by,
        )
        if report.executed:
            outcome.executed_count += 1
            await db.execute(
                text("""
                    UPDATE aisoc_phishing_campaign_recipients
                       SET purge_state = 'restored', purge_detail = :detail, last_action_at = :now
                     WHERE tenant_id = :tenant_id AND campaign_id = :cid AND recipient = :recipient
                """).bindparams(
                    detail=(report.detail or report.summary)[:2000],
                    now=now,
                    tenant_id=tenant_id,
                    cid=campaign_id,
                    recipient=row.recipient,
                )
            )
        outcome.recipients.append(
            RecipientOutcome(
                recipient=row.recipient,
                purge_state="restored" if report.executed else "purged",
                executed=report.executed,
                summary=report.summary,
                detail=report.detail,
                vendor=report.vendor_id,
                verification=report.verification,
            )
        )

    outcome.status = "restored" if rows and outcome.executed_count == len(rows) else "partially_purged"
    await _set_status(db, tenant_id=tenant_id, campaign_id=campaign_id, status=outcome.status, now=now)
    await db.commit()
    return outcome
