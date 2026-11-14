"""Which reports are the same message, and who received it.

Gap-closure 10.3: "group phishing submissions by the same sender, URL or
attachment hash, or a near-duplicate subject, and raise one governed purge
proposal across all recipients".

The grouping ladder
-------------------
Five attributes, tried in descending order of how much they prove:

1. ``internet_message_id`` — the same message, by definition. Added to the
   plan's four because it is both the strongest signal and the one the purge
   needs anyway, and grouping two copies of one message under "same sender"
   would be a weaker claim than the evidence supports.
2. ``attachment_hash`` — the same file reached several people.
3. ``url`` — the same landing page. The first URL in document order, so two
   reports of one message agree regardless of how many links it carried.
4. ``sender`` — the same envelope sender.
5. ``subject`` — a *judgement*, and the only one here that is. Normalised
   (reply/forward prefixes stripped, digits and long tokens collapsed) so
   "Invoice 10452 overdue" and "Invoice 98113 overdue" group, which is the
   whole point and is also exactly why it is last and why
   ``grouping_basis`` records it.

``grouping_basis`` is stored, not derived, because an analyst about to purge
across forty mailboxes is entitled to know whether the forty were joined by a
fact or by a similarity heuristic.

Why the counts are stored
-------------------------
``recipient_count`` feeds ``capability_contracts.scaled_impact``, which turns
it into MODERATE, HIGH or SEVERE and therefore into the approval tier. A
count recomputed on read could change between a proposal being graded and an
approver reading it, which would mean the two saw different actions. It is
recomputed from the recipient rows inside the same transaction that adds one.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.phishing.intake import ReportedMessage, utcnow

logger = structlog.get_logger(__name__)

#: Order matters: the first attribute a message carries decides the group.
GROUPING_ORDER: tuple[str, ...] = ("internet_message_id", "attachment_hash", "url", "sender", "subject")

#: Bases that are a fact about the message rather than a similarity
#: judgement. Published alongside a campaign so a reader does not have to
#: know the ladder to know how strong the claim is.
FACTUAL_BASES: frozenset[str] = frozenset({"internet_message_id", "attachment_hash", "url", "sender"})

_REPLY_PREFIX = re.compile(r"^(?:\s*(?:re|fwd?|fw|aw|tr|rv|enc|antwort)\s*:\s*)+", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")
_WHITESPACE = re.compile(r"\s+")
#: Long opaque tokens — tracking ids, hex blobs, base64 fragments — differ per
#: recipient in exactly the campaigns worth grouping, so they collapse too.
_OPAQUE = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)


def normalise_subject(subject: str) -> str:
    """Strip what varies between copies of one campaign's messages."""
    cleaned = _REPLY_PREFIX.sub("", str(subject or "")).strip().lower()
    cleaned = _OPAQUE.sub("#", cleaned)
    cleaned = _DIGITS.sub("#", cleaned)
    return _WHITESPACE.sub(" ", cleaned).strip()


@dataclass(frozen=True)
class GroupingDecision:
    """Why two reports are the same campaign.

    ``value`` is kept beside the hash so the decision can be explained
    without reversing a digest — "grouped on the sender billing@…" is
    actionable, "grouped on 6f2a…" is not.
    """

    basis: str
    value: str
    key: str

    @property
    def is_factual(self) -> bool:
        return self.basis in FACTUAL_BASES


def grouping_decision(message: ReportedMessage) -> GroupingDecision | None:
    """The strongest attribute this message carries, or ``None``.

    ``None`` is a real answer: a report with no message id, no attachment, no
    URL, no sender and no subject has nothing to group on, and inventing a
    group for it would put an unrelated message into somebody's purge list.
    """
    candidates: list[tuple[str, str]] = []
    if message.internet_message_id:
        candidates.append(("internet_message_id", message.internet_message_id))
    if message.attachment_hashes:
        candidates.append(("attachment_hash", sorted(message.attachment_hashes)[0]))
    if message.urls:
        candidates.append(("url", message.urls[0]))
    if message.sender:
        candidates.append(("sender", message.sender.lower()))
    normalised = normalise_subject(message.subject)
    if normalised:
        candidates.append(("subject", normalised))

    by_basis = dict(candidates)
    for basis in GROUPING_ORDER:
        value = by_basis.get(basis)
        if value:
            # The basis is inside the digest so two campaigns cannot collide
            # by having the same string mean different things — a sender
            # address and a URL are not interchangeable even when equal.
            digest = hashlib.sha256(f"{basis}\x00{value}".encode()).hexdigest()
            return GroupingDecision(basis=basis, value=value, key=digest)
    return None


@dataclass
class CampaignRecord:
    id: uuid.UUID
    grouping_basis: str
    grouping_key: str
    sender: str
    subject: str
    report_count: int
    recipient_count: int
    status: str
    created: bool


async def record_report(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    message: ReportedMessage,
    submission_id: uuid.UUID | None = None,
) -> CampaignRecord | None:
    """Join a reported message to its campaign, creating one if needed.

    Returns ``None`` when the message carries nothing to group on, which the
    caller surfaces rather than hides: a submission that joined no campaign
    is still a submission, and saying so is how somebody notices an intake
    adapter that has stopped parsing recipients.

    The recipient rows are inserted with ``ON CONFLICT DO NOTHING`` on
    ``(campaign_id, recipient)``, so a second report of the same message by a
    second person does not duplicate the mailbox — and does not reset a
    ``purge_state`` the first report's purge already set.
    """
    decision = grouping_decision(message)
    if decision is None:
        logger.info("phishing_campaign.ungroupable", tenant_id=str(tenant_id), source=message.intake_source)
        return None

    now = utcnow()
    campaign_id = uuid.uuid4()
    row = (
        await db.execute(
            text("""
                INSERT INTO aisoc_phishing_campaigns
                    (id, tenant_id, grouping_key, grouping_basis, sender, subject,
                     report_count, recipient_count, first_reported_at, last_reported_at,
                     created_at, updated_at)
                VALUES
                    (:id, :tenant_id, :key, :basis, :sender, :subject,
                     1, 0, :now, :now, :now, :now)
                ON CONFLICT (tenant_id, grouping_key) DO UPDATE
                    SET report_count = aisoc_phishing_campaigns.report_count + 1,
                        last_reported_at = EXCLUDED.last_reported_at,
                        updated_at = EXCLUDED.updated_at,
                        -- Fill a field the first report did not carry, and
                        -- never overwrite one it did: the earliest report is
                        -- the closest to the message as delivered.
                        sender = COALESCE(NULLIF(aisoc_phishing_campaigns.sender, ''), EXCLUDED.sender),
                        subject = COALESCE(NULLIF(aisoc_phishing_campaigns.subject, ''), EXCLUDED.subject)
                RETURNING id, grouping_basis, grouping_key, sender, subject,
                          report_count, recipient_count, status, (xmax = 0) AS inserted
            """).bindparams(
                id=campaign_id,
                tenant_id=tenant_id,
                key=decision.key,
                basis=decision.basis,
                sender=message.sender,
                subject=message.subject,
                now=now,
            )
        )
    ).fetchone()

    campaign_id = row.id
    for recipient in message.recipients:
        await db.execute(
            text("""
                INSERT INTO aisoc_phishing_campaign_recipients
                    (id, campaign_id, tenant_id, recipient, internet_message_id, created_at)
                VALUES (:id, :campaign_id, :tenant_id, :recipient, :message_id, :now)
                ON CONFLICT (campaign_id, recipient) DO NOTHING
            """).bindparams(
                id=uuid.uuid4(),
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                recipient=recipient,
                message_id=message.internet_message_id,
                now=now,
            )
        )

    # Recomputed from the rows rather than incremented, in the same
    # transaction. An incremented counter and a de-duplicating insert
    # disagree the first time two people report the same message, and the
    # counter is what decides the approval tier.
    recount = (
        await db.execute(
            text("""
                UPDATE aisoc_phishing_campaigns
                   SET recipient_count = (
                           SELECT count(*) FROM aisoc_phishing_campaign_recipients
                            WHERE campaign_id = :id AND tenant_id = :tenant_id
                       ),
                       updated_at = :now
                 WHERE id = :id AND tenant_id = :tenant_id
             RETURNING recipient_count
            """).bindparams(id=campaign_id, tenant_id=tenant_id, now=now)
        )
    ).fetchone()

    if submission_id is not None:
        await db.execute(
            text("UPDATE aisoc_phishing_submissions SET campaign_id = :cid WHERE id = :sid AND tenant_id = :tenant_id").bindparams(
                cid=campaign_id, sid=submission_id, tenant_id=tenant_id
            )
        )

    return CampaignRecord(
        id=campaign_id,
        grouping_basis=row.grouping_basis,
        grouping_key=row.grouping_key,
        sender=row.sender or message.sender,
        subject=row.subject or message.subject,
        report_count=row.report_count,
        recipient_count=int(recount.recipient_count if recount else 0),
        status=row.status,
        created=bool(row.inserted),
    )


async def list_campaigns(db: AsyncSession, *, tenant_id: uuid.UUID, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            text("""
                SELECT id, grouping_basis, grouping_key, sender, subject, report_count,
                       recipient_count, status, first_reported_at, last_reported_at
                  FROM aisoc_phishing_campaigns
                 WHERE tenant_id = :tenant_id
                 ORDER BY last_reported_at DESC
                 LIMIT :limit OFFSET :offset
            """).bindparams(tenant_id=tenant_id, limit=limit, offset=offset)
        )
    ).fetchall()
    return [_campaign_dict(r) for r in rows]


async def get_campaign(db: AsyncSession, *, tenant_id: uuid.UUID, campaign_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        await db.execute(
            text("""
                SELECT id, grouping_basis, grouping_key, sender, subject, report_count,
                       recipient_count, status, first_reported_at, last_reported_at
                  FROM aisoc_phishing_campaigns
                 WHERE tenant_id = :tenant_id AND id = :id
            """).bindparams(tenant_id=tenant_id, id=campaign_id)
        )
    ).fetchone()
    if row is None:
        return None
    payload = _campaign_dict(row)
    recipients = (
        await db.execute(
            text("""
                SELECT recipient, internet_message_id, purge_state, purge_detail, vendor, last_action_at
                  FROM aisoc_phishing_campaign_recipients
                 WHERE tenant_id = :tenant_id AND campaign_id = :id
                 ORDER BY recipient
            """).bindparams(tenant_id=tenant_id, id=campaign_id)
        )
    ).fetchall()
    payload["recipients"] = [
        {
            "recipient": r.recipient,
            "internet_message_id": r.internet_message_id,
            "purge_state": r.purge_state,
            "purge_detail": r.purge_detail,
            "vendor": r.vendor,
            "last_action_at": r.last_action_at,
        }
        for r in recipients
    ]
    return payload


def _campaign_dict(row: Any) -> dict[str, Any]:
    basis = row.grouping_basis
    return {
        "id": row.id,
        "grouping_basis": basis,
        "grouping_key": row.grouping_key,
        # Published so a console does not have to carry a second copy of
        # FACTUAL_BASES, and so the distinction cannot be dropped by a
        # renderer that does not know it exists.
        "grouping_is_factual": basis in FACTUAL_BASES,
        "sender": row.sender,
        "subject": row.subject,
        "report_count": row.report_count,
        "recipient_count": row.recipient_count,
        "status": row.status,
        "first_reported_at": row.first_reported_at,
        "last_reported_at": row.last_reported_at,
    }
