"""Email-security vendor alerts as a phishing-intake door.

The phishing pipeline had three doors — the report mailbox, Google
Workspace user reports, the IMAP inbox — all of them *user* reports. The
tenant's own email-security stack (Proofpoint, Mimecast, Abnormal,
Sublime, Defender for Office 365) was meanwhile raising alerts that landed
in the queue as ordinary alerts and never joined the campaigns a user
report would have joined. One phishing wave therefore existed twice: as a
campaign (from whoever reported it) and as unrelated vendor alerts, and
the purge proposal scaled only with the half that came from people.

This module is the fourth door: a vendor alert whose published fields name
a message becomes a :class:`ReportedMessage` (``intake_source:
vendor_alert``) and flows through the SAME ``record_report`` the other
doors use — same campaign grouping, same recipient rows, same purge
scaling. The intake module's own two rules bind hardest here:

* **Only the vendor's documented fields are read.** Each mapper names the
  vendor payload keys it consumes; a field the vendor did not publish
  stays empty, never guessed.
* **An alert that names no message is not an intake record.** A URL-click
  verdict with no sender and no recipient returns ``None`` rather than a
  campaign member with invented identity.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.services.phishing.intake import ReportedMessage

logger = logging.getLogger("aisoc.phishing.vendor_intake")

#: Connector types this door reads, mapped by the functions below.
VENDOR_ALERT_SOURCES: frozenset[str] = frozenset({"proofpoint", "mimecast", "abnormal_security", "sublime_security", "defender"})


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _emails(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v).strip() for v in value if str(v).strip())
    return ()


def _from_proofpoint(raw: dict[str, Any]) -> ReportedMessage | None:
    """Proofpoint TAP SIEM API fields: ``sender``, ``recipient``/``recipients``,
    ``subject``, ``messageTime``, ``messageID``, ``threatsInfoMap[].threat``
    (the URL for url-type threats). Published in the TAP SIEM API reference."""
    sender = str(raw.get("sender") or "")
    recipients = _emails(raw.get("recipients") or raw.get("recipient"))
    if not sender and not recipients:
        return None
    urls = tuple(
        str(t.get("threat") or "")
        for t in raw.get("threatsInfoMap") or []
        if isinstance(t, dict) and str(t.get("threatType") or "").lower() == "url" and t.get("threat")
    )
    return ReportedMessage(
        intake_source="vendor_alert",
        internet_message_id=str(raw.get("messageID") or ""),
        sender=sender,
        subject=str(raw.get("subject") or ""),
        recipients=recipients,
        reported_by="proofpoint",
        received_at=_parse_time(raw.get("messageTime")),
        urls=urls,
        source_message_id=str(raw.get("GUID") or ""),
    )


def _from_mimecast(raw: dict[str, Any]) -> ReportedMessage | None:
    """Mimecast TTP URL log fields: ``userEmailAddress`` (the recipient who
    clicked/received), ``fromUserEmailAddress``, ``url``, ``date``,
    ``subject`` where present. Published in the TTP URL Logs reference."""
    recipient = str(raw.get("userEmailAddress") or "")
    sender = str(raw.get("fromUserEmailAddress") or "")
    if not recipient and not sender:
        return None
    url = str(raw.get("url") or "")
    return ReportedMessage(
        intake_source="vendor_alert",
        internet_message_id=str(raw.get("messageId") or ""),
        sender=sender,
        subject=str(raw.get("subject") or ""),
        recipients=_emails(recipient),
        reported_by="mimecast",
        received_at=_parse_time(raw.get("date")),
        urls=(url,) if url else (),
        source_message_id=str(raw.get("id") or ""),
    )


def _from_abnormal(raw: dict[str, Any]) -> ReportedMessage | None:
    """Abnormal Security threat fields: ``fromAddress``, ``recipientAddress``
    / ``toAddresses``, ``subject``, ``receivedTime``, ``abxMessageId``,
    ``urls``. Published in the Abnormal REST API threat schema."""
    sender = str(raw.get("fromAddress") or "")
    recipients = _emails(raw.get("toAddresses") or raw.get("recipientAddress"))
    if not sender and not recipients:
        return None
    return ReportedMessage(
        intake_source="vendor_alert",
        internet_message_id=str(raw.get("internetMessageId") or ""),
        sender=sender,
        subject=str(raw.get("subject") or ""),
        recipients=recipients,
        reported_by="abnormal_security",
        received_at=_parse_time(raw.get("receivedTime")),
        urls=_emails(raw.get("urls")),
        source_message_id=str(raw.get("abxMessageId") or raw.get("threatId") or ""),
    )


def _from_sublime(raw: dict[str, Any]) -> ReportedMessage | None:
    """Sublime message fields: ``from``/``from_email``, ``recipients``/``to``,
    ``subject``, ``message_id``, ``created_at``. Published in Sublime's
    message-group API."""
    sender_raw = raw.get("from")
    sender = str(sender_raw.get("email") or "") if isinstance(sender_raw, dict) else str(raw.get("from_email") or sender_raw or "")
    recipients = _emails(raw.get("recipients") or raw.get("to"))
    if not sender and not recipients:
        return None
    return ReportedMessage(
        intake_source="vendor_alert",
        internet_message_id=str(raw.get("message_id") or ""),
        sender=sender,
        subject=str(raw.get("subject") or ""),
        recipients=recipients,
        reported_by="sublime_security",
        received_at=_parse_time(raw.get("created_at")),
        source_message_id=str(raw.get("id") or ""),
    )


def _from_defender_email(raw: dict[str, Any]) -> ReportedMessage | None:
    """Defender ``alerts_v2`` whose ``serviceSource`` is the email product:
    the ``entities`` array's ``mailMessage`` entries carry ``sender``/``p1Sender``,
    ``recipient``, ``subject``, ``internetMessageId``. Published in the Graph
    security alert schema."""
    if str(raw.get("serviceSource") or "") != "microsoftDefenderForOffice365":
        return None
    sender = ""
    subject = ""
    message_id = ""
    recipients: list[str] = []
    for entity in raw.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        etype = str(entity.get("@odata.type") or entity.get("entityType") or "").lower()
        if "mailmessage" not in etype and "mailbox" not in etype:
            continue
        sender = sender or str(
            entity.get("sender") or (entity.get("p1Sender") or {}).get("emailAddress", "")
            if isinstance(entity.get("p1Sender"), dict)
            else entity.get("sender") or ""
        )
        subject = subject or str(entity.get("subject") or "")
        message_id = message_id or str(entity.get("internetMessageId") or "")
        recipient = str(entity.get("recipient") or entity.get("mailboxAddress") or "")
        if recipient:
            recipients.append(recipient)
    if not sender and not recipients:
        return None
    return ReportedMessage(
        intake_source="vendor_alert",
        internet_message_id=message_id,
        sender=sender,
        subject=subject,
        recipients=tuple(dict.fromkeys(recipients)),
        reported_by="defender_office365",
        received_at=_parse_time(raw.get("createdDateTime")),
        source_message_id=str(raw.get("id") or ""),
    )


_MAPPERS = {
    "proofpoint": _from_proofpoint,
    "mimecast": _from_mimecast,
    "abnormal_security": _from_abnormal,
    "sublime_security": _from_sublime,
    "defender": _from_defender_email,
}


def from_vendor_alert(connector_type: str, raw_event: dict[str, Any]) -> ReportedMessage | None:
    """The vendor alert as an intake record, or None when it names no message."""
    mapper = _MAPPERS.get(str(connector_type or ""))
    if mapper is None or not isinstance(raw_event, dict):
        return None
    try:
        return mapper(raw_event)
    except Exception as exc:  # noqa: BLE001 — one malformed alert must not stop the sweep
        logger.warning(
            "phishing.vendor_intake.map_failed connector=%s err=%s",
            connector_type,
            type(exc).__name__,
        )
        return None
