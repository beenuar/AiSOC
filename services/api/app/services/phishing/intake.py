"""What a reported phishing message is, and how three sources become one.

Depth 7.1 names three intake doors: a Microsoft 365 report mailbox read
through Graph, Google Workspace user reports, and the existing
``email_inbox`` IMAP connector. They arrive in three unrelated shapes and the
rest of the phishing path must not know that, so this module is the one place
that does.

The canonical record is :class:`ReportedMessage`. Everything downstream —
grouping, the purge fan-out, header analysis — reads it and nothing reads a
vendor payload.

Two rules the adapters share
----------------------------
**A field that was not in the payload is empty, never invented.** A reported
message with no recipient list produces an empty tuple, and the campaign it
joins reports a recipient count of zero rather than guessing one. A purge
proposal over a guessed recipient list is an action over mailboxes nobody
named.

**The vendor's own shape is the input, not a convenient one.** Each adapter
parses what the vendor documents: a Graph ``message`` resource with
``internetMessageHeaders``, a Gmail ``Message`` with
``payload.headers[].name/value``, and the flat ``subject``/``from``/``to``
dict ``EmailInboxConnector._to_event`` emits. Accepting a tidied shape and
testing against it is how an intake path passes every test and fails on the
first real message.

Why ``internet_message_id`` is normalised here
-----------------------------------------------
RFC 5322 brackets a Message-ID, Graph stores it bracketed and Gmail's
``rfc822msgid:`` operator wants it unbracketed. A reported message arrives
both ways — a forwarded header keeps the brackets, a JSON field usually
strips them. The canonical form here is **bracketed**, matching what Graph
stores and what the header itself contains, and the Gmail client strips them
at the point of use. Picking one and converting at the edges is the
difference between a purge that finds the message and one that reports an
empty mailbox.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

#: The three doors depth 7.1 names, plus ``manual`` for ``POST
#: /phishing/submit``. A closed vocabulary so "the M365 report mailbox has
#: gone quiet" is a diagnosis somebody can make.
INTAKE_SOURCES: frozenset[str] = frozenset({"manual", "m365_graph", "google_workspace", "email_inbox"})

_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

#: Deliberately conservative. A URL extractor that also matches bare domains
#: turns every signature block into an indicator, and the resulting campaign
#: groups on "example.com" — joining messages that have nothing to do with
#: each other and proposing a purge across all of them.
_URL = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)


def normalise_message_id(value: str) -> str:
    """Canonical bracketed form, or ``""``.

    Bracketed is the canonical direction because that is what the header
    contains and what Graph stores; Gmail's search operator wants it bare and
    its client strips at the point of use.
    """
    cleaned = "".join(ch for ch in str(value or "") if ch.isprintable()).strip()
    if not cleaned:
        return ""
    cleaned = cleaned.strip("<>").strip()
    return f"<{cleaned}>" if cleaned else ""


def _addresses(raw: Any) -> tuple[str, ...]:
    """Every address in a header value or list, lowercased and de-duplicated.

    ``getaddresses`` handles the forms a real ``To`` header takes — display
    names, quoting, groups, folded lines — which a ``split(",")`` does not.
    """
    if raw is None:
        return ()
    values = [str(v) for v in raw] if isinstance(raw, (list, tuple, set)) else [str(raw)]
    out: list[str] = []
    for _name, addr in getaddresses(values):
        cleaned = addr.strip().lower()
        if cleaned and "@" in cleaned and cleaned not in out:
            out.append(cleaned)
    return tuple(out)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class ReportedMessage:
    """One reported message, in the shape the rest of the path reads.

    Frozen because an intake record is evidence: a later stage that wants a
    different value should derive one rather than edit what the reporter
    sent.
    """

    intake_source: str
    internet_message_id: str = ""
    sender: str = ""
    subject: str = ""
    recipients: tuple[str, ...] = ()
    reported_by: str = ""
    received_at: datetime | None = None
    urls: tuple[str, ...] = ()
    attachment_hashes: tuple[str, ...] = ()
    #: Attachment metadata as the vendor gave it: name, content type, size.
    #: Never content, and never a digest the vendor did not supply —
    #: downloading bytes to hash them would make the report-mailbox poller an
    #: unattended file-egress path out of the customer's tenant.
    attachments: tuple[dict[str, Any], ...] = ()
    #: Raw internet headers, lowercased name -> value. 7.2 reads these; 7.1
    #: carries them so a later analysis does not have to re-fetch the
    #: message from a mailbox that may by then have been purged.
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    #: The vendor's own id for the message in the *report* mailbox, so the
    #: poller can mark it processed without a second search.
    source_message_id: str = ""

    def __post_init__(self) -> None:
        if self.intake_source not in INTAKE_SOURCES:
            raise ValueError(f"unknown intake source {self.intake_source!r}; expected one of {sorted(INTAKE_SOURCES)}")

    @property
    def recipient_count(self) -> int:
        return len(self.recipients)


def _headers_from_pairs(pairs: Any, name_key: str, value_key: str) -> dict[str, str]:
    """Fold a vendor's ``[{name, value}, ...]`` header list into a dict.

    Repeated headers are joined with a newline rather than overwritten.
    ``Received`` appears once per hop and the hop chain is the whole of its
    value; keeping the last one would describe a one-hop delivery for a
    message that crossed five.
    """
    out: dict[str, str] = {}
    if not isinstance(pairs, (list, tuple)):
        return out
    for entry in pairs:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get(name_key) or "").strip().lower()
        value = str(entry.get(value_key) or "").strip()
        if not name:
            continue
        out[name] = f"{out[name]}\n{value}" if name in out else value
    return out


def _indicators(body: str, headers: dict[str, str], attachments: tuple[dict[str, Any], ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """URLs and SHA-256 digests visible in the message, without fetching anything."""
    haystack = "\n".join([body, headers.get("subject", "")])
    urls = tuple(dict.fromkeys(_URL.findall(haystack)))[:50]
    digests: list[str] = []
    for attachment in attachments:
        for key in ("sha256", "hash", "fileHash", "contentSha256"):
            candidate = str(attachment.get(key) or "")
            if _SHA256.fullmatch(candidate):
                digests.append(candidate.lower())
                break
    return urls, tuple(dict.fromkeys(digests))


# ── Microsoft 365, through Graph ────────────────────────────────────────────


def from_graph_message(payload: dict[str, Any], *, reported_by: str = "") -> ReportedMessage:
    """A Microsoft Graph ``message`` resource from a report mailbox.

    The shape is the documented one: ``internetMessageId``,
    ``from.emailAddress.address``, ``toRecipients[].emailAddress.address``,
    ``receivedDateTime``, ``internetMessageHeaders[].name/value``,
    ``body.content`` and an ``attachments`` collection of ``name`` /
    ``contentType`` / ``size``.

    A user who reports phish by **forwarding** it makes themselves the sender
    of the outer message, so ``reported_by`` is taken from the envelope and
    the *reported* sender is read from the original's headers when the
    forward preserved them. Where it did not, the outer sender is recorded as
    the reporter and the sender field stays empty rather than naming the
    victim as the attacker.
    """
    headers = _headers_from_pairs(payload.get("internetMessageHeaders"), "name", "value")
    envelope_sender = str((payload.get("from") or {}).get("emailAddress", {}).get("address") or "").lower()

    # The original sender, preferred from the preserved headers.
    sender = ""
    for key in ("from", "x-ms-exchange-organization-originalfrom", "reply-to", "return-path"):
        candidates = _addresses(headers.get(key))
        if candidates and candidates[0] != envelope_sender:
            sender = candidates[0]
            break

    recipients = _addresses(
        [str((r or {}).get("emailAddress", {}).get("address") or "") for r in (payload.get("toRecipients") or [])]
        + [str((r or {}).get("emailAddress", {}).get("address") or "") for r in (payload.get("ccRecipients") or [])]
    )
    # A forward lands in the report mailbox addressed to the report mailbox,
    # which is not a recipient of the phish. The original recipients are in
    # the preserved `to`/`cc` headers when there are any.
    header_recipients = _addresses(headers.get("to")) + _addresses(headers.get("cc"))
    if header_recipients:
        recipients = tuple(dict.fromkeys(header_recipients))

    attachments = tuple(
        {
            "name": str(a.get("name") or ""),
            "content_type": str(a.get("contentType") or ""),
            "size": a.get("size"),
        }
        for a in (payload.get("attachments") or [])
        if isinstance(a, dict)
    )
    body = str((payload.get("body") or {}).get("content") or "")
    headers.setdefault("subject", str(payload.get("subject") or ""))
    urls, digests = _indicators(body, headers, attachments)

    return ReportedMessage(
        intake_source="m365_graph",
        internet_message_id=normalise_message_id(headers.get("message-id") or str(payload.get("internetMessageId") or "")),
        sender=sender,
        subject=str(payload.get("subject") or ""),
        recipients=recipients,
        reported_by=reported_by or envelope_sender,
        received_at=_parse_time(payload.get("receivedDateTime")),
        urls=urls,
        attachment_hashes=digests,
        attachments=attachments,
        headers=headers,
        body_text=body,
        source_message_id=str(payload.get("id") or ""),
    )


# ── Google Workspace, through Gmail ─────────────────────────────────────────


def from_gmail_message(payload: dict[str, Any], *, reported_by: str = "") -> ReportedMessage:
    """A Gmail ``Message`` resource, as ``users.messages.get`` returns it.

    ``payload.headers`` is a list of ``{name, value}``; ``snippet`` is the
    only body text a ``format=metadata`` read returns, and that read is
    deliberate — see ``GmailClient.get_message``. Where a caller supplied a
    full ``format=full`` message the base64url body is decoded.
    """
    gmail_payload = payload.get("payload") or {}
    headers = _headers_from_pairs(gmail_payload.get("headers"), "name", "value")

    body = str(payload.get("snippet") or "")
    encoded = ((gmail_payload.get("body") or {}).get("data")) if isinstance(gmail_payload.get("body"), dict) else None
    if encoded:
        try:
            body = base64.urlsafe_b64decode(str(encoded) + "==").decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            # A body that will not decode is not a reason to lose the
            # snippet, and it is certainly not a reason to fail the intake.
            pass

    attachments = tuple(
        {
            "name": str(part.get("filename") or ""),
            "content_type": str(part.get("mimeType") or ""),
            "size": (part.get("body") or {}).get("size"),
        }
        for part in (gmail_payload.get("parts") or [])
        if isinstance(part, dict) and part.get("filename")
    )
    urls, digests = _indicators(body, headers, attachments)
    subject = headers.get("subject", "")

    return ReportedMessage(
        intake_source="google_workspace",
        internet_message_id=normalise_message_id(headers.get("message-id", "")),
        sender=(_addresses(headers.get("from")) or ("",))[0],
        subject=subject,
        recipients=tuple(dict.fromkeys(_addresses(headers.get("to")) + _addresses(headers.get("cc")))),
        reported_by=reported_by or (_addresses(headers.get("delivered-to")) or ("",))[0],
        received_at=_parse_time(headers.get("date")),
        urls=urls,
        attachment_hashes=digests,
        attachments=attachments,
        headers=headers,
        body_text=body,
        source_message_id=str(payload.get("id") or ""),
    )


# ── The existing email_inbox connector ──────────────────────────────────────


def from_email_inbox_event(payload: dict[str, Any], *, reported_by: str = "") -> ReportedMessage:
    """The flat dict ``EmailInboxConnector._to_event`` emits.

    Its keys are ``subject`` / ``from`` / ``to`` / ``received_at`` /
    ``message_id`` / ``body``, which that connector's docstring pins to the
    ingest-side ``email-forwarded`` template. This adapter reads exactly
    those and tolerates a ``headers`` dict when a caller has one, because the
    webhook sibling (``POST /v1/inbox/email/{token}``) can carry more than
    IMAP's six fields.
    """
    headers = {str(k).lower(): str(v) for k, v in (payload.get("headers") or {}).items() if isinstance(payload.get("headers"), dict)}
    body = str(payload.get("body") or "")
    subject = str(payload.get("subject") or headers.get("subject", ""))
    headers.setdefault("subject", subject)
    urls, digests = _indicators(body, headers, ())

    return ReportedMessage(
        intake_source="email_inbox",
        internet_message_id=normalise_message_id(payload.get("message_id") or headers.get("message-id", "")),
        sender=(_addresses(payload.get("from") or headers.get("from")) or ("",))[0],
        subject=subject,
        recipients=_addresses(payload.get("to") or headers.get("to")),
        reported_by=reported_by,
        received_at=_parse_time(payload.get("received_at") or headers.get("date")),
        urls=urls,
        attachment_hashes=digests,
        attachments=(),
        headers=headers,
        body_text=body,
    )


#: ``intake source -> adapter``. A dict rather than an ``if`` chain so the
#: route can validate the source against the same set it dispatches on, and
#: so adding a fourth door is one entry rather than two edits that can
#: disagree.
ADAPTERS = {
    "m365_graph": from_graph_message,
    "google_workspace": from_gmail_message,
    "email_inbox": from_email_inbox_event,
}


def normalise(source: str, payload: dict[str, Any], *, reported_by: str = "") -> ReportedMessage:
    """Turn one vendor payload into a :class:`ReportedMessage`.

    Raises ``ValueError`` for an unknown source rather than falling back to a
    lenient parser. A lenient fallback is how the ingest normaliser came to
    stamp "Splunk" onto events from twenty-six other connectors.
    """
    adapter = ADAPTERS.get(source)
    if adapter is None:
        raise ValueError(f"unknown intake source {source!r}; expected one of {sorted(ADAPTERS)}")
    return adapter(payload, reported_by=reported_by)


def utcnow() -> datetime:
    return datetime.now(UTC)
