"""
Email Inbox connector — IMAP-polling pair for ``/v1/inbox/email``.

This connector exists because not every vendor will integrate with our
push endpoint, but almost every vendor on earth knows how to email an
alert. We expose two complementary surfaces:

  * ``POST /v1/inbox/email/{tenant_token}`` — webhook endpoint that
    accepts inbound email from Mailgun / SES Inbound / SendGrid Inbound
    Parse. The vendor (or the customer's mail provider) pushes parsed
    emails directly to us. Lowest latency, no polling cost.

  * This connector — last-resort path for customers who can't (or won't)
    set up an inbound webhook. They forward alerts to a dedicated mailbox
    we can read over IMAP, and this poller pulls the unread messages,
    converts them to the same JSON shape that ``/v1/inbox/email`` would
    have received, and forwards them to the ingest service.

Rules of engagement:
  * The poller only reads UNSEEN messages. It marks them as ``\\Seen``
    after enqueueing so the next poll doesn't double-process them.
  * On any error during IMAP fetch, we leave the message ``\\Unseen``
    so we retry on the next poll. The downside is a poison message can
    block forever — ack that with a future ``move-to-failed-folder``
    knob if it bites.
  * We only read the most recent ``max_messages`` messages per poll to
    bound memory for forgotten mailboxes that have accumulated thousands
    of unread emails.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import ssl
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# Cap how much of a message body we pull in. Real-world alert emails are
# under 64 KB; anything bigger is almost certainly a non-alert (newsletter,
# legal disclaimer footer, etc.) and we'd rather drop characters than
# blow up the ingest pipeline with a 25 MB attachment.
_MAX_BODY_BYTES = 256 * 1024


class EmailInboxConnector(BaseConnector):
    """IMAP-polling sibling of ``/v1/inbox/email/{tenant_token}``.

    The connector treats each unread email in the configured mailbox as
    one normalized event. The body is left as text — the ingest side's
    ``email-forwarded`` template extracts subject / sender / received-at
    into OCSF fields downstream.
    """

    connector_id = "email_inbox"
    connector_name = "Email Inbox (IMAP)"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Poll a mailbox over IMAP and ingest each forwarded alert "
                "email as an event. Pairs with the /v1/inbox/email webhook "
                "for environments that cannot push directly."
            ),
            docs_url="/docs/connectors/email-inbox",
            fields=[
                Field(
                    "host",
                    "string",
                    "IMAP host",
                    placeholder="imap.gmail.com",
                ),
                Field(
                    "port",
                    "number",
                    "IMAP port",
                    required=False,
                    default=993,
                    help_text="Defaults to 993 (IMAPS).",
                ),
                Field(
                    "username",
                    "string",
                    "Username",
                    placeholder="aisoc-alerts@example.com",
                ),
                Field(
                    "password",
                    "secret",
                    "Password / App Password",
                    help_text=("Use an app-specific password for Gmail / Outlook. Never your primary account password."),
                ),
                Field(
                    "mailbox",
                    "string",
                    "Mailbox / folder",
                    required=False,
                    default="INBOX",
                ),
                Field(
                    "max_messages",
                    "number",
                    "Max messages per poll",
                    required=False,
                    default=50,
                    help_text=(
                        "Cap how many unread messages we pull per poll. "
                        "Older unread messages will still arrive — they'll "
                        "just take more polls to drain."
                    ),
                ),
                Field(
                    "use_ssl",
                    "boolean",
                    "Use SSL (IMAPS)",
                    required=False,
                    default=True,
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Pure read — we just pull alerts the user forwarded to us.
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int | str = 993,
        mailbox: str = "INBOX",
        max_messages: int | str = 50,
        use_ssl: bool | str = True,
    ) -> None:
        self._host = host
        self._port = int(port)
        self._username = username
        self._password = password
        self._mailbox = mailbox or "INBOX"
        self._max_messages = max(1, int(max_messages))
        # Boolean fields can arrive as JSON true/false or as the strings
        # "true"/"false" depending on how the wizard form serialised them.
        if isinstance(use_ssl, str):
            self._use_ssl = use_ssl.strip().lower() in ("1", "true", "yes", "on")
        else:
            self._use_ssl = bool(use_ssl)

    # ------------------------------------------------------------------
    # IMAP plumbing — sync code wrapped in ``asyncio.to_thread`` because
    # ``imaplib`` doesn't have an async story and we don't want to pull
    # in a heavier dependency for one connector.
    # ------------------------------------------------------------------

    def _open(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        if self._use_ssl:
            ctx = ssl.create_default_context()
            client: imaplib.IMAP4 | imaplib.IMAP4_SSL = imaplib.IMAP4_SSL(self._host, self._port, ssl_context=ctx)
        else:
            client = imaplib.IMAP4(self._host, self._port)
        client.login(self._username, self._password)
        return client

    @staticmethod
    def _decode_subject(msg: Message) -> str:
        from email.header import decode_header, make_header

        raw = msg.get("Subject") or ""
        try:
            return str(make_header(decode_header(raw)))
        except Exception:  # noqa: BLE001 — best-effort decode
            return raw

    @staticmethod
    def _extract_text(msg: Message) -> str:
        """Return the plaintext body of the message, or empty string.

        We prefer ``text/plain`` parts; fall back to stripped ``text/html``
        only if no plaintext exists. Real-world alert emails almost always
        provide a plaintext alternative, so this rarely matters.
        """
        text_parts: list[str] = []
        html_parts: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = (part.get("Content-Disposition") or "").lower()
                if "attachment" in disp:
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded = payload.decode("utf-8", errors="replace")
                if ctype == "text/plain":
                    text_parts.append(decoded)
                elif ctype == "text/html":
                    html_parts.append(decoded)
        else:
            payload = msg.get_payload(decode=True)
            if payload is not None:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    text_parts.append(payload.decode(charset, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    text_parts.append(payload.decode("utf-8", errors="replace"))

        body = "\n\n".join(p.strip() for p in text_parts if p)
        if not body and html_parts:
            # Cheap HTML strip — no external dep. Ingest side's template
            # only cares about subject / sender / received-at, so the
            # body fidelity isn't critical.
            import re
            from html import unescape

            stripped = re.sub(r"<[^>]+>", " ", html_parts[0])
            body = unescape(re.sub(r"\s+", " ", stripped)).strip()

        if len(body) > _MAX_BODY_BYTES:
            body = body[:_MAX_BODY_BYTES]
        return body

    def _fetch_sync(self) -> list[dict[str, Any]]:
        client = self._open()
        try:
            # ``readonly=False`` so we can mark messages as ``\\Seen`` after
            # we've successfully enqueued them.
            typ, _ = client.select(self._mailbox, readonly=False)
            if typ != "OK":
                raise RuntimeError(f"failed to select mailbox {self._mailbox!r}")

            typ, data = client.search(None, "UNSEEN")
            if typ != "OK":
                raise RuntimeError("IMAP SEARCH UNSEEN failed")
            ids_raw = data[0].split() if data and data[0] else []
            # Most-recent first — last UID is usually newest.
            ids = list(reversed(ids_raw))[: self._max_messages]

            out: list[dict[str, Any]] = []
            for uid in ids:
                try:
                    typ, fetched = client.fetch(uid, "(RFC822)")
                    if typ != "OK" or not fetched or not fetched[0]:
                        continue
                    raw_bytes = fetched[0][1]
                    if not isinstance(raw_bytes, bytes | bytearray):
                        continue
                    msg = email.message_from_bytes(raw_bytes)
                    out.append(self._to_event(msg))
                    # Mark seen only after we've successfully built the
                    # event payload. If we fail mid-loop the message will
                    # show up again on the next poll.
                    client.store(uid, "+FLAGS", "\\Seen")
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "email_inbox.fetch.message_failed",
                        uid=uid.decode("utf-8", errors="replace"),
                        error=str(exc),
                    )
            return out
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass

    def _to_event(self, msg: Message) -> dict[str, Any]:
        """Convert a ``Message`` to the JSON shape ``email-forwarded`` expects.

        The ingest-side ``email-forwarded.yaml`` template reads
        ``subject`` / ``from`` / ``received_at`` / ``body`` keys, so we
        emit exactly that shape. Keep this aligned with that template.
        """
        received_at: str | None = None
        date_hdr = msg.get("Date")
        if date_hdr:
            try:
                received_at = parsedate_to_datetime(date_hdr).isoformat()
            except (TypeError, ValueError):
                received_at = None

        return {
            "subject": self._decode_subject(msg),
            "from": msg.get("From") or "",
            "to": msg.get("To") or "",
            "received_at": received_at,
            "message_id": msg.get("Message-ID") or "",
            "body": self._extract_text(msg),
        }

    # ------------------------------------------------------------------
    # BaseConnector contract.
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        def _probe() -> dict[str, Any]:
            client = self._open()
            try:
                typ, _ = client.select(self._mailbox, readonly=True)
                if typ != "OK":
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"cannot select mailbox {self._mailbox!r}",
                    }
                return {"success": True, "connector": self.connector_id}
            finally:
                try:
                    client.logout()
                except Exception:  # noqa: BLE001
                    pass

        try:
            return await asyncio.to_thread(_probe)
        except Exception as exc:  # noqa: BLE001
            logger.warning("email_inbox.test_connection.failed", error=str(exc))
            return {
                "success": False,
                "connector": self.connector_id,
                "error": str(exc),
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # ``since_seconds`` is ignored: IMAP ``SEARCH UNSEEN`` is its own
        # form of "what changed since last time" and is more accurate
        # than a date filter (which would re-fetch already-processed
        # messages every poll).
        del since_seconds
        try:
            events = await asyncio.to_thread(self._fetch_sync)
        except Exception as exc:  # noqa: BLE001
            logger.warning("email_inbox.fetch_alerts.failed", error=str(exc))
            return []
        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # The ingest side's template handles vendor-specific extraction;
        # we only need to surface the email envelope in a stable shape.
        return raw
