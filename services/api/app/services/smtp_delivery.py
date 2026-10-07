"""The one place this service puts a message on a wire to a person.

Three features in depth 5.2 need to send mail — scheduled reports, the
weekly digest, and the one-click approval email whose issuer and verifier
have shipped since parity 5.2 with nothing calling the sender. One sender
rather than three, because a second copy is a second place for TLS, the
envelope sender and the "did it actually go" answer to be slightly
different, and the generous copy is the one that ends up used.

Off by default
--------------
No ``SMTP_HOST`` means disabled, and disabled is reported as ``skipped``
with a reason rather than as a success. A product that silently starts
emailing a customer's analysts on upgrade is the failure this rule exists
to prevent, and the honest no-op is what lets a caller say "a report was
generated and not delivered, because no relay is configured" instead of
pretending it landed.

``smtplib``, not a dependency
----------------------------
The send blocks, so it runs in a worker thread. ``aiosmtplib`` would be the
obvious alternative and is not worth a new dependency in the service that
already carries the most: the call is one connection, one message, and the
thread pool is where a blocking library belongs.

What it does not do
-------------------
Queue, retry or deduplicate. A caller that needs those has them already —
``outbound_webhooks`` carries its own retry ladder and dead-letter table —
and burying a retry loop here would make every caller inherit a policy none
of them chose.
"""

from __future__ import annotations

import asyncio
import os
import smtplib
import ssl
from dataclasses import dataclass, replace
from email.message import EmailMessage
from email.utils import formataddr

import structlog

logger = structlog.get_logger(__name__)

_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class SmtpSettings:
    """What a relay needs, read from the process environment.

    A frozen dataclass rather than reads scattered through the sender, so a
    test can drive a real relay without monkeypatching ``os.environ`` and so
    "is this configured" is one question with one answer.
    """

    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    sender: str = ""
    sender_name: str = "AiSOC"

    @classmethod
    def from_env(cls) -> SmtpSettings:
        return cls(
            host=os.getenv("SMTP_HOST", "").strip(),
            port=int(os.getenv("SMTP_PORT", "587") or 587),
            username=os.getenv("SMTP_USERNAME", "").strip(),
            password=os.getenv("SMTP_PASSWORD", ""),
            use_tls=os.getenv("SMTP_USE_TLS", "true").strip().lower() not in {"0", "false", "no", "off"},
            sender=os.getenv("SMTP_SENDER", "").strip(),
            sender_name=os.getenv("SMTP_SENDER_NAME", "AiSOC").strip() or "AiSOC",
        )

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender)


@dataclass(frozen=True)
class MailResult:
    """What happened, in terms a caller can record without guessing.

    ``delivered`` is the single field that means a relay accepted the
    message — the same rule the action layer applies to ``executed``. A
    skipped send and a refused send are both ``delivered=False`` and each
    says which it was, because "no relay is configured" and "the relay
    rejected the recipient" send an operator to opposite places.
    """

    delivered: bool
    status: str  # "sent" | "skipped" | "failed"
    detail: str
    recipients: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "delivered": self.delivered,
            "status": self.status,
            "detail": self.detail,
            "recipient_count": len(self.recipients),
        }


def _normalise(recipients: object) -> list[str]:
    if isinstance(recipients, str):
        candidates = recipients.split(",")
    elif isinstance(recipients, list | tuple | set):
        candidates = list(recipients)
    else:
        return []
    return [str(r).strip() for r in candidates if str(r).strip()]


def _build(
    settings: SmtpSettings,
    *,
    recipients: list[str],
    subject: str,
    text_body: str,
    html_body: str = "",
    attachment: tuple[str, bytes, str] | None = None,
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = formataddr((settings.sender_name, settings.sender))
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(text_body)
    if html_body:
        # A plain-text alternative is always set first, so a client that
        # cannot render HTML — or an analyst reading on a locked-down mail
        # gateway — still gets the decision link and the summary.
        message.add_alternative(html_body, subtype="html")
    if attachment is not None:
        filename, payload, mime = attachment
        maintype, _, subtype = mime.partition("/")
        message.add_attachment(payload, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=filename)
    return message


def _send_blocking(settings: SmtpSettings, message: EmailMessage) -> None:
    if settings.use_tls:
        with smtplib.SMTP(settings.host, settings.port, timeout=_TIMEOUT_SECONDS) as server:
            server.starttls(context=ssl.create_default_context())
            if settings.username:
                server.login(settings.username, settings.password)
            server.send_message(message)
        return
    with smtplib.SMTP(settings.host, settings.port, timeout=_TIMEOUT_SECONDS) as server:
        if settings.username:
            server.login(settings.username, settings.password)
        server.send_message(message)


async def send_mail(
    *,
    recipients: object,
    subject: str,
    text_body: str,
    html_body: str = "",
    attachment: tuple[str, bytes, str] | None = None,
    settings: SmtpSettings | None = None,
) -> MailResult:
    """Send one message. Never raises; the result says what happened."""
    resolved = settings or SmtpSettings.from_env()
    addresses = _normalise(recipients)

    if not resolved.configured:
        return MailResult(
            False,
            "skipped",
            "no SMTP relay is configured (set SMTP_HOST and SMTP_SENDER); nothing was sent and nothing was lost",
            tuple(addresses),
        )
    if not addresses:
        return MailResult(False, "skipped", "no recipient addresses", ())

    message = _build(
        resolved,
        recipients=addresses,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        attachment=attachment,
    )
    try:
        await asyncio.to_thread(_send_blocking, resolved, message)
    except Exception as exc:  # noqa: BLE001 — a relay failure is reported, never silent
        logger.warning("smtp.send_failed", recipients=len(addresses), error=str(exc)[:300])
        return MailResult(False, "failed", f"the SMTP relay refused the message: {exc}"[:500], tuple(addresses))

    logger.info("smtp.sent", recipients=len(addresses), subject=subject[:120])
    return MailResult(True, "sent", f"delivered to {len(addresses)} recipient(s)", tuple(addresses))


class SmtpApprovalMailer:
    """An SMTP arm for ``email_approval.MailDeliveryClient``.

    Lives here rather than in ``email_approval.py`` so the sender is one
    implementation of one Protocol, and so adding a transport does not edit
    the module that owns the token format. ``MailgunClient`` next door is
    the hosted alternative; both satisfy the same Protocol and neither knows
    about the other.
    """

    def __init__(self, settings: SmtpSettings | None = None) -> None:
        self._settings = settings or SmtpSettings.from_env()

    @property
    def configured(self) -> bool:
        return self._settings.configured

    async def send(
        self,
        *,
        to: list[str],
        subject: str,
        html: str,
        text: str,
        from_addr: str | None = None,
    ) -> dict[str, object]:
        settings = self._settings if from_addr is None else replace(self._settings, sender=from_addr)
        result = await send_mail(
            recipients=to,
            subject=subject,
            text_body=text,
            html_body=html,
            settings=settings,
        )
        return result.as_dict()
