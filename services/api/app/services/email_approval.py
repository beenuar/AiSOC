"""
Email approval fallback (T3.6).

When Slack / Teams aren't configured or are unreachable, the action
service can mint a signed approval URL and post it to the on-call email
distribution list via Mailgun. The recipient clicks Approve / Deny;
that URL hits ``services/api`` which verifies the HMAC signature and
the 1-hour freshness window, then calls into ``services/actions`` to
record the decision and writes an audit row.

Design notes
============

* **No bespoke crypto.** We use ``hmac.compare_digest`` over
  ``hashlib.sha256`` — the same primitive as the Slack/Teams shared
  HMAC verifier. Keeps key rotation simple (one env var) and lets the
  signed-URL format be reproduced manually for debug.
* **URL-safe-base64 envelope.** The signed token is a single opaque
  string that the recipient never has to URL-encode again. The token
  encodes ``"<decision>|<action_id>|<case_id>|<expires_at>"`` plus the
  signature; the API endpoint decodes, verifies, and dispatches.
* **Mailgun client is injectable.** The default :class:`MailgunClient`
  uses ``httpx`` with ``api`` auth. Tests pass a stub that records the
  sent payload — no network. The Mailgun secret is *only* read inside
  the client constructor, never at module scope.
* **1-hour TTL** by default. Tunable through
  ``AISOC_EMAIL_APPROVAL_TTL_SECONDS``. The expiry stamp is signed
  alongside the rest of the payload so an attacker can't extend it
  client-side.

The endpoint that consumes these tokens (``GET /v1/actions/email-decide``
or similar) is wired in a follow-up — this module ships the *issuer*
side plus the verifier, so any web route can adopt it with three lines
of glue.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
import structlog

log = structlog.get_logger(__name__)

DEFAULT_TTL_SECONDS = 3600  # 1 hour — T3.6 contract


class EmailApprovalError(ValueError):
    """Raised when a signed email-approval token fails verification."""


# ────────────────────────────────────────────────────────────────────────────
# Signing + verification
# ────────────────────────────────────────────────────────────────────────────


@dataclass(slots=True, frozen=True)
class ApprovalToken:
    """One parsed + verified email-approval token."""

    decision: str  # "approved" | "rejected"
    action_id: str
    case_id: str
    expires_at: int

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(token: str) -> bytes:
    pad = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + pad)


def _canonical_payload(decision: str, action_id: str, case_id: str, expires_at: int) -> str:
    return f"{decision}|{action_id}|{case_id}|{int(expires_at)}"


def _hmac_hex(payload: str, *, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(
    *,
    decision: str,
    action_id: str,
    case_id: str,
    secret: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """
    Mint a signed approval token (opaque base64-url string).

    ``decision`` must be ``"approved"`` or ``"rejected"`` so the email
    template generates one URL per choice and the recipient's click is
    self-describing.
    """
    if decision not in {"approved", "rejected"}:
        raise EmailApprovalError(f"unsupported decision {decision!r}")
    if not secret:
        raise EmailApprovalError("signing secret is empty — refusing to issue")
    if not action_id:
        raise EmailApprovalError("action_id is required")

    issued = float(now if now is not None else time.time())
    expires_at = int(issued + max(60, int(ttl_seconds)))
    canonical = _canonical_payload(decision, action_id, case_id, expires_at)
    signature = _hmac_hex(canonical, secret=secret)
    envelope = json.dumps(
        {
            "d": decision,
            "a": action_id,
            "c": case_id,
            "e": expires_at,
            "s": signature,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _b64url_encode(envelope)


def verify_token(token: str, *, secret: str, now: float | None = None) -> ApprovalToken:
    """
    Decode + verify a token issued by :func:`issue_token`.

    Raises :class:`EmailApprovalError` on any failure — malformed
    base64, missing fields, signature mismatch, expired window.
    """
    if not secret:
        raise EmailApprovalError("signing secret is empty — refusing to verify")
    if not token:
        raise EmailApprovalError("empty token")

    try:
        raw = _b64url_decode(token)
        envelope = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise EmailApprovalError(f"malformed token: {exc}") from exc

    decision = str(envelope.get("d") or "")
    action_id = str(envelope.get("a") or "")
    case_id = str(envelope.get("c") or "")
    expires_at_raw = envelope.get("e")
    signature = str(envelope.get("s") or "")

    if decision not in {"approved", "rejected"}:
        raise EmailApprovalError(f"unsupported decision {decision!r}")
    if not action_id:
        raise EmailApprovalError("token missing action_id")
    if not isinstance(expires_at_raw, int):
        raise EmailApprovalError("token missing expires_at")

    canonical = _canonical_payload(decision, action_id, case_id, int(expires_at_raw))
    expected = _hmac_hex(canonical, secret=secret)
    if not hmac.compare_digest(expected, signature):
        raise EmailApprovalError("signature mismatch")

    current = float(now if now is not None else time.time())
    if current > float(expires_at_raw):
        raise EmailApprovalError("token expired")

    return ApprovalToken(
        decision=decision,
        action_id=action_id,
        case_id=case_id,
        expires_at=int(expires_at_raw),
    )


def approval_url(
    *,
    base_url: str,
    endpoint_path: str = "/v1/actions/email-decide",
    decision: str,
    action_id: str,
    case_id: str,
    secret: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """Build the full signed URL embedded in the approval email."""
    token = issue_token(
        decision=decision,
        action_id=action_id,
        case_id=case_id,
        secret=secret,
        ttl_seconds=ttl_seconds,
        now=now,
    )
    qs = urlencode({"token": token})
    return f"{base_url.rstrip('/')}{endpoint_path}?{qs}"


# ────────────────────────────────────────────────────────────────────────────
# Mailgun client
# ────────────────────────────────────────────────────────────────────────────


class MailDeliveryClient(Protocol):
    async def send(
        self,
        *,
        to: list[str],
        subject: str,
        html: str,
        text: str,
        from_addr: str | None = None,
    ) -> dict[str, Any]:
        # Protocol stub body uses ``pass`` rather than ``...`` to silence
        # CodeQL ``py/ineffectual-statement``. Semantically identical for
        # an unimplemented Protocol method.
        pass


class MailgunClient:
    """
    Minimal Mailgun client. Authenticates with the standard
    ``api:<api_key>`` basic-auth header. Reads ``MAILGUN_API_KEY`` and
    ``MAILGUN_DOMAIN`` from the environment unless overridden at
    construction time so unit tests can pass deterministic fixtures.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        domain: str | None = None,
        base_url: str = "https://api.mailgun.net/v3",
        from_addr: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.environ.get("MAILGUN_API_KEY", "")
        self._domain = domain if domain is not None else os.environ.get("MAILGUN_DOMAIN", "")
        self._base_url = base_url.rstrip("/")
        self._from_addr = from_addr or os.environ.get("AISOC_APPROVAL_FROM_ADDR", "approvals@tryaisoc.com")
        self._client = client or httpx.AsyncClient(timeout=10.0)

    async def send(
        self,
        *,
        to: list[str],
        subject: str,
        html: str,
        text: str,
        from_addr: str | None = None,
    ) -> dict[str, Any]:
        if not self._api_key or not self._domain:
            raise EmailApprovalError("Mailgun is not configured — set MAILGUN_API_KEY and MAILGUN_DOMAIN")
        url = f"{self._base_url}/{self._domain}/messages"
        data: dict[str, Any] = {
            "from": from_addr or self._from_addr,
            "to": to,
            "subject": subject,
            "text": text,
            "html": html,
        }
        response = await self._client.post(url, data=data, auth=("api", self._api_key))
        response.raise_for_status()
        return response.json() if response.content else {"ok": True}

    async def aclose(self) -> None:
        await self._client.aclose()


# ────────────────────────────────────────────────────────────────────────────
# High-level send
# ────────────────────────────────────────────────────────────────────────────


def render_approval_email(
    *,
    case: dict[str, Any],
    action: dict[str, Any],
    approve_url: str,
    reject_url: str,
    web_base_url: str,
) -> tuple[str, str, str]:
    """
    Render a plain-text + HTML approval email for a pending action.

    Returns ``(subject, text_body, html_body)``.
    """
    case_number = case.get("case_number") or str(case.get("id") or "")[:8] or "(unknown)"
    action_type = action.get("action_type") or "unknown"
    target = action.get("target") or "unknown"
    rationale = (action.get("rationale") or "(no rationale provided)").strip()

    subject = f"[AiSOC] Approval needed: {action_type} on {target} — case {case_number}"

    text_body = (
        f"AiSOC approval request\n\n"
        f"Case:     {case_number}\n"
        f"Action:   {action_type}\n"
        f"Target:   {target}\n"
        f"Rationale: {rationale}\n\n"
        f"Approve: {approve_url}\n"
        f"Deny:    {reject_url}\n\n"
        f"Open case in AiSOC: {web_base_url.rstrip('/')}/cases/{case.get('id') or ''}\n\n"
        f"This link expires in 60 minutes. Replies to this email are not monitored.\n"
    )

    html_body = (
        f"<p><strong>AiSOC approval request</strong></p>"
        f"<table style='border-collapse:collapse'>"
        f"<tr><td><strong>Case</strong></td><td>{case_number}</td></tr>"
        f"<tr><td><strong>Action</strong></td><td><code>{action_type}</code></td></tr>"
        f"<tr><td><strong>Target</strong></td><td><code>{target}</code></td></tr>"
        f"<tr><td><strong>Rationale</strong></td><td>{rationale}</td></tr>"
        f"</table>"
        f"<p style='margin-top:16px'>"
        f"<a href='{approve_url}' style='background:#16a34a;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;margin-right:8px'>Approve</a>"  # noqa: E501
        f"<a href='{reject_url}' style='background:#dc2626;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none'>Deny</a>"
        f"</p>"
        f"<p style='color:#6b7280;font-size:12px'>This link expires in 60 minutes.</p>"
    )
    return subject, text_body, html_body


async def send_approval_email(
    *,
    recipients: list[str],
    case: dict[str, Any],
    action: dict[str, Any],
    api_base_url: str,
    web_base_url: str,
    secret: str,
    mailer: MailDeliveryClient,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """
    Mint signed approve/deny URLs, render the email body, and dispatch
    through the configured mailer.

    Returns the mailer response unchanged so callers can persist the
    Mailgun message id for the case timeline.
    """
    if not recipients:
        raise EmailApprovalError("no recipients provided")

    action_id = str(action.get("id") or action.get("action_id") or "")
    case_id = str(case.get("id") or "")
    if not action_id:
        raise EmailApprovalError("action.id is required")

    approve = approval_url(
        base_url=api_base_url,
        decision="approved",
        action_id=action_id,
        case_id=case_id,
        secret=secret,
        ttl_seconds=ttl_seconds,
        now=now,
    )
    reject = approval_url(
        base_url=api_base_url,
        decision="rejected",
        action_id=action_id,
        case_id=case_id,
        secret=secret,
        ttl_seconds=ttl_seconds,
        now=now,
    )
    subject, text_body, html_body = render_approval_email(
        case=case,
        action=action,
        approve_url=approve,
        reject_url=reject,
        web_base_url=web_base_url,
    )
    response = await mailer.send(to=recipients, subject=subject, html=html_body, text=text_body)
    log.info(
        "email_approval.sent",
        action_id=action_id,
        case_id=case_id,
        recipients=len(recipients),
        ttl_seconds=ttl_seconds,
    )
    return response
