"""Gmail client — reported-phish remediation across Workspace mailboxes.

Beside :mod:`app.clients.google_workspace_client` rather than inside it, and
the reason is structural rather than tidiness. That client holds **one**
delegated subject for its whole lifetime, because the Admin SDK acts on the
directory and one admin subject covers every user in it. Gmail does not work
that way: under domain-wide delegation the mailbox you may touch is the one
named in the JWT's ``sub`` claim, so acting on twenty-five recipients means
twenty-five tokens. Reusing the existing client would have meant constructing
twenty-five of it, or silently acting on the wrong mailbox.

Verbs, all documented by the Gmail API
--------------------------------------
* search    — ``GET users/{mailbox}/messages?q=rfc822msgid:<id>``
* read      — ``GET users/{mailbox}/messages/{id}?format=metadata``
* trash     — ``POST users/{mailbox}/messages/{id}/trash``
* untrash   — ``POST users/{mailbox}/messages/{id}/untrash``
* filters   — ``POST`` / ``DELETE users/{mailbox}/settings/filters``

Trash is the Workspace half of ``purge_email`` and untrash is its reverse,
exactly as the plan specifies. A trashed message is recoverable for 30 days;
``users.messages.delete`` is permanent, has no reverse, and is deliberately
absent.

As on Microsoft, the sender block is a **per-mailbox** filter. Workspace's
domain-level blocked-sender list lives in Admin console email settings, which
the Admin SDK does not expose, so the organisation-wide verb is not declared.

Scopes the service account needs, granted domain-wide:

* ``https://www.googleapis.com/auth/gmail.modify``         — trash, untrash
* ``https://www.googleapis.com/auth/gmail.settings.basic`` — filters
* ``https://www.googleapis.com/auth/gmail.readonly``       — search, read

Credentials expected in ``LiveActionRequest.params``:

* ``gws_service_account_key`` — the JSON key, as a string or an object
* ``gws_subject_email``       — fallback mailbox when the caller names none,
  normally the report mailbox the poller reads
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import quote

import httpx
import structlog

logger = structlog.get_logger()

_TOKEN_URI = "https://oauth2.googleapis.com/token"
_GMAIL = "https://gmail.googleapis.com/gmail/v1"

_SCOPES = " ".join(
    [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ]
)

#: Headers the intake path needs. Gmail returns only what you ask for in
#: ``metadataHeaders``, so a header omitted here is a header the analysis
#: cannot recover later — the field is not merely unparsed, it was never
#: fetched.
METADATA_HEADERS = (
    "Message-ID",
    "From",
    "Sender",
    "Reply-To",
    "Return-Path",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Received",
    "Received-SPF",
    "Authentication-Results",
    "ARC-Authentication-Results",
    "DKIM-Signature",
)


def quote_gmail_query_value(value: str) -> str:
    """Make an attacker-supplied value safe inside a Gmail ``q=`` expression.

    Gmail's search grammar is whitespace-separated operators, so a raw value
    containing a space, a quote or a colon can close one term and open
    another: ``rfc822msgid:x in:anywhere from:ceo@`` searches for something
    nobody asked for. Every value here comes off a message a stranger sent.

    The refusal is deliberate and follows the osquery lesson: a denylist of
    dangerous characters is the wrong control, and an escaped value that
    reaches the API and matches nothing reports a clean result from a query
    that never ran. So the dangerous shape is made unrepresentable — the value
    is restricted to the characters a message id or an address can contain,
    and anything else raises.
    """
    cleaned = str(value).strip().strip("<>")
    if not cleaned:
        raise ValueError("empty Gmail query value")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.@_-+=/")
    bad = sorted({ch for ch in cleaned if ch not in allowed})
    if bad:
        raise ValueError(f"value is not a message id or an address; refusing rather than escaping (disallowed: {bad!r})")
    return cleaned


class GmailClient:
    """Async Gmail wrapper that mints one delegated token per mailbox.

    Tokens are cached per mailbox for their lifetime less a safety margin, so
    a 25-recipient purge mints 25 tokens once rather than 50 times.
    """

    def __init__(self, service_account_key: str | dict, subject_email: str = "", *, timeout: float = 30.0) -> None:
        if isinstance(service_account_key, str):
            try:
                service_account_key = json.loads(service_account_key)
            except json.JSONDecodeError as exc:
                raise ValueError(f"gws_service_account_key is not valid JSON: {exc}") from exc
        if not isinstance(service_account_key, dict):
            raise ValueError(f"gws_service_account_key must be a JSON object, got {type(service_account_key).__name__}")
        self._key: dict[str, Any] = service_account_key
        self._default_subject = subject_email
        self._timeout = timeout
        #: mailbox -> (access token, expiry epoch seconds)
        self._tokens: dict[str, tuple[str, float]] = {}

    def _subject_for(self, mailbox: str) -> str:
        subject = (mailbox or self._default_subject or "").strip()
        if not subject:
            raise ValueError("Gmail calls need a mailbox: domain-wide delegation impersonates exactly one user per token")
        return subject

    async def _mint_token(self, client: httpx.AsyncClient, subject: str) -> str:
        """Sign a delegated JWT for ``subject`` and exchange it for a token.

        Signed inline for the same reason the Workspace client does it: the
        claim set is fixed and pulling in ``google-auth`` for one RSA-SHA256
        signature is not worth the dependency.
        """
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._key["client_email"],
            "sub": subject,
            "scope": _SCOPES,
            "aud": _TOKEN_URI,
            "iat": now,
            "exp": now + 3600,
        }

        def _b64(blob: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).rstrip(b"=").decode()

        signing_input = f"{_b64(header)}.{_b64(claims)}".encode()
        private_key = serialization.load_pem_private_key(self._key["private_key"].encode(), password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jwt_str = f"{signing_input.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

        resp = await client.post(
            _TOKEN_URI,
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt_str},
        )
        resp.raise_for_status()
        body = resp.json()
        token = str(body["access_token"])
        self._tokens[subject] = (token, time.time() + int(body.get("expires_in", 3600)) - 60)
        return token

    async def _headers_for(self, client: httpx.AsyncClient, mailbox: str) -> dict[str, str]:
        subject = self._subject_for(mailbox)
        cached = self._tokens.get(subject)
        token = cached[0] if cached and time.time() < cached[1] else await self._mint_token(client, subject)
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    @staticmethod
    def _path(mailbox: str, suffix: str) -> str:
        return f"{_GMAIL}/users/{quote(mailbox, safe='')}/{suffix}"

    # ── Reads ────────────────────────────────────────────────────────────

    async def search_messages(
        self,
        mailbox: str,
        *,
        internet_message_id: str = "",
        sender: str = "",
        after_epoch_seconds: int = 0,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Return ``{id, threadId}`` for each match. Terms combine with AND.

        At least one of the message id or the sender is required. An unfiltered
        mailbox listing is a different operation from finding one reported
        message and is not what this is for.
        """
        terms: list[str] = []
        if internet_message_id:
            terms.append(f"rfc822msgid:{quote_gmail_query_value(internet_message_id)}")
        if sender:
            terms.append(f"from:{quote_gmail_query_value(sender)}")
        if not terms:
            raise ValueError("search_messages needs an internet_message_id or a sender")
        if after_epoch_seconds > 0:
            # `after:` takes a bare epoch; it is generated here and never
            # caller-supplied, so there is no value to sanitise.
            terms.append(f"after:{int(after_epoch_seconds)}")

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.get(
                self._path(self._subject_for(mailbox), "messages"),
                headers=headers,
                params={
                    "q": " ".join(terms),
                    "maxResults": str(max(1, min(int(limit), 100))),
                    "includeSpamTrash": "true",
                },
            )
            resp.raise_for_status()
            return list(resp.json().get("messages") or [])

    async def get_message(self, mailbox: str, message_id: str) -> dict[str, Any]:
        """Metadata and headers only. The body is never fetched.

        ``format=metadata`` is a deliberate ceiling: the intake path runs
        unattended against every reported message, and pulling message bodies
        out of a customer's tenant into AiSOC's database is a disclosure
        nobody asked for. Headers are what the analysis needs.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.get(
                self._path(self._subject_for(mailbox), f"messages/{quote(message_id, safe='')}"),
                headers=headers,
                params=[("format", "metadata"), *[("metadataHeaders", h) for h in METADATA_HEADERS]],
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def list_messages_with_label(self, mailbox: str, label: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """List message ids carrying ``label``. Used by the report-mailbox poller."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.get(
                self._path(self._subject_for(mailbox), "messages"),
                headers=headers,
                params={"labelIds": label, "maxResults": str(max(1, min(int(limit), 100)))},
            )
            resp.raise_for_status()
            return list(resp.json().get("messages") or [])

    # ── State changes ────────────────────────────────────────────────────

    async def trash_message(self, mailbox: str, message_id: str) -> dict[str, Any]:
        """Move a message to Trash. Recoverable for 30 days; undone by untrash."""
        return await self._post(mailbox, f"messages/{quote(message_id, safe='')}/trash")

    async def untrash_message(self, mailbox: str, message_id: str) -> dict[str, Any]:
        """Take a message back out of Trash. The declared reverse of trash."""
        return await self._post(mailbox, f"messages/{quote(message_id, safe='')}/untrash")

    async def _post(self, mailbox: str, suffix: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.post(self._path(self._subject_for(mailbox), suffix), headers=headers, json=payload or {})
            resp.raise_for_status()
            return dict(resp.json()) if resp.content else {}

    async def create_filter(self, mailbox: str, sender: str) -> dict[str, Any]:
        """Add a filter trashing future mail from ``sender``. Per-mailbox only."""
        return await self._post(
            mailbox,
            "settings/filters",
            {"criteria": {"from": sender}, "action": {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}},
        )

    async def list_filters(self, mailbox: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.get(self._path(self._subject_for(mailbox), "settings/filters"), headers=headers)
            resp.raise_for_status()
            return list(resp.json().get("filter") or [])

    async def delete_filter(self, mailbox: str, filter_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = await self._headers_for(client, mailbox)
            resp = await client.delete(
                self._path(self._subject_for(mailbox), f"settings/filters/{quote(filter_id, safe='')}"),
                headers=headers,
            )
            resp.raise_for_status()
            return {"deleted": True, "filter_id": filter_id}
