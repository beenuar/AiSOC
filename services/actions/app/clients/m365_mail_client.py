"""Microsoft 365 mailbox client — the read and the soft delete behind reported phish.

Sits beside :mod:`app.clients.azure_entra_client` rather than inside it. The
Entra client speaks to the directory (accounts, sessions, passwords); this one
speaks to mailboxes. They authenticate the same way and share nothing else, and
folding mailbox remediation into the identity client would mean a deployment
that wants to purge mail has to grant ``User.ReadWrite.All`` to get it.

What is declared, and what is deliberately not
----------------------------------------------
Only verbs Microsoft Graph documents an API for:

* ``search_messages``   — ``GET /users/{id}/messages?$filter=internetMessageId eq '…'``
* ``move_message``      — ``POST /users/{id}/messages/{id}/move``
* ``get_message``       — ``GET /users/{id}/messages/{id}``
* ``list_inbox_rules`` / ``create_inbox_rule`` / ``delete_inbox_rule``
  — ``/users/{id}/mailFolders/inbox/messageRules``

There is **no tenant-wide blocked-sender verb here**, because Graph v1.0 does
not expose the Exchange Online Tenant Allow/Block List. That list is reachable
from Exchange Online PowerShell and the Defender portal, neither of which this
platform speaks. :meth:`create_inbox_rule` is a *per-mailbox* block and the
executor that calls it says so in its summary: an analyst who reads "sender
blocked" and believes the organisation is covered has been misled by the
product, which is worse than the product not offering the button.

Purge is a soft delete
----------------------
:meth:`soft_delete_message` moves the message to the ``recoverableitemsdeletions``
well-known folder. That is Graph's documented recoverable-deletion target, it
is what Exchange's own "soft delete" means, and it is undone by moving the
message back — which is why :meth:`move_message` is the one primitive and the
caller supplies the destination. A hard ``DELETE`` has no route back and is not
offered.

The move returns a message with a **new id** in the destination folder. Any
caller that wants to restore has to keep that id and the original
``parentFolderId``; losing either turns a reversible action into a manual
mailbox search during an incident.

Permissions
-----------
Application permissions, consented tenant-wide: ``Mail.ReadWrite`` for the
search, the move and the rules. ``Mail.Read`` alone is enough for the report
mailbox poller and for the verification probe. Grant the narrower one where the
deployment only reads.

Credentials expected in ``LiveActionRequest.params`` (the same three the Entra
client takes, deliberately — one app registration covers both):

* ``azure_tenant_id``
* ``azure_client_id``
* ``azure_client_secret``
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_AUTHORITY = "https://login.microsoftonline.com"
_GRAPH = "https://graph.microsoft.com/v1.0"

#: Graph well-known folder name for the recoverable-items dumpster. Moving a
#: message here is Exchange's soft delete: it leaves the user's view and stays
#: recoverable for the mailbox's retention window.
RECOVERABLE_ITEMS = "recoverableitemsdeletions"

#: Where a restore puts a message back when the caller recorded no original
#: folder. Named rather than inlined so the fallback is visible: restoring to
#: the inbox when the message was filed elsewhere is a change the user notices.
DEFAULT_RESTORE_FOLDER = "inbox"

#: Fields the poller and the search need. Requested explicitly because Graph
#: omits ``internetMessageHeaders`` from the default projection, and a header
#: analysis cannot recover a field the read never asked for — the same defect
#: that left hostname and username null on four of five closed-finding readers.
MESSAGE_SELECT = "id,internetMessageId,subject,from,sender,toRecipients,ccRecipients,receivedDateTime,parentFolderId,hasAttachments,webLink"

#: ``internetMessageHeaders`` is only populated on a single-message GET, never
#: on a collection, so the poller fetches the list and then reads headers per
#: message. Stated here because the asymmetry is a Graph behaviour, not a
#: choice, and a reader will otherwise try to fold the two calls into one.
MESSAGE_DETAIL_SELECT = f"{MESSAGE_SELECT},internetMessageHeaders,body"


def quote_odata_string(value: str) -> str:
    """Escape a value for a single-quoted OData string literal.

    Identical rule to the Entra client's helper, repeated rather than imported
    so neither module depends on the other's internals. A single quote is
    escaped by doubling it; everything else inside the quotes is literal.

    This matters more here than anywhere else in the service: the value is an
    ``internetMessageId`` or a sender address lifted out of a message a
    stranger sent to the customer. It is attacker-authored by definition.
    Control characters are dropped rather than escaped — a newline in a
    message id is not a message id.
    """
    cleaned = "".join(ch for ch in str(value) if ch.isprintable())
    return cleaned.replace("'", "''")


def normalise_internet_message_id(value: str) -> str:
    """Return ``<id@host>`` with the angle brackets Graph stores.

    RFC 5322 brackets a Message-ID and Graph stores it bracketed, so a search
    for the unbracketed form matches nothing and reads as "the message is not
    in that mailbox". Reported-message intake sees both forms — a forwarded
    header keeps the brackets, a vendor JSON field usually strips them.
    """
    cleaned = "".join(ch for ch in str(value) if ch.isprintable()).strip()
    if not cleaned:
        return ""
    if not cleaned.startswith("<"):
        cleaned = f"<{cleaned}"
    if not cleaned.endswith(">"):
        cleaned = f"{cleaned}>"
    return cleaned


class M365MailClient:
    """Async wrapper over the Microsoft Graph mail surfaces AiSOC uses."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, *, timeout: float = 30.0) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._token: str | None = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{_AUTHORITY}/{self._tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        token = str(resp.json()["access_token"])
        self._token = token
        return token

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if not self._token:
            await self._authenticate(client)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    # ── Reads ────────────────────────────────────────────────────────────

    async def search_messages(
        self,
        mailbox: str,
        *,
        internet_message_id: str = "",
        sender: str = "",
        subject: str = "",
        received_after: str = "",
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Return the messages in ``mailbox`` matching the given attributes.

        Every attribute is optional and they combine with ``and``. At least one
        must be supplied: an unfiltered read of a mailbox is a different and far
        more sensitive operation than finding one reported message, and it is
        not what this verb is for.

        Returns ``[]`` when nothing matches. An error is raised, never
        swallowed into an empty list — "no copies of this message" and "the
        search failed" send a responder to opposite conclusions.
        """
        clauses: list[str] = []
        if internet_message_id:
            clauses.append(f"internetMessageId eq '{quote_odata_string(normalise_internet_message_id(internet_message_id))}'")
        if sender:
            clauses.append(f"from/emailAddress/address eq '{quote_odata_string(sender)}'")
        if subject:
            clauses.append(f"subject eq '{quote_odata_string(subject)}'")
        if received_after:
            # A datetime literal in OData is unquoted, so it cannot carry an
            # injected clause the way a string can — but it can still be
            # garbage, and Graph answers 400 rather than ignoring it.
            clauses.append(f"receivedDateTime ge {quote_odata_string(received_after)}")
        if not clauses:
            raise ValueError("search_messages needs at least one of internet_message_id, sender, subject or received_after")

        params = {
            "$filter": " and ".join(clauses),
            "$select": MESSAGE_SELECT,
            "$top": str(max(1, min(int(limit), 100))),
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/messages",
                headers=self._headers(),
                params=params,
            )
            resp.raise_for_status()
            return list(resp.json().get("value") or [])

    async def get_message(self, mailbox: str, message_id: str, *, with_headers: bool = True) -> dict[str, Any]:
        """Read one message, including its internet headers when asked.

        ``with_headers`` is on by default because the only callers are phishing
        intake and header analysis, and both need them. It is a parameter at
        all so the verification probe can ask the cheaper question.
        """
        select = MESSAGE_DETAIL_SELECT if with_headers else MESSAGE_SELECT
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/messages/{quote_odata_string(message_id)}",
                headers=self._headers(),
                params={"$select": select},
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def list_attachments(self, mailbox: str, message_id: str) -> list[dict[str, Any]]:
        """Attachment metadata only — name, type and size. Never content.

        The digest an analyst wants is not in this response and Graph does not
        compute one, so :mod:`app.services.sandbox` is fed a hash the reporter
        supplied or nothing at all. Downloading the bytes to hash them would
        make the report mailbox poller an unattended file-exfiltration path out
        of the customer's tenant, which is exactly the posture the sandbox
        upload policy exists to prevent.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/messages/{quote_odata_string(message_id)}/attachments",
                headers=self._headers(),
                params={"$select": "id,name,contentType,size"},
            )
            resp.raise_for_status()
            return list(resp.json().get("value") or [])

    # ── State changes ────────────────────────────────────────────────────

    async def move_message(self, mailbox: str, message_id: str, destination: str) -> dict[str, Any]:
        """Move a message to a folder. The one state-changing primitive.

        Returns the message **in its new location**, which carries a new ``id``.
        Both the purge and the restore are this call with a different
        destination, so there is one request shape to get right and one place
        a vendor change breaks.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/messages/{quote_odata_string(message_id)}/move",
                headers=self._headers(),
                json={"destinationId": destination},
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def soft_delete_message(self, mailbox: str, message_id: str) -> dict[str, Any]:
        """Move the message into recoverable items. Reversible by ``move_message``."""
        return await self.move_message(mailbox, message_id, RECOVERABLE_ITEMS)

    async def restore_message(self, mailbox: str, message_id: str, destination: str = "") -> dict[str, Any]:
        """Put a soft-deleted message back, in the folder it came from if known."""
        return await self.move_message(mailbox, message_id, destination or DEFAULT_RESTORE_FOLDER)

    async def create_inbox_rule(self, mailbox: str, sender: str, *, display_name: str = "") -> dict[str, Any]:
        """Add an inbox rule deleting future mail from ``sender``.

        **Scoped to this one mailbox.** See the module docstring: Graph has no
        tenant-wide block list, so this is the honest extent of the verb.
        """
        name = display_name or f"AiSOC blocked sender: {sender}"
        body = {
            "displayName": name[:255],
            "sequence": 1,
            "isEnabled": True,
            "conditions": {"senderContains": [sender]},
            "actions": {"delete": True, "stopProcessingRules": True},
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/mailFolders/inbox/messageRules",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def list_inbox_rules(self, mailbox: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/mailFolders/inbox/messageRules",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return list(resp.json().get("value") or [])

    async def delete_inbox_rule(self, mailbox: str, rule_id: str) -> dict[str, Any]:
        """Remove a rule by id. Graph answers 204 with no body."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            await self._ensure_token(client)
            resp = await client.delete(
                f"{_GRAPH}/users/{quote_odata_string(mailbox)}/mailFolders/inbox/messageRules/{quote_odata_string(rule_id)}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return {"deleted": True, "rule_id": rule_id}
