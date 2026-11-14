"""Read an enterprise AI-chat compliance API.

Depth plan wave 2, Phase 7.1.

Vendor reference
----------------
Anthropic's Compliance API, the one enterprise AI-chat compliance surface
with a complete public reference at the time of writing. Every path, scope,
key prefix and response field below was read from these pages, each of which
was fetched and returned 200 before being committed:

* https://platform.claude.com/docs/en/manage-claude/compliance-api
* https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
* https://platform.claude.com/docs/en/manage-claude/compliance-org-data
* https://platform.claude.com/docs/en/manage-claude/compliance-content-data

Two key types exist and they are not interchangeable. A Compliance Access
Key (``sk-ant-api01-``), created in the vendor's own console, reaches every
endpoint. An Admin API key (``sk-ant-admin01-``) reaches the Activity Feed
only and is answered ``403`` everywhere else. The client refuses an admin
key for a content or directory read **before** making the request, because
the alternative is an operator reading a 403 as "my key is wrong" when the
key is fine and the type is not.

What this client deliberately does not expose
---------------------------------------------
There is no method returning message bodies to a caller. ``classify_chat``
takes the messages straight from the HTTP response into the classifier and
returns a ``Classification``; the list never leaves this module. A method
that returned the text would be the one future caller away from a
conversation store, and the rest of this feature is built on the premise
that no such store exists.

Equally, there is no delete method. The vendor offers one and the plan's
rule for this phase is read-only: a collector that can delete a customer's
chats is a different risk conversation, and nothing here needs it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.services.ai_chat_compliance.classifier import Classification, classify_chat

logger = structlog.get_logger()

BASE_URL = "https://api.anthropic.com/v1/compliance"
API_VERSION = "2023-06-01"

#: Prefix of a key that reaches every endpoint.
COMPLIANCE_KEY_PREFIX = "sk-ant-api01-"
#: Prefix of a key that reaches the Activity Feed and nothing else.
ADMIN_KEY_PREFIX = "sk-ant-admin01-"

_PAGE = 100
#: Bound on how much of one conversation is read into memory to classify
#: it. A chat with ten thousand messages is a plausible accident and this
#: process should not try to hold it.
_MAX_MESSAGES = 500


class ComplianceKeyTypeError(ValueError):
    """The stored key cannot reach the endpoint being asked for."""


@dataclass(frozen=True)
class ChatRef:
    """One conversation, without any of its content."""

    external_id: str
    project_external_id: str | None
    org_uuid: str | None
    actor_email: str | None
    occurred_at: str | None


class AiChatComplianceClient:
    """Read-only reads against one tenant's compliance API."""

    def __init__(
        self,
        access_key: str,
        *,
        base_url: str = BASE_URL,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` exists so tests drive the real httpx stack.

        The alternative is a hand-written fake client, which is how a test
        double ends up more capable than the thing it stands in for: a fake
        that answers any URL cannot notice a wrong path, and a fake that
        returns a dict cannot notice a response the real stack would have
        raised on. `httpx.MockTransport` replaces only the network leg, so
        request construction, parameter encoding, `raise_for_status` and
        JSON decoding are all the production code paths.
        """
        self._key = access_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, transport=self._transport)

    @property
    def reaches_content(self) -> bool:
        """Whether this key type can read beyond the Activity Feed.

        An Admin API key is answered 403 by the directory and content
        endpoints. Knowing that from the prefix lets the collector say
        "this key type reads the activity feed only" instead of recording
        four authorisation failures an operator has to decode.
        """
        return self._key.startswith(COMPLIANCE_KEY_PREFIX)

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self._key, "anthropic-version": API_VERSION, "Accept": "application/json"}

    def _require_full_key(self, what: str) -> None:
        if not self.reaches_content:
            raise ComplianceKeyTypeError(
                f"{what} needs a Compliance Access Key ({COMPLIANCE_KEY_PREFIX}…); "
                f"the stored key reaches the activity feed only. Mint one in the "
                f"provider console rather than re-trying this one."
            )

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any]) -> dict[str, Any]:
        resp = await client.get(f"{self._base}{path}", headers=self._headers(), params=params)
        resp.raise_for_status()
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def _paged(self, client: httpx.AsyncClient, path: str, params: dict[str, Any], *, pages: int = 10) -> list[dict[str, Any]]:
        """Follow `next_page` while `has_more`, up to a bound.

        Bounded rather than unbounded: an unbounded follow is one vendor
        bug away from a poll that never returns, and a collector that
        cannot finish a cycle never advances its cursor and therefore never
        makes progress at all.
        """
        rows: list[dict[str, Any]] = []
        page: str | None = None
        for _ in range(pages):
            query = dict(params)
            if page:
                query["page"] = page
            body = await self._get(client, path, query)
            rows.extend(r for r in (body.get("data") or []) if isinstance(r, dict))
            if not body.get("has_more"):
                break
            page = body.get("next_page")
            if not page:
                break
        return rows

    async def list_organizations(self) -> list[dict[str, Any]]:
        self._require_full_key("Listing organizations")
        async with self._client() as client:
            return await self._paged(client, "/organizations", {"limit": _PAGE})

    async def list_users(self, org_uuid: str) -> list[dict[str, Any]]:
        self._require_full_key("Listing users")
        async with self._client() as client:
            return await self._paged(client, f"/organizations/{org_uuid}/users", {"limit": _PAGE})

    async def list_roles(self, org_uuid: str) -> list[dict[str, Any]]:
        self._require_full_key("Listing roles")
        async with self._client() as client:
            return await self._paged(client, f"/organizations/{org_uuid}/roles", {"limit": _PAGE})

    async def list_activities(self, *, cursor: str | None = None, pages: int = 10) -> tuple[list[dict[str, Any]], str | None]:
        """The Activity Feed, and the cursor to resume from.

        Both key types carry this scope, so no refusal here. The cursor is
        returned rather than stored, because the only durable place for it
        is the tenant's config row and this client owns no database.
        """
        params: dict[str, Any] = {"limit": _PAGE}
        rows: list[dict[str, Any]] = []
        page = cursor
        async with self._client() as client:
            for _ in range(pages):
                query = dict(params)
                if page:
                    query["page"] = page
                body = await self._get(client, "/activities", query)
                rows.extend(r for r in (body.get("data") or []) if isinstance(r, dict))
                next_page = body.get("next_page")
                if not body.get("has_more") or not next_page:
                    return rows, page
                page = next_page
        return rows, page

    async def list_chats(self, *, pages: int = 10) -> list[ChatRef]:
        """Conversation *references*. No content crosses this boundary."""
        self._require_full_key("Listing chats")
        async with self._client() as client:
            rows = await self._paged(client, "/apps/chats", {"limit": _PAGE}, pages=pages)
        refs: list[ChatRef] = []
        for row in rows:
            chat_id = str(row.get("id") or "")
            if not chat_id:
                continue
            user = row.get("user") if isinstance(row.get("user"), dict) else {}
            refs.append(
                ChatRef(
                    external_id=chat_id,
                    project_external_id=_text(row.get("project_id")),
                    org_uuid=_text(row.get("organization_uuid")),
                    actor_email=_text((user or {}).get("email_address")),
                    occurred_at=_text(row.get("updated_at")) or _text(row.get("created_at")),
                )
            )
        return refs

    async def classify_chat(self, chat_external_id: str) -> Classification:
        """Fetch one conversation and return only what may be kept.

        The message list is local to this call. It is handed to the
        classifier and goes out of scope; no caller of this method can
        reach it, which is the property that makes
        `aisoc_ai_chat_content_labels` safe to persist.
        """
        self._require_full_key("Reading chat messages")
        async with self._client() as client:
            body = await self._get(client, f"/apps/chats/{chat_external_id}/messages", {"limit": min(_PAGE, _MAX_MESSAGES)})
        messages = [_message_text(row) for row in (body.get("data") or []) if isinstance(row, dict)]
        return classify_chat(messages[:_MAX_MESSAGES])


def _message_text(row: dict[str, Any]) -> str:
    """Flatten one message record to the text a classifier reads.

    The vendor sends either a plain `text` or a list of content blocks; a
    reader that handled only the first would classify half a corpus as
    clean, which is the quiet direction of wrong.
    """
    text = row.get("text")
    if isinstance(text, str):
        return text
    content = row.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [str(block.get("text") or "") for block in content if isinstance(block, dict)]
        return "\n".join(p for p in parts if p)
    return ""


def _text(value: Any) -> str | None:
    if value is None:
        return None
    out = str(value).strip()
    return out or None
