"""
Copilot chat API — persistent conversation history.

Endpoints (all under ``/api/v1/copilot``):

    GET  /conversations             — list the last N conversations
    GET  /conversations/{id}        — retrieve a single conversation
    POST /chat                      — one-shot chat (creates / continues conv.)
    POST /chat/stream               — streaming NDJSON variant

Falls back to synthetic deterministic replies when ``OPENAI_API_KEY`` is
unset so the demo path never breaks.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.api import conversation_store
from app.security.tenant_scope import (
    TenantPrincipal,
    TenantScopeError,
    require_console_or_service_auth,
    resolve_scoped_tenant,
)

logger = structlog.get_logger()

#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"], dependencies=[Depends(require_console_or_service_auth)])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class CopilotMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str  # "user" | "assistant"
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class CopilotChatRequest(BaseModel):
    message: str
    conversationId: str | None = None
    context: dict[str, Any] | None = None


class CopilotChatResponse(BaseModel):
    conversationId: str
    reply: CopilotMessage
    #: ``llm`` when a model produced the reply, ``template`` when this service
    #: fell back to a canned paragraph (no API key, or the call failed).
    #: The console must label a ``template`` reply rather than presenting it as
    #: analysis of the user's environment.
    source: Literal["llm", "template"] = "llm"
    notice: str | None = None


class CopilotConversation(BaseModel):
    id: str
    title: str
    updatedAt: str
    messageCount: int


# ---------------------------------------------------------------------------
# In-memory store (demo: resets on restart; production would use Postgres)
# ---------------------------------------------------------------------------


def _tenant_of(principal: TenantPrincipal) -> uuid.UUID:
    """The one tenant this request may read and write.

    Conversations lived in a module-level dict keyed by conversation id with
    no tenant anywhere, and the list and fetch handlers bound no principal at
    all — so `GET /conversations` returned every tenant's conversations to
    whoever asked, and `GET /conversations/{id}` returned any conversation to
    anyone holding its id. A copilot conversation carries the analyst's
    question, which names hosts and users, and the model's answer, which
    quotes the evidence it was grounded on.
    """
    try:
        return resolve_scoped_tenant(principal)
    except TenantScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


_SYNTHETIC_REPLIES = [
    (
        "I've analysed the alert context. The activity matches T1078 (Valid Accounts) combined"
        " with T1021.002 (SMB/Windows Admin Shares) lateral movement. Recommend isolating the"
        " host and reviewing recent authentication logs."
    ),
    (
        "Based on the indicators, this looks like credential-access activity. The parent process"
        " chain suggests a LOLBin pattern. Consider adding a detection rule for this specific"
        " chain."
    ),
    (
        "The entity risk score is elevated due to multiple failed authentications followed by a"
        " successful login from an unusual geolocation. I recommend triggering a step-up MFA"
        " challenge."
    ),
    (
        "Correlation across the last 24 hours shows this IP was seen in 3 other alerts. The MITRE"
        " mapping points to T1110 (Brute Force). Blocking the IP at the perimeter is the fastest"
        " remediation."
    ),
    (
        "I've reviewed the case timeline. The attacker dwell time appears short (< 2 hours),"
        " suggesting this may be an automated credential-stuffing campaign rather than a targeted"
        " intrusion."
    ),
]

_reply_cycle = itertools.cycle(_SYNTHETIC_REPLIES)


def _synthetic_reply(user_msg: str) -> str:
    return next(_reply_cycle)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _title_from_message(msg: str) -> str:
    return msg[:60] + ("…" if len(msg) > 60 else "")


async def _get_openai_reply(
    conversation: dict[str, Any],
    user_message: str,
) -> tuple[str, str]:
    """Return ``(reply_text, source)`` where source is ``llm`` or ``template``.

    The caller must surface ``template`` to the user. This function silently
    returned a canned paragraph as a normal 200 whenever the key was missing or
    any exception fired, so an analyst read "this IP was seen in 3 other
    alerts" as real analysis of their environment. The frontend had an honest
    fallback of its own that never fired, because the backend reported success.
    """
    from app.llm.factory import resolve_api_key, resolve_model_alias

    model = resolve_model_alias("copilot")
    # Resolved with the route, not from OPENAI_API_KEY directly: when the call
    # goes to the bundled gateway the bearer has to be the gateway's master key.
    api_key = resolve_api_key(model) or ""
    if not api_key:
        return _synthetic_reply(user_message), "template"

    try:
        from app.llm.contract import safe_chat_completions_request
        from app.llm.factory import chat_completions_url

        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "You are AiSOC Copilot, an AI assistant for security operations. "
                    "Help analysts investigate alerts, correlate events, and respond to threats. "
                    "Be concise, technical, and actionable. Reference MITRE ATT&CK techniques "
                    "when relevant. Format recommendations as numbered steps when appropriate."
                ),
            }
        ]
        for m in conversation.get("messages", [])[-10:]:  # last 10 for context
            messages.append({"role": m["role"], "content": m["content"]})
        messages.append({"role": "user", "content": user_message})

        body = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=messages,
            url=chat_completions_url(model),
            max_tokens=512,
        )
        return body["choices"][0]["message"]["content"], "llm"
    except Exception as exc:
        logger.warning("copilot.openai_error", error=str(exc))
        return _synthetic_reply(user_message), "template"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/conversations")
async def list_conversations(
    limit: int = 20,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> dict[str, Any]:
    """This tenant's conversations, newest first."""
    conversations = await conversation_store.list_conversations(tenant_id=_tenant_of(principal), limit=limit)
    return {"conversations": [c.summary() for c in conversations]}


@router.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> dict[str, Any]:
    """One conversation, if it belongs to this tenant.

    404 rather than the previous `{"title": "Not found", "messages": []}`
    body with a 200. A 200 saying "not found" is a shape no client can
    branch on, and it made "this id does not exist" and "this id is
    somebody else's" look the same as a real empty conversation.
    """
    conversation = await conversation_store.get_conversation(tenant_id=_tenant_of(principal), conversation_id=conversation_id)
    if conversation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such conversation.")
    return conversation.full()


@router.post("/chat", response_model=CopilotChatResponse)
async def chat(
    req: CopilotChatRequest,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> CopilotChatResponse:
    tenant_id = _tenant_of(principal)
    now = datetime.now(UTC).isoformat()

    # Read the existing turns under the tenant predicate, so a caller naming
    # another tenant's conversation id gets a new conversation of their own
    # rather than that one's history as model context.
    existing = (
        await conversation_store.get_conversation(tenant_id=tenant_id, conversation_id=req.conversationId) if req.conversationId else None
    )

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }

    history = {"messages": [*(existing.messages if existing else []), user_msg]}
    reply_text, reply_source = await _get_openai_reply(history, req.message)

    assistant_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply_text,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    # Both turns in one append, so two tabs on the same conversation cannot
    # drop each other's messages the way a read-modify-write would.
    stored = await conversation_store.append_messages(
        tenant_id=tenant_id,
        conversation_id=existing.id if existing else None,
        user_id=None,
        title=existing.title if existing else _title_from_message(req.message),
        new_messages=[user_msg, assistant_msg],
    )

    return CopilotChatResponse(
        conversationId=stored.id,
        reply=CopilotMessage(**assistant_msg),
        source=reply_source,
        notice=(
            "This reply came from a built-in template, not a language model. "
            "It is generic guidance and is not analysis of your environment. "
            "Configure an LLM key to get a real investigation."
            if reply_source == "template"
            else None
        ),
    )


@router.post("/chat/stream")
async def chat_stream(
    req: CopilotChatRequest,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> StreamingResponse:
    """Stream a chat reply as NDJSON deltas."""

    tenant_id = _tenant_of(principal)
    now = datetime.now(UTC).isoformat()

    existing = (
        await conversation_store.get_conversation(tenant_id=tenant_id, conversation_id=req.conversationId) if req.conversationId else None
    )

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    history = {"messages": [*(existing.messages if existing else []), user_msg]}

    reply_text, reply_source = await _get_openai_reply(history, req.message)
    msg_id = str(uuid.uuid4())
    assistant_msg: dict[str, Any] = {
        "id": msg_id,
        "role": "assistant",
        "content": reply_text,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    # Persisted before the stream opens, not inside the generator. A client
    # that disconnects mid-stream used to leave the assistant turn unwritten
    # while the user's question had already been appended, so the next
    # request fed the model a conversation ending in an unanswered question.
    # The reply is fully computed by this point, so there is nothing to wait
    # for.
    stored = await conversation_store.append_messages(
        tenant_id=tenant_id,
        conversation_id=existing.id if existing else None,
        user_id=None,
        title=existing.title if existing else _title_from_message(req.message),
        new_messages=[user_msg, assistant_msg],
    )

    async def _stream() -> AsyncIterator[bytes]:
        # Provenance first: a consumer must be able to label the answer before
        # it starts rendering tokens, not after.
        yield (json.dumps({"source": reply_source, "delta": "", "done": False}) + "\n").encode()
        words = reply_text.split(" ")
        for i, word in enumerate(words):
            chunk = word + (" " if i < len(words) - 1 else "")
            yield (json.dumps({"delta": chunk, "done": False}) + "\n").encode()
            await asyncio.sleep(0.01)

        yield (
            json.dumps(
                {
                    "done": True,
                    "conversationId": stored.id,
                    "messageId": msg_id,
                }
            )
            + "\n"
        ).encode()

    return StreamingResponse(_stream(), media_type="application/x-ndjson")
