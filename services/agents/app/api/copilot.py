"""
Copilot chat API — persistent conversation history.

Endpoints (all under ``/api/v1/copilot``):

    GET  /conversations             — list the last N conversations
    GET  /conversations/{id}        — retrieve a single conversation
    POST /chat                      — one-shot chat (creates / continues conv.)
    POST /chat/stream               — streaming NDJSON variant

When no model answers, the reply says so and names which of the two
reasons applies — nothing is configured, or what is configured did not
return. It does not describe the tenant's data, because nothing read it.
"""

from __future__ import annotations

import asyncio
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
from app.api.copilot_grounding import ground_answer, sources_from_context
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
    #: Why no model answered, when ``source`` is ``template``. Additive
    #: rather than a third ``source`` value, so existing clients branching
    #: on ``template`` keep working while a new one can tell "nothing is
    #: configured" from "what is configured did not answer" (issue #1275).
    template_reason: Literal["no_model_configured", "model_call_failed"] | None = None
    notice: str | None = None
    #: Which factual claims in `reply` cite a record, and which cite
    #: nothing (parity 3.6). The console renders the label beside the
    #: answer: an analyst has no other way to tell a claim drawn from the
    #: evidence from one the model produced because it sounded right.
    grounding: dict[str, Any] | None = None


class CopilotConversation(BaseModel):
    id: str
    title: str
    updatedAt: str
    messageCount: int


# ---------------------------------------------------------------------------
# Conversation store
#
# Tenant-scoped and persistent. This said "in-memory (demo: resets on
# restart)" long after `conversation_store` took both a tenant and a
# database, which is the kind of stale comment that makes a reader
# distrust the ones that are true.
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


#: Why no model answered. These are two different operator problems and
#: the old code could not tell them apart (issue #1275).
NO_MODEL = "no_model_configured"
CALL_FAILED = "model_call_failed"


def _fallback_reply(reason: str, *, model: str | None = None, detail: str | None = None) -> str:
    """What to say when no model answered.

    This used to return one of five rotating paragraphs asserting findings
    about an estate it had never seen — "this IP was seen in 3 other
    alerts", "the attacker dwell time appears short (< 2 hours)", "multiple
    failed authentications followed by a successful login from an unusual
    geolocation". None of it was computed from anything. The reporter hit
    exactly that: a ransomware alert described back to them as
    "credential-access activity ... LOLBin pattern", because the function
    ignored its argument and returned the next item in the cycle.

    A canned paragraph that reads like analysis is worse than no answer,
    and the console appending a disclaimer underneath does not fix the
    body. So the reply is now the explanation, and it makes no claim about
    the tenant's data.
    """
    if reason == NO_MODEL:
        return (
            "I can't answer this: no language model is configured for this deployment.\n\n"
            "Nothing about your alerts, cases or detections was looked at, so treat this as "
            "an unanswered question rather than a finding.\n\n"
            "To enable the copilot, configure a model — either a hosted provider key or the "
            "bundled local model — and ask again."
        )

    named = f" ({model})" if model else ""
    because = f"\n\nThe call reported: {detail}" if detail else ""
    return (
        f"I can't answer this: the configured model{named} did not return a reply.{because}\n\n"
        "Nothing about your alerts, cases or detections was looked at, so treat this as an "
        "unanswered question rather than a finding.\n\n"
        "This is a model or gateway problem, not a missing credential — a model is configured. "
        "On a CPU-only deployment the usual cause is contention with the auto-triage backlog, "
        "which holds the same local model. Retrying usually works; if it does not, check the "
        "model service's own logs."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _title_from_message(msg: str) -> str:
    return msg[:60] + ("…" if len(msg) > 60 else "")


def _notice_for(reason: str | None) -> str | None:
    """The one-line banner the console puts above a template reply.

    One string served both fallback conditions and ended "Configure an LLM
    key to get a real investigation". On a deployment running the bundled
    local model that sentence names a credential the deployment does not
    use, so an operator whose model had merely timed out was sent to fix
    something that was not broken.
    """
    if reason == NO_MODEL:
        return "No language model is configured, so nothing answered this question. This is not analysis of your environment."
    if reason == CALL_FAILED:
        return (
            "A model is configured but the call did not return, so nothing answered this "
            "question. This is not analysis of your environment, and it is not a missing "
            "API key."
        )
    return None


async def _get_openai_reply(
    conversation: dict[str, Any],
    user_message: str,
) -> tuple[str, str, str | None]:
    """Return ``(reply_text, source, reason)``.

    ``source`` is ``llm`` or ``template``; ``reason`` is ``None`` on the
    model path and otherwise names *why* no model answered.

    The caller must surface ``template`` to the user. This function silently
    returned a canned paragraph as a normal 200 whenever the key was missing or
    any exception fired, so an analyst read "this IP was seen in 3 other
    alerts" as real analysis of their environment. The frontend had an honest
    fallback of its own that never fired, because the backend reported success.

    The two fallback conditions are now distinguished (issue #1275). They
    used to collapse into one message telling the operator to configure an
    API key — advice that is simply wrong when a local model is configured
    and timed out, which is the common case on CPU. This repository has the
    same lesson recorded from the RBA banner that named fusion while fusion
    was healthy: a diagnostic pointing at the wrong subsystem sends someone
    to fix something that is not broken, and is worse than a vague one.
    """
    from app.llm.factory import resolve_api_key, resolve_model_alias

    model = resolve_model_alias("copilot")
    # Resolved with the route, not from OPENAI_API_KEY directly: when the call
    # goes to the bundled gateway the bearer has to be the gateway's master key.
    api_key = resolve_api_key(model) or ""
    if not api_key:
        return _fallback_reply(NO_MODEL), "template", NO_MODEL

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
        return body["choices"][0]["message"]["content"], "llm", None
    except Exception as exc:
        # `str(exc)` is empty for several httpx timeout classes, which is
        # how the report ended up with `copilot.openai_error` carrying no
        # message at all. The class name always says something.
        detail = str(exc).strip() or type(exc).__name__
        logger.warning("copilot.openai_error", error=detail, model=model)
        return _fallback_reply(CALL_FAILED, model=model, detail=detail), "template", CALL_FAILED


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
    reply_text, reply_source, reply_reason = await _get_openai_reply(history, req.message)

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

    # Grade the answer against what it was given, and say so either way.
    # A template reply is not graded: it asserts nothing about this
    # estate, and labelling generic guidance "uncited" would put a
    # warning where there is no claim to warn about.
    grounding = ground_answer(reply_text, sources_from_context(req.context)).as_dict() if reply_source == "llm" else None

    return CopilotChatResponse(
        conversationId=stored.id,
        reply=CopilotMessage(**assistant_msg),
        source=reply_source,
        template_reason=reply_reason,
        grounding=grounding,
        notice=_notice_for(reply_reason),
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

    reply_text, reply_source, reply_reason = await _get_openai_reply(history, req.message)
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
        yield (
            json.dumps(
                {
                    "source": reply_source,
                    "template_reason": reply_reason,
                    "notice": _notice_for(reply_reason),
                    "delta": "",
                    "done": False,
                }
            )
            + "\n"
        ).encode()
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
