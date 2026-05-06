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

import itertools
import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])


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


class CopilotConversation(BaseModel):
    id: str
    title: str
    updatedAt: str
    messageCount: int


# ---------------------------------------------------------------------------
# In-memory store (demo: resets on restart; production would use Postgres)
# ---------------------------------------------------------------------------

_CONVERSATIONS: dict[str, dict[str, Any]] = {}

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
) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        return _synthetic_reply(user_message)

    try:
        import httpx

        messages = [
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

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": "gpt-4o-mini", "messages": messages, "max_tokens": 512},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        logger.warning("copilot.openai_error", error=str(exc))
        return _synthetic_reply(user_message)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/conversations")
async def list_conversations(limit: int = 20) -> dict[str, Any]:
    convs = sorted(
        _CONVERSATIONS.values(),
        key=lambda c: c["updatedAt"],
        reverse=True,
    )[:limit]
    return {
        "conversations": [
            {
                "id": c["id"],
                "title": c["title"],
                "updatedAt": c["updatedAt"],
                "messageCount": len(c["messages"]),
            }
            for c in convs
        ]
    }


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str) -> dict[str, Any]:
    conv = _CONVERSATIONS.get(conversation_id)
    if conv is None:
        return {"id": conversation_id, "title": "Not found", "messages": []}
    return {
        "id": conv["id"],
        "title": conv["title"],
        "messages": conv["messages"],
    }


@router.post("/chat", response_model=CopilotChatResponse)
async def chat(req: CopilotChatRequest) -> CopilotChatResponse:
    conv_id = req.conversationId or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    if conv_id not in _CONVERSATIONS:
        _CONVERSATIONS[conv_id] = {
            "id": conv_id,
            "title": _title_from_message(req.message),
            "messages": [],
            "updatedAt": now,
        }

    conv = _CONVERSATIONS[conv_id]

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    conv["messages"].append(user_msg)

    reply_text = await _get_openai_reply(conv, req.message)

    assistant_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply_text,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    conv["messages"].append(assistant_msg)
    conv["updatedAt"] = assistant_msg["timestamp"]

    return CopilotChatResponse(
        conversationId=conv_id,
        reply=CopilotMessage(**assistant_msg),
    )


@router.post("/chat/stream")
async def chat_stream(req: CopilotChatRequest) -> StreamingResponse:
    """Stream a chat reply as NDJSON deltas."""

    conv_id = req.conversationId or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    if conv_id not in _CONVERSATIONS:
        _CONVERSATIONS[conv_id] = {
            "id": conv_id,
            "title": _title_from_message(req.message),
            "messages": [],
            "updatedAt": now,
        }

    conv = _CONVERSATIONS[conv_id]
    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    conv["messages"].append(user_msg)

    reply_text = await _get_openai_reply(conv, req.message)
    msg_id = str(uuid.uuid4())

    async def _stream() -> AsyncIterator[bytes]:
        words = reply_text.split(" ")
        for i, word in enumerate(words):
            chunk = word + (" " if i < len(words) - 1 else "")
            yield (json.dumps({"delta": chunk, "done": False}) + "\n").encode()
            # tiny delay to simulate streaming
            import asyncio

            await asyncio.sleep(0.01)

        assistant_msg: dict[str, Any] = {
            "id": msg_id,
            "role": "assistant",
            "content": reply_text,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        conv["messages"].append(assistant_msg)
        conv["updatedAt"] = assistant_msg["timestamp"]

        yield (
            json.dumps(
                {
                    "done": True,
                    "conversationId": conv_id,
                    "messageId": msg_id,
                }
            )
            + "\n"
        ).encode()

    return StreamingResponse(_stream(), media_type="application/x-ndjson")
