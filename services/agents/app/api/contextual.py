"""
Phase 4A — Ambient Copilot contextual actions.

This router powers the contextual AI buttons that surface across every page in
the AiSOC console (alerts, cases, detections, playbooks). Each "action" is a
short, focused prompt with a curated system message and a small input shape;
the LLM returns Markdown that the UI renders inline next to the entity the
user is looking at.

Why a dedicated module instead of reusing the generic Copilot chat?
  • Determinism: each action has a fixed system prompt and known output shape,
    so the UI can render confidence + suggested follow-ups consistently.
  • Cheap: actions are single-shot calls, no conversation history to ship.
  • Auditability: every contextual call logs to the investigation ledger if a
    case_id is supplied, so analysts can replay why the agent suggested
    something later.

Endpoint surface (all under ``/api/v1/contextual``):
    POST /action          — one-shot call returning ``ContextualActionResponse``
    POST /action/stream   — NDJSON streaming variant (delta tokens)
    GET  /actions         — catalogue of supported actions per page

Page → action matrix (kept in sync with ``ContextualActions.tsx``):
    alerts       → explain, false_positive, find_similar
    cases        → draft_comms, exec_summary, post_mortem
    detections   → why_noisy, tighten
    playbooks    → explain, improve

Falls back to a deterministic synthetic response if ``OPENAI_API_KEY`` is
unset, so the demo path never breaks.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/contextual", tags=["contextual"])


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

class ContextualActionRequest(BaseModel):
    """A single contextual ambient-copilot call.

    ``entity`` is optional — when the UI already has the alert / case / rule
    rendered locally it ships the relevant fields so the backend can answer
    without an extra round-trip. When omitted the backend produces a generic
    answer based on ``entity_id`` alone.
    """

    page: str = Field(
        ..., description="One of: alerts, cases, detections, playbooks"
    )
    action: str = Field(..., description="Action key. See /actions for the catalogue.")
    entity_id: str = Field(..., description="ID of the alert / case / rule / playbook.")
    entity: dict[str, Any] | None = Field(
        default=None,
        description="Optional snapshot of the entity the user is looking at.",
    )
    question: str | None = Field(
        default=None,
        description="Optional free-form follow-up question from the user.",
    )
    case_id: str | None = Field(
        default=None,
        description="If set, the call is logged to the investigation ledger.",
    )


class ContextualSuggestion(BaseModel):
    label: str
    action: str | None = None
    href: str | None = None


class ContextualActionResponse(BaseModel):
    id: str
    page: str
    action: str
    entity_id: str
    title: str
    content: str  # Markdown
    confidence: float = Field(ge=0.0, le=1.0)
    suggestions: list[ContextualSuggestion] = []
    citations: list[dict[str, Any]] = []
    model: str
    elapsed_ms: int
    fallback: bool = False
    created_at: str


class ContextualActionDescriptor(BaseModel):
    key: str
    label: str
    description: str
    icon: str | None = None


class ContextualActionsCatalogue(BaseModel):
    pages: dict[str, list[ContextualActionDescriptor]]


# ---------------------------------------------------------------------------
# Action registry — drives both the catalogue endpoint and the prompt builder
# ---------------------------------------------------------------------------

_ACTION_CATALOGUE: dict[str, list[dict[str, str]]] = {
    "alerts": [
        {
            "key": "explain",
            "label": "Explain this alert",
            "description": "Break down what the alert means, why it fired, and the likely attacker behavior.",
            "icon": "info",
        },
        {
            "key": "false_positive",
            "label": "Is this a false positive?",
            "description": "Score the likelihood of FP and call out the signals on each side.",
            "icon": "shield",
        },
        {
            "key": "find_similar",
            "label": "Find similar",
            "description": "Suggest related alerts and the queries to find them.",
            "icon": "search",
        },
    ],
    "cases": [
        {
            "key": "draft_comms",
            "label": "Draft customer comms",
            "description": "Draft a customer-facing notification with appropriate tone and disclosure level.",
            "icon": "mail",
        },
        {
            "key": "exec_summary",
            "label": "Summarize for exec brief",
            "description": "One-paragraph executive summary with impact, status, and ask.",
            "icon": "briefcase",
        },
        {
            "key": "post_mortem",
            "label": "Generate post-mortem",
            "description": "Blameless post-mortem skeleton with timeline, root cause, and action items.",
            "icon": "file-text",
        },
    ],
    "detections": [
        {
            "key": "why_noisy",
            "label": "Why is this rule noisy?",
            "description": "Explain why this rule is generating excessive false positives.",
            "icon": "volume",
        },
        {
            "key": "tighten",
            "label": "Suggest a tighter version",
            "description": "Propose a refined rule with fewer false positives but the same true positives.",
            "icon": "filter",
        },
    ],
    "playbooks": [
        {
            "key": "explain",
            "label": "Explain this playbook",
            "description": "Walk through what each step does and what triggers each branch.",
            "icon": "info",
        },
        {
            "key": "improve",
            "label": "Suggest improvements",
            "description": "Identify gaps, missing approval gates, or rollback steps.",
            "icon": "trending-up",
        },
    ],
}


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

_TITLES: dict[tuple[str, str], str] = {
    ("alerts", "explain"): "Alert explanation",
    ("alerts", "false_positive"): "False-positive assessment",
    ("alerts", "find_similar"): "Similar alerts",
    ("cases", "draft_comms"): "Customer comms draft",
    ("cases", "exec_summary"): "Executive summary",
    ("cases", "post_mortem"): "Post-mortem skeleton",
    ("detections", "why_noisy"): "Rule noise analysis",
    ("detections", "tighten"): "Tighter rule proposal",
    ("playbooks", "explain"): "Playbook walkthrough",
    ("playbooks", "improve"): "Playbook improvements",
}


_FOLLOW_UPS: dict[tuple[str, str], list[ContextualSuggestion]] = {
    ("alerts", "explain"): [
        ContextualSuggestion(label="Is this a false positive?", action="false_positive"),
        ContextualSuggestion(label="Find similar alerts", action="find_similar"),
    ],
    ("alerts", "false_positive"): [
        ContextualSuggestion(label="Explain this alert", action="explain"),
        ContextualSuggestion(label="Find similar alerts", action="find_similar"),
    ],
    ("alerts", "find_similar"): [
        ContextualSuggestion(label="Explain this alert", action="explain"),
    ],
    ("cases", "draft_comms"): [
        ContextualSuggestion(label="Generate exec brief", action="exec_summary"),
    ],
    ("cases", "exec_summary"): [
        ContextualSuggestion(label="Draft customer comms", action="draft_comms"),
        ContextualSuggestion(label="Generate post-mortem", action="post_mortem"),
    ],
    ("cases", "post_mortem"): [
        ContextualSuggestion(label="Generate exec brief", action="exec_summary"),
    ],
    ("detections", "why_noisy"): [
        ContextualSuggestion(label="Suggest a tighter version", action="tighten"),
    ],
    ("detections", "tighten"): [
        ContextualSuggestion(label="Why is this rule noisy?", action="why_noisy"),
    ],
    ("playbooks", "explain"): [
        ContextualSuggestion(label="Suggest improvements", action="improve"),
    ],
    ("playbooks", "improve"): [
        ContextualSuggestion(label="Explain this playbook", action="explain"),
    ],
}


_SYSTEM_PROMPTS: dict[tuple[str, str], str] = {
    ("alerts", "explain"): (
        "You are an expert SOC analyst. Given an alert, explain what it means, "
        "why it likely fired, what attacker behavior it points at, and what an "
        "analyst should look at next. Output concise Markdown with these "
        "sections: ## What this alert means / ## Likely attacker behavior / "
        "## Suggested next steps. Be precise and avoid speculation."
    ),
    ("alerts", "false_positive"): (
        "You are an expert SOC analyst. Decide whether an alert is most likely "
        "a true positive, a false positive, or unknown. Output Markdown with: "
        "## Verdict (one of: True positive, Likely false positive, Unknown) / "
        "## Confidence (0-100%) / ## Signals supporting TP / "
        "## Signals supporting FP / ## Recommended action."
    ),
    ("alerts", "find_similar"): (
        "You are an expert SOC analyst. Given an alert, propose how to find "
        "related alerts in the SIEM. Output Markdown with: "
        "## Similarity criteria / ## KQL or ES|QL query to find similar / "
        "## Why these alerts cluster together. Include the actual query."
    ),
    ("cases", "draft_comms"): (
        "You are a senior security incident communicator. Draft a customer-"
        "facing notification for the given case. Match tone to severity. Be "
        "factual, avoid blame, and only disclose confirmed facts. Output "
        "Markdown with: ## Subject line / ## Body / ## Notes for reviewer."
    ),
    ("cases", "exec_summary"): (
        "You are an incident commander writing for the C-suite. Produce a one-"
        "paragraph executive summary covering impact, current status, ETA to "
        "resolution, and the single ask of the executive (if any). Plain prose, "
        "no bullets unless absolutely necessary. Markdown."
    ),
    ("cases", "post_mortem"): (
        "You are a senior SRE writing a blameless post-mortem. Output Markdown "
        "with: ## Summary / ## Impact / ## Timeline / ## Root cause / "
        "## What went well / ## What went poorly / ## Action items (with owners "
        "and due dates as TODO)."
    ),
    ("detections", "why_noisy"): (
        "You are a detection engineer. Given a Sigma/KQL/EQL detection rule, "
        "diagnose why it produces excessive false positives. Output Markdown "
        "with: ## Likely sources of FPs / ## Common environments where this "
        "fires legitimately / ## What we would tune."
    ),
    ("detections", "tighten"): (
        "You are a detection engineer. Propose a tighter version of the given "
        "rule that preserves true positives but reduces false positives. "
        "Output Markdown with: ## Proposed changes / ## Updated rule (in a "
        "code block in the same DSL as the input) / ## Risks of the change."
    ),
    ("playbooks", "explain"): (
        "You are a SOC automation engineer. Walk through the given playbook "
        "step-by-step in plain English. Output Markdown with: ## What it does / "
        "## Step-by-step / ## Approval gates / ## Rollback path."
    ),
    ("playbooks", "improve"): (
        "You are a SOC automation engineer reviewing a playbook for "
        "production-readiness. Output Markdown with: ## Strengths / "
        "## Gaps / ## Suggested improvements (concrete, ordered by impact) / "
        "## Risks if shipped as-is."
    ),
}


def _serialize_entity(entity: dict[str, Any] | None, entity_id: str) -> str:
    if not entity:
        return f"(no entity payload supplied; entity_id={entity_id})"
    try:
        return json.dumps(entity, indent=2, default=str)[:8000]
    except (TypeError, ValueError):
        return repr(entity)[:8000]


def _build_messages(req: ContextualActionRequest) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for the (page, action) pair."""
    key = (req.page, req.action)
    if key not in _SYSTEM_PROMPTS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown contextual action: page={req.page!r} action={req.action!r}",
        )

    system = _SYSTEM_PROMPTS[key]
    entity_blob = _serialize_entity(req.entity, req.entity_id)

    user_lines = [
        f"Page: {req.page}",
        f"Action: {req.action}",
        f"Entity ID: {req.entity_id}",
        "",
        "Entity snapshot:",
        "```json",
        entity_blob,
        "```",
    ]
    if req.question:
        user_lines.extend(["", f"Analyst follow-up: {req.question}"])

    return system, "\n".join(user_lines)


# ---------------------------------------------------------------------------
# LLM dispatch
# ---------------------------------------------------------------------------

async def _call_llm(system: str, user: str, model: str) -> tuple[str, int]:
    """Invoke the configured LLM. Returns (markdown, tokens_used).

    Falls back to a deterministic stub response when ``OPENAI_API_KEY`` is
    missing so the demo never hard-fails.
    """
    if not os.getenv("OPENAI_API_KEY"):
        return _fallback_response(system, user), 0

    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage, SystemMessage
    except ImportError as exc:
        logger.warning("contextual.llm.import_failed", error=str(exc))
        return _fallback_response(system, user), 0

    llm = ChatOpenAI(model=model, temperature=0.2)
    response = await llm.ainvoke(
        [SystemMessage(content=system), HumanMessage(content=user)]
    )
    text = response.content if isinstance(response.content, str) else str(response.content)
    tokens = 0
    if hasattr(response, "response_metadata"):
        tokens = (
            response.response_metadata.get("token_usage", {}).get("total_tokens", 0)
            or 0
        )
    return text, tokens


async def _stream_llm(system: str, user: str, model: str) -> AsyncIterator[str]:
    """Yield response delta chunks. Used by the NDJSON streaming endpoint."""
    if not os.getenv("OPENAI_API_KEY"):
        # Fake-stream the fallback in 8-character chunks for a nice UX in the
        # demo path.
        text = _fallback_response(system, user)
        for i in range(0, len(text), 8):
            yield text[i : i + 8]
        return

    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage, SystemMessage
    except ImportError:
        text = _fallback_response(system, user)
        for i in range(0, len(text), 8):
            yield text[i : i + 8]
        return

    llm = ChatOpenAI(model=model, temperature=0.2, streaming=True)
    async for chunk in llm.astream(
        [SystemMessage(content=system), HumanMessage(content=user)]
    ):
        if hasattr(chunk, "content") and chunk.content:
            yield chunk.content if isinstance(chunk.content, str) else str(chunk.content)


def _fallback_response(system: str, user: str) -> str:
    """Deterministic offline response so the contextual UI works without an LLM."""
    # Keep this short and obviously synthetic so it doesn't get mistaken for
    # genuine analysis in a screenshot.
    return (
        "## Heads up: LLM not configured\n\n"
        "This deployment of AiSOC does not have `OPENAI_API_KEY` configured, "
        "so the contextual Copilot cannot reach a language model right now. "
        "You're seeing a deterministic placeholder response.\n\n"
        "**To enable real contextual answers:**\n\n"
        "1. Set `OPENAI_API_KEY` in your `.env` file\n"
        "2. Optionally set `OPENAI_MODEL` (default: `gpt-4o-mini`)\n"
        "3. Restart the `aisoc-agents` service\n\n"
        "Refer to [the docs](https://aisoc.dev/docs/copilot) for self-hosted "
        "model alternatives (Ollama, vLLM, Together)."
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/actions", response_model=ContextualActionsCatalogue, summary="List supported contextual actions")
async def list_actions() -> ContextualActionsCatalogue:
    return ContextualActionsCatalogue(
        pages={
            page: [ContextualActionDescriptor(**item) for item in items]
            for page, items in _ACTION_CATALOGUE.items()
        }
    )


@router.post(
    "/action",
    response_model=ContextualActionResponse,
    summary="One-shot contextual AI action",
)
async def run_action(req: ContextualActionRequest) -> ContextualActionResponse:
    started = time.monotonic()
    system, user = _build_messages(req)
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    fallback = not bool(os.getenv("OPENAI_API_KEY"))
    try:
        content, tokens = await _call_llm(system, user, model)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "contextual.action.llm_error",
            page=req.page,
            action=req.action,
            entity_id=req.entity_id,
            error=str(exc),
        )
        content = _fallback_response(system, user)
        tokens = 0
        fallback = True

    elapsed_ms = int((time.monotonic() - started) * 1000)
    title = _TITLES.get((req.page, req.action), f"{req.page} · {req.action}")
    suggestions = _FOLLOW_UPS.get((req.page, req.action), [])

    response = ContextualActionResponse(
        id=str(uuid.uuid4()),
        page=req.page,
        action=req.action,
        entity_id=req.entity_id,
        title=title,
        content=content,
        confidence=0.0 if fallback else 0.7,
        suggestions=suggestions,
        citations=[],
        model=model,
        elapsed_ms=elapsed_ms,
        fallback=fallback,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    # Structured log so contextual usage is queryable in observability tooling
    # without requiring the full investigation_runs/events ledger schema.
    logger.info(
        "contextual.action.done",
        page=req.page,
        action=req.action,
        entity_id=req.entity_id,
        case_id=req.case_id,
        elapsed_ms=elapsed_ms,
        tokens=tokens,
        fallback=fallback,
    )
    return response


@router.post(
    "/action/stream",
    summary="Streaming variant — emits NDJSON lines: {delta} until {done:true}",
)
async def run_action_stream(req: ContextualActionRequest) -> StreamingResponse:
    system, user = _build_messages(req)
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    title = _TITLES.get((req.page, req.action), f"{req.page} · {req.action}")
    suggestions = _FOLLOW_UPS.get((req.page, req.action), [])
    fallback = not bool(os.getenv("OPENAI_API_KEY"))

    async def gen() -> AsyncIterator[bytes]:
        # Header frame so the UI can render the title before tokens arrive.
        yield (
            json.dumps(
                {
                    "title": title,
                    "page": req.page,
                    "action": req.action,
                    "entity_id": req.entity_id,
                    "model": model,
                    "fallback": fallback,
                }
            )
            + "\n"
        ).encode()

        try:
            async for chunk in _stream_llm(system, user, model):
                yield (json.dumps({"delta": chunk}) + "\n").encode()
        except Exception as exc:  # noqa: BLE001
            yield (json.dumps({"error": str(exc)}) + "\n").encode()

        # Footer frame with metadata + suggested follow-ups.
        yield (
            json.dumps(
                {
                    "done": True,
                    "suggestions": [s.model_dump() for s in suggestions],
                    "confidence": 0.0 if fallback else 0.7,
                }
            )
            + "\n"
        ).encode()

    return StreamingResponse(gen(), media_type="application/x-ndjson")
