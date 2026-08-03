"""LLM tool-calling loop (Wave 4a).

A minimal, provider-agnostic ReAct loop: bind the registry's tools to the model,
let the model choose which to call, execute the calls, feed results back, and
repeat until the model answers without a tool call (or a cap is hit). This is
the primitive that lets specialist agents *use tools* instead of reasoning over
a single pre-serialised blob.

Bounded + fail-soft: at most ``max_iters`` round-trips; tool errors come back to
the model as structured results (via ToolRegistry.execute) rather than aborting.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app.tools.registry import ToolRegistry

logger = structlog.get_logger()


async def run_with_tools(
    llm: Any,
    *,
    system: str,
    user: str,
    registry: ToolRegistry,
    max_iters: int = 4,
) -> dict[str, Any]:
    """Run a tool-calling conversation and return the final content + tool trace.

    Returns ``{"content": str, "tool_trace": [...], "iterations": int,
    "truncated": bool}``.
    """
    bound = llm.bind_tools(registry.openai_schemas())
    messages: list[Any] = [SystemMessage(content=system), HumanMessage(content=user)]
    trace: list[dict[str, Any]] = []

    for iteration in range(1, max_iters + 1):
        response = await bound.ainvoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            return {
                "content": _content(response),
                "tool_trace": trace,
                "iterations": iteration,
                "truncated": False,
            }
        for call in tool_calls:
            name = call.get("name", "")
            args = call.get("args", {}) or {}
            call_id = call.get("id", "") or ""
            result = await registry.execute(name, args)
            trace.append({"tool": name, "args": args, "result_preview": str(result)[:200]})
            messages.append(ToolMessage(content=json.dumps(result, default=str)[:4000], tool_call_id=call_id))

    logger.info("tool_loop.truncated", iterations=max_iters, tools_called=len(trace))
    return {"content": _content(messages[-1]), "tool_trace": trace, "iterations": max_iters, "truncated": True}


def _content(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, AIMessage):  # pragma: no cover - defensive
        return str(content.content)
    return str(content)
