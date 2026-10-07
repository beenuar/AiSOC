"""LLM tool-calling loop (Wave 4a).

Lives under ``app.llm`` rather than ``app.agents``: it is a
provider-agnostic loop over ``safe_ainvoke`` and the tool registry, and
nothing about it is agent-specific. The original home created a cycle —
importing ``app.agents.tool_loop`` executes ``app/agents/__init__.py``,
which imports every agent module, so any agent wanting the loop imported
itself. ``app.agents.tool_loop`` re-exports this for existing callers.

A minimal, provider-agnostic ReAct loop: bind the registry's tools to the model,
let the model choose which to call, execute the calls, feed results back, and
repeat until the model answers without a tool call (or a cap is hit). This is
the primitive that lets specialist agents *use tools* instead of reasoning over
a single pre-serialised blob.

Bounded + fail-soft: at most ``max_iters`` round-trips; tool errors come back to
the model as structured results (via ToolRegistry.execute) rather than aborting.
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app.llm.contract import safe_ainvoke
from app.prompting.tool_results import render_tool_message
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
        # Routed through safe_ainvoke rather than calling bound.ainvoke
        # directly. This loop feeds tool output straight back into the prompt,
        # and that output is untrusted: a SIEM row, a graph property or a
        # threat-intel record can carry text that reads as an instruction.
        # Skipping the contract here skipped injection validation on precisely
        # the highest-risk content in the system, and lost the token/cost
        # telemetry for every tool-calling turn.
        response = await safe_ainvoke(bound, messages)
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
            # The only place in this service where a tool result becomes text
            # a model reads. Depth plan 1.3 turned that from an accident of
            # layout into an invariant: `render_tool_message` is the single
            # renderer and this is its single call site, both enforced by
            # `test_tool_result_channel.py` walking the syntax tree. The guard
            # rule `fabricated_tool_result` is sound only while that holds —
            # it reports a tool result inside the evidence fence as fabricated
            # by construction, which is a claim about this loop.
            messages.append(ToolMessage(content=render_tool_message(result), tool_call_id=call_id))

    logger.info("tool_loop.truncated", iterations=max_iters, tools_called=len(trace))
    return {"content": _content(messages[-1]), "tool_trace": trace, "iterations": max_iters, "truncated": True}


def _content(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, AIMessage):  # pragma: no cover - defensive
        return str(content.content)
    return str(content)
