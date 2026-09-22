"""Recursive, tool-driven investigation. The first production caller of the loop.

``run_with_tools`` — a working ReAct loop with tool execution, injection
guarding and cost telemetry — shipped with zero production callers. Every
investigation path fed the model one pre-serialised blob and asked for a
verdict, so the platform's deepest capability was reachable only from tests.

This module closes that. It selects an investigation strategy for the alert,
binds the investigation toolset, and runs the loop, so the model pivots
through the estate rather than summarising one payload.

What this deliberately is not: a workflow engine. The strategy supplies the
plan as guidance and the model chooses the tools. A hard-coded pivot sequence
would break on the first alert that did not match its shape, and would make
the loop decorative.

Three guardrails, because a loop that calls tools is a loop that spends money
and time on the hot path of every escalated alert:

* an iteration cap, inherited from ``run_with_tools``
* a wall-clock budget, since a slow pivot chain is worse than a shallow one
* a depth *record* on the result, so the investigation can be graded rather
  than assumed deep
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.investigator.strategies import Strategy, select_strategy
from app.llm.factory import make_chat_model
from app.llm.tool_loop import run_with_tools
from app.tools.investigation import investigation_tools
from app.tools.registry import default_registry

logger = structlog.get_logger()

#: Off by default is wrong here — a shipped capability nobody enables is the
#: state this module exists to fix — but it must be disableable for air-gapped
#: and eval deployments that have no LLM.
ENABLED = os.getenv("AISOC_DEEP_INVESTIGATION", "true").strip().lower() not in (
    "0",
    "false",
    "off",
    "no",
)

MAX_ITERATIONS = int(os.getenv("AISOC_DEEP_INVESTIGATION_MAX_ITERS", "6"))
BUDGET_SECONDS = float(os.getenv("AISOC_DEEP_INVESTIGATION_BUDGET_SECONDS", "120"))


@dataclass
class DeepInvestigationResult:
    """What the loop found, and how hard it actually looked.

    The depth fields are the point. An investigation that called one tool and
    wrote three paragraphs is alert-enrich-summarise wearing a different
    name, and without a record of pivots taken there is no way to tell the
    two apart after the fact.
    """

    strategy_id: str
    narrative: str = ""
    pivots: list[str] = field(default_factory=list)
    distinct_pivots: int = 0
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    iterations: int = 0
    truncated: bool = False
    latency_ms: int = 0
    over_budget: bool = False
    unavailable_data: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def reached_depth(self) -> bool:
        """Whether the run met the strategy's floor for having investigated."""
        strategy = _STRATEGY_CACHE.get(self.strategy_id)
        floor = strategy.min_pivots if strategy else 2
        return self.distinct_pivots >= floor

    def as_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "narrative": self.narrative,
            "pivots": self.pivots,
            "distinct_pivots": self.distinct_pivots,
            "iterations": self.iterations,
            "truncated": self.truncated,
            "latency_ms": self.latency_ms,
            "over_budget": self.over_budget,
            "reached_depth": self.reached_depth,
            "unavailable_data": self.unavailable_data,
            "error": self.error,
        }

    def findings(self) -> list[str]:
        """Render as investigation findings for the deterministic agent."""
        out: list[str] = []
        if self.error:
            # A failed investigation must not read as a completed one.
            out.append(f"Deep investigation did not complete ({self.error}). " f"Findings below are from the deterministic path only.")
            return out

        if self.narrative:
            out.append(self.narrative.strip())

        if self.pivots:
            out.append(
                f"Investigation depth: {self.distinct_pivots} distinct pivots "
                f"across {self.iterations} reasoning steps "
                f"(strategy: {self.strategy_id}) — {', '.join(sorted(set(self.pivots)))}."
            )
        if self.unavailable_data:
            # Stated as a coverage gap, never as an absence of activity.
            out.append(
                "Coverage gap: the following data classes are not ingested, so this "
                "investigation could not check them — "
                f"{', '.join(sorted(set(self.unavailable_data)))}. "
                "Treat them as unknown rather than clear."
            )
        if self.truncated:
            out.append(f"Investigation hit its {MAX_ITERATIONS}-step cap; the line of enquiry " f"was not exhausted.")
        if self.over_budget:
            out.append(
                f"Investigation exceeded its {BUDGET_SECONDS:.0f}s budget and was cut " f"short; conclusions are based on partial evidence."
            )
        return out


_STRATEGY_CACHE: dict[str, Strategy] = {}


_SYSTEM_PREAMBLE = """You are a senior SOC analyst investigating a security alert.

You have tools that query the organisation's own event lake. Use them. An
investigation is a chain of questions where each answer determines the next:
a suspicious process leads to where else that binary has run, which leads to
which accounts were on those hosts, which leads to where else those accounts
authenticated.

Rules that matter:
- Do not answer from the alert text alone. Call tools.
- Each tool result is the input to your next question, not the end of the
  enquiry.
- If a tool reports that its data class is not ingested, that is a gap in
  visibility. Record it as a gap. It is not evidence the activity did not
  happen.
- An empty result from a tool that *is* backed by data is genuine evidence of
  absence, and you may rely on it.
- Distinguish what you observed from what you inferred. State confidence
  plainly, and say what would change your mind.

Finish with a short narrative: what happened, in what order, what you are
confident about, what you could not determine, and what you would do next."""


def _summarise_alert(state: Any) -> str:
    """The alert as a prompt, without dumping raw payloads into context."""
    raw = getattr(state, "raw_alert", {}) or {}
    parts = [f"Alert: {getattr(state, 'alert_summary', '') or raw.get('title') or 'unknown'}"]
    for key, label in (
        ("severity", "Severity"),
        ("source", "Source"),
        ("connector_type", "Connector"),
    ):
        if raw.get(key):
            parts.append(f"{label}: {raw[key]}")
    for key, label in (
        ("hostname", "Host"),
        ("src_hostname", "Host"),
        ("user_name", "User"),
        ("source_ip", "Source IP"),
        ("dest_ip", "Destination IP"),
        ("process_name", "Process"),
        ("hash_sha256", "SHA-256"),
    ):
        if raw.get(key):
            parts.append(f"{label}: {raw[key]}")
    techniques = getattr(state, "mitre_mappings", None) or []
    if techniques:
        parts.append(f"Mapped ATT&CK techniques: {', '.join(techniques)}")
    return "\n".join(parts)


def _classify_pivots(trace: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Split the trace into pivots taken and data classes that were missing.

    A tool that reported ``available: false`` is not a pivot — counting it
    would let an investigation reach its depth floor by calling four tools
    that all answered "not ingested".
    """
    pivots: list[str] = []
    unavailable: list[str] = []
    for entry in trace:
        name = entry.get("tool", "")
        preview = str(entry.get("result_preview", ""))
        if "'available': False" in preview or '"available": false' in preview:
            unavailable.append(name)
        else:
            pivots.append(name)
    return pivots, unavailable


async def run_deep_investigation(
    state: Any,
    *,
    llm: Any | None = None,
    max_iterations: int | None = None,
) -> DeepInvestigationResult:
    """Investigate by pivoting through the estate, not by summarising the alert.

    Returns a result even on failure: the deterministic path still runs, and
    a raised exception here would take a working investigation down with a
    non-essential enhancement.
    """
    tenant_id = str(getattr(state, "tenant_id", "") or "default")
    summary = getattr(state, "alert_summary", "") or ""
    techniques = list(getattr(state, "mitre_mappings", None) or [])

    strategy = select_strategy(summary=summary, techniques=techniques)
    _STRATEGY_CACHE[strategy.id] = strategy
    result = DeepInvestigationResult(strategy_id=strategy.id)

    if not ENABLED:
        result.error = "deep investigation disabled (AISOC_DEEP_INVESTIGATION)"
        return result

    started = time.monotonic()
    try:
        model = llm if llm is not None else make_chat_model("investigation")

        registry = default_registry()
        for tool in investigation_tools(tenant_id):
            registry.register(tool)

        loop = await asyncio.wait_for(
            run_with_tools(
                model,
                system=f"{_SYSTEM_PREAMBLE}\n\n{strategy.system_guidance()}",
                user=_summarise_alert(state),
                registry=registry,
                max_iters=max_iterations or MAX_ITERATIONS,
            ),
            timeout=BUDGET_SECONDS,
        )
    except TimeoutError:
        result.over_budget = True
        result.error = f"exceeded the {BUDGET_SECONDS:.0f}s budget"
        result.latency_ms = int((time.monotonic() - started) * 1000)
        logger.warning("deep_investigation.over_budget", strategy=strategy.id)
        return result
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.latency_ms = int((time.monotonic() - started) * 1000)
        logger.warning("deep_investigation.failed", strategy=strategy.id, error=type(exc).__name__)
        return result

    result.latency_ms = int((time.monotonic() - started) * 1000)
    result.narrative = loop.get("content", "") or ""
    result.tool_trace = loop.get("tool_trace", []) or []
    result.iterations = int(loop.get("iterations", 0) or 0)
    result.truncated = bool(loop.get("truncated"))

    result.pivots, result.unavailable_data = _classify_pivots(result.tool_trace)
    result.distinct_pivots = len(set(result.pivots))

    logger.info(
        "deep_investigation.complete",
        strategy=strategy.id,
        distinct_pivots=result.distinct_pivots,
        iterations=result.iterations,
        latency_ms=result.latency_ms,
        reached_depth=result.reached_depth,
    )
    return result
