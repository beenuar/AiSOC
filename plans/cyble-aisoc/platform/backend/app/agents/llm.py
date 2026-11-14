"""LLM provider abstraction with native tool-use (Anthropic / OpenAI) and a
deterministic mock.

Two surfaces:

- `complete(...)`  → plain text completion (used for narration / summaries).
- `complete_with_tools(...)` → tool-calling loop. Returns the model's tool
  choices as structured `ToolCallRequest` objects. Caller is responsible for
  executing the tools (so HITL gates can intervene) and feeding the results
  back into the next round.

The mock mode is deterministic: it inspects the offered tool schema and
returns a sensible pre-baked selection so the full agent flow runs offline
without leaking secrets or burning tokens.

Theme 2n — Multi-Model / Tiered Routing
---------------------------------------
The plan's v1 contract is "one model per agent role, evaluated quarterly"
(see cyble-aisoc-plan.md L416–L419). This module implements that as a
three-tier slot (`PREMIUM` / `DEFAULT` / `FAST`) plus per-agent overrides,
not a clever per-token RAG router. Investigator + Responder default to
`PREMIUM` because their reasoning quality directly drives MTTR and
blast-radius; Reporter defaults to `FAST` because it's a summarization
task; everyone else uses `DEFAULT`. The tier slots are configured once
in `app/config.py` so swapping a tier (e.g. promoting Sonnet→Opus for
the next quarter) is one env var, not a code change. The same router
also drives the Responder reflection pass: critique runs on the
PREMIUM tier even when an MSSP has demoted the everyday tier to a
cheaper model.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from app.config import settings
from app.tools.registry import ToolDef


# ───────────────────────── data shapes ──────────────────────────────────────


@dataclass
class ToolCallRequest:
    """One tool invocation the LLM is asking us to make.

    `id` is the provider-specific correlation id so we can feed results back.
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Normalized response from any provider."""

    text: str
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    stop_reason: str = "end"  # "tool_use" | "end" | "max_tokens"
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResultMsg:
    """Pair a tool result back to a previous tool_use id for the next round."""

    tool_call_id: str
    name: str
    content: dict[str, Any]
    is_error: bool = False


# ───────────────────────── tiered router ────────────────────────────────────


class LLMModelTier(str, Enum):
    """The three slots an operator can configure independently.

    `PREMIUM` is the "best reasoning you've authorized this quarter" slot.
    `DEFAULT` is the working horse. `FAST` is for cheap narration / classification.

    We deliberately keep it to three slots, not N. The plan calls for "one
    model per agent role" (v1) — tiered routing is the smallest extension
    that satisfies the t2n-multimodel ask (premium Investigator + reflection)
    without inviting an opaque ML-driven router that we can't audit.
    """

    PREMIUM = "premium"
    DEFAULT = "default"
    FAST = "fast"


# Default tier per agent role. Chosen for blast-radius / reasoning load:
#  - Investigator + Responder: get the PREMIUM slot because their output
#    drives autonomous actions and case closure quality.
#  - Detection sub-agents (ITDR, CDR, Detection Author, Hunter): DEFAULT,
#    they lean on structured tools more than free-form reasoning.
#  - Phishing / Reporter / Triager: FAST, mostly classification or
#    summarization.
_AGENT_TIER_DEFAULTS: dict[str, LLMModelTier] = {
    "investigator": LLMModelTier.PREMIUM,
    "responder": LLMModelTier.PREMIUM,
    "itdr": LLMModelTier.DEFAULT,
    "cdr": LLMModelTier.DEFAULT,
    "hunter": LLMModelTier.DEFAULT,
    "detection_author": LLMModelTier.DEFAULT,
    "phishing": LLMModelTier.FAST,
    "planner": LLMModelTier.DEFAULT,
    "triager": LLMModelTier.FAST,
    "reporter": LLMModelTier.FAST,
}


@dataclass(frozen=True)
class ModelChoice:
    """Resolved (provider, model) pair plus the reason it was picked.

    The reason is logged on the trace so analysts can answer "why did this
    case run on Sonnet-3.5 when I have Opus configured?" without diving
    into env vars.
    """

    provider: str  # "openai" | "anthropic" | "mock"
    model: str
    tier: LLMModelTier
    reason: str

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"


def _tier_model(tier: LLMModelTier) -> str | None:
    """Read the configured model name for a tier slot, if any."""
    return {
        LLMModelTier.PREMIUM: settings.llm_model_premium,
        LLMModelTier.DEFAULT: settings.llm_model_default,
        LLMModelTier.FAST: settings.llm_model_fast,
    }.get(tier)


def _tier_provider(tier: LLMModelTier) -> str | None:
    """Read the optional per-tier provider override.

    Returning None means "use the global llm_provider". The override exists
    so an MSSP can run Investigator on Anthropic Opus but keep Reporter on
    a cheaper OpenAI model — without forking the platform.
    """
    return {
        LLMModelTier.PREMIUM: settings.llm_provider_premium,
        LLMModelTier.DEFAULT: settings.llm_provider_default,
        LLMModelTier.FAST: settings.llm_provider_fast,
    }.get(tier)


def route_for_agent(
    agent: str | None,
    *,
    tier_override: LLMModelTier | None = None,
) -> ModelChoice:
    """Resolve which (provider, model) to call for a given agent role.

    Resolution order, highest precedence first:
      1. `tier_override` (used by Responder reflection to force PREMIUM).
      2. Per-agent model env override (`AISOC_LLM_MODEL_<AGENT>`).
      3. Tier slot for the agent's default tier.
      4. Global `llm_model` (back-compat with v1 single-model config).

    Provider resolution follows the same precedence, falling back to the
    global `llm_provider`. We deliberately *don't* let the per-agent
    override force a provider you haven't configured an API key for — if
    the key is missing we drop to the mock provider rather than blowing
    up at runtime, since deterministic mock is safer than a 401 in prod.
    """
    role = (agent or "").lower()
    tier = tier_override or _AGENT_TIER_DEFAULTS.get(role, LLMModelTier.DEFAULT)

    # 1+2. Per-agent overrides (env: AISOC_LLM_MODEL_INVESTIGATOR etc.)
    per_agent_model = settings.per_agent_model_override(role)
    per_agent_provider = settings.per_agent_provider_override(role)

    provider_pick = per_agent_provider or _tier_provider(tier) or settings.llm_provider
    model_pick = per_agent_model or _tier_model(tier) or settings.llm_model
    reason = (
        "per_agent_override" if per_agent_model
        else f"tier:{tier.value}" if _tier_model(tier)
        else "global_default"
    )

    # Provider availability gate: if the API key is missing, fall back to mock
    # rather than blowing up mid-case. Operators see this in the trace.
    if provider_pick == "openai" and not settings.openai_api_key:
        provider_pick = "mock"
        reason = f"{reason}+missing_openai_key"
    elif provider_pick == "anthropic" and not settings.anthropic_api_key:
        provider_pick = "mock"
        reason = f"{reason}+missing_anthropic_key"

    return ModelChoice(
        provider=provider_pick,
        model=model_pick,
        tier=tier,
        reason=reason,
    )


# ───────────────────────── public API ───────────────────────────────────────


async def complete(
    *,
    system: str,
    user: str,
    max_tokens: int = 600,
    agent: str | None = None,
    tier: LLMModelTier | None = None,
) -> dict[str, Any]:
    """Plain narration completion.

    `agent` is the lowercase agent role (e.g. "reporter", "investigator") and
    drives the tier router. `tier` is an explicit override (used by the
    Responder reflection pass). Both are optional — when neither is given we
    behave exactly like the v1 single-model implementation.
    """
    choice = route_for_agent(agent, tier_override=tier)
    if choice.provider == "openai":
        out = await _openai_text(system=system, user=user, max_tokens=max_tokens, choice=choice)
    elif choice.provider == "anthropic":
        out = await _anthropic_text(system=system, user=user, max_tokens=max_tokens, choice=choice)
    else:
        out = await _mock_text(system=system, user=user, max_tokens=max_tokens, choice=choice)
    # Stamp routing metadata onto the response so callers / traces can see it.
    # We surface the fields both nested (`model_choice`) and at the top level
    # so simple callers can just read `out["model"]` without unpacking.
    out.setdefault("model_choice", {
        "provider": choice.provider,
        "model": choice.model,
        "tier": choice.tier.value,
        "reason": choice.reason,
    })
    out.setdefault("provider", choice.provider)
    out.setdefault("model", choice.model)
    out.setdefault("tier", choice.tier.value)
    out.setdefault("route_reason", choice.reason)
    return out


async def complete_with_tools(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: Sequence[ToolDef],
    max_tokens: int = 800,
    force_tool: str | None = None,
    agent: str | None = None,
    tier: LLMModelTier | None = None,
) -> LLMResponse:
    """Tool-using turn.

    `messages` is the running conversation. Each item is one of:
      {"role": "user"|"assistant", "content": str}
      {"role": "assistant", "content": str, "tool_calls": [ToolCallRequest...]}
      {"role": "tool", "tool_call_id": str, "name": str, "content": dict}

    Returns a single normalized response. The orchestrator decides whether to
    execute tool calls and loop again or finish.

    `agent` selects which tier slot to use via `route_for_agent`. `tier` is an
    explicit override (used by the Responder reflection pass to force PREMIUM
    even when the agent's default tier is lower).
    """
    choice = route_for_agent(agent, tier_override=tier)
    t0 = time.perf_counter()
    if choice.provider == "openai":
        resp = await _openai_tools(
            system=system, messages=messages, tools=tools,
            max_tokens=max_tokens, force_tool=force_tool, choice=choice,
        )
    elif choice.provider == "anthropic":
        resp = await _anthropic_tools(
            system=system, messages=messages, tools=tools,
            max_tokens=max_tokens, force_tool=force_tool, choice=choice,
        )
    else:
        resp = await _mock_tools(
            system=system, messages=messages, tools=tools,
            max_tokens=max_tokens, force_tool=force_tool, choice=choice,
        )
    resp.latency_ms = int((time.perf_counter() - t0) * 1000)
    # Stamp routing metadata so trace events can attribute model + reason
    resp.raw.setdefault("provider", choice.provider)
    resp.raw["model"] = choice.model
    resp.raw["tier"] = choice.tier.value
    resp.raw["route_reason"] = choice.reason
    return resp


async def reflect(
    *,
    system: str,
    plan: str,
    context: str = "",
    max_tokens: int = 400,
    agent: str | None = None,
) -> dict[str, Any]:
    """Run a critique pass over a proposed plan on the PREMIUM tier.

    Used by Responder before it commits to a containment action. The point of
    this pass is to catch (a) tools chosen with insufficient evidence, (b)
    actions disproportionate to the asserted threat level, and (c) missed
    rollback considerations. We deliberately force PREMIUM regardless of the
    caller's default tier — paying for the better model on a one-shot critique
    is cheaper than rolling back a wrongful host isolation.

    Returns a dict with keys:
      - text:    the critique narrative
      - approve: True if the critique judges the plan safe to proceed
      - issues:  short bullet list extracted from the critique
      - model_choice: routing metadata
    """
    critique_user = (
        "Critique the following proposed containment plan. Identify any "
        "step that lacks evidentiary support, any action that's "
        "disproportionate, and any missing rollback consideration. "
        "Finish with a single line of the form `VERDICT: APPROVE` or "
        "`VERDICT: REVISE: <reason>`.\n\n"
        f"CONTEXT:\n{context.strip() or '(none)'}\n\n"
        f"PROPOSED PLAN:\n{plan.strip()}"
    )
    out = await complete(
        system=system,
        user=critique_user,
        max_tokens=max_tokens,
        agent=agent,
        tier=LLMModelTier.PREMIUM,
    )
    text = (out.get("text") or "").strip()
    approve = "VERDICT: APPROVE" in text.upper()
    # Extract "- " bullet lines as the issues list; cheap but effective
    issues = [
        ln.strip("-• ").strip()
        for ln in text.splitlines()
        if ln.strip().startswith(("-", "•")) and len(ln.strip()) > 2
    ][:10]
    return {
        "text": text,
        "approve": approve,
        "issues": issues,
        "model_choice": out.get("model_choice"),
        "tokens_in": out.get("tokens_in", 0),
        "tokens_out": out.get("tokens_out", 0),
    }


# ───────────────────────── mock implementation ─────────────────────────────


def _hash(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16)


async def _mock_text(
    *, system: str, user: str, max_tokens: int, choice: ModelChoice | None = None,
) -> dict[str, Any]:
    await asyncio.sleep(0.02)
    # Reflection critique prompts have a known shape ("Critique the following ...
    # finish with a single line of the form `VERDICT: APPROVE` or
    # `VERDICT: REVISE: <reason>`"). The mock has to produce a verdict-line so
    # reflect() can parse it; default to APPROVE so demo flows don't deadlock,
    # but flip to REVISE for high-impact actions (`disable_user`, `isolate_host`
    # without supporting evidence terms) so the smoke tests can exercise both.
    if "Critique the following" in user and "VERDICT" in user:
        risky = any(
            kw in user.lower()
            for kw in ("disable_user", "isolate_host")
        )
        has_evidence = any(
            kw in user.lower()
            for kw in ("true_positive", "confidence: 0.8", "confidence: 0.9", "malicious", "phishing")
        )
        if risky and not has_evidence:
            text = (
                "- Plan proposes destructive containment without strong evidence.\n"
                "- Consider HITL before isolate_host / disable_user.\n"
                "VERDICT: REVISE: insufficient evidence for destructive action"
            )
        else:
            text = (
                "- Actions proportional to asserted threat level.\n"
                "- Rollback paths exist for executed tools.\n"
                "VERDICT: APPROVE"
            )
    else:
        text = f"[mock-llm] {user[:240]}"
    return {
        "text": text,
        "tokens_in": len(system.split()) + len(user.split()),
        "tokens_out": min(max_tokens, len(text.split()) + 12),
    }


def _mock_pick_tool(
    tools: Sequence[ToolDef], messages: list[dict[str, Any]], force_tool: str | None
) -> tuple[str | None, dict[str, Any]]:
    """Deterministic but reasonable tool selection for the mock provider.

    The mock plays the role of an LLM that's read the conversation and is
    deciding which tool to call. We use very simple keyword routing — enough
    to produce a believable end-to-end flow offline.
    """
    if force_tool:
        td = next((t for t in tools if t.name == force_tool), None)
        if td:
            return force_tool, _mock_args_for(td, messages)

    # Concatenate the last user/assistant text plus any tool results
    blob = " ".join(
        json.dumps(m.get("content", "") if not isinstance(m.get("content"), str) else m["content"])
        for m in messages[-6:]
    ).lower()

    # Already-called set so we don't re-pick the same tool over and over
    called = {
        c["name"]
        for m in messages
        for c in (m.get("tool_calls") or [])
        if isinstance(c, dict) and "name" in c
    }

    def first(*candidates: str) -> str | None:
        for c in candidates:
            if c in called:
                continue
            if any(t.name == c for t in tools):
                return c
        return None

    # Priority routing for SOC mock
    if any(k in blob for k in ("hash", "sha256", "ioc", "indicator")):
        n = first("cti.enrich_ioc")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("user", "account", "identity")):
        n = first("idp.get_user")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("process", "powershell", "tree", "child", "edr")):
        n = first("edr.get_process_tree", "edr.isolate_host")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("phish", "email", "message")):
        n = first("email.analyze_message", "email.block_sender", "email.clawback_message")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("dark", "leak", "credential", "darkweb")):
        n = first("cti.darkweb_search")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("brand", "typosquat", "spoof")):
        n = first("cti.brand_intel")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("expos", "asm", "external")):
        n = first("cti.asm_lookup")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    if any(k in blob for k in ("siem", "search", "events", "related", "lateral")):
        n = first("siem.search_events", "siem.get_related_alerts")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)
    # Containment defaults
    if any(k in blob for k in ("contain", "isolate", "block", "quarant")):
        n = first("edr.isolate_host", "edr.quarantine_file", "idp.revoke_sessions")
        if n:
            return n, _mock_args_for(next(t for t in tools if t.name == n), messages)

    # Default: first uncalled read-only tool, else nothing
    for t in tools:
        if t.name not in called and t.risk_class.value == "READ":
            return t.name, _mock_args_for(t, messages)

    return None, {}


def _mock_args_for(td: ToolDef, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Synthesize args from the conversation. Best-effort, schema-aware."""
    schema = td.params_schema or {}
    props = schema.get("properties") or {}
    args: dict[str, Any] = {}
    blob = " ".join(
        m["content"] if isinstance(m.get("content"), str) else json.dumps(m.get("content"))
        for m in messages[-8:]
    )

    for name, spec in props.items():
        if "default" in spec:
            args[name] = spec["default"]
        elif spec.get("enum"):
            args[name] = spec["enum"][0]
        elif spec.get("type") == "integer":
            args[name] = 60
        elif spec.get("type") == "boolean":
            args[name] = False
        else:
            # Pull plausible string from the blob
            args[name] = _guess_string(name, blob)

    # Required keys must be present
    for r in schema.get("required") or []:
        args.setdefault(r, _guess_string(r, blob))
    return args


def _guess_string(name: str, blob: str) -> str:
    lc = name.lower()
    if "ioc" in lc or "indicator" in lc:
        return "8.8.8.8"
    if "host" in lc:
        return "win-finance-04"
    if "user" in lc or "account" in lc:
        return "[email protected]"
    if "domain" in lc:
        return "cyble.com"
    if "sender" in lc:
        return "[email protected]"
    if "message" in lc:
        return "msg-mock-1"
    if "channel" in lc:
        return "#sec-on-call"
    if "sha" in lc or "hash" in lc:
        return "0" * 64
    if "cve" in lc:
        return "CVE-2024-21887"
    if "query" in lc:
        return blob[:80] or "credential leak"
    if "process" in lc:
        return "powershell.exe"
    if "title" in lc:
        return "AiSOC mock case"
    if "description" in lc:
        return "Auto-generated by mock LLM"
    if "priority" in lc:
        return "P2"
    if "reason" in lc:
        return "AiSOC mock containment"
    return "mock-value"


async def _mock_tools(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: Sequence[ToolDef],
    max_tokens: int,
    force_tool: str | None,
    choice: ModelChoice | None = None,
) -> LLMResponse:
    await asyncio.sleep(0.02)
    name, args = _mock_pick_tool(tools, messages, force_tool)
    if name:
        cid = f"mock_{_hash(name + json.dumps(args, sort_keys=True)):x}"[:24]
        return LLMResponse(
            text="",
            tool_calls=[ToolCallRequest(id=cid, name=name, arguments=args)],
            stop_reason="tool_use",
            tokens_in=len(system.split()) + sum(len(str(m).split()) for m in messages),
            tokens_out=12,
            raw={"provider": "mock"},
        )
    last = next(
        (m.get("content") for m in reversed(messages) if isinstance(m.get("content"), str)),
        "",
    )
    return LLMResponse(
        text=f"[mock-llm] Completed reasoning for: {last[:160]}",
        stop_reason="end",
        tokens_in=len(system.split()) + sum(len(str(m).split()) for m in messages),
        tokens_out=40,
        raw={"provider": "mock"},
    )


# ───────────────────────── OpenAI implementation ────────────────────────────


async def _openai_text(
    *, system: str, user: str, max_tokens: int, choice: ModelChoice | None = None,
) -> dict[str, Any]:
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=settings.openai_api_key)
    model_name = choice.model if choice else settings.llm_model
    resp = await client.chat.completions.create(
        model=model_name,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        max_tokens=max_tokens,
    )
    msg = resp.choices[0].message.content or ""
    return {
        "text": msg,
        "tokens_in": resp.usage.prompt_tokens if resp.usage else 0,
        "tokens_out": resp.usage.completion_tokens if resp.usage else 0,
    }


def _openai_tool_specs(tools: Sequence[ToolDef]) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        out.append({
            "type": "function",
            "function": {
                "name": t.name.replace(".", "_"),
                "description": t.description,
                "parameters": t.params_schema or {"type": "object", "properties": {}},
            },
        })
    return out


def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate our generic message list to OpenAI's tool-calling shape."""
    out = []
    for m in messages:
        role = m["role"]
        if role == "tool":
            out.append({
                "role": "tool",
                "tool_call_id": m["tool_call_id"],
                "name": m["name"].replace(".", "_"),
                "content": json.dumps(m["content"]),
            })
            continue
        if role == "assistant" and m.get("tool_calls"):
            out.append({
                "role": "assistant",
                "content": m.get("content") or "",
                "tool_calls": [
                    {
                        "id": c["id"],
                        "type": "function",
                        "function": {
                            "name": c["name"].replace(".", "_"),
                            "arguments": json.dumps(c["arguments"]),
                        },
                    }
                    for c in m["tool_calls"]
                ],
            })
            continue
        out.append({"role": role, "content": m.get("content") or ""})
    return out


async def _openai_tools(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: Sequence[ToolDef],
    max_tokens: int,
    force_tool: str | None,
    choice: ModelChoice | None = None,
) -> LLMResponse:
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=settings.openai_api_key)
    oa_messages = [{"role": "system", "content": system}] + _to_openai_messages(messages)
    model_name = choice.model if choice else settings.llm_model
    kwargs: dict[str, Any] = {
        "model": model_name,
        "messages": oa_messages,
        "max_tokens": max_tokens,
        "tools": _openai_tool_specs(tools),
    }
    if force_tool:
        kwargs["tool_choice"] = {
            "type": "function",
            "function": {"name": force_tool.replace(".", "_")},
        }
    resp = await client.chat.completions.create(**kwargs)
    choice = resp.choices[0]
    text = choice.message.content or ""
    calls: list[ToolCallRequest] = []
    for c in choice.message.tool_calls or []:
        try:
            args = json.loads(c.function.arguments or "{}")
        except Exception:
            args = {}
        calls.append(ToolCallRequest(
            id=c.id, name=c.function.name.replace("_", ".", 1), arguments=args,
        ))
    stop = "tool_use" if calls else (choice.finish_reason or "end")
    return LLMResponse(
        text=text, tool_calls=calls, stop_reason=stop,
        tokens_in=resp.usage.prompt_tokens if resp.usage else 0,
        tokens_out=resp.usage.completion_tokens if resp.usage else 0,
        raw={"provider": "openai", "finish_reason": choice.finish_reason},
    )


# ───────────────────────── Anthropic implementation ─────────────────────────


async def _anthropic_text(
    *, system: str, user: str, max_tokens: int, choice: ModelChoice | None = None,
) -> dict[str, Any]:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    model_name = choice.model if choice else settings.llm_model
    resp = await client.messages.create(
        model=model_name,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text_blocks = [b.text for b in resp.content if hasattr(b, "text")]
    return {
        "text": "\n".join(text_blocks),
        "tokens_in": resp.usage.input_tokens,
        "tokens_out": resp.usage.output_tokens,
    }


def _anthropic_tool_specs(tools: Sequence[ToolDef]) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        out.append({
            "name": t.name.replace(".", "_"),
            "description": t.description,
            "input_schema": t.params_schema or {"type": "object", "properties": {}},
        })
    return out


def _to_anthropic_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate our generic message list to Anthropic's tool-use shape."""
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "tool":
            out.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": m["tool_call_id"],
                    "content": json.dumps(m["content"]),
                    "is_error": bool(m.get("is_error")),
                }],
            })
            continue
        if role == "assistant" and m.get("tool_calls"):
            content: list[dict[str, Any]] = []
            if m.get("content"):
                content.append({"type": "text", "text": m["content"]})
            for c in m["tool_calls"]:
                content.append({
                    "type": "tool_use",
                    "id": c["id"],
                    "name": c["name"].replace(".", "_"),
                    "input": c["arguments"],
                })
            out.append({"role": "assistant", "content": content})
            continue
        out.append({"role": role, "content": m.get("content") or ""})
    return out


async def _anthropic_tools(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: Sequence[ToolDef],
    max_tokens: int,
    force_tool: str | None,
    choice: ModelChoice | None = None,
) -> LLMResponse:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    model_name = choice.model if choice else settings.llm_model
    kwargs: dict[str, Any] = {
        "model": model_name,
        "max_tokens": max_tokens,
        "system": system,
        "messages": _to_anthropic_messages(messages),
        "tools": _anthropic_tool_specs(tools),
    }
    if force_tool:
        kwargs["tool_choice"] = {"type": "tool", "name": force_tool.replace(".", "_")}
    resp = await client.messages.create(**kwargs)
    text_parts: list[str] = []
    calls: list[ToolCallRequest] = []
    for blk in resp.content:
        btype = getattr(blk, "type", None)
        if btype == "text":
            text_parts.append(blk.text)
        elif btype == "tool_use":
            calls.append(ToolCallRequest(
                id=blk.id,
                name=blk.name.replace("_", ".", 1),
                arguments=blk.input or {},
            ))
    stop = "tool_use" if calls else (resp.stop_reason or "end")
    return LLMResponse(
        text="\n".join(text_parts),
        tool_calls=calls,
        stop_reason=stop,
        tokens_in=resp.usage.input_tokens,
        tokens_out=resp.usage.output_tokens,
        raw={"provider": "anthropic", "stop_reason": resp.stop_reason},
    )
