"""LLMInputContract — fail-closed validator for every LLM call (T2.3).

The contract enforces a minimum-leak policy on every prompt that leaves
``services/agents`` for a third-party LLM. Allowed inputs:

* ``ContextBundle.summary_for_llm`` outputs (summary fields, scores,
  small lists),
* analyst-authored alert summaries / titles / descriptions,
* RAG snippets retrieved via the doc store,
* numerical scores (severity, risk, confidence),
* MITRE technique IDs and short categorical strings.

Forbidden inputs (the call MUST be aborted with
:class:`LLMContractViolation` if any are detected):

* raw OCSF JSON (objects with ``activity_id`` / ``class_uid`` /
  ``time_dt`` keys, ``metadata.product`` blocks, etc.),
* raw vendor log lines (Splunk events, Sentinel JSON arrays, EDR
  process events, Sysmon XML, m365 audit blobs, …),
* serialised PII payloads (passwords, tokens, full credit-card numbers).

The validator is intentionally heuristic — false positives are far less
costly than false negatives. Operators who need to disable the gate for
a debugging session can flip ``AISOC_AGENTS_LLM_CONTRACT_ENFORCED=0``;
in production this stays on by default.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable
from typing import Any

import structlog
from langchain_core.messages import AIMessage

from app.core.cost_telemetry import record_llm_call
from app.llm.response_cache import ResponseCache

logger = structlog.get_logger()

# Wave 1 — content-addressed response cache in the LLM hot path. Identical
# (model + prompt + input) calls are served from cache instead of paid for
# again. Byte-identical to what the model returned, so it's determinism-safe.
# Disable with AISOC_LLM_RESPONSE_CACHE=0.
_RESPONSE_CACHE = ResponseCache()
_RESPONSE_CACHE_ENABLED = os.getenv("AISOC_LLM_RESPONSE_CACHE", "1").lower() not in ("0", "false", "no")


def _model_name(llm: Any) -> str:
    return str(getattr(llm, "model", None) or getattr(llm, "model_name", None) or "")


def _cache_parts(messages: list[Any]) -> tuple[str, str]:
    """Split messages into (system prompt, user input) for the cache key."""
    prompt_parts: list[str] = []
    input_parts: list[str] = []
    for m in messages:
        content = getattr(m, "content", m)
        if not isinstance(content, str):
            content = str(content)
        mtype = (getattr(m, "type", "") or m.__class__.__name__).lower()
        (prompt_parts if "system" in mtype else input_parts).append(content)
    return "\n".join(prompt_parts), "\n".join(input_parts)


# The contract's rules live in ``contract_rules.py``, which imports nothing
# beyond the stdlib so ``services/api`` can vendor the identical file. Keeping
# them here meant the API had no contract at all, because this module imports
# LangChain and the response cache. Re-exported so existing callers and tests
# are unaffected by the split.
from app.llm.contract_rules import (  # noqa: E402,F401 — re-exported
    AGENTS_LLM_CONTRACT_ENFORCED_ENV,
    CONTRACT_DICT_KEY_BLOCKLIST,
    LLMContractViolation,
    LLMInputContract,
    classify_message,
    is_contract_enforced,
    set_contract_enforcement,
    validate_messages,
)

# ---------------------------------------------------------------------------
# Safe LLM invocation wrapper
# ---------------------------------------------------------------------------


async def safe_ainvoke(llm: Any, messages: Iterable[Any], **kwargs: Any) -> Any:
    """Validate ``messages`` against the contract, then call ``llm.ainvoke``.

    All callsites in ``services/agents`` MUST route through this function
    (or :func:`safe_astream` for streaming) so the contract is uniformly
    enforced. Raises :class:`LLMContractViolation` on contract breach.
    """
    materialised = list(messages)
    LLMInputContract.validate(materialised)

    model = _model_name(llm)
    prompt, user_input = _cache_parts(materialised)
    # Only cache plain calls (no per-call kwargs like temperature overrides).
    use_cache = _RESPONSE_CACHE_ENABLED and bool(model) and bool(user_input) and not kwargs
    if use_cache:
        cached = _RESPONSE_CACHE.lookup(model=model, prompt=prompt, user_input=user_input)
        if cached is not None:
            return AIMessage(content=cached)

    t0 = time.monotonic()
    result = await llm.ainvoke(materialised, **kwargs)
    latency_ms = (time.monotonic() - t0) * 1000.0
    # Record token/cost against the active CostTracker (no-op if none bound), so
    # the high-volume auto-triage path is finally visible in the cost dashboard.
    try:
        record_llm_call(result, model=model, latency_ms=latency_ms)
    except Exception:  # noqa: BLE001 — telemetry must never break an LLM call
        pass

    if use_cache:
        content = getattr(result, "content", None)
        if isinstance(content, str) and content:
            _RESPONSE_CACHE.store(model=model, prompt=prompt, user_input=user_input, response=content)
    return result


async def safe_astream(llm: Any, messages: Iterable[Any], **kwargs: Any):
    """Streaming variant of :func:`safe_ainvoke` that yields chunks."""
    materialised = list(messages)
    LLMInputContract.validate(materialised)
    async for chunk in llm.astream(materialised, **kwargs):
        yield chunk


def make_safe_chat_model(llm: Any) -> Any:
    """Wrap a chat model so its ``ainvoke``/``astream`` enforce the contract.

    Useful when an existing function holds an ``llm`` reference and we
    want to upgrade it without rewriting every call site. The wrapper
    delegates everything else to the underlying model unchanged.
    """

    class _ContractGuardedChatModel:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        async def ainvoke(self, messages: Iterable[Any], **kwargs: Any) -> Any:
            return await safe_ainvoke(self._inner, messages, **kwargs)

        def astream(self, messages: Iterable[Any], **kwargs: Any):
            return safe_astream(self._inner, messages, **kwargs)

    return _ContractGuardedChatModel(llm)


# ---------------------------------------------------------------------------
# Raw OpenAI-compatible chat-completions HTTP wrapper
# ---------------------------------------------------------------------------

DEFAULT_OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


async def safe_chat_completions_request(
    *,
    api_key: str,
    model: str,
    messages: Iterable[Any],
    url: str = DEFAULT_OPENAI_CHAT_COMPLETIONS_URL,
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    **extra_body: Any,
) -> dict[str, Any]:
    """Validate ``messages`` against the contract, then issue a chat-completions POST.

    Use this for call sites in ``services/agents`` that talk to an
    OpenAI-compatible chat-completions endpoint over raw HTTP (e.g.
    ``api/copilot.py``, ``nl_query/translator.py``) instead of LangChain.
    The contract is enforced **before** the network request, so a
    violation never leaks log data on the wire.

    Returns the parsed JSON response. Raises:

    * :class:`LLMContractViolation` if any message fails the contract.
    * ``ValueError`` if ``api_key`` is empty.
    * ``httpx.HTTPError`` for transport / non-2xx responses (callers
      decide whether to fall back).
    """
    if not api_key:
        raise ValueError("api_key is required for safe_chat_completions_request")

    materialised = list(messages)
    LLMInputContract.validate(materialised)

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx is a hard dep
        raise RuntimeError("httpx is required for safe_chat_completions_request") from exc

    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    body: dict[str, Any] = {"model": model, "messages": materialised}
    body.update(extra_body)

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        return resp.json()
