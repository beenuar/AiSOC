"""LLM factory — turn a task role into a ready chat model / model alias (#478).

Every live LLM call in ``services/agents`` asks for a **logical task alias**
(``aisoc-triage``, ``aisoc-recon``, …) rather than a concrete model. The LiteLLM
gateway (``infra/litellm/config.yaml``) owns the alias → real-model mapping and
any model-level fallback, so operators re-point models without touching code.
This module is the single place that resolves a role to ``(alias, base_url)`` and
hands back a configured chat model.

Since #478 there is **no hardcoded default model**. The alias comes from
:func:`app.llm.model_pins.get_pin`, which is env-overridable per role
(``AISOC_MODEL_PIN_<ROLE>``) so a deployment that calls a provider directly
instead of through the gateway can pin a concrete model. When no live LLM is
reachable, callers fall back to their deterministic path exactly as before — the
factory never forces a live call.

Routing to the gateway is deliberate: set ``OPENAI_BASE_URL`` (or ``LLM_BASE_URL``)
to the gateway and send ``OPENAI_API_KEY=$LITELLM_MASTER_KEY``. Left unset, the
client talks to its provider default — where an alias only resolves if the
operator has pinned a concrete model via ``AISOC_MODEL_PIN_<ROLE>``.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_openai import ChatOpenAI

from app.llm.contract import DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
from app.llm.model_pins import get_pin


def resolve_model_alias(role: str) -> str:
    """Return the logical model alias AiSOC sends for a task ``role``.

    ``aisoc-<role>`` by default; ``AISOC_MODEL_PIN_<ROLE>`` overrides it with a
    concrete provider model for deployments that bypass the gateway.
    """
    return get_pin(role).primary_model


def resolve_base_url() -> str | None:
    """OpenAI-compatible base URL for live calls, or ``None`` for the client default.

    Honours an explicit ``OPENAI_BASE_URL`` / ``LLM_BASE_URL`` — what an operator
    sets to point AiSOC at the LiteLLM gateway. ``None`` means "use the client's
    provider default" (the direct-to-provider path). We intentionally do **not**
    auto-adopt the compose-provided ``LLM_GATEWAY_URL`` here: routing through the
    gateway is an explicit choice so the bearer token (the gateway master key vs.
    a provider key) is never ambiguous.
    """
    return os.getenv("OPENAI_BASE_URL", "").strip() or os.getenv("LLM_BASE_URL", "").strip() or None


def chat_completions_url() -> str:
    """Full chat-completions URL for the raw-HTTP path (:func:`safe_chat_completions_request`)."""
    base = resolve_base_url()
    if base:
        return base.rstrip("/") + "/chat/completions"
    return DEFAULT_OPENAI_CHAT_COMPLETIONS_URL


def make_chat_model(
    role: str,
    *,
    temperature: float = 0.0,
    max_tokens: int | None = None,
    **kwargs: Any,
) -> ChatOpenAI:
    """Build a :class:`ChatOpenAI` for a task ``role`` (alias + gateway base URL).

    The returned model is **not** contract-guarded — every caller still routes the
    invocation through :func:`app.llm.safe_ainvoke`, which enforces the input
    contract. Extra ``kwargs`` pass straight through to ``ChatOpenAI``.
    """
    params: dict[str, Any] = {
        "model": resolve_model_alias(role),
        "temperature": temperature,
    }
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    base_url = resolve_base_url()
    if base_url:
        params["base_url"] = base_url
    params.update(kwargs)
    return ChatOpenAI(**params)
