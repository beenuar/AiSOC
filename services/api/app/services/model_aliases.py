"""Task role → LiteLLM gateway alias for the API service (#478).

The API service is a separate package from ``services/agents``, so it can't
import ``app.llm.factory``. This is the small mirror of
:func:`services.agents.app.llm.factory.resolve_model_alias`: each LLM-backed API
endpoint (translation, hunts, knowledge base, phishing) asks for a **logical
alias**; the LiteLLM gateway (``infra/litellm/config.yaml``) owns the alias →
real-model mapping. There is no hardcoded default model.

Escape hatch for deployments not running the gateway: override any role with a
concrete provider model via ``AISOC_MODEL_PIN_<ROLE>`` (kept in lockstep with the
agents-side pins), or set a global ``LLM_MODEL`` at the call site.
"""

from __future__ import annotations

import os

# Mirrors the roles in services/agents/app/llm/model_pins.py.
ROLES = frozenset({"triage", "recon", "investigation", "copilot", "summary", "report", "nl"})


DEFAULT_OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


def resolve_model_alias(role: str) -> str:
    """Return the ``aisoc-<role>`` alias, honouring an ``AISOC_MODEL_PIN_<ROLE>`` override."""
    override = os.environ.get(f"AISOC_MODEL_PIN_{role.upper()}", "").strip()
    return override or f"aisoc-{role}"


def resolve_base_url() -> str | None:
    """OpenAI-compatible base URL for live calls, or ``None`` for the default.

    Mirrors :func:`services.agents.app.llm.factory.resolve_base_url`, including
    its deliberate refusal to auto-adopt ``LLM_GATEWAY_URL``: routing through
    the gateway is an explicit choice so it is never ambiguous whether the
    bearer token is the gateway master key or a provider key.
    """
    return os.environ.get("OPENAI_BASE_URL", "").strip() or os.environ.get("LLM_BASE_URL", "").strip() or None


def chat_completions_url() -> str:
    """Full chat-completions URL for the raw-HTTP path.

    Exists so the NL-query translator — one file vendored into both services —
    can resolve the same two helpers from either package. Its LLM path used to
    import ``app.llm.factory``, which does not exist in the API process, and
    the resulting ``ImportError`` was swallowed by a broad ``except``. So
    ``/nl-query`` silently never reached a model and always returned the
    deterministic translation: safe by accident, and invisible.
    """
    base = resolve_base_url()
    if base:
        return base.rstrip("/") + "/chat/completions"
    return DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
