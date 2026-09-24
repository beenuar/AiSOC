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

#: See :data:`services.agents.app.llm.routing.GATEWAY_ALIAS_PREFIX`.
GATEWAY_ALIAS_PREFIX = "aisoc-"

#: See :data:`services.agents.app.llm.routing.BYOK_MODEL_ENV_VARS`.
BYOK_MODEL_ENV_VARS = ("OPENAI_MODEL", "LLM_MODEL", "AISOC_LLM_MODEL")


class UnroutableModelError(RuntimeError):
    """A gateway alias was requested with nowhere to send it.

    Mirror of :class:`services.agents.app.llm.factory.UnroutableModelError`.
    """


def is_gateway_alias(model: str | None) -> bool:
    """Whether ``model`` is a logical alias that only the gateway can resolve."""
    return bool(model) and str(model).strip().startswith(GATEWAY_ALIAS_PREFIX)


def resolve_model_alias(role: str) -> str:
    """Return the ``aisoc-<role>`` alias, honouring an ``AISOC_MODEL_PIN_<ROLE>`` override."""
    override = os.environ.get(f"AISOC_MODEL_PIN_{role.upper()}", "").strip()
    return override or f"aisoc-{role}"


def _explicit_base_url() -> str | None:
    """The base URL an operator set by hand, if any."""
    return os.environ.get("OPENAI_BASE_URL", "").strip() or os.environ.get("LLM_BASE_URL", "").strip() or None


def gateway_url() -> str | None:
    """The bundled LiteLLM gateway's in-network URL, as compose supplies it."""
    return os.environ.get("LLM_GATEWAY_URL", "").strip() or None


def resolve_base_url(model: str | None = None) -> str | None:
    """OpenAI-compatible base URL for ``model``, or ``None`` for the default.

    Mirrors :func:`services.agents.app.llm.factory.resolve_base_url` exactly,
    including the rule that ``LLM_GATEWAY_URL`` — the only base-URL variable
    ``docker-compose.yml`` sets — is adopted for an alias-shaped model and left
    alone for a concrete pinned one.
    """
    explicit = _explicit_base_url()
    if explicit:
        return explicit
    if model is None or is_gateway_alias(model):
        return gateway_url()
    return None


def explicit_base_url() -> str | None:
    """The base URL an operator set by hand, if any."""
    return _explicit_base_url()


def adopted_gateway(model: str | None = None) -> bool:
    """Whether the base URL for ``model`` came from ``LLM_GATEWAY_URL`` rather than an operator."""
    return _explicit_base_url() is None and resolve_base_url(model) is not None


def at_bundled_gateway(base_url: str | None) -> bool:
    """Whether ``base_url`` is the gateway this repo ships a model list for.

    Mirrors :func:`services.agents.app.llm.routing.at_bundled_gateway`.
    """
    gateway = gateway_url()
    if not base_url or not gateway:
        return False
    return str(base_url).rstrip("/") == gateway.rstrip("/")


def resolve_api_key(model: str | None = None) -> str | None:
    """Bearer token to send alongside :func:`resolve_base_url`'s answer.

    Mirrors :func:`services.agents.app.llm.factory.resolve_api_key`: when AiSOC
    picks the bundled gateway itself the bearer is ``LITELLM_MASTER_KEY``, never
    a provider key.
    """
    if adopted_gateway(model):
        return os.environ.get("LITELLM_MASTER_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip() or None
    return os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("LLM_API_KEY", "").strip() or None


def assert_routable(model: str, base_url: str | None) -> None:
    """Raise :class:`UnroutableModelError` if ``model`` can never resolve at ``base_url``."""
    if is_gateway_alias(model) and not base_url:
        raise UnroutableModelError(
            f"model '{model}' is a LiteLLM gateway alias and no gateway is configured. "
            "Set LLM_GATEWAY_URL (docker-compose.yml already does) or OPENAI_BASE_URL to the "
            "gateway, or pin a concrete provider model via AISOC_MODEL_PIN_<ROLE>. "
            "Sending an alias to a provider default returns 404 and degrades silently."
        )


def chat_completions_url(model: str | None = None) -> str:
    """Full chat-completions URL for the raw-HTTP path.

    Exists so the NL-query translator — one file vendored into both services —
    can resolve the same two helpers from either package. Its LLM path used to
    import ``app.llm.factory``, which does not exist in the API process, and
    the resulting ``ImportError`` was swallowed by a broad ``except``. So
    ``/nl-query`` silently never reached a model and always returned the
    deterministic translation: safe by accident, and invisible.
    """
    base = resolve_base_url(model)
    if model is not None:
        assert_routable(model, base)
    if base:
        return base.rstrip("/") + "/chat/completions"
    return DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
