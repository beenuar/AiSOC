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

Which URL a model goes to, and which bearer goes with it, is
:mod:`app.llm.routing` — shared with the BYOK resolver and mirrored in the API
service. The short version: the compose-provided ``LLM_GATEWAY_URL`` is adopted
for an ``aisoc-<role>`` alias (it can resolve nowhere else) and left alone for a
concrete pinned model (which the gateway would not define), and an explicit
``OPENAI_BASE_URL`` always wins.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
from collections.abc import Iterator
from typing import Any

from langchain_openai import ChatOpenAI

from app.core.gateway_cost import INCLUDE_HEADERS_PARAM
from app.llm.contract import DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
from app.llm.model_pins import get_pin

# The routing rule (which URL, which bearer, and when an alias has nowhere to
# go) lives in one stdlib-only module because the BYOK resolver needs it too
# and cannot import this one. Re-exported so existing call sites and tests keep
# importing these names from the factory.
from app.llm.routing import (
    BYOK_MODEL_ENV_VARS,
    GATEWAY_ALIAS_PREFIX,
    UnroutableModelError,
    adopted_gateway,
    assert_routable,
    at_bundled_gateway,
    gateway_url,
    is_gateway_alias,
    resolve_api_key,
    resolve_base_url,
)
from app.llm.routing import explicit_base_url as _explicit_base_url

__all__ = [
    "BYOK_MODEL_ENV_VARS",
    "GATEWAY_ALIAS_PREFIX",
    "UnroutableModelError",
    "adopted_gateway",
    "assert_routable",
    "at_bundled_gateway",
    "chat_completions_url",
    "gateway_url",
    "is_gateway_alias",
    "llm_override",
    "make_chat_model",
    "preflight_llm",
    "resolve_api_key",
    "resolve_base_url",
    "resolve_model_alias",
]

# Wave 1 — per-tenant BYOK override. The auto-triage / investigation paths
# resolve a tenant's own (base_url, model, api_key) via
# app.security.llm_resolver and bind it here so make_chat_model actually routes
# the agent LLM calls to the tenant's key/model — previously BYOK reached only
# the explain path. A contextvar keeps it request-scoped without threading the
# config through every agent signature.
_llm_override: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar("aisoc_llm_override", default=None)


@contextlib.contextmanager
def llm_override(*, api_key: str | None = None, base_url: str | None = None, model: str | None = None) -> Iterator[None]:
    """Bind a per-tenant BYOK override for the duration of the block."""
    override = {k: v for k, v in (("api_key", api_key), ("base_url", base_url), ("model", model)) if v}
    token = _llm_override.set(override or None)
    try:
        yield
    finally:
        _llm_override.reset(token)


def resolve_model_alias(role: str) -> str:
    """Return the logical model alias AiSOC sends for a task ``role``.

    ``aisoc-<role>`` by default; ``AISOC_MODEL_PIN_<ROLE>`` overrides it with a
    concrete provider model for deployments that bypass the gateway.
    """
    return get_pin(role).primary_model


def chat_completions_url(model: str | None = None) -> str:
    """Full chat-completions URL for the raw-HTTP path (:func:`safe_chat_completions_request`).

    ``model`` is what the caller is about to send. Passing it lets the same
    routing rule as :func:`resolve_base_url` apply, and turns an alias with no
    gateway into :class:`UnroutableModelError` here rather than a 404 later.
    """
    base = resolve_base_url(model)
    if model is not None:
        assert_routable(model, base)
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
    override = _llm_override.get()
    model = (override or {}).get("model") or resolve_model_alias(role)
    params: dict[str, Any] = {"model": model, "temperature": temperature}
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    base_url = (override or {}).get("base_url") or resolve_base_url(model)
    assert_routable(model, base_url)
    if base_url:
        params["base_url"] = base_url
    api_key = (override or {}).get("api_key") or resolve_api_key(model)
    if api_key:
        params["api_key"] = api_key
    # Keep the response headers. The gateway reports what it resolved the
    # alias to and what the call actually cost on them, and without this flag
    # `response_metadata` has no `headers` key at all — so the cost tracker
    # had nothing to read and priced the *alias* against a hosted price table,
    # billing a free local run. See app/core/gateway_cost.py.
    if INCLUDE_HEADERS_PARAM in getattr(ChatOpenAI, "model_fields", {}):
        params.setdefault(INCLUDE_HEADERS_PARAM, True)
    params.update(kwargs)
    return ChatOpenAI(**params)


def preflight_llm(roles: tuple[str, ...] = ("triage", "recon", "investigation", "report", "summary", "copilot", "nl")) -> list[str]:
    """Return startup warnings about LLM config that cannot reach a model.

    Checked in both directions, because each one shipped broken:

    * **alias with no gateway** — an ``aisoc-<role>`` alias sent to a provider
      default 404s, and the caller's ``except`` renders that as a deterministic
      fallback. This condition was already reported here, correctly, while
      nothing read the variable that would have fixed it.
    * **concrete model at the gateway** — the reverse. A BYOK model name
      (``OPENAI_MODEL``) or a role pin naming something the gateway does not
      define 400s with "Invalid model name" once traffic is routed through it.

    Empty list => every role has somewhere to send its model.
    """
    warnings: list[str] = []
    aliases = {r: resolve_model_alias(r) for r in roles}

    unrouted = sorted({m for m in aliases.values() if is_gateway_alias(m) and not resolve_base_url(m)})
    if unrouted:
        warnings.append(
            f"No LLM gateway is configured, so LiteLLM aliases ({', '.join(unrouted)}) have "
            "nowhere to resolve and every live call will fail. Set LLM_GATEWAY_URL "
            "(docker-compose.yml already does) or OPENAI_BASE_URL to the gateway, or pin "
            "concrete models via AISOC_MODEL_PIN_<ROLE>. Agents run deterministic-only until then."
        )

    concrete_at_gateway = sorted({m for m in aliases.values() if not is_gateway_alias(m) and at_bundled_gateway(resolve_base_url(m))})
    if concrete_at_gateway:
        warnings.append(
            f"AISOC_MODEL_PIN_<ROLE> names concrete models ({', '.join(concrete_at_gateway)}) while traffic "
            "is routed at the bundled LiteLLM gateway, which 400s any model it does not define. Either add "
            "them to infra/litellm/config.yaml or drop the pins so the aisoc-<role> aliases apply."
        )

    byok = sorted({v for name in BYOK_MODEL_ENV_VARS if (v := os.getenv(name, "").strip()) and not is_gateway_alias(v)})
    if byok and at_bundled_gateway(_explicit_base_url() or gateway_url()):
        warnings.append(
            f"{'/'.join(BYOK_MODEL_ENV_VARS)} names a concrete model ({', '.join(byok)}) the bundled gateway "
            "does not define, so the BYOK / explain path will 400. These never apply to a task role — "
            "set one of them to an aisoc-<role> alias, or add the model to infra/litellm/config.yaml."
        )
    return warnings
