"""Where a model name goes, and which bearer goes with it.

One rule, in one place, because it had been written three times and disagreed
each time. ``app.llm.factory`` resolves it for the LangChain path,
``app.security.llm_resolver`` for the BYOK / "explain this alert" path, and
``app.services.model_aliases`` is the byte-equivalent mirror in the API service
(a separate package that cannot import this one).

The defect this replaces
------------------------
``docker-compose.yml`` set ``LLM_GATEWAY_URL`` on the api and agents services.
Nothing read it. The resolvers honoured only ``OPENAI_BASE_URL`` /
``LLM_BASE_URL``, which compose never set, and declined to adopt the gateway
variable on the grounds that routing through the gateway should be an explicit
choice so the bearer token is never ambiguous. The reasoning was sound and the
result was that the product's headline capability could not reach a model in the
default deployment: an ``aisoc-triage`` alias went to ``api.openai.com``, which
404s, and the caller's ``except`` rendered that as "no LLM available".

Two rules make the adoption unambiguous rather than merely convenient:

**The model decides the route.** ``LLM_GATEWAY_URL`` is adopted only for a
gateway alias. An alias is unroutable anywhere else, so sending it to the
gateway cannot be wrong. A concrete model — ``AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini``,
the documented direct-to-provider escape hatch — is left pointing at its
provider, because hijacking it to a gateway that does not define it would break
a deployment that works today.

**The route decides the bearer.** When AiSOC picks the gateway itself, the
bearer is the gateway's ``LITELLM_MASTER_KEY``; a provider key sent there is
rejected as an invalid proxy token. When the operator set ``OPENAI_BASE_URL``
by hand they own the pairing. That is the ambiguity the old refusal was about,
resolved instead of avoided.

Stdlib only: the BYOK resolver is imported by explain unit tests that avoid the
LangChain dependency graph, so this cannot reach for anything heavier.
"""

from __future__ import annotations

import os

#: The routing rule, named. ``scripts/check_llm_model_routing.py`` requires the
#: API-service mirror to define every one of these, and requires any function
#: in the mirror that reads a routing variable to appear here — so the mirror
#: can neither lose a rule nor grow one this module does not have.
__all__ = [
    "BYOK_MODEL_ENV_VARS",
    "GATEWAY_ALIAS_PREFIX",
    "UnroutableModelError",
    "adopted_gateway",
    "assert_routable",
    "at_bundled_gateway",
    "explicit_base_url",
    "gateway_url",
    "is_gateway_alias",
    "resolve_api_key",
    "resolve_base_url",
]

#: Prefix of every logical task alias the bundled gateway defines. The alias set
#: itself lives in ``infra/litellm/config.yaml``;
#: ``scripts/check_llm_model_routing.py`` reconciles that file against the role
#: pins in both directions. Only the *shape* is known here, because the service
#: images do not ship the gateway config.
GATEWAY_ALIAS_PREFIX = "aisoc-"

#: Env vars holding a model name for the BYOK / "explain this alert" path. They
#: are not role pins. A task role that adopts one has taken a global default for
#: a per-tenant override, which is how ``OPENAI_MODEL`` came to replace
#: ``aisoc-triage`` on the highest-volume path in the product.
BYOK_MODEL_ENV_VARS = ("OPENAI_MODEL", "LLM_MODEL", "AISOC_LLM_MODEL")


class UnroutableModelError(RuntimeError):
    """A gateway alias was requested with nowhere to send it.

    An ``aisoc-<role>`` alias only means something to the LiteLLM gateway. Sent
    to a provider default it returns 404, and the caller's ``except`` turns that
    into a deterministic fallback — a configuration error wearing the costume of
    a degraded-but-working system. Raising names the actual fault.
    """


def is_gateway_alias(model: str | None) -> bool:
    """Whether ``model`` is a logical alias that only the gateway can resolve."""
    return bool(model) and str(model).strip().startswith(GATEWAY_ALIAS_PREFIX)


def explicit_base_url() -> str | None:
    """The base URL an operator set by hand, if any."""
    return os.environ.get("OPENAI_BASE_URL", "").strip() or os.environ.get("LLM_BASE_URL", "").strip() or None


def gateway_url() -> str | None:
    """The bundled LiteLLM gateway's in-network URL, as compose supplies it."""
    return os.environ.get("LLM_GATEWAY_URL", "").strip() or None


def resolve_base_url(model: str | None = None) -> str | None:
    """OpenAI-compatible base URL for ``model``, or ``None`` for the client default.

    Precedence, highest first: ``OPENAI_BASE_URL`` / ``LLM_BASE_URL``, then
    ``LLM_GATEWAY_URL`` when ``model`` is a gateway alias, then nothing.

    ``model=None`` means the caller has not said which model it will send.
    Every task role defaults to an alias, so the gateway is the right answer.
    """
    explicit = explicit_base_url()
    if explicit:
        return explicit
    if model is None or is_gateway_alias(model):
        return gateway_url()
    return None


def adopted_gateway(model: str | None = None) -> bool:
    """Whether the base URL for ``model`` came from ``LLM_GATEWAY_URL``, not an operator."""
    return explicit_base_url() is None and resolve_base_url(model) is not None


def at_bundled_gateway(base_url: str | None) -> bool:
    """Whether ``base_url`` is the gateway this repo ships a model list for.

    Narrower than "some base URL is set" on purpose: an operator pointing at
    their own vLLM with concrete model names is correct, and warning about it
    would be noise. Only ``infra/litellm/config.yaml``'s alias set is knowable
    from here, so only that gateway's contents can be reasoned about.
    """
    gateway = gateway_url()
    if not base_url or not gateway:
        return False
    return str(base_url).rstrip("/") == gateway.rstrip("/")


def resolve_api_key(model: str | None = None) -> str | None:
    """Bearer token that pairs with :func:`resolve_base_url`'s answer for ``model``."""
    if adopted_gateway(model):
        return os.environ.get("LITELLM_MASTER_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip() or None
    return os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("LLM_API_KEY", "").strip() or None


def assert_routable(model: str, base_url: str | None) -> None:
    """Raise :class:`UnroutableModelError` if ``model`` can never resolve at ``base_url``.

    One shape, checked at every entry point: a gateway alias with no gateway to
    send it to. Everything else is the provider's call to make — a wrong
    concrete model name comes back as a 404 from a host that can answer the
    question, which is a diagnosable result rather than a silent one.
    """
    if is_gateway_alias(model) and not base_url:
        raise UnroutableModelError(
            f"model '{model}' is a LiteLLM gateway alias and no gateway is configured. "
            "Set LLM_GATEWAY_URL (docker-compose.yml already does) or OPENAI_BASE_URL to the "
            "gateway, or pin a concrete provider model via AISOC_MODEL_PIN_<ROLE>. "
            "Sending an alias to a provider default returns 404 and degrades silently."
        )
