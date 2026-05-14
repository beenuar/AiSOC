"""Shared CORS configuration helper for AiSOC FastAPI services.

Goal: every FastAPI service in this repo lands at the same, safe CORS posture
without each ``main.py`` re-implementing the parsing + production guard.

Why a helper at all? Before P2-A1 we had five services that each shipped their
own copy of ``app.add_middleware(CORSMiddleware, allow_origins=["*"], ...)``,
one of which (``services/connectors``) combined ``"*"`` with
``allow_credentials=True``. That combo is the canonical CORS misconfiguration:
the browser will refuse the response *and* — if a downstream proxy strips the
``Access-Control-Allow-Credentials`` header — every authenticated endpoint
turns into a CSRF target. Centralising the decision means we can enforce one
invariant ("no wildcard with credentials in production") in one place.

Configuration
-------------
The allow-list is resolved from environment variables, in priority order:

  1. ``AISOC_CORS_ORIGINS`` — canonical, comma-separated.
  2. ``CORS_ORIGINS``       — legacy alias kept for backwards compatibility
                              (some Helm charts and dev scripts still set it).
  3. ``default`` argument   — service-supplied fallback, or
                              :data:`DEFAULT_CORS_ORIGINS` if not provided.

The defaults cover local development (``localhost:3000`` / ``:3001`` and the
``127.0.0.1`` aliases) and the production console at ``tryaisoc.com``. Anything
beyond that should be set explicitly per deployment.

Production guard
----------------
If the resolved allow-list contains ``*`` while ``allow_credentials`` is
``True``:

  * In production (``AISOC_ENV`` / ``ENVIRONMENT`` / ``APP_ENV`` set to
    ``production`` or ``prod``) we raise :class:`CORSConfigurationError` at
    startup so the deploy fails loudly instead of silently exposing CSRF.
  * Outside production we log a warning and auto-disable credentials for this
    process. Local dev stays usable when someone exports ``CORS_ORIGINS=*``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable

logger = logging.getLogger(__name__)

DEFAULT_CORS_ORIGINS: tuple[str, ...] = (
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "https://tryaisoc.com",
    "https://www.tryaisoc.com",
)

# Used when ``allow_credentials`` is True. The CORS spec refuses the response
# if either of these is ``*`` while credentials are enabled, so we enumerate
# the values the AiSOC frontends actually need. Services that don't carry
# cookies/Authorization headers can still pass ``allow_methods=["*"]``.
DEFAULT_ALLOW_METHODS: tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
)
DEFAULT_ALLOW_HEADERS: tuple[str, ...] = (
    "Accept",
    "Accept-Language",
    "Authorization",
    "Content-Type",
    "Content-Language",
    "X-Tenant-ID",
    "X-Requested-With",
    "X-Trace-Id",
    "X-Idempotency-Key",
)

_PRODUCTION_ENV_VALUES = frozenset({"production", "prod"})


class CORSConfigurationError(RuntimeError):
    """Raised when the CORS configuration is unsafe (wildcard + credentials).

    Surfaces at app boot so deploys fail loudly instead of silently exposing
    authenticated endpoints to cross-origin requests from arbitrary attackers.
    """


def _split_origins(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _is_production_environment() -> bool:
    """Return True if any well-known env var indicates a production deploy."""
    env_value = (os.getenv("AISOC_ENV") or os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or "").strip().lower()
    return env_value in _PRODUCTION_ENV_VALUES


def resolve_cors_origins(
    *,
    default: Iterable[str] | None = None,
) -> list[str]:
    """Resolve the CORS allow-list from environment.

    Priority: ``AISOC_CORS_ORIGINS`` > ``CORS_ORIGINS`` > ``default``
    (or :data:`DEFAULT_CORS_ORIGINS`).
    """
    for env_name in ("AISOC_CORS_ORIGINS", "CORS_ORIGINS"):
        origins = _split_origins(os.getenv(env_name))
        if origins:
            return origins
    if default is not None:
        return list(default)
    return list(DEFAULT_CORS_ORIGINS)


def build_cors_kwargs(
    *,
    service_name: str,
    allow_credentials: bool = True,
    default_origins: Iterable[str] | None = None,
    allow_methods: Iterable[str] | None = None,
    allow_headers: Iterable[str] | None = None,
    expose_headers: Iterable[str] | None = None,
) -> dict[str, object]:
    """Return kwargs ready to splat into ``app.add_middleware(CORSMiddleware, ...)``.

    Parameters
    ----------
    service_name:
        Short identifier (``"api"``, ``"agents"`` …) used in startup logs and
        :class:`CORSConfigurationError` messages. Makes deployment failures
        attributable.
    allow_credentials:
        Whether endpoints in this service rely on cookies or
        ``Authorization`` headers across origins. The API + agents services
        do; honeytoken token-trip pixels do not.
    default_origins:
        Optional service-specific fallback when neither
        ``AISOC_CORS_ORIGINS`` nor ``CORS_ORIGINS`` is set.
    allow_methods / allow_headers / expose_headers:
        Optional explicit lists. When ``allow_credentials`` is True and the
        caller passes ``None``, we substitute :data:`DEFAULT_ALLOW_METHODS`
        / :data:`DEFAULT_ALLOW_HEADERS` so we don't have to emit ``"*"`` (the
        CORS spec rejects that combination in browsers).

    Raises
    ------
    CORSConfigurationError
        Allow-list contains ``"*"`` while ``allow_credentials`` is True and
        the process looks like a production deploy. Don't catch this — fix
        the deployment.
    """
    origins = resolve_cors_origins(default=default_origins)
    has_wildcard = "*" in origins

    if has_wildcard and allow_credentials:
        if _is_production_environment():
            raise CORSConfigurationError(
                f"{service_name}: refusing to start with wildcard CORS origin "
                "and allow_credentials=True. Set AISOC_CORS_ORIGINS to an "
                "explicit allow-list (e.g. https://app.example.com)."
            )
        logger.warning(
            "CORS wildcard origin combined with allow_credentials=True "
            "is unsafe; disabling credentials for service=%s. Set "
            "AISOC_CORS_ORIGINS to an explicit allow-list.",
            service_name,
        )
        allow_credentials = False

    if allow_credentials:
        methods = list(allow_methods) if allow_methods is not None else list(DEFAULT_ALLOW_METHODS)
        headers = list(allow_headers) if allow_headers is not None else list(DEFAULT_ALLOW_HEADERS)
    else:
        methods = list(allow_methods) if allow_methods is not None else ["*"]
        headers = list(allow_headers) if allow_headers is not None else ["*"]

    kwargs: dict[str, object] = {
        "allow_origins": origins,
        "allow_credentials": allow_credentials,
        "allow_methods": methods,
        "allow_headers": headers,
    }
    if expose_headers is not None:
        kwargs["expose_headers"] = list(expose_headers)

    logger.info(
        "CORS configured for service=%s origins=%s allow_credentials=%s",
        service_name,
        origins,
        allow_credentials,
    )
    return kwargs


__all__ = [
    "CORSConfigurationError",
    "DEFAULT_ALLOW_HEADERS",
    "DEFAULT_ALLOW_METHODS",
    "DEFAULT_CORS_ORIGINS",
    "build_cors_kwargs",
    "resolve_cors_origins",
]
