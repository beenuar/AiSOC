"""Resolve the effective LLM configuration for a single API-side request.

This module is the API-service twin of
:mod:`services.agents.app.security.llm_resolver`. It exists so the
``POST /api/v1/alerts/{alert_id}/explain`` endpoint can resolve a
tenant's BYOK configuration *without* round-tripping to the agents
service.

Why a second resolver?
----------------------
The agents service has its own resolver because it owns its own
asyncpg pool and isolates from the API service for latency reasons.
This module is the SQLAlchemy equivalent that the API service uses
directly, going through the same RLS context (``app.current_tenant_id``)
that ``get_tenant_db`` already establishes for the request.

Resolution rules (must match the agents resolver exactly)
---------------------------------------------------------
1.  Pull the env baseline (``OPENAI_BASE_URL`` / ``OPENAI_MODEL`` /
    ``OPENAI_API_KEY``, plus the modern ``LLM_*`` aliases).
2.  Look up the enabled ``tenant_llm_credentials`` row. Hosted providers
    use their own default endpoint/model when the tenant leaves them blank.
    An environment credential is inherited only for the same API endpoint;
    a tenant-selected destination otherwise needs its own usable key.
3.  Apply air-gap policy: when ``AISOC_AIRGAPPED`` is on, only allow
    base URLs permitted by the private-host / explicit-allowlist policy.
4.  Return an :class:`LlmConfig` describing whether a live call is
    permitted and the effective ``(base_url, model, api_key)`` triple.

The resolver never raises — every failure path returns
``allowed=False`` with a populated ``reason`` so callers can record
exactly why the explain endpoint fell back to the deterministic
synthesizer.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import is_host_allowed_for_airgap
from app.core.config import settings
from app.models.llm_credential import TenantLlmCredential
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services.llm_tenant_routing import allows_unauthenticated, tenant_route
from app.services.model_aliases import gateway_url, is_gateway_alias, resolve_api_key

logger = logging.getLogger(__name__)


_DEFAULT_OPENAI_BASE = "https://api.openai.com"
_DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
#: See the agents-side resolver: the explain path's work is a summary, and its
#: alias is the default model when a gateway is configured, because the bundled
#: gateway does not define ``gpt-4o-mini``.
_EXPLAIN_ROLE_ALIAS = "aisoc-summary"


@dataclass(frozen=True)
class LlmConfig:
    """Effective LLM configuration for a single explain request.

    Attributes:
        allowed: ``True`` when an outbound LLM call is permitted right
            now. ``False`` means the explain path must use the
            deterministic synthesizer.
        base_url: The base URL to POST chat completions against.
            Always populated, even on ``allowed=False``, so callers
            can log it.
        model: The model identifier to send in the request body.
        api_key: The plaintext API key. Only present when
            ``allowed=True``. Never logged, never returned to clients.
        source: One of ``"tenant"``, ``"environment"``, ``"mixed"``,
            ``"none"`` — describes where the layered config came
            from. Mirrors ``llm_status._compute_status``.
        reason: When ``allowed=False``, a short note explaining why.
            Empty when ``allowed=True``.
    """

    allowed: bool
    base_url: str
    model: str
    api_key: str | None
    source: str
    reason: str
    # Per-field provenance — mirrors the agents-side resolver. ``source``
    # collapses the whole config into one word, which is enough to log and not
    # enough to act on: a caller that binds this as a BYOK *override* needs to
    # know which fields the tenant actually set, or an env baseline silently
    # overrides a per-role model pin.
    model_from_tenant: bool = False
    base_url_from_tenant: bool = False
    api_key_from_tenant: bool = False


def _env_baseline() -> tuple[str, str, str | None]:
    """Return the ``(base_url, model, api_key)`` triple from process env.

    Mirrors :func:`services.api.app.api.v1.endpoints.llm_status._env_baseline`
    and the agents-side resolver so the three code paths can never
    disagree about what "the env baseline" actually is. We accept
    both modern ``LLM_*`` names and legacy ``OPENAI_*`` /
    ``AISOC_LLM_MODEL`` because every deployment in the field today
    uses some mix of the two.
    """
    base_url = os.getenv("OPENAI_BASE_URL", "").strip() or os.getenv("LLM_BASE_URL", "").strip()
    model = os.getenv("OPENAI_MODEL", "").strip() or os.getenv("LLM_MODEL", "").strip() or os.getenv("AISOC_LLM_MODEL", "").strip()
    if not base_url and gateway_url() and is_gateway_alias(model or _EXPLAIN_ROLE_ALIAS):
        # Same rule as every other caller (``app.services.model_aliases``):
        # the compose-provided gateway is adopted for an alias and never for a
        # concrete model. Without this the explain path defaulted straight to
        # ``https://api.openai.com`` and took an alias there.
        base_url = gateway_url() or ""
        model = model or _EXPLAIN_ROLE_ALIAS
    api_key = resolve_api_key(model) or ""
    return base_url, model, (api_key or None)


def _airgap_blocks(base_url: str) -> tuple[bool, str]:
    """Use the same policy as status and the actual API egress boundary."""
    if not settings.AISOC_AIRGAPPED:
        return False, ""
    try:
        hostname = (urlparse(base_url or "https://api.openai.com").hostname or "").lower()
    except ValueError:
        hostname = ""
    if is_host_allowed_for_airgap(hostname, settings.AISOC_AIRGAP_ALLOWLIST):
        return False, ""
    return True, f"AISOC_AIRGAPPED is on and host '{hostname}' is not allowed by the egress policy."


def _decrypt_vault_token(vault_token: str, tenant_id: uuid.UUID) -> str | None:
    """Decrypt a stored ``vault:v1:<base64>`` token; ``None`` on failure.

    The vault may be unconfigured on operator boxes that haven't
    migrated to BYOK yet (``AISOC_CREDENTIAL_KEY`` not set) — log
    once and fall back rather than treating it as an error.
    """
    try:
        vault = get_vault()
    except CredentialVaultError as exc:
        logger.warning(
            "explain.llm_resolve_vault_disabled tenant=%s reason=%s",
            tenant_id,
            exc,
        )
        return None
    try:
        return vault.decrypt(vault_token)
    except CredentialVaultError as exc:
        logger.warning(
            "explain.llm_resolve_decrypt_failed tenant=%s error=%s",
            tenant_id,
            exc,
        )
        return None


def _classify_source(
    *,
    env_base_url: str,
    env_model: str,
    env_key: str | None,
    tenant_contributed_base_url: bool,
    tenant_contributed_model: bool,
    tenant_contributed_key: bool,
) -> str:
    """Label the merge result.

    Mirrors the agents-side resolver and ``llm_status._compute_status``
    so the API-side ``source`` value matches what the Settings UI's
    LLM status indicator reports.
    """
    tenant_contributed = tenant_contributed_base_url or tenant_contributed_model or tenant_contributed_key
    env_contributed = (
        (not tenant_contributed_base_url and bool(env_base_url))
        or (not tenant_contributed_model and bool(env_model))
        or (not tenant_contributed_key and bool(env_key))
    )

    if tenant_contributed and env_contributed:
        return "mixed"
    if tenant_contributed:
        return "tenant"
    if env_contributed:
        return "environment"
    return "none"


async def resolve_llm_config(db: AsyncSession, tenant_id: uuid.UUID) -> LlmConfig:
    """Resolve the effective LLM configuration for ``tenant_id``.

    The DB session must already have its RLS context set to
    ``tenant_id`` (use :class:`TenantDBSession`). We re-pass the
    tenant id explicitly only to scope the SELECT and to avoid
    spelunking through session info dictionaries.

    Returns:
        An :class:`LlmConfig`. Never raises — failures collapse to
        ``allowed=False`` with a populated ``reason``.
    """
    env_base_url, env_model, env_key = _env_baseline()

    base_url = env_base_url
    model = env_model
    api_key = env_key
    tenant_contributed_base_url = False
    tenant_contributed_model = False
    tenant_contributed_key = False
    allows_no_auth = False

    try:
        result = await db.execute(
            select(TenantLlmCredential).where(
                TenantLlmCredential.tenant_id == tenant_id,
                TenantLlmCredential.enabled.is_(True),
            )
        )
        cred = result.scalar_one_or_none()
    except Exception as exc:  # noqa: BLE001
        logger.warning("explain.llm_resolve_db_failed tenant=%s error=%s", tenant_id, exc)
        cred = None

    if cred is not None and cred.enabled:
        base_url, model, tenant_contributed_base_url, tenant_contributed_model, inherit_env_key = tenant_route(
            provider=cred.provider,
            base_url=cred.base_url,
            model=cred.model,
            env_base=env_base_url,
            env_model=env_model,
        )
        if not inherit_env_key:
            # A tenant-controlled destination must never receive the bundled
            # gateway master key or a different provider's environment key.
            api_key = None
            env_key = None
        allows_no_auth = allows_unauthenticated(cred.provider, cred.base_url, bool(cred.api_key_vault))
        if cred.api_key_vault:
            decrypted = _decrypt_vault_token(cred.api_key_vault, tenant_id)
            if decrypted is not None:
                api_key = decrypted
                tenant_contributed_key = True
            # A failed decrypt may use an environment key only when it
            # belongs to this same endpoint. Otherwise the call is refused.

    source = _classify_source(
        env_base_url=env_base_url,
        env_model=env_model,
        env_key=env_key,
        tenant_contributed_base_url=tenant_contributed_base_url,
        tenant_contributed_model=tenant_contributed_model,
        tenant_contributed_key=tenant_contributed_key,
    )

    final_base = base_url or _DEFAULT_OPENAI_BASE
    final_model = model or _DEFAULT_OPENAI_MODEL

    if not api_key and not allows_no_auth:
        return LlmConfig(
            allowed=False,
            base_url=final_base,
            model=final_model,
            api_key=None,
            source=source,
            reason="no API key configured for this endpoint (neither tenant BYOK nor matching environment credentials)",
            model_from_tenant=tenant_contributed_model,
            base_url_from_tenant=tenant_contributed_base_url,
            api_key_from_tenant=tenant_contributed_key,
        )

    blocked, reason = _airgap_blocks(base_url)
    if blocked:
        # Discard the api_key on the failure path so callers physically
        # cannot exfiltrate it via a wayward log statement.
        return LlmConfig(
            allowed=False,
            base_url=final_base,
            model=final_model,
            api_key=None,
            source=source,
            reason=reason,
            model_from_tenant=tenant_contributed_model,
            base_url_from_tenant=tenant_contributed_base_url,
            api_key_from_tenant=tenant_contributed_key,
        )

    return LlmConfig(
        allowed=True,
        base_url=final_base,
        model=final_model,
        api_key=api_key,
        source=source,
        reason="",
        model_from_tenant=tenant_contributed_model,
        base_url_from_tenant=tenant_contributed_base_url,
        api_key_from_tenant=tenant_contributed_key,
    )
