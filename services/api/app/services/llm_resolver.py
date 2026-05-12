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
2.  Look up ``tenant_llm_credentials`` for this tenant. If a row
    exists and ``enabled=true``, layer non-NULL fields over the env
    baseline and decrypt the ciphertext via :class:`CredentialVault`.
3.  Apply air-gap policy: when ``AISOC_AIRGAPPED`` is on, only allow
    base URLs that point at a non-``api.openai.com`` host.
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

from app.models.llm_credential import TenantLlmCredential
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)


_DEFAULT_OPENAI_BASE = "https://api.openai.com"
_DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


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
    api_key = os.getenv("OPENAI_API_KEY", "").strip() or os.getenv("LLM_API_KEY", "").strip()
    return base_url, model, (api_key or None)


def _airgap_blocks(base_url: str) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` under the current air-gap policy.

    Replicates the semantics of the agents-side ``_airgap_blocks``
    helper. We deliberately do not import :func:`enforce_airgap_for_url`
    from ``app.core.airgap`` because that helper is intended for the
    actual outbound call and raises; here we want a non-raising
    classification for the resolver's "would this be allowed?"
    decision. The two paths must agree on the same hostname rule
    (no ``api.openai.com``), and they do.
    """
    airgapped = os.getenv("AISOC_AIRGAPPED", "").lower() in ("1", "true", "yes")
    if not airgapped:
        return False, ""

    base = (base_url or "").strip()
    if not base:
        return (
            True,
            "AISOC_AIRGAPPED is on and no base_url is configured (would default to api.openai.com).",
        )
    try:
        hostname = (urlparse(base).hostname or "").lower()
    except Exception:  # noqa: BLE001
        hostname = ""
    # Exact hostname or subdomain match — substring matching would
    # let ``evil.com/api.openai.com`` slip through.
    if hostname == "api.openai.com" or hostname.endswith(".api.openai.com"):
        return True, "AISOC_AIRGAPPED is on and base_url points at api.openai.com."
    return False, ""


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

    if cred is not None:
        if cred.base_url:
            base_url = cred.base_url
            tenant_contributed_base_url = True
        if cred.model:
            model = cred.model
            tenant_contributed_model = True
        if cred.api_key_vault:
            decrypted = _decrypt_vault_token(cred.api_key_vault, tenant_id)
            if decrypted is not None:
                api_key = decrypted
                tenant_contributed_key = True
            # else: fall through to env_key — corrupt tenant ciphertext
            # should not break a tenant that has a working env baseline.

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

    if not api_key:
        return LlmConfig(
            allowed=False,
            base_url=final_base,
            model=final_model,
            api_key=None,
            source=source,
            reason="no API key configured (neither tenant BYOK nor env)",
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
        )

    return LlmConfig(
        allowed=True,
        base_url=final_base,
        model=final_model,
        api_key=api_key,
        source=source,
        reason="",
    )
