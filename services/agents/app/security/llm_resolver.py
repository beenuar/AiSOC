"""Per-tenant LLM credential resolution for the explain endpoint (WS-H2).

What this resolves
------------------

The explain endpoint needs to answer a single question on every request:

    "For *this* tenant, do I make a live LLM call right now? If so,
    against which base URL, with which model, and using which API key?"

Up to v1.0 the answer was hard-coded to the process-level env vars
(``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` / ``OPENAI_MODEL``). The new
BYOK feature (WS-H2) lets each tenant override any of those three
fields by writing a vault-encrypted row to ``tenant_llm_credentials``
in the platform database. This module is the read path that the
agents service uses at request time.

Why we ported this here instead of calling the API service
----------------------------------------------------------

The agents service is already a database client (``investigator/ledger.py``)
and already has the env-vars + air-gap policy locally for the explain
path. Adding a second outbound HTTP hop to ``services/api`` just to
read three columns would:

* widen the explain-path latency budget on every alert,
* introduce an availability cross-dependency for what is a *fallback-
  capable* path (Explain must keep working when the API is down), and
* require a service-to-service auth model (mTLS or a shared secret)
  that we don't otherwise need.

Instead we vendor the read primitives — :class:`CredentialVault` for
ciphertext, plus this resolver — into the agents service. The API
service remains the sole owner of the *write* path, so there is one
place to gate ``settings:write`` RBAC, validation, and audit emission.

Resolution rules (must match :func:`tenant_llm_status` in services/api)
-----------------------------------------------------------------------

For each of the three fields we resolve in this order:

1. Tenant row (when present, ``enabled=true``, and successfully
   decrypted in the ``api_key_vault`` case).
2. Process env vars (``OPENAI_*`` / ``LLM_*``).
3. Platform default (``https://api.openai.com`` / ``gpt-4o-mini``)
   so the explain path always has a deterministic config to log
   against, even when it ultimately decides ``allowed=False``.

Whichever field came from the tenant row is recorded so the resolver
can label the resolved config with a ``source`` of ``"tenant"``,
``"environment"``, or ``"mixed"`` — useful for log-based debugging
of "wait, which key did this request actually use?".

Air-gap policy is the *last* thing we check, after layering. This
mirrors the semantics of the legacy ``_llm_allowed()`` helper so a
tenant who BYOKs a private LiteLLM gateway gets ``allowed=True`` even
when ``AISOC_AIRGAPPED=true``, which is exactly what the air-gap
deployment story promises.

Failure modes
-------------

This module is on the explain hot path, so every failure is best-
effort: a missing ``DATABASE_URL``, an unreachable database, an
unconfigured ``AISOC_CREDENTIAL_KEY``, a corrupt ciphertext, or a
tenant row with ``enabled=false`` all degrade gracefully to the env-
only baseline. The reason for the degradation is logged once at
``warning`` so an operator can spot misconfiguration, but the alert
drawer never errors out — it just renders the deterministic
fallback summary, exactly the same surface analysts already see when
no LLM is configured.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import asyncpg
import structlog

from app.security.credential_vault import CredentialVaultError, get_vault

# NOTE: ``app.investigator.ledger`` is imported lazily inside
# :func:`resolve_llm_config` rather than at module load time. The
# ``app.investigator`` package's ``__init__`` eagerly imports the LangGraph
# orchestrator, which in turn pulls in heavyweight dependencies that the
# explain unit tests deliberately avoid. Deferring the import to the path
# that actually needs a database pool keeps the explain endpoint testable
# in isolation while still using the canonical pool factory in production.

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
#
# These mirror the documented "no override" behaviour of the explain
# endpoint. When the resolver decides ``allowed=False`` we still surface
# a fully-formed ``LlmConfig`` so the caller can log "fallback because
# X" with concrete values rather than ``None`` placeholders.

_DEFAULT_OPENAI_BASE = "https://api.openai.com"
_DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


@dataclass(frozen=True)
class LlmConfig:
    """Effective LLM configuration for a single explain request.

    Attributes:
        allowed: ``True`` when an outbound LLM call is permitted *right
            now*. ``False`` means the explain path must use the
            deterministic synthesizer.
        base_url: The base URL to POST chat completions against. Always
            populated, even when ``allowed=False``, so callers can log
            it.
        model: The model identifier to send in the request body. Same
            "always populated" guarantee as ``base_url``.
        api_key: The plaintext API key. Only present when
            ``allowed=True``. Never logged, never returned to clients.
        source: One of ``"tenant"``, ``"environment"``, ``"mixed"``,
            ``"none"`` — describes where the layered config came from.
            ``"none"`` indicates neither the tenant row nor the env
            baseline contributed any usable values (which forces
            ``allowed=False``).
        reason: When ``allowed=False``, a short human-readable note
            explaining the reason. Empty when ``allowed=True``.
    """

    allowed: bool
    base_url: str
    model: str
    api_key: str | None
    source: str
    reason: str


# ---------------------------------------------------------------------------
# Env-var baseline
# ---------------------------------------------------------------------------


def _env_baseline() -> tuple[str, str, str | None]:
    """Return the ``(base_url, model, api_key)`` triple from process env.

    Mirrors :func:`services.api.app.api.v1.endpoints.llm_status._env_baseline`
    so the agents-side resolver and the API-side status indicator can
    never disagree about what "the env baseline" actually is. We
    intentionally accept both the modern ``LLM_*`` names and the legacy
    ``OPENAI_*`` / ``AISOC_LLM_MODEL`` names — every deployment in the
    field today uses some mix of the two.
    """
    base_url = os.getenv("OPENAI_BASE_URL", "").strip() or os.getenv("LLM_BASE_URL", "").strip()
    model = os.getenv("OPENAI_MODEL", "").strip() or os.getenv("LLM_MODEL", "").strip() or os.getenv("AISOC_LLM_MODEL", "").strip()
    api_key = os.getenv("OPENAI_API_KEY", "").strip() or os.getenv("LLM_API_KEY", "").strip()
    return base_url, model, (api_key or None)


# ---------------------------------------------------------------------------
# Air-gap policy
# ---------------------------------------------------------------------------


def _airgap_blocks(base_url: str) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` under the current air-gap policy.

    Replicates the semantics of the legacy ``_llm_allowed`` helper:

    * ``AISOC_AIRGAPPED`` off  → never blocks.
    * ``AISOC_AIRGAPPED`` on:
        * empty ``base_url`` would default to ``api.openai.com`` → blocked.
        * ``base_url`` containing ``api.openai.com`` → blocked.
        * any other host (private LiteLLM/Ollama/vLLM proxy) → allowed.

    Note that we deliberately do *not* call into ``services/api/app/core/airgap``
    here — that helper performs IP/CIDR allowlist checks that the
    agents service does not need (the request is already in-process,
    and the LLM host shape is enough to gate egress for explain).
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
        parsed = urlparse(base)
        hostname = (parsed.hostname or "").lower()
    except Exception:  # noqa: BLE001
        hostname = ""
    # Check hostname exactly or as a subdomain to avoid substring-match bypass
    # (e.g. evil.com/api.openai.com or api.openai.com.evil.com).
    if hostname == "api.openai.com" or hostname.endswith(".api.openai.com"):
        return True, "AISOC_AIRGAPPED is on and base_url points at api.openai.com."
    return False, ""


# ---------------------------------------------------------------------------
# Tenant-row lookup
# ---------------------------------------------------------------------------


async def _resolve_tenant_uuid(conn: asyncpg.Connection, tenant_ref: str) -> uuid.UUID | None:
    """Resolve a tenant reference (UUID, slug, or name) to a UUID.

    Inlined rather than imported from
    :mod:`app.investigator.ledger` so the resolver does not depend on
    that module's private helpers. Logic must stay in lockstep with
    :func:`app.investigator.ledger._resolve_tenant_id` — change one,
    change both.
    """
    try:
        return uuid.UUID(tenant_ref)
    except (ValueError, TypeError):
        pass

    row = await conn.fetchrow(
        """
        SELECT id FROM tenants
        WHERE slug = $1 OR name = $1
        LIMIT 1
        """,
        tenant_ref,
    )
    return row["id"] if row else None


async def _set_rls_context(conn: asyncpg.Connection, tenant_id: uuid.UUID) -> None:
    """Set the RLS GUC so policies on ``tenant_llm_credentials`` admit us."""
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", str(tenant_id))


async def _fetch_tenant_credential(pool: asyncpg.Pool, tenant_ref: str) -> dict[str, Any] | None:
    """Resolve ``tenant_ref`` and fetch the ``tenant_llm_credentials`` row.

    Returns ``None`` when:

    * the tenant reference cannot be resolved (unknown slug/name/UUID),
    * no row exists for the tenant,
    * the row exists but ``enabled=false`` (treated as "no override" so
      operators can pause BYOK without deleting the row), or
    * any database error occurs (logged once at ``warning``).

    A non-None return is always a sane dict with the columns this
    resolver consumes.
    """
    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_uuid(conn, tenant_ref)
            if tenant_id is None:
                return None
            await _set_rls_context(conn, tenant_id)
            row = await conn.fetchrow(
                """
                SELECT
                    provider,
                    base_url,
                    model,
                    api_key_vault,
                    settings,
                    enabled
                FROM tenant_llm_credentials
                WHERE tenant_id = $1
                """,
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "explain.llm_resolve_db_failed",
            tenant=tenant_ref,
            error=str(exc),
        )
        return None

    if row is None or not row["enabled"]:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def resolve_llm_config(tenant_ref: str | None) -> LlmConfig:
    """Resolve the effective LLM configuration for ``tenant_ref``.

    Args:
        tenant_ref: The tenant identifier carried on the explain request
            (UUID, slug, or name). When ``None`` or ``"default"`` we
            skip the database lookup and return the env-only baseline,
            matching the behaviour of the rest of the agents service.

    Returns:
        An :class:`LlmConfig` describing whether a live LLM call is
        permitted and which base URL / model / key the explain path
        should use. The resolver never raises — every failure path
        returns an ``allowed=False`` config with a populated ``reason``.

    Telemetry:
        Successful resolutions are not logged (would dominate the
        explain log). Failures (db error, decrypt error, vault key
        missing) are logged at ``warning`` with the tenant ref so an
        operator can find the offending row.
    """
    env_base_url, env_model, env_key = _env_baseline()

    base_url = env_base_url
    model = env_model
    api_key = env_key
    tenant_contributed_base_url = False
    tenant_contributed_model = False
    tenant_contributed_key = False

    skip_db_lookup = tenant_ref is None or not tenant_ref.strip() or tenant_ref == "default"
    if not skip_db_lookup:
        # Lazy import: see module-level NOTE. We only reach this branch
        # when the request carries a real tenant ref. Importing the
        # investigator package transitively loads the LangGraph
        # orchestrator, which is an optional dependency in slim
        # deployments and in unit tests that exercise the explain
        # endpoint in isolation. Treat a missing dependency the same way
        # we treat a missing DATABASE_URL: log once and fall through to
        # the environment baseline rather than failing the request.
        pool = None
        try:
            from app.investigator import ledger as _ledger  # noqa: PLC0415

            pool = await _ledger.get_pool()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "explain.llm_resolve_ledger_unavailable",
                tenant=tenant_ref,
                error=str(exc),
            )

        if pool is not None:
            row = await _fetch_tenant_credential(pool, tenant_ref)
            if row is not None:
                if row.get("base_url"):
                    base_url = row["base_url"]
                    tenant_contributed_base_url = True
                if row.get("model"):
                    model = row["model"]
                    tenant_contributed_model = True
                vault_token = row.get("api_key_vault")
                if vault_token:
                    api_key = _decrypt_vault_token(vault_token, tenant_ref)
                    if api_key is not None:
                        tenant_contributed_key = True
                    else:
                        # Decrypt failed (already logged) — fall back to
                        # the env key so a corrupt tenant ciphertext
                        # doesn't break a tenant that also has a working
                        # env baseline.
                        api_key = env_key

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
            source=source if source != "none" else "none",
            reason="no API key configured (neither tenant BYOK nor env)",
        )

    blocked, reason = _airgap_blocks(base_url)
    if blocked:
        return LlmConfig(
            allowed=False,
            base_url=final_base,
            model=final_model,
            api_key=api_key,  # safe: caller does not log this on failure
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decrypt_vault_token(vault_token: str, tenant_ref: str) -> str | None:
    """Decrypt a stored ``vault:v1:<base64>`` token. Returns ``None`` on failure.

    The vault may be unconfigured (``AISOC_CREDENTIAL_KEY`` not set) on
    operator boxes that haven't migrated to BYOK yet — that's a
    legitimate configuration, so we log once and fall back rather than
    treating it as an error.
    """
    vault = get_vault()
    if vault is None:
        logger.warning(
            "explain.llm_resolve_vault_disabled",
            tenant=tenant_ref,
            reason=("AISOC_CREDENTIAL_KEY not set; tenant BYOK key cannot be decrypted, falling back to environment baseline"),
        )
        return None
    try:
        return vault.decrypt(vault_token)
    except CredentialVaultError as exc:
        logger.warning(
            "explain.llm_resolve_decrypt_failed",
            tenant=tenant_ref,
            error=str(exc),
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
    """Label the merge result. Mirrors ``tenant_llm_status`` in services/api.

    The three flags say which fields the *tenant row* contributed. The
    env values say which fields the environment *would have*
    contributed if the tenant didn't. If both contributed something to
    the final config, the merge is "mixed" — exactly what the API-side
    status endpoint reports.
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
