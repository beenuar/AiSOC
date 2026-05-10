"""LLM provider status endpoint — Tier 3.1 (operator visibility).

Exposes a redacted snapshot of the active LLM configuration so operators
and auditors can verify the runtime LLM provider, model, and air-gap
compliance without shelling into a pod or grepping ``.env``. The
endpoint mirrors the shape of ``/api/v1/airgap/status`` and is paired
with the "Deployment & AI" Settings panel in the web app
(WS-H2 BYOK / WS-H4 air-gap operator UX).

Contract
--------

* **Read-only.** No knobs to flip, no secrets returned. The API key
  itself is never serialized — only ``key_set: bool``.
* **Best-effort.** When the operator hasn't set ``OPENAI_API_KEY`` /
  ``OPENAI_BASE_URL`` (and the tenant hasn't BYOK'd a row in
  ``tenant_llm_credentials``), the endpoint reports ``provider="none"``
  and ``effective_path="fallback"`` so the UI can clearly say
  "running on deterministic fallback".
* **Air-gap aware.** Reuses ``app.core.airgap.is_host_allowed_for_airgap``
  so the answer to "would my LLM call actually leave the pod under the
  current air-gap policy?" comes from the *same* code path that gates
  egress at request time. No drift between the indicator and reality.

Two views: env-only vs tenant-resolved
--------------------------------------

* :func:`llm_status` returns the *environment-only* baseline — what the
  pod would do if no tenant context were involved. This is what the
  unauthenticated ``GET /api/v1/llm/status`` endpoint serves and what
  legacy callers like ``cost_dashboard`` consume.
* :func:`tenant_llm_status` layers per-tenant BYOK overrides from
  ``tenant_llm_credentials`` on top of the env baseline. Used by callers
  that already have an authenticated tenant context. The ``source``
  field on the returned snapshot says where each value came from
  (``"environment"`` / ``"tenant"`` / ``"mixed"``) so the UI can surface
  the layering honestly.

The agents service performs the equivalent resolution over its raw
``asyncpg`` connection (see ``services/agents/app/api/explain.py``)
using the vendored credential vault, so the indicator and the
runtime path stay in lockstep.

Why we don't reuse ``deployment.get_airgap_status``
---------------------------------------------------

``app.api.v1.endpoints.deployment.get_airgap_status`` is an in-memory
mock for a legacy UI. This module deliberately reads the *real*
env-var-driven config (and ``tenant_llm_credentials``) so the
indicator the operator sees in Settings matches the policy the
gateway enforces.
"""

from __future__ import annotations

import os
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import is_host_allowed_for_airgap
from app.core.config import settings
from app.models.llm_credential import TenantLlmCredential
from app.security.credential_vault import CredentialVaultError, get_vault

router = APIRouter(prefix="/llm", tags=["llm"])

# Map known hostnames → human-readable provider names so the UI doesn't
# have to do its own substring matching. Order matters only for the
# substring tier (entries earlier in the tuple win).
_HOSTED_PROVIDERS: dict[str, str] = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
}

_HOSTED_SUBSTRINGS: tuple[tuple[str, str], ...] = (
    (".openai.azure.com", "azure-openai"),
    (".azureapi.net", "azure-openai"),
    (".anthropic.com", "anthropic"),
    ("ollama", "local-ollama"),
    ("vllm", "local-vllm"),
    ("litellm", "local-litellm"),
)


def _classify_provider(base_url: str) -> str:
    """Return a stable provider id for the given base URL.

    Returns ``"none"`` when the operator hasn't configured a base URL
    *and* hasn't set ``OPENAI_API_KEY`` (i.e. the explain path is
    forced onto the deterministic fallback).
    """
    if not base_url:
        # No explicit base — treat as the OpenAI default, unless the
        # caller has also blanked the API key (handled by ``provider``
        # logic below).
        return "openai"

    host = (urlparse(base_url).hostname or "").lower()
    if not host:
        return "custom"

    if host in _HOSTED_PROVIDERS:
        return _HOSTED_PROVIDERS[host]

    for needle, provider in _HOSTED_SUBSTRINGS:
        if needle in host:
            return provider

    return "custom"


def _is_loopback_or_private_host(host: str) -> bool:
    """Cheap "is this clearly a local LLM" classifier for the UI badge.

    We don't want to claim "running locally" for a host the operator
    just happened to put in ``AISOC_AIRGAP_ALLOWLIST`` (e.g. an internal
    SaaS gateway), so this is intentionally narrower than the full
    air-gap host classifier.
    """
    if not host:
        return False
    host = host.lower().strip()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    # Bare service name with no dots (docker-compose: "ollama") is local.
    if "." not in host:
        return True
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".lan"):
        return True
    return False


def _env_baseline() -> tuple[str, str, bool]:
    """Resolve the ``(base_url, model, key_set)`` triple from env vars.

    Pulled out of :func:`llm_status` so both the env-only path and the
    tenant-resolved path start from exactly the same baseline. Returns
    a tuple rather than a dict so callers can immediately layer
    overrides on top by name.
    """
    base_url = os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL") or ""
    model = os.getenv("LLM_MODEL") or os.getenv("OPENAI_MODEL") or os.getenv("AISOC_LLM_MODEL") or ""
    key_set = bool(os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY"))
    return base_url, model, key_set


def _compute_status(
    *,
    base_url: str,
    model: str,
    key_set: bool,
    source: str,
) -> dict[str, object]:
    """Compute the redacted status snapshot for a resolved config triple.

    All classification (``provider``, ``airgap_compliant``, ``is_local``,
    ``effective_path``, ``policy_note``) happens here so env-only and
    tenant-resolved paths produce identical-shaped payloads. The
    ``source`` argument is threaded through to the response so callers
    can tell where each value came from without re-doing the merge.
    """
    airgap_enabled = bool(settings.AISOC_AIRGAPPED)

    # If neither base_url nor key are set, the operator is running on
    # the deterministic fallback. Surface that explicitly so the
    # Settings UI can say "no LLM configured" rather than implying the
    # default OpenAI path is wired up.
    if not base_url and not key_set:
        provider = "none"
    else:
        provider = _classify_provider(base_url)

    host = (urlparse(base_url).hostname or "").lower() if base_url else ""

    # Air-gap compliance: when air-gap is OFF this is always True (the
    # check is moot). When ON, we ask the same classifier the egress
    # gate uses so the answer matches what would actually happen at
    # request time.
    if not airgap_enabled:
        airgap_compliant = True
    elif provider == "none":
        # No outbound call would happen anyway — fallback path is
        # always air-gap compliant.
        airgap_compliant = True
    elif not host:
        # base_url unset but key is set → would default to api.openai.com
        # which is never compliant under air-gap.
        airgap_compliant = False
    else:
        airgap_compliant = is_host_allowed_for_airgap(host, settings.AISOC_AIRGAP_ALLOWLIST)

    is_local = _is_loopback_or_private_host(host)

    # Effective path tells the UI which branch the explain endpoint
    # would actually take right now. Mirrors ``_llm_allowed`` in
    # ``services/agents/app/api/explain.py`` semantics so the indicator
    # cannot drift from runtime behaviour.
    if not key_set:
        effective_path = "fallback"
    elif airgap_enabled and not airgap_compliant:
        effective_path = "fallback"
    else:
        effective_path = "live"

    if provider == "none":
        policy_note = (
            "No LLM is configured. The Explain endpoint will return "
            "deterministic OCSF + MITRE summaries and skip natural-language "
            "narration. Set OPENAI_BASE_URL + OPENAI_API_KEY (or LLM_BASE_URL "
            "+ LLM_API_KEY) to enable LLM-backed summaries."
        )
    elif airgap_enabled and not airgap_compliant:
        policy_note = (
            f"Air-gapped mode is ON and host '{host or 'api.openai.com'}' is "
            "not allowed by the egress policy. The Explain endpoint will "
            "fall back to deterministic summaries until the LLM points at a "
            "host in AISOC_AIRGAP_ALLOWLIST or a private/internal endpoint."
        )
    elif effective_path == "fallback":
        # key_set is False but base_url may be set — uncommon but possible.
        policy_note = (
            "OPENAI_API_KEY (or LLM_API_KEY) is unset, so LLM calls are disabled and Explain falls back to deterministic summaries."
        )
    elif is_local:
        policy_note = f"LLM calls are routed to a local provider ({provider}). No external network egress is required for the Explain path."
    else:
        policy_note = f"LLM calls are routed to {provider} at {host}. Outbound HTTP is required."

    return {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "host": host,
        "key_set": key_set,
        "airgap_enabled": airgap_enabled,
        "airgap_compliant": airgap_compliant,
        "is_local": is_local,
        "effective_path": effective_path,
        "policy_note": policy_note,
        "source": source,
    }


def llm_status() -> dict[str, object]:
    """Return the env-only LLM provider snapshot.

    Shape::

        {
            "provider": "local-ollama",
            "model": "llama3.1:8b",
            "base_url": "http://ollama:11434/v1",
            "host": "ollama",
            "key_set": false,
            "airgap_enabled": true,
            "airgap_compliant": true,
            "is_local": true,
            "effective_path": "live",
            "policy_note": "...",
            "source": "environment",
        }

    Notes:
        * ``base_url`` is returned verbatim (no path-stripping) because
          operators sometimes encode the model behind the path on
          single-tenant LiteLLM gateways and stripping it confuses
          troubleshooting.
        * ``key_set`` is the *only* signal we expose for the API key.
          We never return the key itself, even partially redacted.
        * For tenant-resolved snapshots that layer
          ``tenant_llm_credentials`` overrides on top of the env
          baseline, see :func:`tenant_llm_status`.
    """
    base_url, model, key_set = _env_baseline()
    return _compute_status(
        base_url=base_url,
        model=model,
        key_set=key_set,
        source="environment",
    )


async def tenant_llm_status(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict[str, object]:
    """Return the LLM snapshot with per-tenant BYOK overrides applied.

    Layers values from ``tenant_llm_credentials`` on top of the env
    baseline. Resolution rules per field:

    * ``base_url``  → tenant value if set, else env baseline.
    * ``model``     → tenant value if set, else env baseline.
    * ``key_set``   → ``True`` when the tenant row carries a vault token
      *or* the env baseline has one. The vault token is decrypted only
      to validate it, never returned.

    The returned ``source`` field reports the layering result:

    * ``"environment"`` — no tenant row (or row disabled) and at least
      one env-level value resolved.
    * ``"tenant"``      — every populated field came from the tenant row.
    * ``"mixed"``       — the tenant row contributed at least one value
      but at least one other value still came from the env baseline.

    A disabled tenant row (``enabled = false``) is treated as if it did
    not exist, matching the behaviour of the agents service.
    """
    env_base_url, env_model, env_key_set = _env_baseline()

    row = await db.execute(select(TenantLlmCredential).where(TenantLlmCredential.tenant_id == tenant_id))
    cred = row.scalar_one_or_none()

    if cred is None or not cred.enabled:
        return _compute_status(
            base_url=env_base_url,
            model=env_model,
            key_set=env_key_set,
            source="environment",
        )

    # Layer tenant overrides on top of env baseline. Track which fields
    # the tenant actually contributed so the ``source`` field can
    # reflect the merge honestly (full tenant vs partial overlay).
    tenant_contributed = False
    env_contributed = False

    if cred.base_url:
        base_url = cred.base_url
        tenant_contributed = True
    else:
        base_url = env_base_url
        if env_base_url:
            env_contributed = True

    if cred.model:
        model = cred.model
        tenant_contributed = True
    else:
        model = env_model
        if env_model:
            env_contributed = True

    tenant_key_set = False
    if cred.api_key_vault:
        # Validate the vault token decrypts cleanly so we don't claim
        # ``key_set=True`` for a row whose ciphertext is corrupt or
        # written under a key we no longer hold. Plaintext is dropped
        # immediately — never returned, never logged.
        try:
            get_vault().decrypt(cred.api_key_vault)
            tenant_key_set = True
            tenant_contributed = True
        except CredentialVaultError:
            tenant_key_set = False

    if tenant_key_set:
        key_set = True
    else:
        key_set = env_key_set
        if env_key_set:
            env_contributed = True

    if tenant_contributed and env_contributed:
        source = "mixed"
    elif tenant_contributed:
        source = "tenant"
    else:
        source = "environment"

    return _compute_status(
        base_url=base_url,
        model=model,
        key_set=key_set,
        source=source,
    )


@router.get("/status", summary="Current LLM provider configuration")
async def get_llm_status() -> dict[str, object]:
    """Return the env-only LLM provider snapshot for this pod.

    Intentionally **unauthenticated** and **env-only**, mirroring
    ``GET /api/v1/airgap/status``: the response carries no secrets
    (only ``key_set: bool``) and is safe for operator dashboards,
    auditors, and k8s liveness probes.

    Tenant-aware callers (the web UI's "Deployment & AI" Settings
    panel, the agents service's explain path) layer per-tenant BYOK
    overrides on top of this baseline by either:

    * calling :func:`tenant_llm_status` with their own DB session, or
    * pairing this response with ``GET /api/v1/llm/credentials`` to
      perform the merge client-side.
    """
    return llm_status()
