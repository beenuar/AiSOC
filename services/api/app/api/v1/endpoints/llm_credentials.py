"""Per-tenant BYOK LLM credentials — WS-H2 (buyer-value plan).

Endpoint contract
-----------------

* ``GET    /api/v1/llm/credentials``
    Read-only projection of the tenant's stored credential. Never returns
    the API key; only ``has_api_key: bool`` so the UI can render a
    "credential present, last rotated N days ago" badge.

* ``PUT    /api/v1/llm/credentials``
    Upsert (provider + base_url + model + api_key + settings + enabled).
    The plaintext key is encrypted via :class:`CredentialVault` and only
    the ``vault:v1:<base64>`` ciphertext touches the database. Pass
    ``api_key=null`` to keep the existing ciphertext (rotation-only PUT
    that updates provider/base_url/model without re-typing the key).

* ``DELETE /api/v1/llm/credentials``
    Hard-delete the row. The platform falls back to env-var configuration
    on the next request (the existing v1 behaviour).

Why this lives in services/api
------------------------------

The agents service handles the actual LLM call but doesn't own
Postgres write paths — the explain endpoint reads the resolved
credential at request time via a vendored read-path vault (same
pattern as ``services/connectors/app/security/credential_vault.py``).
Keeping the write path here means we have one place that holds the
encrypt key authority, matches connector + OAuth credential management,
and audit rows for credential changes land in the same ``audit_log``
table as the rest of the platform.

Security rules
--------------

* ``settings:read`` to view, ``settings:write`` to mutate. Tenant admin
  only by default (see ``app.core.security.ROLE_PERMISSIONS``).
* The plaintext API key is never logged (we only log fact-of-rotation +
  provider + actor) and never round-tripped to the UI.
* Every PUT/DELETE emits an immutable ``audit_log`` row via
  :func:`emit_audit` so a buyer's compliance team has a paper trail of
  who put which provider where, and when keys rotated.
* The provider whitelist mirrors the DB ``CHECK`` constraint and
  :mod:`app.api.v1.endpoints.llm_status`. Adding a provider is a
  three-way change (migration + Pydantic enum + classifier).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.llm_credential import TenantLlmCredential
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import orcarouter
from app.services.audit import emit_audit
from app.services.llm_credential_probe import ProbeResult, probe_credential

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm/credentials", tags=["llm"])


# --------------------------------------------------------------- constants

# Mirror of the ``CHECK`` constraint in
# ``services/api/migrations/038_tenant_llm_credentials.sql`` and the
# classifier in :mod:`app.api.v1.endpoints.llm_status`. Keep in sync.
LlmProvider = Literal[
    "openai",
    "anthropic",
    "azure-openai",
    "local-ollama",
    "local-vllm",
    "local-litellm",
    "custom",
    # OrcaRouter Cyber Inference — two credential paths, one provider. The
    # paste-a-key entry and the OAuth 2.0 + PKCE connect entry share an
    # inference adapter, a base URL and a catalog; keeping the ids apart lets
    # the settings panel say which path minted the stored key.
    "orcarouter",
    "orcarouter-oauth",
]

# Providers that *require* a non-NULL ``base_url``. Hosted SaaS providers
# default to a canonical endpoint and reject base-URL spoofing; local +
# custom providers must tell us where to point.
_PROVIDERS_REQUIRING_BASE_URL: frozenset[str] = frozenset({"local-ollama", "local-vllm", "local-litellm", "custom"})

# Providers that require a non-NULL API key. Local providers without
# auth (Ollama default install, vLLM behind an internal LB) legitimately
# have no key. ``custom`` is permissive — operators run all sorts of
# proxies behind it (LiteLLM with org auth, internal API gateways, etc.).
_PROVIDERS_REQUIRING_KEY: frozenset[str] = frozenset({"openai", "anthropic", "azure-openai", "orcarouter", "orcarouter-oauth"})


# --------------------------------------------------------------- request / response models


class LlmCredentialUpsert(BaseModel):
    """Payload for ``PUT /api/v1/llm/credentials``.

    ``api_key`` is intentionally optional. Sending ``null`` (or omitting
    it) on an *existing* row keeps the stored ciphertext untouched — that
    lets operators flip ``enabled``, swap ``model``, or change the
    ``base_url`` without re-typing a 100-character secret. On a *new*
    row, ``api_key`` is required when the chosen provider mandates one
    (we surface a 422 in that case rather than silently storing NULL).
    """

    provider: LlmProvider
    base_url: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, max_length=120)
    api_key: str | None = Field(default=None, max_length=4096)
    settings: dict | None = Field(default=None)
    enabled: bool = Field(default=True)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        # Light shape check — we don't want to over-validate (operators
        # legitimately run weird proxies on weird ports inside private
        # networks) but we should reject obvious garbage so the UI gets
        # a useful 422 instead of a 500 at request time.
        parsed = urlparse(v)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("base_url must be an http(s) URL")
        if not parsed.hostname:
            raise ValueError("base_url must include a hostname")
        return v

    @field_validator("api_key")
    @classmethod
    def _validate_api_key(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        return v or None


class LlmCredentialView(BaseModel):
    """Read-only projection of :class:`TenantLlmCredential`.

    The plaintext key is intentionally absent. ``has_api_key`` is the
    only signal we expose — same convention the OAuth credential view
    uses (``has_secret``).
    """

    provider: LlmProvider
    base_url: str | None
    model: str | None
    has_api_key: bool
    settings: dict
    enabled: bool
    created_at: datetime
    updated_at: datetime
    last_rotated_at: datetime | None
    #: True when the provider rejected this exact credential generation. The
    #: key is durable, not refreshable, so the remedy is re-authentication —
    #: the UI says so rather than retrying a revoked key.
    needs_reauth: bool = False


# --------------------------------------------------------------- helpers


def _project(row: TenantLlmCredential) -> LlmCredentialView:
    """Build the read-only view from an ORM row."""
    return LlmCredentialView(
        provider=row.provider,  # type: ignore[arg-type]
        base_url=row.base_url,
        model=row.model,
        has_api_key=bool(row.api_key_vault),
        settings=dict(row.settings or {}),
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_rotated_at=row.last_rotated_at,
        needs_reauth=bool((row.settings or {}).get("needs_reauth")),
    )


def _enforce_provider_invariants(
    payload: LlmCredentialUpsert,
    *,
    existing: TenantLlmCredential | None,
) -> None:
    """Raise 422 if the payload is internally inconsistent.

    Cross-field rules can't be expressed in a single ``field_validator``
    so they live here. Mirrors the contract documented at the top of the
    module: hosted SaaS providers need a key, local + custom providers
    need a base_url. On rotation-only PUTs we check the *resolved* state
    (``payload`` ⊕ ``existing``), so a PUT with ``api_key=null`` on an
    existing row passes as long as the row already has a key.
    """
    if payload.provider in _PROVIDERS_REQUIRING_BASE_URL and not payload.base_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"provider '{payload.provider}' requires base_url",
        )

    requires_key = payload.provider in _PROVIDERS_REQUIRING_KEY
    if requires_key:
        # Either the payload supplies a fresh key, or the existing row
        # already has one we're keeping. Otherwise refuse.
        has_existing_key = bool(existing and existing.api_key_vault)
        if not payload.api_key and not has_existing_key:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"provider '{payload.provider}' requires api_key",
            )

    # A light shape check, and only that: the prefix catches a pasted secret
    # from the wrong provider or a truncated paste, and it is not evidence
    # that the key is valid. Validity is established by the first real call.
    if payload.provider in orcarouter.ORCAROUTER_PROVIDERS and payload.api_key and not payload.api_key.startswith("sk-orca-"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="An OrcaRouter API key starts with 'sk-orca-'. Check the value you pasted.",
        )


def _orcarouter_defaults(provider: str, base_url: str | None, model: str | None) -> tuple[str | None, str | None]:
    """Fill the fixed endpoint and default model for the OrcaRouter providers.

    Both are stored so every downstream resolver — the explain path, the agents
    service, the probe — reads one row and never has to know an OrcaRouter
    default exists. An operator override still wins.
    """
    if provider not in orcarouter.ORCAROUTER_PROVIDERS:
        return base_url, model
    if base_url:
        resolved_base = base_url
    else:
        try:
            resolved_base = orcarouter.api_base()
        except orcarouter.OrcaRouterError as exc:
            # A malformed self-hosted override is a configuration error; store
            # nothing and say so rather than silently writing the public URL.
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.message) from exc
    return resolved_base, (model or orcarouter.DEFAULT_MODEL)


async def _mark_needs_reauth(db, *, tenant_id, generation: str | None) -> bool:
    """Mark the exact credential generation the provider rejected.

    Returns whether the row was marked. A credential written after this
    request began carries a different generation, and its failure belongs to a
    credential that no longer exists — updating it would send the operator to
    re-authorize a key that works.
    """
    if not generation:
        return False
    res = await db.execute(select(TenantLlmCredential).where(TenantLlmCredential.tenant_id == tenant_id))
    row = res.scalar_one_or_none()
    if row is None:
        return False
    if (row.settings or {}).get("credential_generation") != generation:
        return False
    settings = dict(row.settings or {})
    settings["needs_reauth"] = True
    settings["needs_reauth_generation"] = generation
    row.settings = settings
    await db.commit()
    return True


async def _clear_needs_reauth(db, *, tenant_id, generation: str | None) -> bool:
    """Drop a stale re-authentication flag after a call that worked.

    Same generation guard as :func:`_mark_needs_reauth`: a success for an
    older credential says nothing about the key that replaced it.
    """
    if not generation:
        return False
    res = await db.execute(select(TenantLlmCredential).where(TenantLlmCredential.tenant_id == tenant_id))
    row = res.scalar_one_or_none()
    if row is None:
        return False
    if (row.settings or {}).get("credential_generation") != generation:
        return False
    settings = dict(row.settings or {})
    if not settings.get("needs_reauth"):
        return False
    settings["needs_reauth"] = False
    settings.pop("needs_reauth_generation", None)
    row.settings = settings
    await db.commit()
    return True


# --------------------------------------------------------------- endpoints


@router.get(
    "",
    response_model=LlmCredentialView | None,
    summary="Read the tenant's BYOK LLM credential",
)
async def get_llm_credential(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> LlmCredentialView | None:
    """Return the per-tenant LLM credential, or ``null`` if none stored.

    Returning ``null`` (rather than 404) on the empty case lets the UI
    render a single "Configure your LLM" CTA without dispatching on
    error codes. The Settings panel renders a "no credential set —
    falling back to platform defaults" hint when this is null.
    """
    res = await db.execute(
        select(TenantLlmCredential).where(
            TenantLlmCredential.tenant_id == current_user.tenant_id,
        )
    )
    row = res.scalar_one_or_none()
    if row is None:
        return None
    return _project(row)


@router.put(
    "",
    response_model=LlmCredentialView,
    summary="Upsert the tenant's BYOK LLM credential",
)
async def upsert_llm_credential(
    payload: LlmCredentialUpsert,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> LlmCredentialView:
    """Create or update the tenant's BYOK credential.

    Behaviour notes:

    * ``api_key`` is required for hosted SaaS providers on first write.
      A subsequent PUT with ``api_key=null`` keeps the stored
      ciphertext (useful when toggling ``enabled`` or changing
      ``model`` without re-typing the secret).
    * Whenever ``api_key`` is provided we bump ``last_rotated_at`` so
      the UI can render "rotated 3 days ago".
    * The audit row's ``changes`` payload includes the *fact* of a
      rotation but never the key itself — we only record whether the
      key was changed, the previous + new providers, and whether the
      row is enabled.
    """
    res = await db.execute(
        select(TenantLlmCredential).where(
            TenantLlmCredential.tenant_id == current_user.tenant_id,
        )
    )
    existing: TenantLlmCredential | None = res.scalar_one_or_none()

    _enforce_provider_invariants(payload, existing=existing)

    # Encrypt the new key if one was supplied. We do this *before* the
    # upsert so a vault failure short-circuits without partial writes.
    new_ciphertext: str | None
    if payload.api_key is not None:
        try:
            new_ciphertext = get_vault().encrypt(payload.api_key)
        except CredentialVaultError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to encrypt LLM API key",
            ) from exc
    else:
        new_ciphertext = None  # marker: keep existing

    now = datetime.now(UTC)
    rotated = False
    previous_provider: str | None = None
    resolved_base, resolved_model = _orcarouter_defaults(payload.provider, payload.base_url, payload.model)

    # A new key rotates the credential generation. A late 401 from the
    # previous credential is then recognisable as stale and cannot mark the
    # replacement as broken.
    write_settings = payload.settings
    if payload.provider in orcarouter.ORCAROUTER_PROVIDERS and new_ciphertext is not None:
        carried = payload.settings if payload.settings is not None else ((existing.settings if existing else None) or {})
        write_settings = {**dict(carried), "credential_generation": uuid.uuid4().hex, "needs_reauth": False}
        write_settings.pop("needs_reauth_generation", None)

    if existing is None:
        row = TenantLlmCredential(
            tenant_id=current_user.tenant_id,
            provider=payload.provider,
            base_url=resolved_base,
            model=resolved_model,
            api_key_vault=new_ciphertext,
            settings=write_settings or {},
            enabled=payload.enabled,
            created_at=now,
            updated_at=now,
            last_rotated_at=now if new_ciphertext else None,
        )
        db.add(row)
        rotated = bool(new_ciphertext)
    else:
        previous_provider = existing.provider
        existing.provider = payload.provider
        existing.base_url = resolved_base
        existing.model = resolved_model
        if new_ciphertext is not None:
            existing.api_key_vault = new_ciphertext
            existing.last_rotated_at = now
            rotated = True
        if write_settings is not None:
            existing.settings = write_settings
        existing.enabled = payload.enabled
        existing.updated_at = now
        row = existing

    await db.commit()
    await db.refresh(row)

    # Audit row. We deliberately keep this tight — provider transitions,
    # rotation flag, enabled state. No URL / model leakage either, since
    # the next call to GET /llm/credentials returns those fields if the
    # auditor needs them.
    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="settings.llm.upsert",
            resource="llm_credential",
            resource_id=str(current_user.tenant_id),
            changes={
                "provider": payload.provider,
                "previous_provider": previous_provider,
                "rotated": rotated,
                "enabled": payload.enabled,
                "created": existing is None,
            },
            request=request,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
        )
    except Exception as exc:  # noqa: BLE001 — audit must not fail the call
        logger.error(
            "settings.llm.audit.failed tenant_id=%r error=%s",
            str(current_user.tenant_id),
            type(exc).__name__,
        )

    # ``payload.provider`` is a Pydantic ``LlmProvider`` Literal, so it can only
    # ever be one of a small fixed set of strings. Sanitize defensively at the
    # log boundary to satisfy CodeQL's ``py/log-injection`` rule, which flags
    # any user-supplied attribute reaching ``logger.*``.
    safe_provider = str(payload.provider).replace("\n", " ").replace("\r", " ")[:32]
    logger.info(
        "settings.llm.upsert",
        extra={
            "tenant": str(current_user.tenant_id),
            "provider": safe_provider,
            "rotated": rotated,
            "created": existing is None,
        },
    )
    return _project(row)


@router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Remove the tenant's BYOK LLM credential",
)
async def delete_llm_credential(
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> None:
    """Hard-delete the credential. Platform falls back to env-var config."""
    res = await db.execute(
        select(TenantLlmCredential).where(
            TenantLlmCredential.tenant_id == current_user.tenant_id,
        )
    )
    existing: TenantLlmCredential | None = res.scalar_one_or_none()

    await db.execute(
        delete(TenantLlmCredential).where(
            TenantLlmCredential.tenant_id == current_user.tenant_id,
        )
    )
    await db.commit()

    if existing is None:
        # Idempotent — DELETE on an empty row is a no-op, no audit needed.
        return

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="settings.llm.delete",
            resource="llm_credential",
            resource_id=str(current_user.tenant_id),
            changes={
                "provider": existing.provider,
            },
            request=request,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "settings.llm.audit.failed tenant_id=%s error=%s",
            current_user.tenant_id,
            exc,
        )

    logger.info(
        "settings.llm.delete",
        extra={
            "tenant": str(current_user.tenant_id),
            "provider": existing.provider,
        },
    )


# --------------------------------------------------------- test connection


class LlmCredentialTestResult(BaseModel):
    """What a real call to the configured provider did.

    Four outcomes, and `unverified` is one of them on purpose: an air-gapped
    deployment refuses the egress rather than attempting it, and reporting that
    as a failure would send an operator to debug a credential that is fine.
    """

    outcome: Literal["ok", "refused", "unreachable", "unverified"]
    detail: str
    provider: str
    model: str | None = None
    latency_ms: int | None = None


@router.post(
    # The router already carries `prefix="/llm/credentials"`, so this is the
    # bare suffix. It read "/credentials/test" and published
    # `/api/v1/llm/credentials/credentials/test` -- an endpoint reachable at
    # no URL anything calls. Thirteen tests passed throughout, because every
    # one of them called the probe function rather than the route.
    "/test",
    response_model=LlmCredentialTestResult,
    summary="Make one real call with this tenant's credential",
)
async def test_llm_credential(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> LlmCredentialTestResult:
    """Place one minimal completion and report what happened.

    There was no way to find out whether a saved key worked. The three routes
    above validate *shape* -- that the URL parses, that the provider/key/base
    combination is internally consistent -- and none of them talks to the
    provider, so an operator who pasted a revoked key learned about it when
    triage silently fell back to the deterministic path. That failure is quiet
    by design, which is exactly what makes it hard to attribute.

    `settings:write` rather than `settings:read`: this spends the tenant's
    money and touches an external service, which is not a read.
    """
    res = await db.execute(select(TenantLlmCredential).where(TenantLlmCredential.tenant_id == current_user.tenant_id))
    existing: TenantLlmCredential | None = res.scalar_one_or_none()

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No credential is configured for this tenant, so there is nothing to test. The platform is using its environment defaults."
            ),
        )

    api_key: str | None = None
    if existing.api_key_vault:
        try:
            api_key = get_vault().decrypt(existing.api_key_vault)
        except CredentialVaultError:
            # A key that cannot be decrypted is a real finding and not an
            # outage: it means the vault key rotated without this row being
            # re-encrypted, and triage is already falling back.
            return LlmCredentialTestResult(
                outcome="refused",
                detail=(
                    "The stored key could not be decrypted. It was encrypted with a vault key "
                    "this deployment no longer has; re-enter it to fix."
                ),
                provider=existing.provider,
            )

    result: ProbeResult = await probe_credential(
        provider=existing.provider,
        base_url=existing.base_url,
        model=existing.model,
        api_key=api_key,
    )

    # A durable key that the provider rejects is a reauthentication signal, not
    # a retry signal: there is no refresh grant to fall back to. Mark only the
    # generation that was rejected — a late failure must not make a credential
    # that was just replaced look broken.
    if existing.provider in orcarouter.ORCAROUTER_PROVIDERS and result.status_code in (401, 403):
        await _mark_needs_reauth(
            db,
            tenant_id=current_user.tenant_id,
            generation=(existing.settings or {}).get("credential_generation"),
        )
    elif existing.provider in orcarouter.ORCAROUTER_PROVIDERS and result.outcome == "ok":
        # Includes 429: reaching the quota means the credential authenticated.
        await _clear_needs_reauth(
            db,
            tenant_id=current_user.tenant_id,
            generation=(existing.settings or {}).get("credential_generation"),
        )

    return LlmCredentialTestResult(
        outcome=result.outcome,
        detail=result.detail,
        provider=existing.provider,
        model=result.model,
        latency_ms=result.latency_ms,
    )
