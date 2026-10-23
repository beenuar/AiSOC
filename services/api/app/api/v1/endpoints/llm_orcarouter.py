"""OrcaRouter Cyber Inference — connect flow and model discovery.

Two authentication entries, one credential shape
------------------------------------------------
``orcarouter`` is the paste-an-existing-key entry and ``orcarouter-oauth`` is
"Connect with OrcaRouter" (OAuth 2.0 + PKCE). Both end in the same place: a
normal OrcaRouter API key, vault-encrypted into ``tenant_llm_credentials`` and
used by every downstream path through the existing resolver. Neither is a
replacement for the other — a user without a browser keeps the key path, and a
user without a key can sign in.

Why Flow B (out-of-band) rather than a loopback redirect
-------------------------------------------------------
AiSOC is self-hosted and its install address differs on every deployment (a
LAN box, a NAS, a port somebody moved), and the API service runs in a
container where a callback to the operator's browser loopback cannot arrive.
The out-of-band flow exists for exactly that shape: the consent screen shows a
code, the operator pastes it here, and no redirect URI has to be predictable or
pre-registered.

The verifier is generated server-side, stored only in
``orcarouter_connect_states``, and deleted before the code is exchanged. The
browser holds the ``state`` and the code, never the verifier. A replayed state
therefore cannot redeem a second key, and a stolen code is useless without the
verifier.

Model discovery
---------------
``POST /models`` asks the inference origin for ``?capability=chat`` with the
tenant's key, on the server, and returns only the metadata a selector needs.
The key never reaches the browser; the browser only ever learns that one is
stored (``has_api_key``). When discovery fails, the verified seed is returned
with ``degraded=true`` and a reason — never merged into a live answer.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.llm_credentials import LlmCredentialView, _project
from app.models.llm_credential import TenantLlmCredential
from app.models.orcarouter_connect import OrcaRouterConnectState
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import orcarouter
from app.services.audit import emit_audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm/orcarouter", tags=["llm"])

#: The provider's own window. An attempt that outlives the code it waits for
#: is only a replay surface.
CONNECT_STATE_TTL = timedelta(minutes=10)

#: A label the consent screen shows. Spelled for a human, not a hostname.
CONNECT_APP_NAME = "AiSOC"


class ConnectStartResponse(BaseModel):
    authorize_url: str
    state: str
    expires_at: datetime
    expires_in_seconds: int
    provider: str
    flow: Literal["pkce-oob"]


class ConnectFinishRequest(BaseModel):
    state: str = Field(min_length=16, max_length=256)
    #: The code shown on the consent screen. Bounded so a paste cannot become
    #: an unbounded request body.
    code: str = Field(min_length=4, max_length=1024)


class ModelDiscoveryRequest(BaseModel):
    """Ask for the tenant's catalog.

    ``api_key`` lets the settings panel show a real dropdown before the key is
    saved. It is optional: when omitted the stored (vault-encrypted) key is
    used, which is the normal path. A key supplied here is used for one
    request, never stored, and never echoed.
    """

    api_key: str | None = Field(default=None, max_length=4096)
    capability: Literal["chat"] = "chat"


class ModelCatalogView(BaseModel):
    object: Literal["list"] = "list"
    data: list[dict[str, Any]]
    source: Literal["live", "fallback"]
    degraded: bool
    detail: str = ""
    #: Provider-published routing ids offered above the discovery result —
    #: the default, the cyber models and the general fallback. Deliberately a
    #: separate field: these are recommendations, not entries the catalog
    #: answered with, and a caller that merges them into a "live" claim would
    #: be lying about what was verified.
    recommended: list[dict[str, Any]] = []
    default_model: str = orcarouter.DEFAULT_MODEL


# --------------------------------------------------------------- helpers


async def _stored_credential_row(db, tenant_id: uuid.UUID) -> TenantLlmCredential | None:
    res = await db.execute(select(TenantLlmCredential).where(TenantLlmCredential.tenant_id == tenant_id))
    return res.scalar_one_or_none()


def _decrypt_stored_key(row: TenantLlmCredential | None) -> str | None:
    if row is None or row.provider not in orcarouter.ORCAROUTER_PROVIDERS or not row.api_key_vault:
        return None
    try:
        return get_vault().decrypt(row.api_key_vault)
    except CredentialVaultError:
        return None


def _http_error(exc: orcarouter.OrcaRouterError) -> HTTPException:
    """Map a safe OrcaRouter failure onto a status code and the same sentence."""
    mapped = {
        "config": status.HTTP_400_BAD_REQUEST,
        "protocol": status.HTTP_400_BAD_REQUEST,
        "state": status.HTTP_400_BAD_REQUEST,
        "denied": status.HTTP_403_FORBIDDEN,
        "scope": status.HTTP_403_FORBIDDEN,
        "auth": status.HTTP_401_UNAUTHORIZED,
        "rate_limit": status.HTTP_429_TOO_MANY_REQUESTS,
        "timeout": status.HTTP_504_GATEWAY_TIMEOUT,
        "network": status.HTTP_502_BAD_GATEWAY,
    }
    return HTTPException(status_code=mapped.get(exc.code, status.HTTP_400_BAD_REQUEST), detail=exc.message)


async def _persist_key(
    db,
    *,
    tenant_id: uuid.UUID,
    key: str,
    base_url: str,
    method: str,
) -> TenantLlmCredential:
    """Store a connect-flow key in the tenant's existing credential row.

    Same vault and same table as the paste path — no second secret store. The
    generation is rotated with the key so a late 401 from the previous
    credential can never mark the new one as broken.
    """
    ciphertext = get_vault().encrypt(key)
    now = datetime.now(UTC)
    generation = uuid.uuid4().hex
    settings = {
        "credential_generation": generation,
        "connect_flow": method,
        "needs_reauth": False,
    }

    row = await _stored_credential_row(db, tenant_id)
    if row is None:
        row = TenantLlmCredential(
            tenant_id=tenant_id,
            provider=orcarouter.OAUTH_PROVIDER,
            base_url=base_url,
            model=orcarouter.DEFAULT_MODEL,
            api_key_vault=ciphertext,
            settings=settings,
            enabled=True,
            created_at=now,
            updated_at=now,
            last_rotated_at=now,
        )
        db.add(row)
    else:
        # A model id belongs to the provider that advertised it: a tenant that
        # connected while configured for OpenAI must not end up asking
        # OrcaRouter for "gpt-4o". An existing OrcaRouter model choice stands.
        previous_provider = row.provider
        keep_model = previous_provider in orcarouter.ORCAROUTER_PROVIDERS and row.model
        row.provider = orcarouter.OAUTH_PROVIDER
        row.base_url = base_url
        row.model = row.model if keep_model else orcarouter.DEFAULT_MODEL
        row.api_key_vault = ciphertext
        row.settings = settings
        # `enabled` is left as it was: connecting is not saving, and a tenant
        # that had disabled its override should not have it switched on by a
        # side effect of the consent screen. The form's toggle owns that.
        row.updated_at = now
        row.last_rotated_at = now
    await db.commit()
    await db.refresh(row)
    return row


# --------------------------------------------------------------- connect


@router.post(
    "/connect/start",
    response_model=ConnectStartResponse,
    summary="Begin an OrcaRouter sign-in (OAuth 2.0 + PKCE, out-of-band)",
)
async def start_orcarouter_connect(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> ConnectStartResponse:
    """Mint a fresh verifier/state pair and return the consent URL.

    The verifier stays in this process's database row. The response carries
    the state (which is public by design — it is a CSRF token echoed through
    the browser) and never the verifier.
    """
    try:
        attempt = orcarouter.new_pkce_attempt()
        authorize_url = orcarouter.build_authorize_url(attempt.challenge, attempt.state, app_name=CONNECT_APP_NAME)
    except orcarouter.OrcaRouterError as exc:
        raise _http_error(exc) from exc

    now = datetime.now(UTC)
    expires_at = now + CONNECT_STATE_TTL
    db.add(
        OrcaRouterConnectState(
            state=attempt.state,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            code_verifier=attempt.verifier,
            created_at=now,
            expires_at=expires_at,
        )
    )
    await db.commit()

    logger.info("llm.orcarouter.connect.start tenant=%s", str(current_user.tenant_id))
    return ConnectStartResponse(
        authorize_url=authorize_url,
        state=attempt.state,
        expires_at=expires_at,
        expires_in_seconds=int(CONNECT_STATE_TTL.total_seconds()),
        provider=orcarouter.OAUTH_PROVIDER,
        flow="pkce-oob",
    )


@router.post(
    "/connect/finish",
    response_model=LlmCredentialView,
    summary="Redeem the code shown on the consent screen",
)
async def finish_orcarouter_connect(
    payload: ConnectFinishRequest,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> LlmCredentialView:
    """Exchange the out-of-band code for a key and store it.

    State is compared in constant time, the attempt is deleted before the code
    is exchanged (single-use, so a replay cannot redeem a second key), and the
    exchange goes to the auth origin only.
    """
    res = await db.execute(
        select(OrcaRouterConnectState).where(
            OrcaRouterConnectState.state == payload.state,
            OrcaRouterConnectState.tenant_id == current_user.tenant_id,
        )
    )
    pending: OrcaRouterConnectState | None = res.scalar_one_or_none()
    if pending is None or not orcarouter.states_match(pending.state, payload.state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This authorization attempt is unknown or already used. Start the connection again.",
        )

    expires_at = pending.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        await db.execute(delete(OrcaRouterConnectState).where(OrcaRouterConnectState.state == pending.state))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This authorization attempt expired. Start the connection again.",
        )

    verifier = pending.code_verifier
    await db.execute(delete(OrcaRouterConnectState).where(OrcaRouterConnectState.state == pending.state))
    await db.commit()

    try:
        exchanged = await orcarouter.exchange_code(payload.code.strip(), verifier)
    except orcarouter.OrcaRouterError as exc:
        logger.info("llm.orcarouter.connect.failed tenant=%s code=%s", str(current_user.tenant_id), exc.code)
        raise _http_error(exc) from exc

    row = await _persist_key(
        db,
        tenant_id=current_user.tenant_id,
        key=exchanged.key,
        base_url=orcarouter.api_base(),
        method="pkce-oob",
    )

    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="settings.llm.orcarouter_connect",
            resource="llm_credential",
            resource_id=str(current_user.tenant_id),
            changes={"provider": orcarouter.OAUTH_PROVIDER, "flow": "pkce-oob", "rotated": True},
            request=request,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — audit must not fail the call
        logger.error("settings.llm.audit.failed tenant=%s error=%s", str(current_user.tenant_id), type(exc).__name__)

    logger.info("llm.orcarouter.connect.success tenant=%s", str(current_user.tenant_id))
    return _project(row)


# --------------------------------------------------------------- models


@router.post(
    "/models",
    response_model=ModelCatalogView,
    summary="Model catalog for the OrcaRouter provider",
)
async def list_orcarouter_models(
    payload: ModelDiscoveryRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> ModelCatalogView:
    """Return the chat catalog from the inference origin.

    Runs server-side with the tenant's key. An unsaved key may be supplied for
    pre-save discovery; it is used once and discarded.
    """
    supplied = (payload.api_key or "").strip()
    if supplied:
        if not supplied.startswith("sk-orca-"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="An OrcaRouter API key starts with 'sk-orca-'. Check the value you pasted.",
            )
        key = supplied
    else:
        key = _decrypt_stored_key(await _stored_credential_row(db, current_user.tenant_id))
        if not key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No OrcaRouter API key is stored yet. Paste one or connect your account, then refresh the model list.",
            )

    try:
        catalog = await orcarouter.fetch_catalog(key, capability=payload.capability)
    except orcarouter.OrcaRouterError as exc:
        raise _http_error(exc) from exc

    return ModelCatalogView(
        data=[m.as_dict() for m in catalog.models],
        source=catalog.source,
        degraded=catalog.degraded,
        detail=catalog.detail,
        recommended=orcarouter.recommended_models(),
    )


__all__ = ["router"]
