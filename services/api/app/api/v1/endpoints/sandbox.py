"""File and URL analysis: hash lookup, submission, polling, and the upload consent.

Every route authenticates and takes its tenant from the credential. The
provider is named in the request because a deployment may have several; the
tenant never is, because a request that could name a tenant is a request that
could name somebody else's.

Permissions follow what the action discloses rather than what it reads:

* a hash lookup and a poll need ``threat_intel:read``, which analysts hold
* enabling uploads needs ``settings:write``, which only a tenant administrator
  holds, because it is a standing agreement to disclose customer files
* submitting needs ``threat_intel:write``, and is refused anyway unless the
  standing agreement exists
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession
from app.services.sandbox import (
    CONSENT_TEXT_VERSION,
    SandboxResult,
    analyse_file,
    analyse_url,
    build_registry,
    consent_text_for,
    lookup_hash,
    poll,
)
from app.services.sandbox.store import list_consent, read_consent, record_decision, set_consent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
#: Matches the ingest path's own attachment ceiling. A sandbox is not a file
#: store, and an unbounded base64 body is a denial-of-service surface before it
#: is anything else.
_MAX_UPLOAD_BYTES = 32 * 1024 * 1024


# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────


class ProviderInfo(BaseModel):
    name: str
    local: bool
    usable: bool
    supports_file_submission: bool
    supports_url_submission: bool
    submissions_are_public_by_default: bool
    description: str
    uploads_enabled_for_tenant: bool
    consent_text: str
    consent_text_version: str
    #: False for every hosted provider whose authentication this repository has
    #: not confirmed against a real key. Rendered as a caveat, never as a tick.
    authentication_verified: bool
    unusable_reason: str | None = None


class ProvidersResponse(BaseModel):
    airgapped: bool
    providers: list[ProviderInfo]


class LookupRequest(BaseModel):
    sha256: str = Field(..., description="The file's SHA-256 digest. Nothing but the digest is sent.")
    provider: str | None = None


class SubmitFileRequest(BaseModel):
    file_base64: str = Field(..., description="The file contents, base64-encoded.")
    file_name: str = Field(..., max_length=512)
    provider: str | None = None
    #: The caller's acknowledgement that this specific upload is intended.
    #: Tenant consent is the standing agreement; this is the per-action one,
    #: and both are required so a standing agreement cannot turn every future
    #: call into a silent upload.
    confirm_upload: bool = False


class SubmitUrlRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    provider: str | None = None


class SandboxResultResponse(BaseModel):
    outcome: Literal["known", "pending", "not_seen", "upload_refused", "could_not_check"]
    provider: str
    detail: str
    sha256: str | None = None
    uploaded: bool = False
    report: dict[str, Any] | None = None
    handle: str | None = None
    poll_after_seconds: int | None = None
    decision: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)


class ConsentRequest(BaseModel):
    provider: str
    uploads_enabled: bool
    #: Must be the version the caller was shown. A stale console tab agreeing
    #: to superseded wording is refused rather than recorded as agreement to
    #: the current text.
    consent_text_version: str | None = None


class ConsentResponse(BaseModel):
    provider: str
    uploads_enabled: bool
    consent_text_version: str | None = None
    consent_text: str


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _to_response(result: SandboxResult) -> SandboxResultResponse:
    return SandboxResultResponse(**result.as_dict())


def _resolve(provider_name: str | None) -> tuple[Any, Any]:
    """Return ``(registry, provider)``, raising 4xx when the provider is unusable.

    Air-gap mode produces a 403 rather than a 404: the provider exists and is
    configured, and telling an operator it is missing would send them to add
    configuration that is already there.
    """
    registry = build_registry()
    provider = registry.get(provider_name) if provider_name else registry.default()
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No analysis provider named {provider_name!r}."
                if provider_name
                else "No analysis provider is configured for this deployment."
            ),
        )
    if not registry.is_usable(provider):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Air-gapped mode is on and {provider.name} runs outside this deployment. Only local analysis providers are permitted."
            ),
        )
    return registry, provider


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("/providers", response_model=ProvidersResponse, summary="Analysis providers and this tenant's upload consent")
async def providers(db: DBSession, user: AuthUser) -> ProvidersResponse:
    user.require_permission("threat_intel:read")
    registry = build_registry()
    consent = {c.provider: c.uploads_enabled for c in await list_consent(db, tenant_id=user.tenant_id)}
    out: list[ProviderInfo] = []
    for name in registry.names():
        provider = registry.get(name)
        if provider is None:  # pragma: no cover - names() is derived from the same map
            continue
        caps = provider.capabilities
        usable = registry.is_usable(provider)
        out.append(
            ProviderInfo(
                name=caps.name,
                local=caps.local,
                usable=usable,
                supports_file_submission=caps.supports_file_submission,
                supports_url_submission=caps.supports_url_submission,
                submissions_are_public_by_default=caps.submissions_are_public_by_default,
                description=caps.description,
                uploads_enabled_for_tenant=consent.get(caps.name, False),
                consent_text=consent_text_for(caps),
                consent_text_version=CONSENT_TEXT_VERSION,
                authentication_verified=bool(getattr(provider, "authentication_is_verified", True)),
                unusable_reason=(None if usable else "Air-gapped mode permits local providers only."),
            )
        )
    return ProvidersResponse(airgapped=registry.airgapped, providers=out)


@router.post("/lookup", response_model=SandboxResultResponse, summary="Look a file hash up (nothing is uploaded)")
async def lookup(body: LookupRequest, db: DBSession, user: AuthUser) -> SandboxResultResponse:
    user.require_permission("threat_intel:read")
    if not _SHA256.match(body.sha256.strip()):
        raise HTTPException(status_code=422, detail="sha256 must be a 64-character hexadecimal digest.")
    _, provider = _resolve(body.provider)
    result = await lookup_hash(provider, body.sha256.strip().lower())
    await record_decision(db, tenant_id=user.tenant_id, result=result, artifact_kind="hash", actor_id=user.user_id)
    return _to_response(result)


@router.post("/files", response_model=SandboxResultResponse, summary="Analyse a file, uploading only if policy allows")
async def submit_file(body: SubmitFileRequest, db: DBSession, user: AuthUser) -> SandboxResultResponse:
    user.require_permission("threat_intel:write")
    try:
        content = base64.b64decode(body.file_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="file_base64 is not valid base64.") from exc
    if not content:
        raise HTTPException(status_code=422, detail="file_base64 decoded to zero bytes.")
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB analysis limit.")

    registry, provider = _resolve(body.provider)
    result = await analyse_file(
        provider,
        content=content,
        file_name=body.file_name,
        registry=registry,
        tenant_uploads_enabled=await read_consent(db, tenant_id=user.tenant_id, provider=provider.name),
        # The hash lookup always runs; only the upload half is gated on the
        # caller confirming this specific transfer.
        allow_upload=body.confirm_upload,
    )
    await record_decision(
        db,
        tenant_id=user.tenant_id,
        result=result,
        artifact_kind="file",
        file_name=body.file_name,
        actor_id=user.user_id,
    )
    return _to_response(result)


@router.post("/urls", response_model=SandboxResultResponse, summary="Submit a URL for analysis")
async def submit_url(body: SubmitUrlRequest, db: DBSession, user: AuthUser) -> SandboxResultResponse:
    user.require_permission("threat_intel:write")
    registry, provider = _resolve(body.provider)
    result = await analyse_url(provider, body.url.strip(), registry=registry)
    await record_decision(db, tenant_id=user.tenant_id, result=result, artifact_kind="url", actor_id=user.user_id)
    return _to_response(result)


@router.get("/analyses/{provider_name}/{handle}", response_model=SandboxResultResponse, summary="Poll an analysis")
async def get_analysis(provider_name: str, handle: str, user: AuthUser) -> SandboxResultResponse:
    user.require_permission("threat_intel:read")
    _, provider = _resolve(provider_name)
    return _to_response(await poll(provider, handle))


@router.put("/consent", response_model=ConsentResponse, summary="Allow or refuse file uploads to a provider")
async def put_consent(body: ConsentRequest, db: DBSession, user: AuthUser) -> ConsentResponse:
    # settings:write, not threat_intel:write. This is a standing agreement to
    # disclose customer files, which is an administrator's decision rather than
    # an analyst's.
    user.require_permission("settings:write")
    _, provider = _resolve(body.provider)
    if body.uploads_enabled and body.consent_text_version not in (None, CONSENT_TEXT_VERSION):
        raise HTTPException(
            status_code=409,
            detail=(
                f"The disclosure text has changed since this page was loaded (shown {body.consent_text_version}, "
                f"current {CONSENT_TEXT_VERSION}). Reload and read the current text before enabling uploads."
            ),
        )
    record = await set_consent(
        db,
        tenant_id=user.tenant_id,
        provider=provider.name,
        enabled=body.uploads_enabled,
        actor_id=user.user_id,
    )
    return ConsentResponse(
        provider=record.provider,
        uploads_enabled=record.uploads_enabled,
        consent_text_version=record.consent_text_version,
        consent_text=consent_text_for(provider.capabilities),
    )
