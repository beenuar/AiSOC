"""Mobile/PWA HITL approver API (Theme 2m).

The mobile surface is intentionally a thin, narrow API distinct from the
console HITL routes. Three concerns drive that split:

1. **Auth shape.** Mobile uses passkey assertions (WebAuthn-style)
   instead of TOTP/dev-shared-secret. Folding that into the existing
   ``HitlDecisionBody`` would muddy a contract that already works for
   the console.
2. **Voice readout.** On-call analysts need a TL;DR they can hear, not
   read. The readout endpoint runs *inside the tenant context* so the
   audit row records which principal saw which spoken script.
3. **Channel attribution.** All decisions here are recorded with
   ``HitlChannel.MOBILE``, which the gateway already understands. That
   keeps the audit trail honest — "decided from a phone over a
   passkey" is a distinct claim from "decided in the console".

The routes deliberately mirror the structure of ``hitl_routes`` so the
two surfaces stay legible side-by-side.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.api.hitl_routes import _enforce_tenant_for_decision, _req_to_dict
from app.db import engine
from app.hitl.gateway import gateway
from app.hitl.passkey import (
    PasskeyVerificationError,
    finalize_registration,
    issue_assertion_challenge,
    issue_registration_challenge,
    list_passkeys,
    revoke_passkey,
    verify_assertion,
)
from app.hitl.readout import render_voice_payload
from app.models.hitl import HitlChannel, HitlRequest
from app.security.tenant import TenantContext, ensure_row_visible, require_tenant

router = APIRouter(prefix="/mobile", tags=["mobile-hitl"])


# ── Passkey enrollment ───────────────────────────────────────────────────


class RegisterChallengeBody(BaseModel):
    user_name: str | None = Field(
        None, description="Friendly label shown by the platform authenticator"
    )


@router.post("/passkeys/register/challenge")
def passkey_register_challenge(
    body: RegisterChallengeBody | None = None,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Begin a passkey enrollment ceremony.

    The principal is the JWT subject we already authenticated; the client
    never gets to pick it. Returns the WebAuthn-shaped challenge the
    authenticator signs.
    """
    challenge = issue_registration_challenge(
        principal=ctx.subject,
        tenant_id=ctx.active_tenant_id,
        user_name=(body.user_name if body else None),
    )
    return {
        "challenge": challenge.challenge,
        "rp": {"id": challenge.rp_id, "name": challenge.rp_name},
        "user": {"id": challenge.user_id, "name": challenge.user_name},
        "pubKeyCredParams": challenge.pub_key_cred_params,
        "timeout": challenge.timeout_ms,
    }


class RegisterFinalizeBody(BaseModel):
    challenge: str
    credential_id: str
    public_key: str
    aaguid: str | None = None
    transports: str | None = None
    label: str | None = None


@router.post("/passkeys/register")
def passkey_register_finalize(
    body: RegisterFinalizeBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Finish passkey enrollment after the device signs the challenge."""
    try:
        registered = finalize_registration(
            tenant_id=ctx.active_tenant_id,
            principal=ctx.subject,
            challenge=body.challenge,
            credential_id=body.credential_id,
            public_key=body.public_key,
            aaguid=body.aaguid,
            transports=body.transports,
            label=body.label,
        )
    except PasskeyVerificationError as exc:
        raise HTTPException(status_code=400, detail=f"passkey rejected: {exc}") from exc
    return {
        "id": registered.id,
        "credential_id": registered.credential_id,
        "label": registered.label,
        "aaguid": registered.aaguid,
        "transports": registered.transports,
        "created_at": registered.created_at.isoformat(),
    }


@router.get("/passkeys")
def passkeys_list(
    ctx: TenantContext = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """List the caller's registered passkeys."""
    creds = list_passkeys(tenant_id=ctx.active_tenant_id, principal=ctx.subject)
    return [
        {
            "id": c.id,
            "credential_id": c.credential_id,
            "label": c.label,
            "aaguid": c.aaguid,
            "transports": c.transports,
            "created_at": c.created_at.isoformat(),
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in creds
    ]


@router.delete("/passkeys/{credential_id}")
def passkeys_revoke(
    credential_id: str,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Revoke a passkey. Future assertions against it will be rejected."""
    try:
        revoke_passkey(
            tenant_id=ctx.active_tenant_id,
            principal=ctx.subject,
            credential_id=credential_id,
        )
    except PasskeyVerificationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"revoked": credential_id}


# ── HITL readout + decision ──────────────────────────────────────────────


@router.get("/hitl/{request_id}/readout")
def hitl_readout(
    request_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Return a voice-readout payload for a pending HITL.

    Deliberately scoped to the caller's tenant — an MSSP analyst can only
    hear the readout for cases they're cleared to see.
    """
    with Session(engine) as s:
        req = s.get(HitlRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="HITL request not found")
    ensure_row_visible(ctx, req.tenant_id)
    return render_voice_payload(req)


@router.post("/hitl/{request_id}/assertion-challenge")
def hitl_assertion_challenge(
    request_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Issue a passkey assertion challenge for an analyst about to decide.

    The request_id is required in the path so the audit log can record
    "this challenge was issued *for this HITL*" — a stolen challenge
    can't be reused against a different case.
    """
    _enforce_tenant_for_decision(request_id, ctx)
    challenge = issue_assertion_challenge(
        principal=ctx.subject, tenant_id=ctx.active_tenant_id
    )
    return {
        "challenge": challenge.challenge,
        "rpId": challenge.rp_id,
        "allowCredentials": challenge.allow_credentials,
        "timeout": challenge.timeout_ms,
        "userVerification": challenge.user_verification,
        "request_id": request_id,
    }


class MobileDecisionBody(BaseModel):
    credential_id: str = Field(..., description="Passkey credential id used to sign")
    challenge: str = Field(..., description="Server-issued challenge being asserted")
    signature: str = Field(..., description="Authenticator's signature over the challenge")
    sign_counter: int = Field(..., description="Authenticator-reported signature counter")
    reason: str | None = Field(None, description="Optional analyst comment")


def _decide_mobile(
    *, request_id: int, approve: bool, body: MobileDecisionBody, ctx: TenantContext
) -> dict[str, Any]:
    _enforce_tenant_for_decision(request_id, ctx)
    try:
        receipt = verify_assertion(
            tenant_id=ctx.active_tenant_id,
            principal=ctx.subject,
            credential_id=body.credential_id,
            challenge=body.challenge,
            signature=body.signature,
            sign_counter=body.sign_counter,
        )
    except PasskeyVerificationError as exc:
        raise HTTPException(status_code=401, detail=f"passkey rejected: {exc}") from exc
    try:
        req = gateway.decide(
            request_id=request_id,
            approve=approve,
            decided_by=ctx.subject,
            mfa_method=receipt.method,
            mfa_receipt_hash=receipt.receipt_hash,
            channel=HitlChannel.MOBILE,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _req_to_dict(req)


@router.post("/hitl/{request_id}/approve")
def hitl_approve(
    request_id: int,
    body: MobileDecisionBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Approve a HITL request from a mobile passkey."""
    return _decide_mobile(request_id=request_id, approve=True, body=body, ctx=ctx)


@router.post("/hitl/{request_id}/deny")
def hitl_deny(
    request_id: int,
    body: MobileDecisionBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Deny a HITL request from a mobile passkey."""
    return _decide_mobile(request_id=request_id, approve=False, body=body, ctx=ctx)
