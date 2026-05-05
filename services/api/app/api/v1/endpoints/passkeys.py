"""Passkey (WebAuthn) endpoints for the mobile responder PWA.

Lets users enroll passkeys on their phone (Face ID / Touch ID / platform
authenticators) and sign in passwordlessly. The PWA needs this because
typing a password on a phone in the middle of an incident is a non-starter.

Flow
----
**Registration** (must already be logged in via password to bootstrap):
1. ``POST /passkeys/register/begin`` → returns publicKey creation options
2. Browser invokes ``navigator.credentials.create``
3. ``POST /passkeys/register/finish`` → verifies attestation, persists credential

**Authentication** (passwordless):
1. ``POST /passkeys/authenticate/begin`` (optional ``email`` hint) → options
2. Browser invokes ``navigator.credentials.get``
3. ``POST /passkeys/authenticate/finish`` → verifies, returns JWT pair

**Management**:
* ``GET    /passkeys/credentials``       – list my credentials
* ``DELETE /passkeys/credentials/{id}``  – revoke one

Security notes
--------------
* Challenges live in a server-side ``passkey_challenges`` table with a
  short TTL (default 5 min) and are single-use (``consumed_at``).
* RP ID / origin / name come from settings — set ``PASSKEY_RP_ID`` to the
  exact host the PWA loads from in production (no scheme, no port for the
  RP ID; full ``https://...`` URLs go in ``PASSKEY_RP_ORIGINS``).
* On success we issue the same JWT pair as ``/auth/login`` so the rest of
  the API surface is unaware of the auth method.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import and_, select, update

from app.api.v1.deps import AuthUser, DBSession
from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.db.rls import TenantDBSession
from app.models.responder import PasskeyChallenge, PasskeyCredential
from app.models.tenant import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/passkeys", tags=["responder", "passkeys"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _b64url_encode(data: bytes) -> str:
    """Base64URL-encode without padding (WebAuthn convention)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode a Base64URL string, tolerating missing padding."""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _now() -> datetime:
    return datetime.now(UTC)


def _challenge_expiry() -> datetime:
    return _now() + timedelta(seconds=settings.PASSKEY_CHALLENGE_TTL_SECONDS)


async def _store_challenge(
    db: Any,
    *,
    purpose: str,
    challenge: bytes,
    user_id: uuid.UUID | None,
    tenant_id: uuid.UUID | None,
    email_hint: str | None,
) -> str:
    """Persist a challenge and return its base64url representation."""
    encoded = _b64url_encode(challenge)
    row = PasskeyChallenge(
        purpose=purpose,
        challenge=encoded,
        user_id=user_id,
        tenant_id=tenant_id,
        email_hint=email_hint,
        rp_id=settings.PASSKEY_RP_ID,
        expires_at=_challenge_expiry(),
    )
    db.add(row)
    await db.commit()
    return encoded


async def _consume_challenge(db: Any, *, encoded: str, purpose: str) -> PasskeyChallenge:
    """Look up an unconsumed, unexpired challenge and mark it consumed."""
    row = (
        await db.execute(
            select(PasskeyChallenge).where(
                PasskeyChallenge.challenge == encoded,
                PasskeyChallenge.purpose == purpose,
                PasskeyChallenge.consumed_at.is_(None),
                PasskeyChallenge.expires_at > _now(),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown, expired, or already-consumed passkey challenge",
        )
    row.consumed_at = _now()
    await db.commit()
    return row


def _import_webauthn() -> Any:
    """Import the ``webauthn`` library lazily so the rest of the API can boot
    even when the optional dependency is missing (e.g. minimal test images)."""
    try:
        import webauthn  # noqa: PLC0415
        from webauthn.helpers import structs as webauthn_structs  # noqa: PLC0415

        return webauthn, webauthn_structs
    except ImportError as exc:  # pragma: no cover - exercised in CI when missing
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=("Passkey (WebAuthn) support is not installed on this server. Install the `webauthn` Python package."),
        ) from exc


# --------------------------------------------------------------------------- #
# Pydantic surface
# --------------------------------------------------------------------------- #


class PasskeyCredentialOut(BaseModel):
    id: uuid.UUID
    device_name: str
    transports: list[str]
    is_discoverable: bool
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CredentialsListResponse(BaseModel):
    items: list[PasskeyCredentialOut]


class RegisterBeginRequest(BaseModel):
    device_name: str = Field(default="My phone", max_length=120)


class FinishRequest(BaseModel):
    credential: dict[str, Any]
    challenge: str = Field(min_length=8, max_length=512)


class AuthenticateBeginRequest(BaseModel):
    email: EmailStr | None = None


class AuthenticateFinishResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


@router.post("/register/begin")
async def passkey_register_begin(
    body: RegisterBeginRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> dict[str, Any]:
    """Start passkey enrollment for the currently logged-in user.

    Returns a JSON payload directly suitable for
    ``navigator.credentials.create({ publicKey: <returned> })`` after the
    standard Base64URL-decoding of the binary fields.
    """
    webauthn, _ = _import_webauthn()

    # Pull existing credential IDs so the browser hides them in the picker.
    existing_rows = (
        (
            await db.execute(
                select(PasskeyCredential.credential_id).where(
                    PasskeyCredential.user_id == user.user_id,
                    PasskeyCredential.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )

    user_row = (await db.execute(select(User).where(User.id == user.user_id))).scalar_one_or_none()
    if user_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    options = webauthn.generate_registration_options(
        rp_id=settings.PASSKEY_RP_ID,
        rp_name=settings.PASSKEY_RP_NAME,
        user_id=str(user.user_id).encode("utf-8"),
        user_name=user_row.email,
        user_display_name=user_row.username or user_row.email,
        exclude_credentials=[{"id": _b64url_decode(cid), "type": "public-key"} for cid in existing_rows],
    )

    options_json = json.loads(webauthn.options_to_json(options))
    encoded_challenge = await _store_challenge(
        db,
        purpose="register",
        challenge=options.challenge,
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        email_hint=user_row.email,
    )

    # Carry the encoded challenge alongside the publicKey options so the
    # client can echo it back without having to parse it from the binary
    # struct.
    return {
        "publicKey": options_json,
        "challenge": encoded_challenge,
        "device_name_default": body.device_name,
    }


@router.post("/register/finish", response_model=PasskeyCredentialOut)
async def passkey_register_finish(
    body: FinishRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> PasskeyCredentialOut:
    """Verify the attestation response and persist the new credential."""
    webauthn, _ = _import_webauthn()

    challenge_row = await _consume_challenge(db, encoded=body.challenge, purpose="register")
    if challenge_row.user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge does not belong to the current user",
        )

    try:
        verified = webauthn.verify_registration_response(
            credential=body.credential,
            expected_challenge=_b64url_decode(body.challenge),
            expected_rp_id=settings.PASSKEY_RP_ID,
            expected_origin=settings.PASSKEY_RP_ORIGINS,
            require_user_verification=True,
        )
    except Exception as exc:  # webauthn raises a base ``InvalidRegistrationResponse``
        logger.warning("Passkey registration verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {exc}",
        ) from exc

    transports = body.credential.get("response", {}).get("transports") or []
    device_name = body.credential.get("device_name") or "My phone"

    row = PasskeyCredential(
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        credential_id=_b64url_encode(verified.credential_id),
        public_key=_b64url_encode(verified.credential_public_key),
        sign_count=int(verified.sign_count),
        transports=transports,
        device_name=device_name[:120],
        aaguid=getattr(verified, "aaguid", None) or None,
        is_discoverable=getattr(verified, "credential_backed_up", True),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    return PasskeyCredentialOut.model_validate(row)


# --------------------------------------------------------------------------- #
# Authentication (passwordless)
# --------------------------------------------------------------------------- #


@router.post("/authenticate/begin")
async def passkey_authenticate_begin(
    body: AuthenticateBeginRequest,
    db: DBSession,
) -> dict[str, Any]:
    """Start a passkey-based login.

    If ``email`` is provided we constrain ``allowCredentials`` so only that
    user's keys are tried. If omitted we go fully discoverable (the browser
    picks the right credential from its store).
    """
    webauthn, _ = _import_webauthn()

    allow_credentials: list[dict[str, Any]] = []
    target_user: User | None = None

    if body.email:
        user_row = (
            await db.execute(
                select(User).where(
                    User.email == body.email,
                    User.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()
        if user_row is not None:
            target_user = user_row
            cred_rows = (
                (
                    await db.execute(
                        select(PasskeyCredential).where(
                            PasskeyCredential.user_id == user_row.id,
                            PasskeyCredential.revoked_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            allow_credentials = [
                {
                    "id": _b64url_decode(c.credential_id),
                    "type": "public-key",
                    "transports": c.transports or None,
                }
                for c in cred_rows
            ]

    options = webauthn.generate_authentication_options(
        rp_id=settings.PASSKEY_RP_ID,
        allow_credentials=allow_credentials or None,
    )
    options_json = json.loads(webauthn.options_to_json(options))

    encoded_challenge = await _store_challenge(
        db,
        purpose="authenticate",
        challenge=options.challenge,
        user_id=target_user.id if target_user else None,
        tenant_id=target_user.tenant_id if target_user else None,
        email_hint=body.email,
    )

    return {"publicKey": options_json, "challenge": encoded_challenge}


@router.post("/authenticate/finish", response_model=AuthenticateFinishResponse)
async def passkey_authenticate_finish(
    body: FinishRequest,
    db: DBSession,
) -> AuthenticateFinishResponse:
    """Verify a passkey assertion and mint JWTs."""
    webauthn, _ = _import_webauthn()

    await _consume_challenge(db, encoded=body.challenge, purpose="authenticate")

    raw_credential_id = body.credential.get("id") or body.credential.get("rawId")
    if not isinstance(raw_credential_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing credential id in assertion",
        )

    cred_row = (
        await db.execute(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == raw_credential_id,
                PasskeyCredential.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if cred_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown or revoked passkey",
        )

    user_row = (
        await db.execute(
            select(User).where(
                User.id == cred_row.user_id,
                User.is_active == True,  # noqa: E712
            )
        )
    ).scalar_one_or_none()
    if user_row is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    try:
        verified = webauthn.verify_authentication_response(
            credential=body.credential,
            expected_challenge=_b64url_decode(body.challenge),
            expected_rp_id=settings.PASSKEY_RP_ID,
            expected_origin=settings.PASSKEY_RP_ORIGINS,
            credential_public_key=_b64url_decode(cred_row.public_key),
            credential_current_sign_count=cred_row.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.warning("Passkey authentication verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Passkey verification failed: {exc}",
        ) from exc

    cred_row.sign_count = int(verified.new_sign_count)
    cred_row.last_used_at = _now()
    await db.execute(update(User).where(User.id == user_row.id).values(last_login=_now()))
    await db.commit()

    token_data = {
        "sub": str(user_row.id),
        "tenant_id": str(user_row.tenant_id),
        "role": user_row.role,
        "email": user_row.email,
    }
    return AuthenticateFinishResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


# --------------------------------------------------------------------------- #
# Credential management
# --------------------------------------------------------------------------- #


@router.get("/credentials", response_model=CredentialsListResponse)
async def list_my_credentials(
    user: AuthUser,
    db: TenantDBSession,
) -> CredentialsListResponse:
    """List the current user's active passkeys."""
    rows = (
        (
            await db.execute(
                select(PasskeyCredential)
                .where(
                    and_(
                        PasskeyCredential.user_id == user.user_id,
                        PasskeyCredential.revoked_at.is_(None),
                    )
                )
                .order_by(PasskeyCredential.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return CredentialsListResponse(items=[PasskeyCredentialOut.model_validate(r) for r in rows])


@router.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_credential(
    credential_id: uuid.UUID,
    user: AuthUser,
    db: TenantDBSession,
) -> None:
    """Revoke (soft-delete) one of the current user's passkeys."""
    row = (
        await db.execute(
            select(PasskeyCredential).where(
                PasskeyCredential.id == credential_id,
                PasskeyCredential.user_id == user.user_id,
                PasskeyCredential.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found or already revoked",
        )
    row.revoked_at = _now()
    await db.commit()
