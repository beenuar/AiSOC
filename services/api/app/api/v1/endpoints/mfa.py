"""A second factor for the desktop console: enrolment, challenge, policy, reset.

Fix pass 4.2.

`POST /auth/login` verified a password and returned a token pair, and
nothing a user or an administrator could do made that insufficient.
Passkeys existed on `/responder/*` only, so the surface an analyst works
from all day was single-factor by construction.

The flow
--------
**Enrolment** (already signed in, or holding an enrolment challenge):

1. ``POST /auth/mfa/enroll/begin``   → a secret and an ``otpauth://`` URI
2. ``POST /auth/mfa/enroll/confirm`` → a code from that secret; returns the
   recovery codes, which exist in plaintext exactly once

**Sign-in**:

1. ``POST /auth/login`` with a correct password answers **202** and a
   short-lived challenge token instead of a session
2. ``POST /auth/mfa/verify`` with that token and a code (or a recovery
   code) returns the ordinary token pair

The 202 is deliberate. Extending the 200 body would have made
``access_token`` optional, which `scripts/openapi_diff.py` correctly calls
a break for every generated client; a 401 would collide with the console's
own ``handleUnauthorized``, which clears storage and bounces to `/login`.
202 reads as what it is — the credentials were accepted, something remains
to be done — and `fetch` treats it as a success, so the console reads the
body rather than an exception.

The challenge token
-------------------
Signed with ``SECRET_KEY`` like every other token, carrying
``type: "mfa_challenge"``. `get_current_user` requires ``type == "access"``,
so this authenticates no route: it is only an argument to the two handlers
below that look for it.

Enrolling under a policy you have not yet satisfied
---------------------------------------------------
When a tenant turns enforcement on, every user who has not enrolled holds
a correct password and no second factor. Refusing them outright locks out
the whole tenant at once, so the challenge token issued in that case
carries ``purpose: "enroll"`` and the two enrolment handlers accept it.

The trade-off is explicit: somebody who has stolen a password can enrol
*their own* authenticator before the real user does. It is bounded by the
password still being required, by the window being only until the real
user enrols, and by `mfa.enrolled` being audited with the source address —
and it is the trade every product that rolls MFA out to an existing user
base makes. The alternative, an administrator-issued enrolment ticket per
user, is a reasonable future addition and not a reason to ship a flow that
bricks a tenant.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, bearer_scheme, get_current_user, require_permission
from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.db.rls import set_rls_context
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import mfa as totp
from app.services.audit import emit_audit
from app.services.login_throttle import client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/mfa", tags=["auth", "mfa"])

CHALLENGE_TOKEN_TYPE = "mfa_challenge"
#: Long enough to open an authenticator app and read a code, short enough
#: that a challenge left in a browser's history is not a standing
#: half-credential.
CHALLENGE_TTL_SECONDS = 300


def _sanitize(value: object, limit: int = 120) -> str:
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


def _issuer_label() -> str:
    """What the authenticator app shows beside the code."""
    return (getattr(settings, "PROJECT_NAME", None) or "AiSOC").strip() or "AiSOC"


# ─── The challenge token ──────────────────────────────────────────────────────


def mint_challenge(*, user_id: uuid.UUID, tenant_id: uuid.UUID, purpose: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "purpose": purpose,
            "type": CHALLENGE_TOKEN_TYPE,
            "iat": now,
            "exp": now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def read_challenge(token: str, *, expect_purpose: str | None = None) -> dict[str, Any]:
    try:
        payload = dict(jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]))
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This sign-in attempt has expired. Sign in again.") from exc
    if payload.get("type") != CHALLENGE_TOKEN_TYPE:
        # An access token presented here would otherwise let a session that
        # is already authenticated mint a *second* one with no code.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sign-in challenge.")
    if expect_purpose is not None and payload.get("purpose") != expect_purpose:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sign-in challenge.")
    return payload


# ─── Stored state ─────────────────────────────────────────────────────────────


async def enrolment_row(db: Any, user_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        (
            await db.execute(
                text(
                    "SELECT user_id, tenant_id, secret_encrypted, confirmed_at, last_used_step FROM aisoc_user_mfa WHERE user_id = :u"
                ).bindparams(u=user_id)
            )
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


async def has_confirmed_factor(db: Any, user_id: uuid.UUID) -> bool:
    row = await enrolment_row(db, user_id)
    return bool(row and row["confirmed_at"])


async def tenant_requires_totp(db: Any, tenant_id: uuid.UUID) -> bool:
    """Whether this tenant has asked for a second factor.

    **Absence of a row means no.** No migration writes one: a backfill of a
    row per tenant would change the meaning of every predicate that counts
    rows in that table, and this repository has already shipped a
    zero-permission administrator on a fresh install that way.
    """
    row = (
        (await db.execute(text("SELECT require_totp FROM aisoc_tenant_mfa_policy WHERE tenant_id = :t").bindparams(t=tenant_id)))
        .mappings()
        .first()
    )
    return bool(row and row["require_totp"])


def _decrypt_secret(stored: str) -> str:
    try:
        return get_vault().decrypt(stored)
    except CredentialVaultError as exc:
        # Fails closed. A secret this service cannot read authenticates
        # nobody, and the honest answer is "this deployment's credential key
        # changed", not "your code is wrong".
        logger.error("mfa.secret_undecryptable error=%s", _sanitize(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The stored second factor cannot be read on this deployment. An administrator must reset it.",
        ) from exc


# ─── The principal that may enrol ─────────────────────────────────────────────


class EnrolmentPrincipal(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    #: True when this principal arrived with a challenge token rather than a
    #: session, which is the "the tenant just turned enforcement on" path.
    from_challenge: bool = False


class _ChallengeBody(BaseModel):
    mfa_token: str | None = None


async def _principal_for_enrolment(
    db: DBSession,
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> EnrolmentPrincipal:
    """Either an ordinary session, or an enrolment challenge.

    Written as one dependency rather than two routes because the two paths
    differ only in how the principal was established; splitting them would
    put the enrolment logic in two places and let one drift.

    The bearer credential is taken through `get_current_user` itself rather
    than decoded here. A second decoder would be a second place for the
    `type == "access"` rule to be forgotten, and that rule is what stops a
    challenge token being presented as a session.
    """
    if credentials is not None:
        user = await get_current_user(request=request, credentials=credentials, db=db)
        return EnrolmentPrincipal(user_id=user.user_id, tenant_id=user.tenant_id, email=user.email)

    body = await _maybe_json(request)
    token = (body or {}).get("mfa_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in first, or supply the mfa_token the sign-in returned.",
        )
    payload = read_challenge(str(token), expect_purpose="enroll")
    row = (
        (
            await db.execute(
                text("SELECT id, tenant_id, email FROM users WHERE id = :u AND is_active IS TRUE").bindparams(
                    u=uuid.UUID(str(payload["sub"]))
                )
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sign-in challenge.")
    return EnrolmentPrincipal(user_id=row["id"], tenant_id=row["tenant_id"], email=row["email"], from_challenge=True)


async def _maybe_json(request: Request) -> dict[str, Any] | None:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001 - an absent or unparseable body is "no token"
        return None
    return payload if isinstance(payload, dict) else None


EnrolPrincipal = Annotated[EnrolmentPrincipal, Depends(_principal_for_enrolment)]


# ─── Models ───────────────────────────────────────────────────────────────────


class MfaStatus(BaseModel):
    enrolled: bool
    tenant_requires_totp: bool
    recovery_codes_remaining: int


class EnrollBegin(BaseModel):
    secret: str
    otpauth_uri: str


class ConfirmRequest(_ChallengeBody):
    code: str = Field(min_length=1, max_length=64)


class EnrollConfirmed(BaseModel):
    recovery_codes: list[str]
    #: Present only when enrolment completed from a challenge, so the user
    #: lands signed in rather than having to authenticate twice.
    access_token: str | None = None
    refresh_token: str | None = None


class VerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=1, max_length=64)


class SessionTokens(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class DisableRequest(BaseModel):
    code: str = Field(min_length=1, max_length=64)


class ResetRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class MfaPolicy(BaseModel):
    require_totp: bool


# ─── Routes ───────────────────────────────────────────────────────────────────


@router.get("/status", response_model=MfaStatus)
async def mfa_status(current_user: AuthUser, db: DBSession) -> MfaStatus:
    """Whether this user holds a second factor, and whether they must."""
    remaining = (
        await db.execute(
            text("SELECT count(*) FROM aisoc_user_mfa_recovery_codes WHERE user_id = :u AND used_at IS NULL").bindparams(
                u=current_user.user_id
            )
        )
    ).scalar() or 0
    return MfaStatus(
        enrolled=await has_confirmed_factor(db, current_user.user_id),
        tenant_requires_totp=await tenant_requires_totp(db, current_user.tenant_id),
        recovery_codes_remaining=int(remaining),
    )


@router.post("/enroll/begin", response_model=EnrollBegin)
async def enroll_begin(principal: EnrolPrincipal, db: DBSession) -> EnrollBegin:
    """Mint a secret and return it once, with the URI an app scans.

    Re-enrolling replaces an *unconfirmed* row and refuses a confirmed one:
    silently rotating a working factor would turn a mis-click into a
    lockout, and `DELETE /auth/mfa` is the deliberate way to remove one.
    """
    existing = await enrolment_row(db, principal.user_id)
    if existing and existing["confirmed_at"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A second factor is already enrolled. Remove it first, or ask an administrator to reset it.",
        )

    secret = totp.new_secret()
    await set_rls_context(db, principal.tenant_id)
    await db.execute(
        text("""
            INSERT INTO aisoc_user_mfa (user_id, tenant_id, secret_encrypted, confirmed_at, last_used_step, updated_at)
            VALUES (:u, :t, :s, NULL, NULL, now())
            ON CONFLICT (user_id) DO UPDATE
               SET secret_encrypted = EXCLUDED.secret_encrypted,
                   confirmed_at = NULL,
                   last_used_step = NULL,
                   updated_at = now()
        """).bindparams(u=principal.user_id, t=principal.tenant_id, s=get_vault().encrypt(secret))
    )
    await db.commit()
    return EnrollBegin(secret=secret, otpauth_uri=totp.provisioning_uri(secret, account=principal.email, issuer=_issuer_label()))


@router.post("/enroll/confirm", response_model=EnrollConfirmed)
async def enroll_confirm(body: ConfirmRequest, principal: EnrolPrincipal, db: DBSession, request: Request) -> EnrollConfirmed:
    """Prove the secret arrived, then hand over the recovery codes.

    Confirmation is what makes the row a credential. Without it, an
    enrolment begun on a device that never received the QR code would lock
    the user out at their next sign-in.
    """
    row = await enrolment_row(db, principal.user_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Start an enrolment first.")
    if row["confirmed_at"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A second factor is already enrolled.")

    step = totp.verify_totp(_decrypt_secret(row["secret_encrypted"]), body.code)
    if step is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That code is not valid. Check your authenticator's clock.")

    codes = totp.new_recovery_codes()
    await set_rls_context(db, principal.tenant_id)
    await db.execute(
        text("UPDATE aisoc_user_mfa SET confirmed_at = now(), last_used_step = :s, updated_at = now() WHERE user_id = :u").bindparams(
            s=step, u=principal.user_id
        )
    )
    await db.execute(text("DELETE FROM aisoc_user_mfa_recovery_codes WHERE user_id = :u").bindparams(u=principal.user_id))
    for code in codes:
        await db.execute(
            text("INSERT INTO aisoc_user_mfa_recovery_codes (user_id, tenant_id, code_hash) VALUES (:u, :t, :h)").bindparams(
                u=principal.user_id, t=principal.tenant_id, h=totp.hash_recovery_code(code)
            )
        )
    await emit_audit(
        db=db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        actor_email=principal.email,
        action="mfa.enrolled",
        resource="user",
        resource_id=str(principal.user_id),
        changes={"method": "totp", "from_challenge": principal.from_challenge, "source_ip": client_ip(request)},
        request=request,
    )
    await db.commit()

    tokens: dict[str, str] = {}
    if principal.from_challenge:
        tokens = await _issue_session(db, principal.user_id)
    return EnrollConfirmed(recovery_codes=codes, **tokens)


@router.post("/verify", response_model=SessionTokens)
async def verify(body: VerifyRequest, db: DBSession, request: Request) -> SessionTokens:
    """Complete a sign-in that `POST /auth/login` answered with 202."""
    payload = read_challenge(body.mfa_token, expect_purpose="verify")
    user_id = uuid.UUID(str(payload["sub"]))
    row = await enrolment_row(db, user_id)
    if row is None or not row["confirmed_at"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No second factor is enrolled for this account.")

    await set_rls_context(db, row["tenant_id"])
    step = totp.verify_totp(_decrypt_secret(row["secret_encrypted"]), body.code, last_used_step=row["last_used_step"])
    if step is not None:
        await db.execute(
            text("UPDATE aisoc_user_mfa SET last_used_step = :s, updated_at = now() WHERE user_id = :u").bindparams(s=step, u=user_id)
        )
        await db.commit()
        return SessionTokens(**await _issue_session(db, user_id))

    if await _consume_recovery_code(db, user_id=user_id, tenant_id=row["tenant_id"], code=body.code, request=request):
        return SessionTokens(**await _issue_session(db, user_id))

    logger.warning("mfa.verify_failed user=%s source=%s", _sanitize(user_id), _sanitize(client_ip(request), 64))
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That code is not valid.")


async def _consume_recovery_code(db: Any, *, user_id: uuid.UUID, tenant_id: uuid.UUID, code: str, request: Request) -> bool:
    """Spend one unused recovery code, or report that none matched.

    The `used_at IS NULL` predicate is in the UPDATE rather than only in
    the preceding SELECT, so two concurrent attempts with the same code
    cannot both succeed: the second updates zero rows.
    """
    normalised = totp.normalise_recovery_code(code)
    if not normalised:
        return False
    candidate = totp.hash_recovery_code(normalised)
    spent = await db.execute(
        text(
            "UPDATE aisoc_user_mfa_recovery_codes SET used_at = now() "
            "WHERE user_id = :u AND code_hash = :h AND used_at IS NULL RETURNING id"
        ).bindparams(u=user_id, h=candidate)
    )
    if spent.first() is None:
        await db.rollback()
        return False
    remaining = (
        await db.execute(
            text("SELECT count(*) FROM aisoc_user_mfa_recovery_codes WHERE user_id = :u AND used_at IS NULL").bindparams(u=user_id)
        )
    ).scalar() or 0
    await emit_audit(
        db=db,
        tenant_id=tenant_id,
        actor_id=user_id,
        action="mfa.recovery_code_used",
        resource="user",
        resource_id=str(user_id),
        changes={"remaining": int(remaining), "source_ip": client_ip(request)},
        request=request,
    )
    await db.commit()
    return True


async def require_current_factor(db: Any, *, user_id: uuid.UUID, tenant_id: uuid.UUID, code: str, request: Request) -> None:
    """Refuse unless the caller can still produce this account's factor.

    An authorization decision, and a stronger one than any role permission:
    it asks what the principal *holds*, not what their role says. That
    distinction matters to `scripts/check_route_authz.py`, which reads
    `require_permission` and would otherwise record a route guarded by a
    possession proof as guarded by nothing — so this name is registered
    there, in the same way `_admin_scope` is.

    A role permission here would be theatre in the other direction too:
    the only principal who should be able to remove this factor is the one
    already identified, and no permission can be held by exactly them.
    """
    row = await enrolment_row(db, user_id)
    if row is None or not row["confirmed_at"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No second factor is enrolled.")

    await set_rls_context(db, tenant_id)
    if totp.verify_totp(_decrypt_secret(row["secret_encrypted"]), code, last_used_step=row["last_used_step"]) is not None:
        return
    if await _consume_recovery_code(db, user_id=user_id, tenant_id=tenant_id, code=code, request=request):
        return
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That code is not valid.")


async def _issue_session(db: Any, user_id: uuid.UUID) -> dict[str, str]:
    row = (
        (await db.execute(text("SELECT id, tenant_id, role, email FROM users WHERE id = :u AND is_active IS TRUE").bindparams(u=user_id)))
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    claims = {"sub": str(row["id"]), "tenant_id": str(row["tenant_id"]), "role": row["role"], "email": row["email"]}
    await db.execute(text("UPDATE users SET last_login = now() WHERE id = :u").bindparams(u=user_id))
    await db.commit()
    return {"access_token": create_access_token(claims), "refresh_token": create_refresh_token(claims)}


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def disable(body: DisableRequest, current_user: AuthUser, db: DBSession, request: Request) -> None:
    """Remove your own second factor, proving you still hold it.

    A current code is required. Without it, a stolen session could strip
    the factor it was supposed to be protected by, which makes the factor
    worth exactly as much as the session.
    """
    await require_current_factor(
        db,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
        code=body.code,
        request=request,
    )

    await set_rls_context(db, current_user.tenant_id)
    await _forget(db, user_id=current_user.user_id)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="mfa.disabled",
        resource="user",
        resource_id=str(current_user.user_id),
        changes={"by": "self", "source_ip": client_ip(request)},
        request=request,
    )
    await db.commit()


@router.post("/reset/{user_id}", status_code=status.HTTP_200_OK)
async def reset(
    user_id: uuid.UUID,
    body: ResetRequest,
    db: DBSession,
    request: Request,
    current_user: Annotated[Any, Depends(require_permission("users:write"))],
) -> dict[str, str]:
    """Remove somebody else's second factor. The lost-phone path.

    Three constraints, each of which is the reason an administrative reset
    is normally the weakest link in an MFA deployment:

    * the target must be in the caller's own tenant, resolved from the
      authenticated principal and never from the request;
    * a `reason` is required and lands in the audit row, because "an admin
      reset it" without one is not an answer to "who removed this and why";
    * an administrator may not reset **their own** factor here. That would
      be a self-disable with no code, bypassing `DELETE /auth/mfa`.
    """
    if user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Use DELETE /auth/mfa to remove your own second factor; it requires a current code.",
        )
    target = (
        (
            await db.execute(
                text("SELECT id, email FROM users WHERE id = :u AND tenant_id = :t").bindparams(u=user_id, t=current_user.tenant_id)
            )
        )
        .mappings()
        .first()
    )
    if target is None:
        # 404 and not 403: a caller outside this tenant learns nothing about
        # whether the id names anybody.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such user in this tenant.")

    await set_rls_context(db, current_user.tenant_id)
    await _forget(db, user_id=user_id)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="mfa.reset",
        resource="user",
        resource_id=str(user_id),
        changes={"target_email": target["email"], "reason": body.reason, "source_ip": client_ip(request)},
        request=request,
    )
    await db.commit()
    return {"status": "reset", "user_id": str(user_id)}


async def _forget(db: Any, *, user_id: uuid.UUID) -> None:
    await db.execute(text("DELETE FROM aisoc_user_mfa_recovery_codes WHERE user_id = :u").bindparams(u=user_id))
    await db.execute(text("DELETE FROM aisoc_user_mfa WHERE user_id = :u").bindparams(u=user_id))


@router.get("/policy", response_model=MfaPolicy)
async def get_policy(current_user: AuthUser, db: DBSession) -> MfaPolicy:
    """Readable by any member: a user is entitled to know what their own
    tenant requires of them."""
    return MfaPolicy(require_totp=await tenant_requires_totp(db, current_user.tenant_id))


@router.put("/policy", response_model=MfaPolicy)
async def put_policy(
    body: MfaPolicy,
    db: DBSession,
    request: Request,
    current_user: Annotated[Any, Depends(require_permission("settings:write"))],
) -> MfaPolicy:
    """Require, or stop requiring, a second factor across this tenant.

    The tenant is the caller's, never a parameter. A row is written only
    when an administrator asks for one, so a tenant that has never visited
    this endpoint has no row and is not enforced.
    """
    await set_rls_context(db, current_user.tenant_id)
    await db.execute(
        text("""
            INSERT INTO aisoc_tenant_mfa_policy (tenant_id, require_totp, updated_by, updated_at)
            VALUES (:t, :r, :u, now())
            ON CONFLICT (tenant_id) DO UPDATE
               SET require_totp = EXCLUDED.require_totp, updated_by = EXCLUDED.updated_by, updated_at = now()
        """).bindparams(t=current_user.tenant_id, r=body.require_totp, u=current_user.user_id)
    )
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="mfa.policy_changed",
        resource="tenant",
        resource_id=str(current_user.tenant_id),
        changes={"require_totp": body.require_totp},
        request=request,
    )
    await db.commit()
    return MfaPolicy(require_totp=body.require_totp)
