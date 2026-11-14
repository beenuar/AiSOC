"""Minting, verifying and rotating SCIM bearer credentials.

A SCIM token is the only credential in this tree that is long-lived,
unattended and held by a third party's software. Everything here follows from
that: the raw secret exists once, lookup is by digest, rotation overlaps
rather than cuts over, and verification answers with a reason the caller can
audit instead of a bare boolean.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scim import ScimToken

#: Distinguishes a SCIM credential from an ``aisoc_`` API key at a glance, in
#: a log line and in the dependency that resolves it. The two are verified by
#: different code against different tables, and a support conversation that
#: starts by naming the wrong one costs an hour.
TOKEN_PREFIX: Final[str] = "aisoc_scim_"

#: 192 bits from ``secrets``. A digest is the right store for this and a
#: password KDF would not be: there is no low-entropy guess to slow down, and
#: a KDF on the request path would put a deliberate delay in front of every
#: call an identity provider makes on its sync schedule.
_TOKEN_BYTES: Final[int] = 24

#: How long a rotated-out credential keeps working by default. Long enough
#: for an administrator to paste the replacement into the identity provider,
#: short enough that a leaked secret is not indefinite.
DEFAULT_ROTATION_GRACE: Final[timedelta] = timedelta(hours=24)


def hash_token(raw: str) -> str:
    """SHA-256 hex digest of a raw SCIM token."""
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_token() -> tuple[str, str, str]:
    """Return ``(raw, prefix, digest)`` for a fresh credential."""
    raw = f"{TOKEN_PREFIX}{secrets.token_hex(_TOKEN_BYTES)}"
    return raw, raw[: len(TOKEN_PREFIX) + 6], hash_token(raw)


@dataclass(frozen=True)
class ScimPrincipal:
    """The authenticated identity behind a SCIM request.

    ``tenant_id`` comes from the token row. There is no request field that
    can influence it, which is the whole reason this type exists rather than
    the handlers reading a header.
    """

    token_id: uuid.UUID
    tenant_id: uuid.UUID
    org_id: uuid.UUID | None
    token_name: str


class ScimAuthError(Exception):
    """A SCIM credential that will not authenticate, with a recordable reason.

    The reason is for the audit log and the server's own logs. What goes back
    to the caller is an undifferentiated 401: telling an unauthenticated
    client whether a secret was wrong, revoked or merely expired is telling it
    which secrets exist.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def verify_token(db: AsyncSession, raw: str, *, now: datetime | None = None) -> ScimPrincipal:
    """Resolve a raw bearer token to its principal, or raise.

    Records ``last_used_at`` on success. That column is what makes an
    abandoned integration visible: a token nobody has used for months is a
    standing credential with no owner, and there is no other signal for it.
    """
    moment = now or datetime.now(UTC)

    if not raw or not raw.startswith(TOKEN_PREFIX):
        raise ScimAuthError("token does not carry the SCIM prefix")

    result = await db.execute(select(ScimToken).where(ScimToken.token_hash == hash_token(raw)))
    token = result.scalar_one_or_none()
    if token is None:
        raise ScimAuthError("no SCIM token matches that digest")

    if token.revoked_at is not None:
        raise ScimAuthError(f"token {token.token_prefix} was revoked at {token.revoked_at.isoformat()}")
    if token.expires_at is not None and token.expires_at <= moment:
        raise ScimAuthError(f"token {token.token_prefix} expired at {token.expires_at.isoformat()}")

    token.last_used_at = moment

    return ScimPrincipal(
        token_id=token.id,
        tenant_id=token.tenant_id,
        org_id=token.org_id,
        token_name=token.name,
    )


async def mint_token(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    org_id: uuid.UUID | None,
    name: str,
    created_by: uuid.UUID | None,
    expires_at: datetime | None = None,
    rotated_from_id: uuid.UUID | None = None,
) -> tuple[ScimToken, str]:
    """Create a credential and return it with its raw secret.

    The raw secret is returned, never stored, and is the only time it exists
    outside the identity provider's configuration.
    """
    raw, prefix, digest = generate_token()
    token = ScimToken(
        tenant_id=tenant_id,
        org_id=org_id,
        name=name,
        token_prefix=prefix,
        token_hash=digest,
        created_by=created_by,
        expires_at=expires_at,
        rotated_from_id=rotated_from_id,
    )
    db.add(token)
    await db.flush()
    return token, raw


async def rotate_token(
    db: AsyncSession,
    *,
    token: ScimToken,
    created_by: uuid.UUID | None,
    grace: timedelta | None = None,
    now: datetime | None = None,
) -> tuple[ScimToken, str]:
    """Mint a replacement and put the old credential on a clock.

    Both secrets authenticate until the grace window closes. A rotation that
    invalidated the old secret immediately would take the integration down
    for as long as it takes a person to copy the new one across, which is the
    reason rotation gets deferred and secrets get old.

    A grace of zero is honoured, for the case rotation is a response to a
    disclosure rather than hygiene.
    """
    moment = now or datetime.now(UTC)
    window = DEFAULT_ROTATION_GRACE if grace is None else grace

    replacement, raw = await mint_token(
        db,
        tenant_id=token.tenant_id,
        org_id=token.org_id,
        name=token.name,
        created_by=created_by,
        expires_at=token.expires_at,
        rotated_from_id=token.id,
    )

    if window <= timedelta(0):
        token.revoked_at = moment
    else:
        # Never extend: a token already expiring sooner than the grace window
        # keeps its earlier deadline.
        deadline = moment + window
        token.expires_at = deadline if token.expires_at is None else min(token.expires_at, deadline)

    return replacement, raw
