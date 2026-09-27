"""Applying SCIM operations to the principals this platform already has.

Everything here writes to tables that existed before SCIM did: ``users``,
``api_keys`` and the RBAC role a request is actually checked against. SCIM
owns no parallel copy of a principal, because two stores of "who may sign in"
drift, and the one an attacker finds is whichever the request path reads.

Deprovisioning, which is the operation that has to be real
-----------------------------------------------------------
:func:`deactivate_user` does three things, and the second and third are the
ones that make it more than a flag:

1. ``users.is_active = False``. The request path re-reads this column on
   every authenticated call, so an in-flight session stops at the next
   request rather than at the next token expiry.
2. ``users.sessions_revoked_at = now``. Without it, re-activating the
   principal resurrects every access token minted before the deactivation
   that is still inside its expiry window. Tokens carry ``iat``; a token
   issued at or before this instant is refused whatever the flag says.
3. Every ``api_keys`` row the principal owns is deactivated. An API key is a
   credential that outlives sessions entirely and is not reached by either
   of the first two steps, so a deprovisioned user who had minted one would
   otherwise keep full programmatic access indefinitely.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scim import ScimGroup, ScimGroupMember, ScimUser
from app.models.tenant import ApiKey, User
from app.services.scim.roles import DEFAULT_PROVISIONED_ROLE, effective_role


@dataclass(frozen=True)
class DeactivationResult:
    """What ending one principal's access actually ended.

    Counts rather than a boolean, so an audit record and a test can both
    assert on the work done instead of on the call having been made.
    """

    already_inactive: bool
    api_keys_revoked: int
    sessions_revoked_at: datetime


async def deactivate_user(db: AsyncSession, user: User, *, now: datetime | None = None) -> DeactivationResult:
    """End a principal's access: sessions, future tokens and API keys."""
    moment = now or datetime.now(UTC)
    already_inactive = not user.is_active

    user.is_active = False
    user.sessions_revoked_at = moment

    revoked = await db.execute(
        update(ApiKey)
        .where(ApiKey.user_id == user.id, ApiKey.tenant_id == user.tenant_id, ApiKey.is_active.is_(True))
        .values(is_active=False)
    )

    return DeactivationResult(
        already_inactive=already_inactive,
        api_keys_revoked=int(revoked.rowcount or 0),
        sessions_revoked_at=moment,
    )


async def reactivate_user(db: AsyncSession, user: User) -> None:
    """Restore sign-in for a principal an identity provider re-enabled.

    Deliberately does not restore API keys. They were revoked individually
    and a key a person cannot see was revoked is a key they will not rotate;
    re-minting is an explicit act with a fresh secret.

    ``sessions_revoked_at`` is left where it is, so tokens from before the
    deactivation stay dead.
    """
    user.is_active = True


async def recompute_role(db: AsyncSession, user: User) -> str:
    """Set ``users.role`` from the principal's mapped group memberships.

    This is the column ``CurrentUser.require_permission`` reads, so writing
    it is what makes a group membership mean anything. A principal in no
    mapped group lands on the least-privilege default rather than keeping
    the authority a group used to confer.
    """
    result = await db.execute(
        select(ScimGroup.mapped_role)
        .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
        .where(
            ScimGroupMember.user_id == user.id,
            ScimGroupMember.tenant_id == user.tenant_id,
            ScimGroup.tenant_id == user.tenant_id,
        )
    )
    resolved = effective_role([row[0] for row in result.all()])
    user.role = resolved
    return resolved


async def recompute_roles_for_group(db: AsyncSession, group: ScimGroup) -> dict[uuid.UUID, str]:
    """Recompute every current member's role after a group changed.

    Used when a group's own mapping changes, where the members are unchanged
    but what their membership confers is not.
    """
    members = await db.execute(
        select(User)
        .join(ScimGroupMember, ScimGroupMember.user_id == User.id)
        .where(
            ScimGroupMember.group_id == group.id,
            ScimGroupMember.tenant_id == group.tenant_id,
            User.tenant_id == group.tenant_id,
        )
    )
    return {user.id: await recompute_role(db, user) for user in members.scalars().all()}


async def find_user_by_username(db: AsyncSession, tenant_id: uuid.UUID, username: str) -> User | None:
    """Locate a principal by SCIM ``userName``, which this platform maps to email.

    Compared case-insensitively. Identity providers do not guarantee the
    casing of an address is stable between syncs, and a second principal
    created because one sync sent ``A@b.com`` and the next sent ``a@b.com``
    is a duplicate account with its own permissions.
    """
    result = await db.execute(select(User).where(User.tenant_id == tenant_id, func.lower(User.email) == username.strip().casefold()))
    return result.scalar_one_or_none()


async def find_user_by_external_id(db: AsyncSession, tenant_id: uuid.UUID, external_id: str) -> User | None:
    """Locate a principal by the identity provider's own identifier."""
    result = await db.execute(
        select(User).join(ScimUser, ScimUser.user_id == User.id).where(ScimUser.tenant_id == tenant_id, ScimUser.external_id == external_id)
    )
    return result.scalar_one_or_none()


def default_role() -> str:
    """The role a principal holds before any group confers one."""
    return DEFAULT_PROVISIONED_ROLE
