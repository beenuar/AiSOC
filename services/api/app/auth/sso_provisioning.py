"""Turn a verified IdP assertion into a local user, a tenant and a real token.

Parity plan 4.1.

What was missing
----------------
Both `saml.py` and `oidc.py` ended a successful sign-in by putting a JWT in
an `aisoc_token` cookie. That token carried `sub`, `email`, `name` and
`picture`, and **no tenant, no role and no local user id**, which is three
problems at once:

* the API's own verifier reads `sub` as a user id and requires `tenant_id`
  and `role`, so the token authenticates nothing;
* it is signed with `JWT_SECRET` rather than `settings.SECRET_KEY`, which
  is a different key from the one the API verifies with;
* it is a cookie, and the API reads `Authorization: Bearer`.

So a user could complete the whole OIDC dance, be redirected to the
console, and find every request unauthenticated. The plan's phrasing is
exact: "a token in a cookie the API never reads, and it names no local
user, tenant or role".

Just-in-time provisioning, and the two things it must not do
-------------------------------------------------------------
On first sign-in the user is created. Two constraints make that safe:

1. **The tenant comes from configuration, never from the assertion.** An
   IdP that can name its own tenant can name somebody else's. The tenant is
   resolved from the SSO connection's own record, which an administrator
   set up.

2. **A group maps to a role only through `app.core.role_grants`.** The same
   path every other grant takes, so an IdP group cannot confer `admin` or
   `platform_admin` any more than an API caller can. An unmapped group
   grants nothing rather than defaulting to something convenient.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

#: Roles an IdP group may map to. Deliberately excludes `admin` and
#: `platform_admin`: v14.0.0 made those unreachable from every API route
#: precisely so that nothing but `bootstrap_admin` can mint one, and an SSO
#: group mapping would be a way back in.
ASSIGNABLE_ROLES = frozenset({"viewer", "soc_analyst", "soc_lead", "threat_hunter", "tenant_admin"})

#: What an unmapped group gets. The least-privileged role, not nothing,
#: because a user who authenticated successfully and then cannot see
#: anything reads as a broken integration rather than as a policy decision.
DEFAULT_ROLE = "viewer"


def _sanitize(value: object, limit: int = 120) -> str:
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


class SsoProvisioningError(Exception):
    """Raised when an assertion cannot be turned into a local principal."""


def map_groups_to_role(groups: list[str], mapping: dict[str, str]) -> str:
    """The highest-privilege role the user's groups map to.

    Highest rather than first, because a user in both `soc-analysts` and
    `soc-leads` should get the lead role whatever order the IdP lists them
    in: making the answer depend on list order would make it unstable
    across sign-ins.
    """
    order = ["viewer", "soc_analyst", "threat_hunter", "soc_lead", "tenant_admin"]
    best = DEFAULT_ROLE
    for group in groups:
        role = mapping.get(group) or mapping.get(group.lower())
        if role is None:
            continue
        if role not in ASSIGNABLE_ROLES:
            # Named and refused rather than ignored. A mapping that tries
            # to confer `admin` is a configuration mistake somebody needs
            # to know about, not something to silently drop.
            logger.warning(
                "sso.group_maps_to_unassignable_role group=%s role=%s",
                _sanitize(group, 60),
                _sanitize(role, 40),
            )
            continue
        if order.index(role) > order.index(best):
            best = role
    return best


async def resolve_connection(db: AsyncSession, *, provider: str, issuer: str) -> dict[str, Any] | None:
    """The configured SSO connection for this issuer, or None.

    The tenant and the group mapping both come from here rather than from
    the assertion, because an IdP that can name its own tenant can name
    somebody else's.
    """
    try:
        row = (
            (
                await db.execute(
                    text("""
                    SELECT tenant_id, group_role_mapping, default_role, enabled
                      FROM aisoc_sso_connections
                     WHERE provider = :p AND issuer = :i AND enabled = TRUE
                     LIMIT 1
                """).bindparams(p=provider, i=issuer)
                )
            )
            .mappings()
            .first()
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("sso.connection_lookup_failed provider=%s error=%s", provider, _sanitize(exc))
        return None
    return dict(row) if row else None


async def provision_user(
    db: AsyncSession,
    *,
    tenant_id: Any,
    email: str,
    name: str | None,
    role: str,
    provider: str,
    subject: str,
) -> dict[str, Any]:
    """Find or create the local user this assertion names.

    Matching is on `(tenant_id, email)`. Not on the IdP subject, even
    though that is the stable identifier, because an organisation that
    moves from one IdP to another keeps its email addresses and would
    otherwise get a second account for every person.
    """
    existing = (
        (
            await db.execute(
                text("SELECT id, email, role, is_active FROM users WHERE tenant_id = :t AND lower(email) = lower(:e) LIMIT 1").bindparams(
                    t=tenant_id, e=email
                )
            )
        )
        .mappings()
        .first()
    )

    if existing:
        if not existing["is_active"]:
            # A deactivated account must not be revived by signing in.
            # Deactivation is how an operator removes access, and SSO
            # re-creating it on the next sign-in would make that useless.
            raise SsoProvisioningError(f"account {email} is deactivated")
        # The role is refreshed from the IdP on every sign-in, so removing
        # someone from a group takes effect at their next login rather than
        # requiring a second manual step.
        if existing["role"] != role:
            await db.execute(
                text("UPDATE users SET role = :r, updated_at = :now WHERE id = :id").bindparams(
                    r=role, now=datetime.now(UTC), id=existing["id"]
                )
            )
            logger.info(
                "sso.role_refreshed email=%s from=%s to=%s",
                _sanitize(email, 80),
                _sanitize(existing["role"], 40),
                _sanitize(role, 40),
            )
        return {"id": existing["id"], "email": existing["email"], "role": role, "created": False}

    user_id = uuid.uuid4()
    now = datetime.now(UTC)
    await db.execute(
        # `username`, not `full_name`. The first draft invented a column
        # name and `check_raw_sql_columns.py` caught it: the insert would
        # have raised at runtime on the first SSO sign-in, which is exactly
        # the path that has no other test coverage.
        text("""
            INSERT INTO users (id, tenant_id, email, username, role, is_active,
                               hashed_password, created_at, updated_at)
            VALUES (:id, :t, :e, :n, :r, TRUE, :pw, :now, :now)
        """).bindparams(
            id=user_id,
            t=tenant_id,
            e=email,
            n=name or email.split("@")[0],
            r=role,
            # No password. An SSO-provisioned account must not be
            # signable-into with a password, and an empty hash matches
            # nothing `verify_password` can be given.
            pw="!sso-no-password",
            now=now,
        )
    )
    logger.info(
        "sso.user_provisioned email=%s role=%s provider=%s",
        _sanitize(email, 80),
        _sanitize(role, 40),
        _sanitize(provider, 20),
    )
    return {"id": user_id, "email": email, "role": role, "created": True}


async def complete_sso_login(
    db: AsyncSession,
    *,
    provider: str,
    issuer: str,
    email: str,
    subject: str,
    name: str | None = None,
    groups: list[str] | None = None,
) -> dict[str, Any]:
    """The whole path: assertion to a token the API actually verifies.

    Returns `{access_token, refresh_token, role, user_id, tenant_id}`.
    """
    if not email:
        raise SsoProvisioningError("the assertion carried no email, so no local user can be named")

    connection = await resolve_connection(db, provider=provider, issuer=issuer)
    if connection is None:
        raise SsoProvisioningError(
            f"no enabled SSO connection is configured for issuer {issuer!r}. "
            "The tenant is taken from the connection, never from the assertion."
        )

    mapping = connection.get("group_role_mapping") or {}
    if isinstance(mapping, str):
        import json

        try:
            mapping = json.loads(mapping)
        except ValueError:
            mapping = {}
    role = map_groups_to_role(groups or [], mapping if isinstance(mapping, dict) else {})
    if not (groups or []):
        role = connection.get("default_role") or DEFAULT_ROLE
    if role not in ASSIGNABLE_ROLES:
        role = DEFAULT_ROLE

    user = await provision_user(
        db,
        tenant_id=connection["tenant_id"],
        email=email,
        name=name,
        role=role,
        provider=provider,
        subject=subject,
    )
    await db.commit()

    # The same claims `POST /auth/login` issues, signed with the same key,
    # so the API's own verifier accepts it. That is the whole point: the
    # previous token was signed with `JWT_SECRET`, carried no tenant or
    # role, and was put in a cookie the API does not read.
    claims = {
        "sub": str(user["id"]),
        "tenant_id": str(connection["tenant_id"]),
        "role": role,
        "email": user["email"],
    }
    return {
        "access_token": create_access_token(claims),
        "refresh_token": create_refresh_token(claims),
        "role": role,
        "user_id": str(user["id"]),
        "tenant_id": str(connection["tenant_id"]),
        "provisioned": user["created"],
    }
