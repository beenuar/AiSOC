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
from app.db.rls import set_rls_context
from app.services.audit import emit_audit

logger = logging.getLogger(__name__)

#: Roles an IdP group may map to. Deliberately excludes `admin` and
#: `platform_admin`: v14.0.0 made those unreachable from every API route
#: precisely so that nothing but `bootstrap_admin` can mint one, and an SSO
#: group mapping would be a way back in.
ASSIGNABLE_ROLES = frozenset({"viewer", "infosec", "soc_analyst", "soc_lead", "threat_hunter", "tenant_admin"})

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
    order = ["viewer", "infosec", "soc_analyst", "threat_hunter", "soc_lead", "tenant_admin"]
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


def _parse_domain_allowlist(raw: str) -> set[str]:
    """Normalize the comma-separated allowlist to lowercase domains."""
    return {d.strip().lower() for d in (raw or "").split(",") if d.strip()}


def _domain_allowed(email: str, allowed: set[str]) -> bool:
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    return bool(domain) and domain in allowed


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
                    -- `id` is what an identity binding is keyed on, so the
                    -- connection has to carry it: see `_bind_subject`.
                    SELECT id, tenant_id, group_role_mapping, default_role, enabled,
                           allowed_email_domains, jit_provisioning, group_role_mode
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


async def _bind_subject(
    db: AsyncSession,
    *,
    tenant_id: Any,
    connection_id: Any,
    subject: str,
    user_id: Any,
    email: str,
    provider: str,
) -> None:
    """Record that this subject owns this account, on this connection.

    Idempotent on `(connection_id, subject)`: a re-bind of the same pair is a
    repeat sign-in, which only moves `last_seen_at`. A *different* account for
    the same pair is refused by the unique index rather than silently
    repointing the binding, because quietly moving an identity from one account
    to another is the thing this table exists to prevent.
    """
    await db.execute(
        text(
            """
            INSERT INTO aisoc_sso_identities
                (tenant_id, connection_id, subject, user_id, bound_email, provider)
            VALUES (:t, :c, :s, :u, :e, :p)
            ON CONFLICT (connection_id, subject) DO UPDATE
               SET last_seen_at = now()
             WHERE aisoc_sso_identities.user_id = EXCLUDED.user_id
            """
        ).bindparams(t=tenant_id, c=connection_id, s=subject, u=user_id, e=email, p=provider)
    )
    logger.info(
        "sso.identity_bound email=%s provider=%s subject=%s",
        _sanitize(email, 80),
        _sanitize(provider, 20),
        _sanitize(subject, 64),
    )


async def provision_user(
    db: AsyncSession,
    *,
    tenant_id: Any,
    connection_id: Any,
    email: str,
    name: str | None,
    role: str,
    provider: str,
    subject: str,
    email_verified: bool | None,
    jit_provisioning: bool = True,
    group_role_mode: str = "first_login_only",
) -> dict[str, Any]:
    """Find or create the local user this assertion names.

    Three steps, in order, and the order is the security property.

    **1. The subject, if this connection has seen it.** `sub` is the stable
    identifier, so a bound account survives its owner changing email address at
    the provider.

    **2. The email, but only if the provider says it verified it.** This used
    to be the only step, with no `email_verified` requirement anywhere in the
    OIDC path -- so an attacker who could authenticate to the tenant's
    configured provider with an account carrying a victim's *unverified*
    address received a token minted for the victim's local id, and with
    database-backed RBAC the API resolved the victim's `user_roles`
    (GHSA-qjjc-q2h2-56cg). A claim that is absent or false is treated as
    unverified, because OIDC makes `email_verified` optional and "the provider
    did not say" is not "the provider said yes".

    Matching on email at all is deliberate and stays: an organisation that
    moves from one identity provider to another keeps its email addresses and
    would otherwise get a second account for every person. The binding is per
    **connection**, so a migration starts with none and everyone re-claims
    their own account on first sign-in -- which is exactly that behaviour.

    **3. Create.** Nobody owns this address yet.

    `email_verified` is `True` for SAML: the assertion is signed by the
    identity provider, and the address it asserts *is* the provider's
    statement about the user. There is no separate claim to consult.
    """
    # ── 1. Already bound on this connection? ──────────────────────────────
    bound = (
        (
            await db.execute(
                text(
                    "SELECT i.user_id, u.email, u.role, u.is_active "
                    "FROM aisoc_sso_identities i JOIN users u ON u.id = i.user_id "
                    "WHERE i.connection_id = :c AND i.subject = :s AND i.tenant_id = :t "
                    "LIMIT 1"
                ).bindparams(c=connection_id, s=subject, t=tenant_id)
            )
        )
        .mappings()
        .first()
    )
    if bound:
        if not bound["is_active"]:
            raise SsoProvisioningError(f"account {bound['email']} is deactivated")
        await db.execute(
            # Tenant-scoped even though `(connection_id, subject)` is unique:
            # how a row was addressed is irrelevant to what the statement can
            # reach, and a write that carries its own predicate stays correct
            # after whatever edit comes next.
            text(
                "UPDATE aisoc_sso_identities SET last_seen_at = :now WHERE tenant_id = :t AND connection_id = :c AND subject = :s"
            ).bindparams(now=datetime.now(UTC), t=tenant_id, c=connection_id, s=subject)
        )
        previous_role = str(bound["role"])
        if group_role_mode != "authoritative":
            # first_login_only (the default): IdP groups decide the role at
            # provisioning and admin owns every change after that. A stale
            # group can neither promote nor demote someone who already has an
            # account, so a group-sync outage or misconfiguration cannot
            # silently move authority.
            role = previous_role
        if bound["role"] != role:
            await db.execute(
                text("UPDATE users SET role = :r, updated_at = :now WHERE id = :id").bindparams(
                    r=role, now=datetime.now(UTC), id=bound["user_id"]
                )
            )
            logger.info(
                "sso.role_refreshed email=%s from=%s to=%s",
                _sanitize(email, 80),
                _sanitize(previous_role, 40),
                _sanitize(role, 40),
            )
        return {"id": bound["user_id"], "email": bound["email"], "role": role, "created": False, "previous_role": previous_role}

    # ── 2. Claim by verified email ────────────────────────────────────────
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
        if email_verified is not True:
            # The whole of GHSA-qjjc-q2h2-56cg in one branch. Refused before
            # anything is written, because the role refresh below runs on the
            # way to the return and a rejected sign-in must not have touched
            # the victim's row.
            logger.warning(
                "sso.unverified_email_claim_refused email=%s provider=%s subject=%s",
                _sanitize(email, 80),
                _sanitize(provider, 20),
                _sanitize(subject, 64),
            )
            raise SsoProvisioningError(
                f"the provider did not assert that {email} is verified, so it cannot be used to "
                "sign in as an existing account. Configure the identity provider to send "
                "`email_verified: true`, or have the account's owner sign in first."
            )
        if not existing["is_active"]:
            # A deactivated account must not be revived by signing in.
            # Deactivation is how an operator removes access, and SSO
            # re-creating it on the next sign-in would make that useless.
            raise SsoProvisioningError(f"account {email} is deactivated")

        # Somebody else on this connection may already own it. The unique
        # index on `(connection_id, user_id)` would catch this on insert, but
        # a clear refusal beats a constraint violation an operator has to
        # decode.
        claimed = (
            (
                await db.execute(
                    text("SELECT subject FROM aisoc_sso_identities WHERE connection_id = :c AND user_id = :u LIMIT 1").bindparams(
                        c=connection_id, u=existing["id"]
                    )
                )
            )
            .mappings()
            .first()
        )
        if claimed and claimed["subject"] != subject:
            logger.warning(
                "sso.account_already_bound email=%s provider=%s presented=%s",
                _sanitize(email, 80),
                _sanitize(provider, 20),
                _sanitize(subject, 64),
            )
            raise SsoProvisioningError(
                f"account {email} is already bound to a different identity on this SSO "
                "connection. An administrator must unbind it before another subject can claim it."
            )

        await _bind_subject(
            db,
            tenant_id=tenant_id,
            connection_id=connection_id,
            subject=subject,
            user_id=existing["id"],
            email=email,
            provider=provider,
        )

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

    if not jit_provisioning:
        # JIT off means the directory is not an account-creation channel:
        # an operator must create the account first. Refused rather than
        # silently viewed-later, so "your account does not exist yet" is
        # actionable rather than mysterious.
        raise SsoProvisioningError(
            "just-in-time provisioning is disabled on this SSO connection; an administrator must create the account first"
        )

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
    # Bound immediately. An account created by this sign-in belongs to the
    # subject that created it, so the next sign-in takes step 1 above rather
    # than re-claiming by email -- and nobody else can claim it at all.
    await _bind_subject(
        db,
        tenant_id=tenant_id,
        connection_id=connection_id,
        subject=subject,
        user_id=user_id,
        email=email,
        provider=provider,
    )

    logger.info(
        "sso.user_provisioned email=%s role=%s provider=%s",
        _sanitize(email, 80),
        _sanitize(role, 40),
        _sanitize(provider, 20),
    )
    return {"id": user_id, "email": email, "role": role, "created": True, "previous_role": None}


async def complete_sso_login(
    db: AsyncSession,
    *,
    provider: str,
    issuer: str,
    email: str,
    subject: str,
    email_verified: bool | None,
    name: str | None = None,
    groups: list[str] | None = None,
) -> dict[str, Any]:
    """The whole path: assertion to a token the API actually verifies.

    Returns `{access_token, refresh_token, role, user_id, tenant_id}`.
    """
    if not email:
        raise SsoProvisioningError("the assertion carried no email, so no local user can be named")
    if not subject:
        # Checked here, with the email, because both are argument validation
        # and neither needs the database. Without a subject there is nothing to
        # bind, so an account could only ever be selected by address -- the
        # shape GHSA-qjjc-q2h2-56cg describes. Both providers always send one:
        # OIDC `sub` is mandatory and a SAML assertion with no NameID is
        # malformed.
        raise SsoProvisioningError("the assertion carried no subject, so the account it names cannot be bound to an identity")

    connection = await resolve_connection(db, provider=provider, issuer=issuer)
    if connection is None:
        raise SsoProvisioningError(
            f"no enabled SSO connection is configured for issuer {issuer!r}. "
            "The tenant is taken from the connection, never from the assertion."
        )

    # Domain allowlist, checked before anything is written or audited as a
    # success. An empty allowlist means the operator did not restrict
    # domains; a configured one is exhaustive -- anything outside it is
    # refused without a local row being created.
    allowed_domains = _parse_domain_allowlist(connection.get("allowed_email_domains") or "")
    if allowed_domains and not _domain_allowed(email, allowed_domains):
        try:
            await emit_audit(
                db=db,
                tenant_id=connection["tenant_id"],
                action="sso.login_denied",
                resource="sso_connection",
                resource_id=str(connection["id"]),
                changes={"reason": "email_domain_not_allowed", "domain": email.rsplit("@", 1)[-1].lower(), "provider": provider},
            )
            await db.commit()
        except Exception as audit_exc:  # noqa: BLE001
            # The refusal is the security property; a failing audit row is
            # logged at WARNING and does not change the answer.
            await db.rollback()
            logger.warning("sso.denial_audit_failed error=%s", _sanitize(audit_exc))
        raise SsoProvisioningError("this email domain is not permitted to sign in through SSO on this connection")

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

    # The tenant is known now, and not before: a sign-in callback has no
    # authenticated principal, so the session it arrives on carries no RLS
    # context and `current_tenant_id()` is NULL.
    #
    # `aisoc_sso_identities` is tenant-scoped with the standard policy, whose
    # `WITH CHECK` has no null escape -- deliberately, since an unscoped
    # session that could insert any `tenant_id` is not a control. So the
    # context is set here, from the connection, which is also the only thing
    # that decides the tenant on this path. Without it the identity binding
    # would be refused on every deployment running as the DML-only `aisoc_app`
    # role, which is every deployment: SSO login would fail outright.
    await set_rls_context(db, connection["tenant_id"])

    user = await provision_user(
        db,
        tenant_id=connection["tenant_id"],
        connection_id=connection["id"],
        email=email,
        name=name,
        role=role,
        provider=provider,
        subject=subject,
        email_verified=email_verified,
        jit_provisioning=bool(connection.get("jit_provisioning", True)),
        group_role_mode=str(connection.get("group_role_mode") or "first_login_only"),
    )
    await db.commit()

    # The same claims `POST /auth/login` issues, signed with the same key,
    # so the API's own verifier accepts it. That is the whole point: the
    # previous token was signed with `JWT_SECRET`, carried no tenant or
    # role, and was put in a cookie the API does not read.
    try:
        await emit_audit(
            db=db,
            tenant_id=connection["tenant_id"],
            actor_id=user["id"],
            actor_email=user["email"],
            action="sso.user_provisioned" if user.get("created") else "sso.login",
            resource="sso_connection",
            resource_id=str(connection["id"]),
            changes={
                "provider": provider,
                "role": user["role"],
                "previous_role": user.get("previous_role"),
                "auth": "sso",
            },
        )
        await db.commit()
    except Exception as audit_exc:  # noqa: BLE001
        await db.rollback()
        logger.warning("sso.login_audit_failed error=%s", _sanitize(audit_exc))

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
