"""Configure which identity provider signs a tenant's users in.

Wave 0 of the gap-closure plan.

`aisoc_sso_connections` has existed since migration 080 and nothing has
ever written to it. `sso_provisioning.resolve_connection` selects from it
on every SAML and OIDC sign-in and returns `None` when there is no row,
which raises `SsoProvisioningError` and answers **403**. So both SSO
paths were complete, tested, and unreachable: a deployment could not sign
a single user in through an identity provider without someone writing an
`INSERT` by hand.

Why the tenant lives here and not in the assertion
----------------------------------------------------
This is the design decision the table was built around, and it is worth
restating at the write path because this module is where it could be
undone. An identity provider that can name its own tenant can name
somebody else's, so the tenant is a property of the *connection* an
administrator configured. The assertion only says who the person is.

The same reasoning governs group mapping: an IdP group confers a role
only because an administrator in this deployment said it should.

What this refuses
-----------------
**A mapping to `admin` or `platform_admin`.** v14.0.0 made those
unreachable from every API route so that only `bootstrap_admin` can mint
one, and a group mapping would be a way back in — register an issuer,
claim a group, hold the wildcard. The check runs against
`role_grants.authorize_role_grant` rather than a local list, because a
second list would eventually disagree with the first.

**An issuer another tenant already claims.** The unique index enforces
it, but a 409 naming the conflict is more useful than an integrity
error, and it deliberately does not say which tenant holds it.

**A connection a caller cannot reach.** Every route is tenant-scoped on
the session, so one tenant cannot read, edit or delete another's
connection even knowing its id.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser, require_permission
from app.core import role_grants
from app.db.rls import TenantDBSession
from app.services.audit import emit_audit

router = APIRouter(prefix="/sso-connections", tags=["sso"])

#: Providers the two handlers in `app/auth/` implement. A value outside
#: this set would store cleanly and never match a sign-in, which is the
#: quiet-failure shape this whole wave exists to remove.
PROVIDERS = ("oidc", "saml")


class SsoConnectionIn(BaseModel):
    provider: str
    issuer: str = Field(min_length=1, max_length=512)
    display_name: str | None = Field(default=None, max_length=200)
    enabled: bool = False
    group_role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: str = "viewer"
    metadata_url: str | None = Field(default=None, max_length=1024)
    metadata_xml: str | None = None
    #: Comma-separated email domains provisioning is restricted to. Empty
    #: means unrestricted; anything outside a configured list is refused at
    #: the provisioning chokepoint, before any row is written.
    allowed_email_domains: str = Field(default="", max_length=2000)
    jit_provisioning: bool = True
    group_role_mode: str = "first_login_only"
    login_label: str = Field(default="", max_length=80)

    @field_validator("group_role_mode")
    @classmethod
    def _known_mode(cls, v: str) -> str:
        if v not in ("first_login_only", "authoritative"):
            raise ValueError("group_role_mode must be 'first_login_only' or 'authoritative'")
        return v

    @field_validator("provider")
    @classmethod
    def _known_provider(cls, v: str) -> str:
        if v not in PROVIDERS:
            raise ValueError(f"provider must be one of {list(PROVIDERS)}")
        return v


class SsoConnectionOut(BaseModel):
    id: str
    tenant_id: str
    provider: str
    issuer: str
    display_name: str | None
    enabled: bool
    group_role_mapping: dict[str, str]
    default_role: str
    allowed_email_domains: str
    jit_provisioning: bool
    group_role_mode: str
    login_label: str
    metadata_url: str | None
    #: Whether XML was supplied, never the XML itself. A SAML metadata
    #: document is not a secret, but it is large and echoing it on every
    #: list call is noise an operator has to scroll past.
    has_metadata_xml: bool
    created_at: str | None
    updated_at: str | None


def _row_to_out(row: Any) -> SsoConnectionOut:
    return SsoConnectionOut(
        id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        provider=row["provider"],
        issuer=row["issuer"],
        display_name=row["display_name"],
        enabled=bool(row["enabled"]),
        group_role_mapping=dict(row["group_role_mapping"] or {}),
        default_role=row["default_role"],
        allowed_email_domains=row.get("allowed_email_domains") or "",
        jit_provisioning=bool(row.get("jit_provisioning", True)),
        group_role_mode=str(row.get("group_role_mode") or "first_login_only"),
        login_label=str(row.get("login_label") or ""),
        metadata_url=row["metadata_url"],
        has_metadata_xml=bool(row["metadata_xml"]),
        created_at=row["created_at"].isoformat() if row["created_at"] else None,
        updated_at=row["updated_at"].isoformat() if row["updated_at"] else None,
    )


def _assert_roles_grantable(caller: AuthUser, body: SsoConnectionIn) -> None:
    """Refuse a mapping that would confer more than the caller holds.

    Checked against the shared `role_grants` authority rather than a
    local allow-list. A connection is a standing grant to everyone who
    can authenticate against that issuer, so it must be held to at least
    the same bar as creating one user with that role.
    """
    wanted = {body.default_role, *body.group_role_mapping.values()}
    for role in sorted(wanted):
        try:
            role_grants.authorize_role_grant(
                granter_role=getattr(caller, "role", "viewer"),
                granter_scopes=getattr(caller, "scopes", None),
                granter_permissions=getattr(caller, "resolved_permissions", None),
                requested_role=role,
            )
        except role_grants.RoleGrantDenied as denied:
            # 422 for a role outside the vocabulary, 403 for one the caller
            # simply cannot confer. The distinction matters: the first is a
            # typo, the second is an authorization decision.
            raise HTTPException(
                status_code=(status.HTTP_422_UNPROCESSABLE_ENTITY if denied.unknown else status.HTTP_403_FORBIDDEN),
                detail=f"this connection would map users to {role!r}: {denied}",
            ) from denied


@router.get("", response_model=list[SsoConnectionOut])
async def list_sso_connections(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: TenantDBSession,
) -> list[SsoConnectionOut]:
    """Every SSO connection this tenant has configured."""
    rows = (
        (
            await db.execute(
                text("""
                SELECT id, tenant_id, provider, issuer, display_name, enabled,
                       group_role_mapping, default_role, metadata_url, metadata_xml,
                       allowed_email_domains, jit_provisioning, group_role_mode, login_label,
                       created_at, updated_at
                  FROM aisoc_sso_connections
                 WHERE tenant_id = CAST(:t AS uuid)
                 ORDER BY created_at DESC
            """).bindparams(t=str(current_user.tenant_id))
            )
        )
        .mappings()
        .all()
    )
    return [_row_to_out(r) for r in rows]


@router.post("", response_model=SsoConnectionOut, status_code=status.HTTP_201_CREATED)
async def create_sso_connection(
    body: SsoConnectionIn,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: TenantDBSession,
) -> SsoConnectionOut:
    """Configure an identity provider for this tenant.

    Until one of these exists, every SAML and OIDC sign-in answers 403 —
    `resolve_connection` finds no row and refuses rather than guessing a
    tenant from the assertion.
    """
    _assert_roles_grantable(current_user, body)

    # The conflict is detected by letting the unique index raise, not by
    # a SELECT first. Two reasons, and the tenant-predicate gate found
    # the first:
    #
    # A cross-tenant `SELECT 1 ... WHERE issuer = :i` cannot work here.
    # The session runs as the DML-only role with a bound tenant, so RLS
    # shows it only this tenant's rows — it would miss the very case it
    # exists to catch and then fail on the insert anyway, with a raw
    # integrity error instead of a 409.
    #
    # And check-then-insert is a race: two tenants registering one issuer
    # at the same moment both see nothing and both proceed.
    try:
        row = (
            (
                await db.execute(
                    text("""
                    INSERT INTO aisoc_sso_connections
                        (tenant_id, provider, issuer, display_name, enabled,
                         group_role_mapping, default_role, metadata_url, metadata_xml,
                         allowed_email_domains, jit_provisioning, group_role_mode, login_label)
                    VALUES (CAST(:t AS uuid), :p, :i, :d, :e,
                            CAST(:m AS jsonb), :r, :mu, :mx,
                            :dom, :jit, :mode, :label)
                    RETURNING id, tenant_id, provider, issuer, display_name, enabled,
                              group_role_mapping, default_role, metadata_url, metadata_xml,
                              allowed_email_domains, jit_provisioning, group_role_mode, login_label,
                              created_at, updated_at
                """).bindparams(
                        t=str(current_user.tenant_id),
                        p=body.provider,
                        i=body.issuer,
                        d=body.display_name,
                        e=body.enabled,
                        m=json.dumps(body.group_role_mapping),
                        r=body.default_role,
                        mu=body.metadata_url,
                        mx=body.metadata_xml,
                        dom=body.allowed_email_domains,
                        jit=body.jit_provisioning,
                        mode=body.group_role_mode,
                        label=body.login_label,
                    )
                )
            )
            .mappings()
            .first()
        )
    except IntegrityError as exc:
        await db.rollback()
        # Deliberately does not say which tenant holds it.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"issuer {body.issuer!r} is already registered for {body.provider}",
        ) from exc

    if row is None:  # pragma: no cover - RETURNING always yields on success
        raise HTTPException(status_code=500, detail="connection was not created")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="sso.connection_created",
        resource="sso_connection",
        resource_id=str(row["id"]),
        changes={
            "provider": body.provider,
            "issuer": body.issuer,
            "enabled": body.enabled,
            "default_role": body.default_role,
            "group_role_mode": body.group_role_mode,
        },
    )
    await db.commit()
    return _row_to_out(row)


@router.patch("/{connection_id}", response_model=SsoConnectionOut)
async def update_sso_connection(
    connection_id: uuid.UUID,
    body: SsoConnectionIn,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: TenantDBSession,
) -> SsoConnectionOut:
    """Replace a connection's configuration.

    The tenant is not settable: moving a connection between tenants would
    silently re-home every user who signs in through it.
    """
    _assert_roles_grantable(current_user, body)

    row = (
        (
            await db.execute(
                text("""
                UPDATE aisoc_sso_connections
                   SET provider = :p, issuer = :i, display_name = :d, enabled = :e,
                       group_role_mapping = CAST(:m AS jsonb), default_role = :r,
                       metadata_url = :mu, metadata_xml = :mx,
                       allowed_email_domains = :dom, jit_provisioning = :jit,
                       group_role_mode = :mode, login_label = :label, updated_at = NOW()
                 WHERE id = CAST(:id AS uuid) AND tenant_id = CAST(:t AS uuid)
                RETURNING id, tenant_id, provider, issuer, display_name, enabled,
                          group_role_mapping, default_role, metadata_url, metadata_xml,
                          allowed_email_domains, jit_provisioning, group_role_mode, login_label,
                          created_at, updated_at
            """).bindparams(
                    id=str(connection_id),
                    t=str(current_user.tenant_id),
                    p=body.provider,
                    i=body.issuer,
                    d=body.display_name,
                    e=body.enabled,
                    m=json.dumps(body.group_role_mapping),
                    r=body.default_role,
                    mu=body.metadata_url,
                    mx=body.metadata_xml,
                    dom=body.allowed_email_domains,
                    jit=body.jit_provisioning,
                    mode=body.group_role_mode,
                    label=body.login_label,
                )
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="connection not found")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="sso.connection_updated",
        resource="sso_connection",
        resource_id=str(connection_id),
        changes={
            "enabled": body.enabled,
            "default_role": body.default_role,
            "group_role_mapping": body.group_role_mapping,
            "group_role_mode": body.group_role_mode,
        },
    )
    await db.commit()
    return _row_to_out(row)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_sso_connection(
    connection_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: TenantDBSession,
) -> None:
    """Remove a connection. Sign-ins through that issuer start answering 403 again."""
    result = await db.execute(
        text("""
        DELETE FROM aisoc_sso_connections
         WHERE id = CAST(:id AS uuid) AND tenant_id = CAST(:t AS uuid)
    """).bindparams(id=str(connection_id), t=str(current_user.tenant_id))
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="connection not found")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="sso.connection_deleted",
        resource="sso_connection",
        resource_id=str(connection_id),
    )
    await db.commit()
