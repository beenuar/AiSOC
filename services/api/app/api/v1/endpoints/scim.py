"""SCIM 2.0 provisioning endpoints (RFC 7643, RFC 7644).

Mounted outside ``/api/v1``. Identity providers are configured with a base
URL and append ``/Users`` and ``/Groups`` to it, so the path has to be the
one an administrator can paste, and the discovery documents have to describe
the same place.

Three properties hold across every handler here
------------------------------------------------
* **The tenant comes from the credential.** ``ScimAuth`` resolves a bearer
  token to a row, and that row carries the tenant. No handler reads a tenant
  from a path, a query or a body, and there is no SCIM attribute that could
  carry one.
* **Every write is audited.** Each mutating handler emits an ``scim:*``
  action through the existing hash-chained audit log, with the token name as
  the actor. The actor of a SCIM change is a machine, and an audit trail that
  cannot say which machine is not one.
* **Responses are SCIM-shaped.** Errors carry the RFC 7644 error schema and
  the ``application/scim+json`` content type, because a provider that
  receives a FastAPI validation error surfaces "unexpected response" to an
  administrator with nothing actionable in it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.scim import ScimGroup, ScimGroupMember, ScimUser
from app.models.tenant import User
from app.services.audit import emit_audit
from app.services.scim import filters as scim_filters
from app.services.scim import patch as scim_patch
from app.services.scim import provisioning, resources, roles, tokens

router = APIRouter(prefix=resources.SCIM_BASE, tags=["scim"])

_bearer = HTTPBearer(auto_error=False)


class ScimResponse(JSONResponse):
    """A response labelled ``application/scim+json``.

    Some provisioning clients reject ``application/json`` on a SCIM path.
    """

    media_type = resources.SCIM_CONTENT_TYPE


def _error(status_code: int, detail: str, *, scim_type: str | None = None) -> ScimResponse:
    return ScimResponse(status_code=status_code, content=resources.error_response(status_code, detail, scim_type=scim_type))


class ScimAuthFailed(Exception):
    """Raised by the dependency so the handler chain returns a SCIM error."""


async def scim_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> tokens.ScimPrincipal:
    """Resolve the bearer credential to a principal, or refuse.

    The 401 body is deliberately undifferentiated. The reason is recorded
    server-side; telling an unauthenticated caller whether a secret was
    wrong, revoked or expired tells it which secrets exist.
    """
    if credentials is None:
        raise ScimAuthFailed("no bearer credential presented")
    try:
        return await tokens.verify_token(db, credentials.credentials)
    except tokens.ScimAuthError as exc:
        raise ScimAuthFailed(exc.reason) from exc


ScimAuth = Annotated[tokens.ScimPrincipal, Depends(scim_principal)]
ScimDB = Annotated[AsyncSession, Depends(get_db)]


async def _audit(
    db: AsyncSession,
    principal: tokens.ScimPrincipal,
    request: Request,
    *,
    action: str,
    resource: str,
    resource_id: str | None,
    changes: dict[str, Any] | None = None,
) -> None:
    """Record one SCIM operation.

    ``actor_id`` is null because the actor is not a person. The credential's
    name and id go into ``changes`` so the trail can answer which
    integration made the change, which is the question an incident review
    asks first.

    The key is ``provisioned_by`` rather than anything containing "token",
    and the count below is ``programmatic_access_revoked`` rather than
    anything containing "api_key". ``audit_redaction`` masks values under
    secret-shaped keys, correctly, and neither of these values is a secret:
    naming them that way would replace the only two facts this record exists
    to carry with ``[REDACTED]`` while the row still looked complete.
    """
    payload = dict(changes or {})
    payload["provisioned_by"] = {"integration_id": str(principal.token_id), "integration": principal.token_name}
    if principal.org_id is not None:
        payload["org_id"] = str(principal.org_id)
    await emit_audit(
        db=db,
        tenant_id=principal.tenant_id,
        actor_id=None,
        actor_email=f"scim:{principal.token_name}",
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=payload,
        request=request,
    )


# ── Discovery ─────────────────────────────────────────────────────────────
#
# Authenticated like everything else. RFC 7644 permits these to be
# anonymous, and both supported providers send the credential anyway. An
# anonymous discovery endpoint would publish which SCIM features a
# deployment has enabled to anyone who asks.


@router.get("/ServiceProviderConfig")
async def get_service_provider_config(principal: ScimAuth) -> ScimResponse:
    del principal
    return ScimResponse(content=resources.service_provider_config())


@router.get("/ResourceTypes")
async def list_resource_types(principal: ScimAuth) -> ScimResponse:
    del principal
    types = resources.resource_types()
    return ScimResponse(content=resources.list_response(types, total=len(types), start_index=1, count=len(types)))


@router.get("/ResourceTypes/{resource_type_id}")
async def get_resource_type(resource_type_id: str, principal: ScimAuth) -> ScimResponse:
    del principal
    for entry in resources.resource_types():
        if entry["id"].casefold() == resource_type_id.casefold():
            return ScimResponse(content=entry)
    return _error(status.HTTP_404_NOT_FOUND, f"no resource type {resource_type_id!r}")


@router.get("/Schemas")
async def list_schemas(principal: ScimAuth) -> ScimResponse:
    del principal
    docs = resources.schemas()
    return ScimResponse(content=resources.list_response(docs, total=len(docs), start_index=1, count=len(docs)))


@router.get("/Schemas/{schema_id:path}")
async def get_schema(schema_id: str, principal: ScimAuth) -> ScimResponse:
    del principal
    for doc in resources.schemas():
        if doc["id"].casefold() == schema_id.casefold():
            return ScimResponse(content=doc)
    return _error(status.HTTP_404_NOT_FOUND, f"no schema {schema_id!r}")


# ── Shared helpers ────────────────────────────────────────────────────────


async def _load_scim_user(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> tuple[User, ScimUser | None] | None:
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None
    meta = await db.execute(select(ScimUser).where(ScimUser.user_id == user.id, ScimUser.tenant_id == tenant_id))
    return user, meta.scalar_one_or_none()


async def _user_groups(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
    rows = await db.execute(
        select(ScimGroup.id, ScimGroup.display_name)
        .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
        .where(
            ScimGroupMember.user_id == user_id,
            ScimGroupMember.tenant_id == tenant_id,
            ScimGroup.tenant_id == tenant_id,
        )
        .order_by(ScimGroup.display_name)
    )
    return [(row[0], row[1]) for row in rows.all()]


async def _render_user(db: AsyncSession, user: User, meta: ScimUser | None) -> dict[str, Any]:
    return resources.user_resource(
        user_id=user.id,
        user_name=user.email,
        active=user.is_active,
        external_id=meta.external_id if meta else None,
        given_name=meta.given_name if meta else None,
        family_name=meta.family_name if meta else None,
        created_at=user.created_at,
        updated_at=meta.updated_at if meta else user.created_at,
        groups=await _user_groups(db, user.tenant_id, user.id),
    )


async def _group_members(db: AsyncSession, tenant_id: uuid.UUID, group_id: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
    rows = await db.execute(
        select(User.id, User.email)
        .join(ScimGroupMember, ScimGroupMember.user_id == User.id)
        .where(
            ScimGroupMember.group_id == group_id,
            ScimGroupMember.tenant_id == tenant_id,
            User.tenant_id == tenant_id,
        )
        .order_by(User.email)
    )
    return [(row[0], row[1]) for row in rows.all()]


async def _render_group(db: AsyncSession, group: ScimGroup) -> dict[str, Any]:
    return resources.group_resource(
        group_id=group.id,
        display_name=group.display_name,
        external_id=group.external_id,
        mapped_role=group.mapped_role,
        created_at=group.created_at,
        updated_at=group.updated_at,
        members=await _group_members(db, group.tenant_id, group.id),
    )


def _paging(start_index: int, count: int) -> tuple[int, int]:
    """Clamp SCIM's one-based paging to something a query can use."""
    start = max(start_index, 1)
    size = min(max(count, 1), resources.MAX_PAGE_SIZE)
    return start, size


def _string_attr(value: Any) -> str | None:
    """Read an attribute a provider may send as a string or omit."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _extract_names(body: dict[str, Any]) -> tuple[str | None, str | None]:
    name = body.get("name")
    if not isinstance(name, dict):
        return None, None
    given = family = None
    for key, value in name.items():
        if not isinstance(key, str):
            continue
        folded = key.casefold()
        if folded == "givenname":
            given = _string_attr(value)
        elif folded == "familyname":
            family = _string_attr(value)
    return given, family


def _extract_username(body: dict[str, Any]) -> str | None:
    """Read ``userName``, falling back to a primary work email.

    One provider omits ``userName`` when the directory's username attribute
    is unset and sends only ``emails``. Without the fallback that create
    fails with a validation error the administrator reads as "SCIM is
    broken".
    """
    for key, value in body.items():
        if isinstance(key, str) and key.casefold() == "username":
            found = _string_attr(value)
            if found:
                return found
    emails = body.get("emails")
    if isinstance(emails, list):
        primary = None
        first = None
        for entry in emails:
            if not isinstance(entry, dict):
                continue
            value = _string_attr(entry.get("value"))
            if value is None:
                continue
            first = first or value
            if entry.get("primary") is True:
                primary = primary or value
        return primary or first
    return None


def _extract_active(body: dict[str, Any], *, default: bool) -> bool:
    for key, value in body.items():
        if isinstance(key, str) and key.casefold() == "active":
            if value is None:
                return default
            return scim_patch.coerce_bool(value, attribute="active")
    return default


# ── Users ─────────────────────────────────────────────────────────────────


@router.get("/Users")
async def list_users(
    principal: ScimAuth,
    db: ScimDB,
    filter_: Annotated[str | None, Query(alias="filter")] = None,
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(alias="count", ge=0)] = resources.DEFAULT_PAGE_SIZE,
) -> ScimResponse:
    """List or look up principals.

    A provider calls this with a filter before every create, so the
    filter path is the hot one and an unsupported filter must be an error
    rather than a full listing.
    """
    try:
        parsed = scim_filters.parse_equality(filter_, scim_filters.USER_FILTER_ATTRS)
    except scim_filters.ScimFilterError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    stmt = select(User).where(User.tenant_id == principal.tenant_id)
    if parsed is not None:
        if parsed.attribute == "username":
            stmt = stmt.where(func.lower(User.email) == parsed.value.strip().casefold())
        elif parsed.attribute == "external_id":
            stmt = stmt.join(ScimUser, ScimUser.user_id == User.id).where(
                ScimUser.external_id == parsed.value, ScimUser.tenant_id == principal.tenant_id
            )
        elif parsed.attribute == "id":
            try:
                stmt = stmt.where(User.id == uuid.UUID(parsed.value))
            except ValueError:
                return ScimResponse(content=resources.list_response([], total=0, start_index=start_index, count=0))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    start, size = _paging(start_index, count)
    rows = await db.execute(stmt.order_by(User.created_at, User.id).offset(start - 1).limit(size))
    users = list(rows.scalars().all())

    rendered = []
    for user in users:
        meta = await db.execute(select(ScimUser).where(ScimUser.user_id == user.id, ScimUser.tenant_id == principal.tenant_id))
        rendered.append(await _render_user(db, user, meta.scalar_one_or_none()))

    return ScimResponse(content=resources.list_response(rendered, total=int(total), start_index=start, count=size))


@router.get("/Users/{user_id}")
async def get_user(user_id: str, principal: ScimAuth, db: ScimDB) -> ScimResponse:
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    found = await _load_scim_user(db, principal.tenant_id, parsed_id)
    if found is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    user, meta = found
    return ScimResponse(content=await _render_user(db, user, meta))


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Create a principal, or return the existing one.

    A repeated create for a ``userName`` that already exists is answered
    409, which is what RFC 7644 specifies and what a provider uses to
    reconcile. Creating a second principal for the same address instead
    would give one person two accounts with two sets of permissions.
    """
    if not isinstance(body, dict):
        return _error(status.HTTP_400_BAD_REQUEST, "request body must be a JSON object")

    user_name = _extract_username(body)
    if not user_name:
        return _error(status.HTTP_400_BAD_REQUEST, "userName is required", scim_type="invalidValue")

    try:
        active = _extract_active(body, default=True)
    except scim_patch.ScimPatchError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    external_id = _string_attr(body.get("externalId"))
    given, family = _extract_names(body)

    existing = await provisioning.find_user_by_username(db, principal.tenant_id, user_name)
    if existing is not None:
        return _error(status.HTTP_409_CONFLICT, f"userName {user_name!r} already exists", scim_type="uniqueness")

    # No password is set. A provisioned principal signs in through the
    # identity provider; an unusable hash means the password route cannot be
    # used to reach this account at all. `bcrypt` never produces a digest
    # that verifies against this value.
    user = User(
        tenant_id=principal.tenant_id,
        email=user_name,
        username=user_name,
        hashed_password="!scim-provisioned-no-password",
        role=provisioning.default_role(),
        is_active=active,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    meta = ScimUser(
        user_id=user.id,
        tenant_id=principal.tenant_id,
        external_id=external_id,
        given_name=given,
        family_name=family,
        token_id=principal.token_id,
    )
    db.add(meta)
    await db.flush()

    await _audit(
        db,
        principal,
        request,
        action="scim:user:create",
        resource="user",
        resource_id=str(user.id),
        changes={"user_name": user_name, "external_id": external_id, "active": active, "role": user.role},
    )
    await db.commit()

    return ScimResponse(status_code=status.HTTP_201_CREATED, content=await _render_user(db, user, meta))


@router.put("/Users/{user_id}")
async def replace_user(user_id: str, body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Replace a principal's attributes.

    One provider sends PUT for ordinary profile updates and for
    deactivation, so this path has to handle ``active: false`` with the same
    consequences the PATCH path gives it.
    """
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    found = await _load_scim_user(db, principal.tenant_id, parsed_id)
    if found is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    user, meta = found

    if not isinstance(body, dict):
        return _error(status.HTTP_400_BAD_REQUEST, "request body must be a JSON object")

    try:
        active = _extract_active(body, default=user.is_active)
    except scim_patch.ScimPatchError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    changes: dict[str, Any] = {}
    user_name = _extract_username(body)
    if user_name and user_name.casefold() != user.email.casefold():
        clash = await provisioning.find_user_by_username(db, principal.tenant_id, user_name)
        if clash is not None and clash.id != user.id:
            return _error(status.HTTP_409_CONFLICT, f"userName {user_name!r} already exists", scim_type="uniqueness")
        changes["user_name"] = {"from": user.email, "to": user_name}
        user.email = user_name
        user.username = user_name

    if meta is None:
        meta = ScimUser(user_id=user.id, tenant_id=principal.tenant_id, token_id=principal.token_id)
        db.add(meta)
    given, family = _extract_names(body)
    meta.given_name = given
    meta.family_name = family
    external_id = _string_attr(body.get("externalId"))
    if external_id is not None:
        meta.external_id = external_id
    meta.updated_at = datetime.now(UTC)

    changes.update(await _apply_active(db, user, active))

    await _audit(db, principal, request, action="scim:user:replace", resource="user", resource_id=str(user.id), changes=changes)
    await db.commit()
    return ScimResponse(content=await _render_user(db, user, meta))


async def _apply_active(db: AsyncSession, user: User, active: bool) -> dict[str, Any]:
    """Apply an ``active`` value, doing the real work when it goes false.

    Returns what changed, so the audit record describes the effect rather
    than the request.
    """
    if active == user.is_active:
        return {}
    if not active:
        result = await provisioning.deactivate_user(db, user)
        return {
            "active": {"from": True, "to": False},
            "programmatic_access_revoked": result.api_keys_revoked,
            "sessions_revoked_at": result.sessions_revoked_at.isoformat(),
        }
    await provisioning.reactivate_user(db, user)
    return {"active": {"from": False, "to": True}}


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Apply a PATCH, which is how both providers deactivate a principal.

    The body shapes differ between providers in five ways, all resolved by
    ``app.services.scim.patch``.
    """
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    found = await _load_scim_user(db, principal.tenant_id, parsed_id)
    if found is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    user, meta = found

    try:
        operations = scim_patch.parse_patch(body)
    except scim_patch.ScimPatchError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    changes: dict[str, Any] = {}
    for op in operations:
        attribute = op.attribute or ""
        if attribute == "active":
            try:
                active = scim_patch.coerce_bool(op.value, attribute="active")
            except scim_patch.ScimPatchError as exc:
                return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)
            changes.update(await _apply_active(db, user, active))
        elif attribute == "username":
            new_name = _string_attr(op.value)
            if new_name and new_name.casefold() != user.email.casefold():
                clash = await provisioning.find_user_by_username(db, principal.tenant_id, new_name)
                if clash is not None and clash.id != user.id:
                    return _error(status.HTTP_409_CONFLICT, f"userName {new_name!r} already exists", scim_type="uniqueness")
                changes["user_name"] = {"from": user.email, "to": new_name}
                user.email = new_name
                user.username = new_name
        elif attribute in {"name.givenname", "givenname"}:
            if meta is None:
                meta = ScimUser(user_id=user.id, tenant_id=principal.tenant_id, token_id=principal.token_id)
                db.add(meta)
            meta.given_name = _string_attr(op.value)
            changes["given_name"] = meta.given_name
        elif attribute in {"name.familyname", "familyname"}:
            if meta is None:
                meta = ScimUser(user_id=user.id, tenant_id=principal.tenant_id, token_id=principal.token_id)
                db.add(meta)
            meta.family_name = _string_attr(op.value)
            changes["family_name"] = meta.family_name
        elif attribute == "externalid":
            if meta is None:
                meta = ScimUser(user_id=user.id, tenant_id=principal.tenant_id, token_id=principal.token_id)
                db.add(meta)
            meta.external_id = _string_attr(op.value)
            changes["external_id"] = meta.external_id
        elif attribute == "name":
            # A pathless replace sends the whole complex attribute.
            if isinstance(op.value, dict):
                if meta is None:
                    meta = ScimUser(user_id=user.id, tenant_id=principal.tenant_id, token_id=principal.token_id)
                    db.add(meta)
                given, family = _extract_names({"name": op.value})
                meta.given_name, meta.family_name = given, family
                changes["name"] = {"given": given, "family": family}
        else:
            # An attribute this platform does not store. Recorded rather than
            # rejected: a provider sends its whole mapped attribute set, and
            # 400-ing on `title` would fail the deactivation in the same body.
            changes.setdefault("ignored_attributes", []).append(attribute)

    if meta is not None:
        meta.updated_at = datetime.now(UTC)

    await _audit(db, principal, request, action="scim:user:patch", resource="user", resource_id=str(user.id), changes=changes)
    await db.commit()
    return ScimResponse(content=await _render_user(db, user, meta))


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, principal: ScimAuth, db: ScimDB, request: Request) -> Response:
    """Deprovision a principal.

    Deactivates rather than deletes. A deleted row takes its audit
    attribution, case ownership and approval history with it, and this
    platform's own records reference the principal. Access ends completely
    either way, which is what DELETE means here.
    """
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    found = await _load_scim_user(db, principal.tenant_id, parsed_id)
    if found is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no user {user_id!r}")
    user, _meta = found

    result = await provisioning.deactivate_user(db, user)
    await db.execute(delete(ScimGroupMember).where(ScimGroupMember.user_id == user.id, ScimGroupMember.tenant_id == principal.tenant_id))

    await _audit(
        db,
        principal,
        request,
        action="scim:user:delete",
        resource="user",
        resource_id=str(user.id),
        changes={
            "already_inactive": result.already_inactive,
            "programmatic_access_revoked": result.api_keys_revoked,
            "sessions_revoked_at": result.sessions_revoked_at.isoformat(),
        },
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Groups ────────────────────────────────────────────────────────────────


@router.get("/Groups")
async def list_groups(
    principal: ScimAuth,
    db: ScimDB,
    filter_: Annotated[str | None, Query(alias="filter")] = None,
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(alias="count", ge=0)] = resources.DEFAULT_PAGE_SIZE,
) -> ScimResponse:
    try:
        parsed = scim_filters.parse_equality(filter_, scim_filters.GROUP_FILTER_ATTRS)
    except scim_filters.ScimFilterError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    stmt = select(ScimGroup).where(ScimGroup.tenant_id == principal.tenant_id)
    if parsed is not None:
        if parsed.attribute == "display_name":
            stmt = stmt.where(ScimGroup.display_name == parsed.value)
        elif parsed.attribute == "external_id":
            stmt = stmt.where(ScimGroup.external_id == parsed.value)
        elif parsed.attribute == "id":
            try:
                stmt = stmt.where(ScimGroup.id == uuid.UUID(parsed.value))
            except ValueError:
                return ScimResponse(content=resources.list_response([], total=0, start_index=start_index, count=0))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    start, size = _paging(start_index, count)
    rows = await db.execute(stmt.order_by(ScimGroup.created_at, ScimGroup.id).offset(start - 1).limit(size))
    rendered = [await _render_group(db, group) for group in rows.scalars().all()]
    return ScimResponse(content=resources.list_response(rendered, total=int(total), start_index=start, count=size))


@router.get("/Groups/{group_id}")
async def get_group(group_id: str, principal: ScimAuth, db: ScimDB) -> ScimResponse:
    group = await _load_group(db, principal.tenant_id, group_id)
    if group is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no group {group_id!r}")
    return ScimResponse(content=await _render_group(db, group))


async def _load_group(db: AsyncSession, tenant_id: uuid.UUID, group_id: str) -> ScimGroup | None:
    try:
        parsed_id = uuid.UUID(group_id)
    except ValueError:
        return None
    result = await db.execute(select(ScimGroup).where(ScimGroup.id == parsed_id, ScimGroup.tenant_id == tenant_id))
    return result.scalar_one_or_none()


@router.post("/Groups", status_code=status.HTTP_201_CREATED)
async def create_group(body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Create a directory group and resolve what it confers.

    The resolved role is recorded at create time and returned in the
    response, so an administrator can see immediately whether the group they
    pushed grants anything.
    """
    if not isinstance(body, dict):
        return _error(status.HTTP_400_BAD_REQUEST, "request body must be a JSON object")

    display_name = None
    for key, value in body.items():
        if isinstance(key, str) and key.casefold() == "displayname":
            display_name = _string_attr(value)
    if not display_name:
        return _error(status.HTTP_400_BAD_REQUEST, "displayName is required", scim_type="invalidValue")

    existing = await db.execute(select(ScimGroup).where(ScimGroup.tenant_id == principal.tenant_id, ScimGroup.display_name == display_name))
    if existing.scalar_one_or_none() is not None:
        return _error(status.HTTP_409_CONFLICT, f"displayName {display_name!r} already exists", scim_type="uniqueness")

    group = ScimGroup(
        tenant_id=principal.tenant_id,
        display_name=display_name,
        external_id=_string_attr(body.get("externalId")),
        mapped_role=roles.resolve_role(display_name),
        token_id=principal.token_id,
    )
    db.add(group)
    await db.flush()

    added = await _add_members(db, principal.tenant_id, group, _member_ids_from_body(body))

    await _audit(
        db,
        principal,
        request,
        action="scim:group:create",
        resource="scim_group",
        resource_id=str(group.id),
        changes={"display_name": display_name, "mapped_role": group.mapped_role, "members_added": added},
    )
    await db.commit()
    return ScimResponse(status_code=status.HTTP_201_CREATED, content=await _render_group(db, group))


def _member_ids_from_body(body: dict[str, Any]) -> list[str]:
    members = body.get("members")
    if not isinstance(members, list):
        return []
    found: list[str] = []
    for entry in members:
        if isinstance(entry, str) and entry:
            found.append(entry)
        elif isinstance(entry, dict):
            for key, value in entry.items():
                if isinstance(key, str) and key.casefold() == "value" and isinstance(value, str) and value:
                    found.append(value)
    return found


async def _add_members(db: AsyncSession, tenant_id: uuid.UUID, group: ScimGroup, raw_ids: list[str]) -> int:
    """Add members, ignoring ids that are not principals of this tenant.

    A member id from outside the tenant is dropped rather than errored. It
    is a stale reference in the provider's own state, and failing the whole
    sync over one would stop every other change in the same push.
    """
    added = 0
    for raw in raw_ids:
        try:
            member_id = uuid.UUID(raw)
        except ValueError:
            continue
        exists = await db.execute(select(User.id).where(User.id == member_id, User.tenant_id == tenant_id))
        if exists.scalar_one_or_none() is None:
            continue
        already = await db.execute(
            select(ScimGroupMember).where(
                ScimGroupMember.group_id == group.id,
                ScimGroupMember.user_id == member_id,
                ScimGroupMember.tenant_id == tenant_id,
            )
        )
        if already.scalar_one_or_none() is not None:
            continue
        db.add(ScimGroupMember(group_id=group.id, user_id=member_id, tenant_id=tenant_id))
        added += 1

    if added:
        await db.flush()
        await provisioning.recompute_roles_for_group(db, group)
    return added


async def _remove_members(db: AsyncSession, group: ScimGroup, raw_ids: list[str]) -> int:
    removed = 0
    affected: list[uuid.UUID] = []
    for raw in raw_ids:
        try:
            member_id = uuid.UUID(raw)
        except ValueError:
            continue
        result = await db.execute(
            delete(ScimGroupMember).where(
                ScimGroupMember.group_id == group.id,
                ScimGroupMember.user_id == member_id,
                ScimGroupMember.tenant_id == group.tenant_id,
            )
        )
        if result.rowcount:
            removed += int(result.rowcount)
            affected.append(member_id)

    # Recomputed after the deletes land, so a principal who has just lost the
    # group that granted their authority drops to the default rather than
    # keeping it. This is the step that makes removal mean something.
    for member_id in affected:
        user = await db.get(User, member_id)
        if user is not None:
            await provisioning.recompute_role(db, user)
    return removed


@router.put("/Groups/{group_id}")
async def replace_group(group_id: str, body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Replace a group, including its entire membership.

    PUT on a group is a *set* operation: members absent from the body are
    removed. One provider uses it to reconcile a group wholesale.
    """
    group = await _load_group(db, principal.tenant_id, group_id)
    if group is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no group {group_id!r}")
    if not isinstance(body, dict):
        return _error(status.HTTP_400_BAD_REQUEST, "request body must be a JSON object")

    changes: dict[str, Any] = {}
    for key, value in body.items():
        if isinstance(key, str) and key.casefold() == "displayname":
            new_name = _string_attr(value)
            if new_name and new_name != group.display_name:
                changes["display_name"] = {"from": group.display_name, "to": new_name}
                group.display_name = new_name
                group.mapped_role = roles.resolve_role(new_name)
                changes["mapped_role"] = group.mapped_role

    external_id = _string_attr(body.get("externalId"))
    if external_id is not None:
        group.external_id = external_id

    desired = set(_member_ids_from_body(body))
    current = {str(member_id) for member_id, _ in await _group_members(db, group.tenant_id, group.id)}
    changes["members_added"] = await _add_members(db, principal.tenant_id, group, sorted(desired - current))
    changes["members_removed"] = await _remove_members(db, group, sorted(current - desired))
    group.updated_at = datetime.now(UTC)

    if "mapped_role" in changes:
        await provisioning.recompute_roles_for_group(db, group)

    await _audit(db, principal, request, action="scim:group:replace", resource="scim_group", resource_id=str(group.id), changes=changes)
    await db.commit()
    return ScimResponse(content=await _render_group(db, group))


@router.patch("/Groups/{group_id}")
async def patch_group(group_id: str, body: dict[str, Any], principal: ScimAuth, db: ScimDB, request: Request) -> ScimResponse:
    """Apply a group PATCH, which is how membership changes arrive.

    Both providers express member removal two ways, and one of those puts
    the member id in the path filter rather than the value. Both shapes are
    normalised before they reach this handler.
    """
    group = await _load_group(db, principal.tenant_id, group_id)
    if group is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no group {group_id!r}")

    try:
        operations = scim_patch.parse_patch(body)
    except scim_patch.ScimPatchError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, exc.detail, scim_type=exc.scim_type)

    changes: dict[str, Any] = {"members_added": 0, "members_removed": 0}
    for op in operations:
        attribute = op.attribute or ""
        if attribute == "members":
            ids = scim_patch.member_ids(op)
            if op.op == "remove":
                if not ids and op.member_id is None and op.value is None:
                    # `remove` on `members` with nothing named empties the
                    # group. RFC 7644 allows it and a provider sends it when
                    # the last member leaves.
                    current = [str(member_id) for member_id, _ in await _group_members(db, group.tenant_id, group.id)]
                    changes["members_removed"] += await _remove_members(db, group, current)
                else:
                    changes["members_removed"] += await _remove_members(db, group, ids)
            elif op.op == "replace":
                current = [str(member_id) for member_id, _ in await _group_members(db, group.tenant_id, group.id)]
                changes["members_removed"] += await _remove_members(db, group, sorted(set(current) - set(ids)))
                changes["members_added"] += await _add_members(db, principal.tenant_id, group, sorted(set(ids) - set(current)))
            else:
                changes["members_added"] += await _add_members(db, principal.tenant_id, group, ids)
        elif attribute == "displayname":
            new_name = _string_attr(op.value)
            if new_name and new_name != group.display_name:
                changes["display_name"] = {"from": group.display_name, "to": new_name}
                group.display_name = new_name
                group.mapped_role = roles.resolve_role(new_name)
                changes["mapped_role"] = group.mapped_role
                await provisioning.recompute_roles_for_group(db, group)
        elif attribute == "externalid":
            group.external_id = _string_attr(op.value)
        else:
            changes.setdefault("ignored_attributes", []).append(attribute)

    group.updated_at = datetime.now(UTC)
    await _audit(db, principal, request, action="scim:group:patch", resource="scim_group", resource_id=str(group.id), changes=changes)
    await db.commit()
    return ScimResponse(content=await _render_group(db, group))


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: str, principal: ScimAuth, db: ScimDB, request: Request) -> Response:
    """Delete a group and recompute what its members are left holding."""
    group = await _load_group(db, principal.tenant_id, group_id)
    if group is None:
        return _error(status.HTTP_404_NOT_FOUND, f"no group {group_id!r}")

    members = [member_id for member_id, _ in await _group_members(db, group.tenant_id, group.id)]
    await db.execute(delete(ScimGroupMember).where(ScimGroupMember.group_id == group.id, ScimGroupMember.tenant_id == group.tenant_id))
    await db.delete(group)
    await db.flush()

    # Losing the group that granted a role has to take the role with it.
    for member_id in members:
        user = await db.get(User, member_id)
        if user is not None:
            await provisioning.recompute_role(db, user)

    await _audit(
        db,
        principal,
        request,
        action="scim:group:delete",
        resource="scim_group",
        resource_id=group_id,
        changes={"members_detached": len(members)},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
