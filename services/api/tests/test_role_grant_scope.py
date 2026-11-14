"""GHSA-pm3f-h6gc-rvgp: a principal conferring authority it does not hold.

`POST /api/v1/tenants/me/users` took a `role` string from the body and wrote
it to `users.role`, the column `CurrentUser.require_permission` reads. With
`platform_admin` and `admin` both declared `["*"]`, a `tenant_admin` could
create an account holding every permission in the product and sign in as it.

Five more routes had the same defect and the report named only the first, so
the tests here are organised by call site rather than by advisory:

* `PATCH /tenants/me/users/{id}` — the same grant, spelled as a promotion.
* `POST /api-keys` and `PATCH /api-keys/{id}` — the check they *did* have read
  `current_user.role not in ("platform_admin", "tenant_admin")` and covered
  only `"*"`, so `tenant_admin` could mint a wildcard key (total escalation,
  no user created) and anyone with `users:write` could mint a `plugins:admin`
  key they were themselves refused.
* `POST /rbac/users/{id}/roles` — `users:write` attaching a database-backed
  role authored under `roles:write`, which `has_permission_db` then prefers
  over the static map.
* `POST /mssp/delegations` — an unvalidated role string stored against a
  customer tenant.
* `PUT /mssp/organizations/current/members` — `ORG_ROLES` is a vocabulary, not
  a grant scope, and `_admin_scope` admits `admin` as well as `owner`.

**Nothing here imports `app.core.role_grants`.** A test that imports a symbol
added by the fix fails on the old tree with `ImportError`, which proves the
symbol is absent and says nothing about whether the escalation was possible.
These call the shipped handlers and assert on what they do, so against the
pre-fix tree they fail because the grant *succeeded*.

Every call site is asserted in both directions: the escalating request is
refused **and no write is issued**, and a legitimate grant still lands.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys as api_keys_mod
from app.api.v1.endpoints import mssp as mssp_mod
from app.api.v1.endpoints import rbac as rbac_mod
from app.api.v1.endpoints import tenants as tenants_mod
from fastapi import HTTPException


def _http_request(method: str = "POST", path: str = "/api/v1/rbac/roles"):
    """Minimal starlette Request for direct handler calls in tests."""
    from starlette.requests import Request

    return Request({"type": "http", "method": method, "path": path, "headers": [], "query_string": b""})


TENANT = uuid.uuid4()

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _principal(role: str, *, scopes: list[str] | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=TENANT,
        role=role,
        email=f"{role}@tenant-a.example",
        scopes=scopes,
    )


def _db(*, found: Any = None) -> AsyncMock:
    """An async session whose reads answer `found` and whose writes are visible."""
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=found)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    db.execute = AsyncMock(return_value=result)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()

    async def _refresh(obj: Any) -> None:
        # Stand in for the flush that would populate server-side defaults, so
        # a *successful* call can still build its response model and the
        # positive direction is a real assertion rather than an xfail.
        for field, value in (
            ("id", uuid.uuid4()),
            ("created_at", datetime.now(UTC)),
            ("is_active", True),
            ("last_login", None),
            ("expires_at", None),
            ("last_used_at", None),
            ("scopes", getattr(obj, "scopes", None) or []),
            ("revoked_at", None),
            ("granted_by_user", None),
        ):
            if getattr(obj, field, None) is None:
                try:
                    setattr(obj, field, value)
                except (AttributeError, ValueError):  # pragma: no cover - ORM guard
                    pass

    db.refresh = AsyncMock(side_effect=_refresh)
    return db


def _wrote(db: AsyncMock) -> bool:
    """Whether the handler issued any write at all."""
    return bool(db.add.call_args_list) or bool(db.commit.call_args_list)


# ---------------------------------------------------------------------------
# POST /api/v1/tenants/me/users — the reported route
# ---------------------------------------------------------------------------


class TestCreateUser:
    @pytest.mark.parametrize("role", ["platform_admin", "admin"])
    async def test_a_tenant_admin_cannot_mint_a_wildcard_role(self, role: str) -> None:
        db = _db()
        body = tenants_mod.CreateUserRequest(
            email="backdoor@tenant-a.example",
            username="backdoor",
            password="AnotherLongPassword2!",
            role=role,
        )

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.create_user(request=body, current_user=_principal("tenant_admin"), db=db)

        assert exc.value.status_code == 403
        assert not _wrote(db), "the refused request still wrote a row"

    async def test_an_unknown_role_is_refused_rather_than_stored(self) -> None:
        """A role outside `ROLE_PERMISSIONS` grants nothing and reads in a
        console as though it grants something, which is worse than refusing."""
        db = _db()
        body = tenants_mod.CreateUserRequest(
            email="ghost@tenant-a.example",
            username="ghost",
            password="AnotherLongPassword2!",
            role="superuser",
        )

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.create_user(request=body, current_user=_principal("tenant_admin"), db=db)

        assert exc.value.status_code == 422
        assert not _wrote(db)

    async def test_an_api_key_is_bounded_by_its_scopes_not_its_owners_role(self) -> None:
        """The authority of an API-key principal is its scope list.

        `CurrentUser.require_permission` takes the scopes branch whenever
        `scopes` is not None, so a narrow key owned by a `tenant_admin` must
        not be able to grant everything `tenant_admin` holds.
        """
        db = _db()
        body = tenants_mod.CreateUserRequest(
            email="lateral@tenant-a.example",
            username="lateral",
            password="AnotherLongPassword2!",
            role="soc_lead",
        )

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.create_user(
                request=body,
                current_user=_principal("tenant_admin", scopes=["alerts:read", "cases:read"]),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)

    @pytest.mark.parametrize("role", ["viewer", "soc_analyst", "threat_hunter", "soc_lead", "tenant_admin"])
    async def test_a_tenant_admin_can_still_create_every_ordinary_role(self, role: str) -> None:
        db = _db()
        body = tenants_mod.CreateUserRequest(
            email=f"{role}@tenant-a.example",
            username=role,
            password="AnotherLongPassword2!",
            role=role,
        )

        out = await tenants_mod.create_user(request=body, current_user=_principal("tenant_admin"), db=db)

        assert out.role == role
        assert db.add.call_args.args[0].role == role


# ---------------------------------------------------------------------------
# PATCH /api/v1/tenants/me/users/{id}
# ---------------------------------------------------------------------------


def _existing_user(role: str) -> Any:
    user = MagicMock()
    user.id = uuid.uuid4()
    user.tenant_id = TENANT
    user.email = "target@tenant-a.example"
    user.username = "target"
    user.role = role
    user.is_active = True
    user.last_login = None
    user.created_at = datetime.now(UTC)
    return user


class TestUpdateUser:
    @pytest.mark.parametrize("role", ["platform_admin", "admin"])
    async def test_promotion_to_a_wildcard_role_is_refused(self, role: str) -> None:
        target = _existing_user("viewer")
        db = _db(found=target)

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.update_user(
                user_id=target.id,
                request=tenants_mod.UpdateUserRequest(role=role),
                current_user=_principal("tenant_admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not db.commit.call_args_list, "the refused promotion still committed"
        assert target.role == "viewer"

    async def test_a_wildcard_principal_cannot_be_re_roled_either(self) -> None:
        """Otherwise the route that cannot create a `platform_admin` can still
        demote the one that exists, ending the only principal able to undo it."""
        target = _existing_user("platform_admin")
        db = _db(found=target)

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.update_user(
                user_id=target.id,
                request=tenants_mod.UpdateUserRequest(role="viewer"),
                current_user=_principal("tenant_admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not db.commit.call_args_list

    async def test_a_refused_role_does_not_write_the_other_fields_either(self) -> None:
        target = _existing_user("viewer")
        db = _db(found=target)

        with pytest.raises(HTTPException):
            await tenants_mod.update_user(
                user_id=target.id,
                request=tenants_mod.UpdateUserRequest(username="renamed", role="admin", is_active=False),
                current_user=_principal("tenant_admin"),
                db=db,
            )

        assert not db.commit.call_args_list
        assert target.username == "target"

    async def test_an_ordinary_promotion_still_succeeds(self) -> None:
        target = _existing_user("viewer")
        db = _db(found=target)

        await tenants_mod.update_user(
            user_id=target.id,
            request=tenants_mod.UpdateUserRequest(role="soc_lead"),
            current_user=_principal("tenant_admin"),
            db=db,
        )

        assert db.commit.call_args_list, "a legitimate promotion was not committed"


# ---------------------------------------------------------------------------
# POST /api/v1/api-keys and PATCH /api/v1/api-keys/{id}
# ---------------------------------------------------------------------------


class TestApiKeyScopes:
    async def test_a_tenant_admin_cannot_mint_a_wildcard_key(self) -> None:
        """The escalation the advisory describes, with no user created at all.

        A `*` key satisfies every `require_permission` on the API-key branch,
        so this is the same total compromise by a quieter door.
        """
        db = _db()
        body = api_keys_mod.CreateApiKeyRequest(name="backdoor-key", scopes=["*"])

        with pytest.raises(HTTPException) as exc:
            await api_keys_mod.create_api_key(body=body, db=db, current_user=_principal("tenant_admin"))

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_a_key_cannot_carry_a_scope_its_minter_is_refused(self) -> None:
        """`plugins:admin` is held by no role in `ROLE_PERMISSIONS`, and
        plugin import runs code. A `tenant_admin` gets 403 from
        `POST /plugins/discover` and could mint a key that does not."""
        db = _db()
        body = api_keys_mod.CreateApiKeyRequest(name="plugin-key", scopes=["plugins:admin"])

        with pytest.raises(HTTPException) as exc:
            await api_keys_mod.create_api_key(body=body, db=db, current_user=_principal("tenant_admin"))

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_a_wildcard_principal_may_still_mint_a_wildcard_key(self) -> None:
        """It confers nothing the caller does not already hold."""
        db = _db()
        body = api_keys_mod.CreateApiKeyRequest(name="ops-key", scopes=["*"])

        out = await api_keys_mod.create_api_key(body=body, db=db, current_user=_principal("platform_admin"))

        assert out.scopes == ["*"]

    async def test_a_tenant_admin_may_still_mint_a_key_within_its_own_authority(self) -> None:
        db = _db()
        body = api_keys_mod.CreateApiKeyRequest(name="reporting-key", scopes=["alerts:read", "cases:write"])

        out = await api_keys_mod.create_api_key(body=body, db=db, current_user=_principal("tenant_admin"))

        assert sorted(out.scopes) == ["alerts:read", "cases:write"]

    async def test_widening_an_existing_key_is_refused_and_writes_nothing(self) -> None:
        key = MagicMock()
        key.id = uuid.uuid4()
        key.name = "reporting-key"
        key.prefix = "aisoc_abc123"
        key.key_prefix = "aisoc_abc123"
        key.scopes = ["alerts:read"]
        key.is_active = True
        key.expires_at = None
        key.last_used_at = None
        key.created_at = datetime.now(UTC)
        db = _db(found=key)

        with pytest.raises(HTTPException) as exc:
            await api_keys_mod.update_api_key(
                key_id=key.id,
                body=api_keys_mod.UpdateApiKeyRequest(name="renamed", scopes=["*"]),
                db=db,
                current_user=_principal("tenant_admin"),
            )

        assert exc.value.status_code == 403
        assert key.scopes == ["alerts:read"]
        assert key.name == "reporting-key", "the refused request still renamed the key"
        assert not db.commit.call_args_list


# ---------------------------------------------------------------------------
# POST /api/v1/rbac/users/{id}/roles and POST /api/v1/rbac/roles
# ---------------------------------------------------------------------------


def _permission(name: str) -> Any:
    perm = MagicMock()
    perm.id = uuid.uuid4()
    perm.name = name
    perm.description = name
    perm.category = name.split(":")[0]
    return perm


def _rbac_db(*, scalars_queue: list[Any], permissions: list[Any]) -> AsyncMock:
    """A session where row reads are a queue and permission reads are not.

    Deliberately not a fixed `side_effect` list. The fix inserts one extra
    `SELECT` (the role's permissions) into these handlers, so a positional
    list would make every test here fail on the pre-fix tree purely because
    the call count moved — which looks exactly like a caught defect and is
    not one. `scalar_one_or_none` pops; `scalars().all()` always answers the
    permission set; both orderings work.
    """
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    pending = list(scalars_queue)

    async def _flush() -> None:
        # Stands in for the server-side default on `roles.id`, so the pre-fix
        # handler runs to completion and fails the assertion rather than
        # tripping over an unpopulated primary key.
        for call in db.add.call_args_list:
            obj = call.args[0]
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    db.flush = AsyncMock(side_effect=_flush)

    result = MagicMock()
    result.scalar_one_or_none = MagicMock(side_effect=lambda: pending.pop(0) if pending else None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=permissions)))
    db.execute = AsyncMock(return_value=result)
    return db


class TestRbacRoleAssignment:
    async def test_users_write_cannot_attach_a_role_carrying_permissions_it_lacks(self) -> None:
        """`user_roles` is a live authorization path: `has_permission_db`
        prefers it over the static map for any principal holding a row."""
        role = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        role.name = "shadow-admin"  # `name=` on a MagicMock names the mock, not the attribute
        target = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        db = _rbac_db(scalars_queue=[role, target, None], permissions=[_permission("roles:write")])

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.assign_role(
                user_id=target.id,
                body=rbac_mod.UserRoleAssignment(user_id=target.id, role_id=role.id),
                current_user=_principal("tenant_admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_a_role_within_the_granters_authority_still_attaches(self) -> None:
        role = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        role.name = "triage"
        target = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        db = _rbac_db(scalars_queue=[role, target, None], permissions=[_permission("alerts:read")])

        out = await rbac_mod.assign_role(
            user_id=target.id,
            body=rbac_mod.UserRoleAssignment(user_id=target.id, role_id=role.id),
            current_user=_principal("tenant_admin"),
            db=db,
        )

        assert out.role_name == "triage"
        assert db.add.call_args_list

    async def test_authoring_a_role_beyond_the_authors_authority_is_refused(self) -> None:
        perm = _permission("plugins:admin")
        db = _rbac_db(scalars_queue=[None], permissions=[perm])

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.create_role(
                request=_http_request(),
                body=rbac_mod.RoleIn(name="plugin-ops", permission_ids=[perm.id]),
                current_user=_principal("tenant_admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db), "the refused request still created the role row"


# ---------------------------------------------------------------------------
# POST /api/v1/mssp/delegations
# ---------------------------------------------------------------------------


class TestDelegationRole:
    async def test_a_delegation_cannot_name_a_wildcard_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        child = uuid.uuid4()
        db = _db()
        monkeypatch.setattr(mssp_mod, "_require_own_child", AsyncMock())
        body = MagicMock(child_tenant_id=child, granted_role="admin", expires_at=None)

        with pytest.raises(HTTPException) as exc:
            await mssp_mod.create_delegation(body=body, db=db, current_user=_principal("tenant_admin"))

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_an_ordinary_delegation_still_lands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        child = uuid.uuid4()
        db = _db()
        monkeypatch.setattr(mssp_mod, "_require_own_child", AsyncMock())
        body = MagicMock(child_tenant_id=child, granted_role="soc_analyst", expires_at=None)

        await mssp_mod.create_delegation(body=body, db=db, current_user=_principal("tenant_admin"))

        assert db.add.call_args.args[0].granted_role == "soc_analyst"


# ---------------------------------------------------------------------------
# PUT /api/v1/mssp/organizations/current/members
# ---------------------------------------------------------------------------


def _scope(org_role: str) -> Any:
    scope = MagicMock()
    scope.org_id = uuid.uuid4()
    scope.org_role = org_role
    return scope


class TestOrganisationMemberRole:
    async def test_an_org_admin_cannot_appoint_an_owner(self) -> None:
        target = MagicMock(id=uuid.uuid4(), email="staff@provider.example")
        db = _db(found=None)
        db.get = AsyncMock(return_value=target)

        with pytest.raises(HTTPException) as exc:
            await mssp_mod.upsert_member(
                body=mssp_mod.MemberUpsert(user_id=target.id, org_role="owner"),
                scope=_scope("admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_an_org_admin_cannot_demote_the_sitting_owner(self) -> None:
        target = MagicMock(id=uuid.uuid4(), email="founder@provider.example")
        member = MagicMock(org_role="owner")
        db = _db(found=member)
        db.get = AsyncMock(return_value=target)

        with pytest.raises(HTTPException) as exc:
            await mssp_mod.upsert_member(
                body=mssp_mod.MemberUpsert(user_id=target.id, org_role="viewer"),
                scope=_scope("admin"),
                db=db,
            )

        assert exc.value.status_code == 403
        assert member.org_role == "owner"
        assert not _wrote(db)

    async def test_an_org_admin_may_still_appoint_at_or_below_its_own_level(self) -> None:
        target = MagicMock(id=uuid.uuid4(), email="staff@provider.example")
        db = _db(found=None)
        db.get = AsyncMock(return_value=target)

        out = await mssp_mod.upsert_member(
            body=mssp_mod.MemberUpsert(user_id=target.id, org_role="operator"),
            scope=_scope("admin"),
            db=db,
        )

        assert out.org_role == "operator"
        assert db.add.call_args_list

    async def test_an_owner_may_still_appoint_an_owner(self) -> None:
        target = MagicMock(id=uuid.uuid4(), email="cofounder@provider.example")
        db = _db(found=None)
        db.get = AsyncMock(return_value=target)

        out = await mssp_mod.upsert_member(
            body=mssp_mod.MemberUpsert(user_id=target.id, org_role="owner"),
            scope=_scope("owner"),
            db=db,
        )

        assert out.org_role == "owner"
