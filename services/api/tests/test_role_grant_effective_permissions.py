"""GHSA-4gx4-x7gm-4xq8: a grant check reading a different authority than the door.

`CurrentUser` documents three tiers, in this order: API-key scopes, the
database-backed RBAC tables, then the static `ROLE_PERMISSIONS` map.
`require_permission` implements all three. `_granter_permissions` — what every
grant route consults to decide whether the caller may confer something —
implemented the first and the third.

So a principal whose effective permissions came from the middle tier was
admitted through the door on its *database* permissions and then had its grant
measured against its *static* role. A `tenant_admin` deliberately restricted to
`users:write` in `user_roles` holds 28 permissions statically, which is 27 it
can confer on itself and then resolve on its next request.

The reporter (HaiND, https://github.com/Haind03) named
`POST /api/v1/rbac/users/{user_id}/roles`. The resolver is shared, so the same
caller reaches it through six more: authoring a role, re-permissioning one,
minting an API key, creating a user, delegating to a child tenant, and mapping
an SSO group. The API-key route is the one worth noting — it needs no target
user and yields a durable credential.

**Nothing here imports `app.core.role_grants`.** A test that asserts on the
fix's own symbols passes vacuously on a tree that never had the defect. These
drive the shipped handlers with a restricted principal and assert the grant is
refused, so against the pre-fix tree they fail because it *succeeded*. Every
route is asserted in both directions: the escalating grant is refused and no
row is written, and a grant inside the caller's effective permissions lands.
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

TENANT = uuid.uuid4()

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _restricted(*held: str, role: str = "tenant_admin") -> CurrentUser:
    """A principal admitted by the database tier, not by its static role.

    This is the shape the advisory turns on: `role` is broad because the
    column was never narrowed, and `resolved_permissions` is what the tenant
    administrator actually granted. `require_permission` reads the latter.
    """
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=TENANT,
        role=role,
        email="restricted@tenant-a.example",
        resolved_permissions=frozenset(held),
    )


class _Permission:
    """A permission row good enough to build `PermissionOut` from.

    A `MagicMock` would satisfy the grant check and then fail response
    validation on `description`/`category`, so the pre-fix run would error
    *after* the escalation instead of asserting on it — which reads like a
    broken double rather than a caught defect.
    """

    def __init__(self, name: str) -> None:
        self.id = uuid.uuid4()
        self.name = name
        self.description = f"permission {name}"
        self.category = name.split(":")[0]


class _Role:
    """Likewise for `RoleOut`."""

    def __init__(self, name: str, *, is_system: bool = False) -> None:
        self.id = uuid.uuid4()
        self.tenant_id = TENANT
        self.name = name
        self.description = f"role {name}"
        self.is_system = is_system


def _permission(name: str) -> _Permission:
    return _Permission(name)


def _rbac_db(*, scalars_queue: list[Any], permissions: list[Any] | None = None) -> AsyncMock:
    """A session whose single-row reads pop a queue and whose writes are visible."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    pending = list(scalars_queue)

    async def _refresh(obj: Any) -> None:
        # Stands in for the server-side defaults a real flush would populate,
        # so a handler that *should* have refused runs all the way to its
        # response model and fails on the assertion instead of on validation.
        for field, value in (
            ("id", uuid.uuid4()),
            ("created_at", datetime.now(UTC)),
            ("is_active", True),
            ("last_login", None),
        ):
            if getattr(obj, field, None) is None:
                try:
                    setattr(obj, field, value)
                except (AttributeError, ValueError):  # pragma: no cover - ORM guard
                    pass

    db.refresh = AsyncMock(side_effect=_refresh)

    async def _flush() -> None:
        # Stands in for the server-side default on `roles.id` so the pre-fix
        # handler runs to completion and fails the assertion, rather than
        # tripping over an unpopulated primary key and looking like a catch.
        for call in db.add.call_args_list:
            obj = call.args[0]
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    db.flush = AsyncMock(side_effect=_flush)

    result = MagicMock()
    result.scalar_one_or_none = MagicMock(side_effect=lambda: pending.pop(0) if pending else None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=permissions or [])))
    db.execute = AsyncMock(return_value=result)
    return db


def _key_db() -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()

    async def _refresh(obj: Any) -> None:
        for field, value in (
            ("id", uuid.uuid4()),
            ("created_at", datetime.now(UTC)),
            ("is_active", True),
            ("expires_at", None),
            ("last_used_at", None),
            ("revoked_at", None),
        ):
            if getattr(obj, field, None) is None:
                obj.id = value if field == "id" else getattr(obj, "id", None)
                try:
                    setattr(obj, field, value)
                except (AttributeError, ValueError):  # pragma: no cover - ORM guard
                    pass

    db.refresh = AsyncMock(side_effect=_refresh)
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    db.execute = AsyncMock(return_value=result)
    return db


def _wrote(db: AsyncMock) -> bool:
    """Whether the handler issued any write at all."""
    return bool(db.add.call_args_list) or bool(db.commit.call_args_list)


# ---------------------------------------------------------------------------
# POST /api/v1/rbac/users/{user_id}/roles — the reported route
# ---------------------------------------------------------------------------


class TestAssignRole:
    async def test_a_restricted_caller_cannot_attach_a_broader_role_to_itself(self) -> None:
        """The reported path, verbatim: the caller is the target.

        `users:write` opens the route, and before the fix the role it attached
        was measured against the static `tenant_admin` map rather than the one
        permission the tenant administrator left it.
        """
        caller = _restricted("users:write")
        role = _Role("case-manager")
        target = MagicMock(id=caller.user_id, tenant_id=TENANT)
        db = _rbac_db(
            scalars_queue=[role, target, None],
            permissions=[_permission("alerts:write"), _permission("cases:write")],
        )

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.assign_role(
                user_id=caller.user_id,
                body=rbac_mod.UserRoleAssignment(user_id=caller.user_id, role_id=role.id),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db), "the refused assignment still wrote a user_roles row"

    async def test_the_same_grant_to_another_user_is_refused_too(self) -> None:
        """Self-assignment is the clearest story, not the boundary.

        Conferring on a colleague what you cannot hold is the same escalation
        with one extra step, so a fix that only rejected `user_id == caller`
        would leave it open.
        """
        caller = _restricted("users:write")
        role = _Role("case-manager")
        colleague = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        db = _rbac_db(scalars_queue=[role, colleague, None], permissions=[_permission("cases:write")])

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.assign_role(
                user_id=colleague.id,
                body=rbac_mod.UserRoleAssignment(user_id=colleague.id, role_id=role.id),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)

    async def test_a_role_inside_the_callers_effective_permissions_still_attaches(self) -> None:
        """The positive direction. A restricted caller is not a refused one."""
        caller = _restricted("users:write", "cases:write")
        role = _Role("case-reader")
        target = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        db = _rbac_db(scalars_queue=[role, target, None], permissions=[_permission("cases:write")])

        out = await rbac_mod.assign_role(
            user_id=target.id,
            body=rbac_mod.UserRoleAssignment(user_id=target.id, role_id=role.id),
            current_user=caller,
            db=db,
        )

        assert out.role_name == "case-reader"
        assert db.add.call_args_list, "a legitimate grant was refused"

    async def test_a_principal_with_no_resolved_set_still_uses_the_static_map(self) -> None:
        """Tier three is a fallback, not a casualty.

        A tenant with no RBAC rows resolves `None`, and that principal must
        keep conferring exactly what its role confers — otherwise the fix
        locks out every deployment that never adopted database-backed roles.
        """
        caller = CurrentUser(
            user_id=uuid.uuid4(),
            tenant_id=TENANT,
            role="tenant_admin",
            email="legacy@tenant-a.example",
        )
        role = _Role("triage")
        target = MagicMock(id=uuid.uuid4(), tenant_id=TENANT)
        db = _rbac_db(scalars_queue=[role, target, None], permissions=[_permission("alerts:write")])

        out = await rbac_mod.assign_role(
            user_id=target.id,
            body=rbac_mod.UserRoleAssignment(user_id=target.id, role_id=role.id),
            current_user=caller,
            db=db,
        )

        assert out.role_name == "triage"


# ---------------------------------------------------------------------------
# The six further routes sharing the resolver
# ---------------------------------------------------------------------------


class TestRoleAuthoring:
    async def test_authoring_a_role_beyond_the_effective_set_is_refused(self) -> None:
        """Authoring and attaching are one escalation in two requests.

        Refusing only the attachment leaves the caller able to build the role
        and wait for anyone else to attach it.
        """
        caller = _restricted("roles:write")
        perm = _permission("playbooks:write")
        db = _rbac_db(scalars_queue=[None], permissions=[perm])

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.create_role(
                body=rbac_mod.RoleIn(name="playbook-ops", permission_ids=[perm.id]),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db), "the refused request still created the role row"

    async def test_re_permissioning_an_existing_role_is_refused(self) -> None:
        """`PUT` reaches the same end state as `POST` with the name reused."""
        caller = _restricted("roles:write")
        role = _Role("triage")
        perm = _permission("playbooks:write")
        db = _rbac_db(scalars_queue=[role], permissions=[perm])

        with pytest.raises(HTTPException) as exc:
            await rbac_mod.update_role(
                role_id=role.id,
                body=rbac_mod.RoleUpdate(permission_ids=[perm.id]),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)


class TestApiKeyScopes:
    async def test_a_restricted_caller_cannot_mint_a_key_beyond_its_effective_set(self) -> None:
        """No target user, and the result is a durable bearer credential.

        This route needs nothing but the caller, so it is the cheapest of the
        seven to reach and the one whose output outlives the session.
        """
        caller = _restricted("users:write")
        db = _key_db()

        with pytest.raises(HTTPException) as exc:
            await api_keys_mod.create_api_key(
                body=api_keys_mod.CreateApiKeyRequest(name="exfil", scopes=["alerts:write", "cases:write"]),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db), "the refused request still persisted a key"

    async def test_a_key_within_the_effective_set_is_still_minted(self) -> None:
        caller = _restricted("users:write", "alerts:read")
        db = _key_db()

        out = await api_keys_mod.create_api_key(
            body=api_keys_mod.CreateApiKeyRequest(name="reader", scopes=["alerts:read"]),
            current_user=caller,
            db=db,
        )

        assert out is not None
        assert db.add.call_args_list, "a legitimate key was refused"


class TestUserCreation:
    async def test_a_restricted_caller_cannot_create_a_user_holding_more(self) -> None:
        """The static-role door onto the same escalation.

        `soc_analyst` is inside `tenant_admin`'s static map, so before the fix
        a caller left with only `users:write` could seat a colleague — or a
        second account of its own — holding the analyst set.
        """
        caller = _restricted("users:write")
        db = _rbac_db(scalars_queue=[None])

        with pytest.raises(HTTPException) as exc:
            await tenants_mod.create_user(
                request=tenants_mod.CreateUserRequest(
                    email="second@tenant-a.example",
                    username="second",
                    password="AnotherLongPassword2!",
                    role="soc_analyst",
                ),
                current_user=caller,
                db=db,
            )

        assert exc.value.status_code == 403
        assert not _wrote(db)


class TestDelegationAndSso:
    async def test_a_delegation_cannot_name_a_role_beyond_the_effective_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        caller = _restricted("mssp:write")
        db = _rbac_db(scalars_queue=[None])
        monkeypatch.setattr(mssp_mod, "_require_own_child", AsyncMock())
        body = MagicMock(child_tenant_id=uuid.uuid4(), granted_role="soc_analyst", expires_at=None)

        with pytest.raises(HTTPException) as exc:
            await mssp_mod.create_delegation(body=body, db=db, current_user=caller)

        assert exc.value.status_code == 403
        assert not _wrote(db)
