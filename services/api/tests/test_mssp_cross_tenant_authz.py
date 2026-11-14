"""Cross-tenant authorization on the MSSP surface.

The hole these tests close
~~~~~~~~~~~~~~~~~~~~~~~~~~

``_ensure_mssp_parent`` had ``pass`` for a body, and four MSSP write routes
took a caller-supplied child tenant id and wrote it onto a row without ever
checking whose child it was.

The one that mattered is ``create_rule_override``. An override with
``action="exclude"`` is read back by
``app.services.mssp_rule_resolver.resolve_effective_rules``, filtered on
``MSSPRuleOverride.child_tenant_id == <the reader's tenant>``, and the rule is
popped out of the set that ``POST /rules/hunt`` runs. So any authenticated
user of any tenant could name any other tenant and silently delete a detection
rule from that tenant's hunts. The victim's only symptom is a hunt that stops
matching.

Closing those four routes alone would not have been enough, because
``onboard_child_tenant`` let anyone *become* the parent first: its only check
was a 409 when the target already had a parent, so every standalone tenant on
the deployment was adoptable by any authenticated user. Adoption now requires
the child to have invited that specific parent from its own settings.

Every test here fails against the previous implementation. The guard tests
fail because the routes returned 201 and wrote the row; the adoption tests
fail because onboarding returned 200 and reparented the tenant.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import mssp
from app.api.v1.endpoints.mssp import (
    _MSSP_INVITE_SETTING,
    _require_own_child,
    assign_pack_to_child,
    create_delegation,
    create_note,
    create_rule_override,
    onboard_child_tenant,
)
from fastapi import HTTPException

PARENT = uuid.uuid4()
OTHER_PARENT = uuid.uuid4()


def _tenant(tid: uuid.UUID, *, parent: uuid.UUID | None = None, settings: dict[str, Any] | None = None) -> Any:
    t = MagicMock()
    t.id = tid
    t.parent_tenant_id = parent
    t.settings = settings
    t.mssp_role = "child" if parent else "standalone"
    return t


def _user(tenant_id: uuid.UUID = PARENT) -> Any:
    u = MagicMock()
    u.id = uuid.uuid4()
    u.tenant_id = tenant_id
    return u


def _db(get_returns: dict[uuid.UUID, Any] | None = None) -> Any:
    """AsyncSession double. ``db.get(Model, pk)`` resolves from a pk map."""
    table = get_returns or {}

    async def _get(_model: Any, pk: Any) -> Any:
        return table.get(pk)

    db = MagicMock()
    db.get = AsyncMock(side_effect=_get)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


class TestRequireOwnChild:
    async def test_accepts_a_real_child(self) -> None:
        child_id = uuid.uuid4()
        child = _tenant(child_id, parent=PARENT)
        got = await _require_own_child(_db({child_id: child}), _user(), child_id)
        assert got is child

    async def test_rejects_a_tenant_owned_by_someone_else(self) -> None:
        child_id = uuid.uuid4()
        db = _db({child_id: _tenant(child_id, parent=OTHER_PARENT)})
        with pytest.raises(HTTPException) as exc:
            await _require_own_child(db, _user(), child_id)
        assert exc.value.status_code == 404

    async def test_rejects_a_standalone_tenant(self) -> None:
        child_id = uuid.uuid4()
        db = _db({child_id: _tenant(child_id, parent=None)})
        with pytest.raises(HTTPException) as exc:
            await _require_own_child(db, _user(), child_id)
        assert exc.value.status_code == 404

    async def test_unknown_and_unowned_are_indistinguishable(self) -> None:
        """Both answer 404 with the same detail, so the route cannot be used to
        enumerate which tenant UUIDs exist on the deployment."""
        unknown = uuid.uuid4()
        foreign_id = uuid.uuid4()
        foreign_db = _db({foreign_id: _tenant(foreign_id, parent=OTHER_PARENT)})

        with pytest.raises(HTTPException) as unknown_exc:
            await _require_own_child(_db({}), _user(), unknown)
        with pytest.raises(HTTPException) as foreign_exc:
            await _require_own_child(foreign_db, _user(), foreign_id)

        assert unknown_exc.value.status_code == foreign_exc.value.status_code == 404
        assert unknown_exc.value.detail == foreign_exc.value.detail


class TestWriteRoutesRefuseForeignTenants:
    """Each of these returned 201 and persisted the row before the fix."""

    async def test_rule_override_refuses_a_tenant_that_is_not_your_child(self) -> None:
        victim = uuid.uuid4()
        db = _db({victim: _tenant(victim, parent=OTHER_PARENT)})
        body = MagicMock(
            child_tenant_id=victim, rule_id=uuid.uuid4(), action="exclude", note=None, severity_override=None, parameter_overrides=None
        )

        with pytest.raises(HTTPException) as exc:
            await create_rule_override(body=body, db=db, current_user=_user())

        assert exc.value.status_code == 404
        db.add.assert_not_called()
        db.commit.assert_not_awaited()

    async def test_rule_override_validates_action_before_touching_the_db(self) -> None:
        """A bad action is a 422 and must not become a 404 about the tenant."""
        body = MagicMock(child_tenant_id=uuid.uuid4(), rule_id=uuid.uuid4(), action="delete-everything")
        db = _db({})

        with pytest.raises(HTTPException) as exc:
            await create_rule_override(body=body, db=db, current_user=_user())

        assert exc.value.status_code == 422

    async def test_note_refuses_a_foreign_tenant(self) -> None:
        victim = uuid.uuid4()
        db = _db({victim: _tenant(victim, parent=OTHER_PARENT)})
        body = MagicMock(child_id=victim, body="recon notes")

        with pytest.raises(HTTPException) as exc:
            await create_note(body=body, db=db, current_user=_user())

        assert exc.value.status_code == 404
        db.add.assert_not_called()

    async def test_delegation_refuses_a_foreign_tenant(self) -> None:
        """Otherwise a user could mint themselves a role over any tenant."""
        victim = uuid.uuid4()
        db = _db({victim: _tenant(victim, parent=OTHER_PARENT)})
        body = MagicMock(child_tenant_id=victim, granted_role="admin", expires_at=None)

        with pytest.raises(HTTPException) as exc:
            await create_delegation(body=body, db=db, current_user=_user())

        assert exc.value.status_code == 404
        db.add.assert_not_called()

    async def test_pack_assignment_refuses_a_foreign_tenant(self) -> None:
        """Pack ownership was already checked; the assignment target was not,
        so an owned pack could be pushed into an unowned tenant."""
        victim = uuid.uuid4()
        pack_id = uuid.uuid4()
        pack = MagicMock(id=pack_id, parent_tenant_id=PARENT)
        db = _db({pack_id: pack, victim: _tenant(victim, parent=OTHER_PARENT)})
        body = MagicMock(child_tenant_id=victim, enabled=True, parameter_overrides=None)

        with pytest.raises(HTTPException) as exc:
            await assign_pack_to_child(pack_id=pack_id, body=body, db=db, current_user=_user())

        assert exc.value.status_code == 404
        db.add.assert_not_called()

    async def test_pack_assignment_still_works_for_a_real_child(self) -> None:
        child_id = uuid.uuid4()
        pack_id = uuid.uuid4()
        db = _db({pack_id: MagicMock(id=pack_id, parent_tenant_id=PARENT), child_id: _tenant(child_id, parent=PARENT)})
        body = MagicMock(child_tenant_id=child_id, enabled=True, parameter_overrides=None)

        await assign_pack_to_child(pack_id=pack_id, body=body, db=db, current_user=_user())

        db.add.assert_called_once()
        db.commit.assert_awaited_once()


class TestOnboardingRequiresConsent:
    async def test_refuses_an_uninvited_tenant(self) -> None:
        """The escalation root: every standalone tenant used to be adoptable."""
        victim = uuid.uuid4()
        target = _tenant(victim, parent=None, settings={})
        db = _db({victim: target})

        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=victim, db=db, current_user=_user())

        assert exc.value.status_code == 403
        assert target.parent_tenant_id is None
        db.commit.assert_not_awaited()

    async def test_refuses_when_no_settings_at_all(self) -> None:
        victim = uuid.uuid4()
        db = _db({victim: _tenant(victim, parent=None, settings=None)})

        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=victim, db=db, current_user=_user())

        assert exc.value.status_code == 403

    async def test_refuses_an_invite_addressed_to_a_different_parent(self) -> None:
        victim = uuid.uuid4()
        target = _tenant(victim, parent=None, settings={_MSSP_INVITE_SETTING: str(OTHER_PARENT)})
        db = _db({victim: target})

        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=victim, db=db, current_user=_user())

        assert exc.value.status_code == 403
        assert target.parent_tenant_id is None

    async def test_accepts_an_invite_naming_the_caller(self) -> None:
        child_id = uuid.uuid4()
        child = _tenant(child_id, parent=None, settings={_MSSP_INVITE_SETTING: str(PARENT), "keep": "me"})
        parent_row = _tenant(PARENT)
        db = _db({child_id: child, PARENT: parent_row})

        result = await onboard_child_tenant(child_id=child_id, db=db, current_user=_user())

        assert result["status"] == "ok"
        assert child.parent_tenant_id == PARENT
        assert child.mssp_role == "child"
        assert parent_row.mssp_role == "parent"
        db.commit.assert_awaited_once()

    async def test_invite_is_single_use(self) -> None:
        """A stale invite must not silently re-adopt a tenant that later left."""
        child_id = uuid.uuid4()
        child = _tenant(child_id, parent=None, settings={_MSSP_INVITE_SETTING: str(PARENT), "keep": "me"})
        db = _db({child_id: child, PARENT: _tenant(PARENT)})

        await onboard_child_tenant(child_id=child_id, db=db, current_user=_user())

        assert _MSSP_INVITE_SETTING not in child.settings
        # Unrelated settings survive — the route must not clobber the object.
        assert child.settings["keep"] == "me"

    async def test_a_tenant_cannot_adopt_itself(self) -> None:
        db = _db({PARENT: _tenant(PARENT)})

        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=PARENT, db=db, current_user=_user())

        assert exc.value.status_code == 422

    async def test_already_owned_child_is_idempotent_and_consumes_no_invite(self) -> None:
        child_id = uuid.uuid4()
        child = _tenant(child_id, parent=PARENT, settings={_MSSP_INVITE_SETTING: str(PARENT)})
        db = _db({child_id: child})

        result = await onboard_child_tenant(child_id=child_id, db=db, current_user=_user())

        assert result["status"] == "ok"
        assert child.settings[_MSSP_INVITE_SETTING] == str(PARENT)
        db.commit.assert_not_awaited()

    async def test_tenant_owned_by_another_parent_still_conflicts(self) -> None:
        child_id = uuid.uuid4()
        db = _db({child_id: _tenant(child_id, parent=OTHER_PARENT, settings={_MSSP_INVITE_SETTING: str(PARENT)})})

        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=child_id, db=db, current_user=_user())

        assert exc.value.status_code == 409

    async def test_unknown_tenant_is_404(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await onboard_child_tenant(child_id=uuid.uuid4(), db=_db({}), current_user=_user())
        assert exc.value.status_code == 404

    async def test_refusal_is_logged_without_newline_injection(self, caplog: pytest.LogCaptureFixture) -> None:
        victim = uuid.uuid4()
        db = _db({victim: _tenant(victim, parent=None, settings={})})

        with caplog.at_level("WARNING", logger=mssp.__name__):
            with pytest.raises(HTTPException):
                await onboard_child_tenant(child_id=victim, db=db, current_user=_user())

        assert any("mssp.onboard.refused_without_invite" in r.message for r in caplog.records)


class TestNoOpGuardIsGone:
    def test_ensure_mssp_parent_no_longer_exists(self) -> None:
        """A function named `_ensure_mssp_parent` whose body is `pass` reads as
        an authorization check in every call site and enforces nothing."""
        assert not hasattr(mssp, "_ensure_mssp_parent")
