"""Unit tests for the grant-scope chokepoint itself.

Separate from `test_role_grant_scope.py` on purpose. That file asserts what
the shipped handlers do and imports nothing the fix added, so every failure
there is a failure of the product. This file tests `app.core.role_grants`
directly and therefore cannot run against a tree that predates it — which is
fine for a unit test and would be worthless as a regression proof.

The ratchet is `test_every_declared_role_has_a_decision`: a role added to
`ROLE_PERMISSIONS` that is neither grantable nor recorded as refused fails
here, because silence about a new role reads as "assignable" to a reviewer
and as "refused" to the code.
"""

from __future__ import annotations

import pytest
from app.core.role_grants import (
    GRANTABLE_ROLES,
    RoleGrantDenied,
    authorize_permission_grant,
    authorize_role_change,
    authorize_role_grant,
    missing_permissions,
    never_grantable,
    permissions_for,
    vocabulary_problems,
    wildcard_roles,
)
from app.core.security import ROLE_PERMISSIONS
from app.services.scim import roles as scim_roles


class TestVocabulary:
    def test_every_declared_role_has_a_decision(self) -> None:
        assert vocabulary_problems() == []

    def test_no_grantable_role_holds_the_wildcard(self) -> None:
        """The whole finding in one assertion: a single unchecked string must
        not be able to confer every permission in the product."""
        assert not (set(GRANTABLE_ROLES) & wildcard_roles())

    def test_the_wildcard_set_is_derived_not_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A third role declared `["*"]` must be refused without anyone
        remembering to add it to a list."""
        monkeypatch.setitem(ROLE_PERMISSIONS, "break_glass", ["*"])
        assert "break_glass" in never_grantable()
        with pytest.raises(RoleGrantDenied):
            authorize_role_grant(granter_role="platform_admin", requested_role="break_glass")

    def test_scim_shares_this_vocabulary_rather_than_copying_it(self) -> None:
        assert scim_roles.ROLE_PRECEDENCE is GRANTABLE_ROLES
        assert scim_roles.UNREACHABLE_BY_GROUP == never_grantable()
        assert scim_roles.validate_vocabulary() == []


class TestRoleGrant:
    @pytest.mark.parametrize("role", sorted(never_grantable()))
    def test_a_refused_role_is_refused_even_for_a_wildcard_caller(self, role: str) -> None:
        with pytest.raises(RoleGrantDenied) as exc:
            authorize_role_grant(granter_role="platform_admin", requested_role=role)
        assert not exc.value.unknown

    def test_an_unknown_role_is_flagged_as_unknown(self) -> None:
        with pytest.raises(RoleGrantDenied) as exc:
            authorize_role_grant(granter_role="platform_admin", requested_role="superuser")
        assert exc.value.unknown

    @pytest.mark.parametrize("role", GRANTABLE_ROLES)
    def test_a_tenant_admin_covers_every_grantable_role(self, role: str) -> None:
        """If this ever fails, the refusal below is a real capability loss and
        not just a closed hole — which is the thing to notice before shipping."""
        assert authorize_role_grant(granter_role="tenant_admin", requested_role=role) == role

    def test_a_viewer_cannot_grant_an_analyst(self) -> None:
        with pytest.raises(RoleGrantDenied) as exc:
            authorize_role_grant(granter_role="viewer", requested_role="soc_analyst")
        assert "alerts:write" in exc.value.reason

    def test_the_two_hunter_and_analyst_roles_cannot_grant_each_other(self) -> None:
        """Permission sets are only partially ordered, so `GRANTABLE_ROLES`
        order is presentation and the subset check is the authority."""
        with pytest.raises(RoleGrantDenied):
            authorize_role_grant(granter_role="soc_analyst", requested_role="threat_hunter")
        with pytest.raises(RoleGrantDenied):
            authorize_role_grant(granter_role="threat_hunter", requested_role="soc_analyst")


class TestPermissionGrant:
    def test_a_resource_wildcard_covers_its_members(self) -> None:
        assert missing_permissions(frozenset({"alerts:*"}), ["alerts:read", "alerts:delete"]) == []

    def test_a_held_scope_list_bounds_an_api_key_principal(self) -> None:
        with pytest.raises(RoleGrantDenied):
            authorize_permission_grant(
                granter_role="tenant_admin",
                granter_scopes=["alerts:read"],
                requested=["cases:write"],
            )

    def test_a_wildcard_holder_may_confer_the_wildcard(self) -> None:
        assert authorize_permission_grant(granter_role="platform_admin", requested=["*"]) == ["*"]

    def test_a_scoped_role_may_not(self) -> None:
        with pytest.raises(RoleGrantDenied):
            authorize_permission_grant(granter_role="tenant_admin", requested=["*"])


class TestRoleChange:
    def test_a_principal_holding_a_refused_role_cannot_be_re_roled(self) -> None:
        with pytest.raises(RoleGrantDenied):
            authorize_role_change(granter_role="tenant_admin", current_role="admin", requested_role="viewer")

    def test_an_ordinary_change_is_allowed(self) -> None:
        assert authorize_role_change(granter_role="tenant_admin", current_role="viewer", requested_role="soc_lead") == "soc_lead"

    def test_permissions_for_an_unknown_role_is_empty(self) -> None:
        assert permissions_for("superuser") == frozenset()
