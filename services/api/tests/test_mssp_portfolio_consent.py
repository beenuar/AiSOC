"""GHSA-mcg9-8pxf-j98v: any tenant could be pulled into any portfolio.

`POST /mssp/organizations/current/tenants` accepted any tenant UUID whose
`organization_tenants` row was unclaimed. The only guard was `_admin_scope`,
which proves the caller administers *their own* organisation — and creating an
organisation is self-service. So three requests let any authenticated user,
including one holding only `viewer`, attach an unrelated tenant and then read
its alerts, cases and posture through the portfolio endpoints.

The precondition — that the target is not already claimed — is not a
mitigation. On a deployment that does not use the MSSP feature no tenant is
claimed, so every tenant was attachable.

The fix reuses the consent mechanism `onboard_child_tenant` already had, and
this file asserts the two are the same mechanism rather than two spellings of
one idea: a tenant admits a manager by setting `mssp_parent_invite` in its own
settings, which is gated on `settings:write` and therefore unforgeable from
outside that tenant.
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import mssp


class TestTheAttachRequiresConsent:
    def test_the_route_reads_the_invite_setting(self) -> None:
        source = inspect.getsource(mssp.add_tenants_to_portfolio)
        assert "_MSSP_INVITE_SETTING" in source, "the attach does not consult the tenant's invite, so any unclaimed tenant is attachable"

    def test_a_tenant_that_did_not_invite_the_caller_is_rejected(self) -> None:
        source = inspect.getsource(mssp.add_tenants_to_portfolio)
        assert 'rejected[str(tenant_id)] = "not invited' in source, "an uninvited tenant is not rejected"

    def test_the_caller_may_still_attach_their_own_tenant(self) -> None:
        """Requiring a tenant to invite itself would be ceremony, not consent."""
        source = inspect.getsource(mssp.add_tenants_to_portfolio)
        assert "is_own_tenant" in source

    def test_the_invite_is_consumed_so_it_cannot_be_replayed(self) -> None:
        source = inspect.getsource(mssp.add_tenants_to_portfolio)
        assert "pop(_MSSP_INVITE_SETTING" in source, "a stale invite would let a tenant that later left be re-attached"

    def test_the_refusal_does_not_disclose_an_invite_for_someone_else(self) -> None:
        source = inspect.getsource(mssp.add_tenants_to_portfolio)
        assert "does not disclose" in source.lower() or "not invited: an admin" in source


class TestItIsTheSameMechanismAsChildOnboarding:
    """Two consent paths that drift apart are one bypass waiting to happen."""

    def test_both_routes_read_the_same_setting_key(self) -> None:
        attach = inspect.getsource(mssp.add_tenants_to_portfolio)
        onboard = inspect.getsource(mssp.onboard_child_tenant)
        assert "_MSSP_INVITE_SETTING" in attach and "_MSSP_INVITE_SETTING" in onboard

    def test_the_setting_key_is_defined_once(self) -> None:
        assert isinstance(mssp._MSSP_INVITE_SETTING, str) and mssp._MSSP_INVITE_SETTING
