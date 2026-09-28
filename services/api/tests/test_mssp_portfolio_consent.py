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

The fix reuses the consent mechanism `onboard_child_tenant` already had: a
tenant admits a manager by setting `mssp_parent_invite` in its own settings,
which is gated on `settings:write` and therefore unforgeable from outside that
tenant.

Every test here used to be `inspect.getsource(...)` plus a substring
assertion. That is the wrong instrument for a security fix in two ways. It
cannot distinguish a guard that is present from a guard that is *reached* —
`assert "is_own_tenant" in source` passes on a variable that is assigned and
never read. And the strongest of them asserted a string literal
(`'rejected[...] = "not invited'`), so nothing proved an uninvited tenant is
actually refused, or that no row is written when it is. One of them matched a
*comment*. These now call the route.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import mssp
from app.models.organization import OrganizationTenant
from app.services.org_scope import PortfolioScope


class _Tenant:
    """A tenant row carrying only what the route reads."""

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.settings = settings or {}


class _Session:
    """An async session over an in-memory tenant table and claim table."""

    def __init__(self, tenants: dict[uuid.UUID, _Tenant], claims: dict[uuid.UUID, OrganizationTenant] | None = None) -> None:
        self._tenants = tenants
        self._claims = claims or {}
        self.added: list[Any] = []
        self.committed = False

    async def get(self, _model: Any, tenant_id: uuid.UUID) -> _Tenant | None:
        return self._tenants.get(tenant_id)

    async def execute(self, statement: Any) -> MagicMock:
        # The route issues exactly one select: the claim lookup, filtered on
        # the tenant id. Pull the bound id back out so the fake answers the
        # question that was actually asked.
        compiled = statement.compile()
        wanted = next((v for v in compiled.params.values() if isinstance(v, uuid.UUID)), None)
        assert wanted is not None, f"the claim lookup bound no tenant id: {compiled.params}"
        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=self._claims.get(wanted))
        return result

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        self.committed = True


def _caller(tenant_id: uuid.UUID) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="admin", email="mssp-admin@example.com")


def _scope(org_id: uuid.UUID) -> PortfolioScope:
    return PortfolioScope(org_id=org_id, org_slug="acme", org_name="Acme", org_role="owner", tenant_ids=frozenset())


async def _attach(db: _Session, caller: CurrentUser, org_id: uuid.UUID, *targets: uuid.UUID) -> dict[str, Any]:
    return await mssp.add_tenants_to_portfolio(
        body=mssp.TenantGrant(tenant_ids=list(targets)),
        scope=_scope(org_id),
        db=db,  # type: ignore[arg-type]
        current_user=caller,
    )


class TestTheAttachRequiresConsent:
    @pytest.mark.asyncio
    async def test_a_tenant_that_did_not_invite_the_caller_is_rejected(self) -> None:
        """The vulnerability itself: an unclaimed, uninvited tenant.

        Nothing is claimed here, which on a deployment not using MSSP is
        every tenant. The route must refuse, and must write no row.
        """
        victim, attacker_tenant, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        db = _Session({victim: _Tenant(), attacker_tenant: _Tenant()})

        result = await _attach(db, _caller(attacker_tenant), org, victim)

        assert result["added"] == [], "an uninvited tenant was attached"
        assert "not invited" in result["rejected"][str(victim)]
        assert db.added == [], "no portfolio link may be written for a tenant that did not consent"

    @pytest.mark.asyncio
    async def test_an_invite_naming_a_different_manager_does_not_admit_this_one(self) -> None:
        """An invite is consent to *one* organisation, not to anyone who asks."""
        victim, attacker_tenant, someone_else, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        db = _Session({victim: _Tenant({mssp._MSSP_INVITE_SETTING: str(someone_else)})})

        result = await _attach(db, _caller(attacker_tenant), org, victim)

        assert result["added"] == []
        assert "not invited" in result["rejected"][str(victim)]
        assert db.added == []

    @pytest.mark.asyncio
    async def test_a_tenant_that_invited_the_caller_is_attached(self) -> None:
        managing, invited, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        tenant = _Tenant({mssp._MSSP_INVITE_SETTING: str(managing)})
        db = _Session({invited: tenant})
        caller = _caller(managing)

        result = await _attach(db, caller, org, invited)

        assert result["added"] == [str(invited)]
        assert result["rejected"] == {}
        assert len(db.added) == 1
        link = db.added[0]
        assert (link.org_id, link.tenant_id, link.onboarded_by) == (org, invited, caller.user_id)

    @pytest.mark.asyncio
    async def test_the_caller_may_still_attach_their_own_tenant(self) -> None:
        """Requiring a tenant to invite itself would be ceremony, not consent."""
        own, org = uuid.uuid4(), uuid.uuid4()
        db = _Session({own: _Tenant()})

        result = await _attach(db, _caller(own), org, own)

        assert result["added"] == [str(own)]
        assert len(db.added) == 1

    @pytest.mark.asyncio
    async def test_the_invite_is_consumed_so_it_cannot_be_replayed(self) -> None:
        """A stale invite would let a tenant that later left be re-attached."""
        managing, invited, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        tenant = _Tenant({mssp._MSSP_INVITE_SETTING: str(managing), "keep": "me"})
        db = _Session({invited: tenant})

        await _attach(db, _caller(managing), org, invited)

        assert mssp._MSSP_INVITE_SETTING not in tenant.settings, "the invite survived and can be replayed"
        assert tenant.settings.get("keep") == "me", "consuming the invite must not clear the tenant's other settings"

    @pytest.mark.asyncio
    async def test_a_tenant_managed_by_another_organisation_is_not_reassigned(self) -> None:
        managing, claimed, org, other_org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        existing = OrganizationTenant(org_id=other_org, tenant_id=claimed, relationship="managed")
        db = _Session({claimed: _Tenant({mssp._MSSP_INVITE_SETTING: str(managing)})}, claims={claimed: existing})

        result = await _attach(db, _caller(managing), org, claimed)

        assert result["added"] == []
        assert result["rejected"][str(claimed)] == "managed by another organisation"
        assert db.added == []

    @pytest.mark.asyncio
    async def test_the_refusal_does_not_disclose_an_invite_for_someone_else(self) -> None:
        """Both refusals must read identically, or the response is an oracle.

        A caller who can tell "nobody invited anyone" from "somebody else was
        invited" can enumerate which tenants are mid-onboarding with another
        provider.
        """
        no_invite, other_invite, attacker_tenant, org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        db = _Session(
            {
                no_invite: _Tenant(),
                other_invite: _Tenant({mssp._MSSP_INVITE_SETTING: str(uuid.uuid4())}),
            }
        )

        result = await _attach(db, _caller(attacker_tenant), org, no_invite, other_invite)

        assert result["rejected"][str(no_invite)] == result["rejected"][str(other_invite)]


class TestItIsTheSameMechanismAsChildOnboarding:
    """Two consent paths that drift apart are one bypass waiting to happen."""

    @pytest.mark.asyncio
    async def test_child_onboarding_reads_the_key_the_attach_writes_off(self) -> None:
        """Both routes must key on the same setting, proven by behaviour.

        The old test asserted the identifier `_MSSP_INVITE_SETTING` appeared
        in both function bodies, which a rename to a second constant with a
        different value would satisfy. This drives `onboard_child_tenant`
        with an invite written under the key the attach route consumes: if
        the two ever key differently, the adoption is refused here.
        """
        parent, child = uuid.uuid4(), uuid.uuid4()
        tenant = MagicMock()
        tenant.id = child
        tenant.parent_tenant_id = None
        tenant.settings = {mssp._MSSP_INVITE_SETTING: str(parent)}

        db = MagicMock()
        db.get = AsyncMock(return_value=tenant)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        db.execute = AsyncMock()

        await mssp.onboard_child_tenant(child_id=child, db=db, current_user=_caller(parent))

        assert tenant.parent_tenant_id == parent, "the invite key the attach route consumes did not admit a child"
        assert mssp._MSSP_INVITE_SETTING not in tenant.settings, "child onboarding must consume the invite too"

    def test_the_setting_key_is_defined_once(self) -> None:
        assert isinstance(mssp._MSSP_INVITE_SETTING, str) and mssp._MSSP_INVITE_SETTING
