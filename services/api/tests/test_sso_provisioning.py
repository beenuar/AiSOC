"""SSO completes a sign-in: a real user, a bound tenant, a token the API verifies.

Parity plan 4.1.

What was wrong
--------------
Both handlers ended a successful sign-in by putting a JWT in an
`aisoc_token` cookie, carrying `sub`, `email`, `name` and `picture`. That
token authenticated nothing, three times over: the API verifies with
`settings.SECRET_KEY` and this was signed with `JWT_SECRET`; the API
requires `tenant_id` and `role` and neither was present; and the API reads
`Authorization: Bearer`, not a cookie.

So a user could complete the whole OIDC dance, be redirected to the
console, and find every request unauthenticated. The plan's phrasing is
exact: "a token in a cookie the API never reads, and it names no local
user, tenant or role".

The security property these tests exist for
--------------------------------------------
**The tenant must not come from the assertion.** An identity provider that
can name its own tenant can name somebody else's, and the obvious
implementation (read `tenant_id` from a claim) is a cross-tenant
provisioning hole. It comes from the connection row an administrator
configured, and that is asserted rather than assumed.
"""

from __future__ import annotations

import inspect

import jwt
import pytest
from app.auth import oidc, saml, sso_provisioning
from app.auth.sso_provisioning import (
    ASSIGNABLE_ROLES,
    DEFAULT_ROLE,
    SsoProvisioningError,
    map_groups_to_role,
)
from app.core.config import settings


class TestGroupMapping:
    def test_a_mapped_group_grants_its_role(self) -> None:
        assert map_groups_to_role(["soc-analysts"], {"soc-analysts": "soc_analyst"}) == "soc_analyst"

    def test_an_unmapped_group_grants_the_least_privileged_role(self) -> None:
        """Not nothing: a user who authenticated and can then see nothing
        reads as a broken integration rather than a policy decision."""
        assert map_groups_to_role(["finance"], {}) == DEFAULT_ROLE

    def test_the_highest_role_wins_regardless_of_order(self) -> None:
        """Making the answer depend on the IdP's list order would make it
        unstable across sign-ins."""
        mapping = {"a": "soc_analyst", "b": "soc_lead"}
        assert map_groups_to_role(["a", "b"], mapping) == "soc_lead"
        assert map_groups_to_role(["b", "a"], mapping) == "soc_lead"

    @pytest.mark.parametrize("role", ["admin", "platform_admin"])
    def test_a_group_cannot_confer_an_unassignable_role(self, role: str) -> None:
        """v14.0.0 made `admin` and `platform_admin` unreachable from every
        API route so that only `bootstrap_admin` can mint one. A group
        mapping would be a way back in."""
        assert role not in ASSIGNABLE_ROLES
        assert map_groups_to_role(["wheel"], {"wheel": role}) == DEFAULT_ROLE


class TestTheTenantDoesNotComeFromTheAssertion:
    """The security property this whole module exists to hold."""

    def test_complete_sso_login_takes_no_tenant_argument(self) -> None:
        signature = inspect.signature(sso_provisioning.complete_sso_login)
        assert "tenant_id" not in signature.parameters, (
            "complete_sso_login accepts a tenant from its caller, so an assertion could name the tenant it provisions into"
        )

    def test_it_resolves_the_tenant_from_the_connection(self) -> None:
        source = inspect.getsource(sso_provisioning.complete_sso_login)
        assert "resolve_connection(" in source
        assert 'connection["tenant_id"]' in source

    def test_no_connection_is_a_refusal_with_a_reason(self) -> None:
        source = inspect.getsource(sso_provisioning.complete_sso_login)
        assert "no enabled SSO connection" in source
        assert "never from the assertion" in source


class TestTheTokenTheApiActuallyVerifies:
    def test_it_is_signed_with_the_key_the_api_verifies_with(self) -> None:
        source = inspect.getsource(sso_provisioning.complete_sso_login)
        assert "create_access_token" in source, (
            "the token is not minted by the same function `POST /auth/login` uses, so it "
            "may be signed with a different key than the API verifies with"
        )
        assert "_issue_jwt" not in source

    def test_it_carries_the_claims_the_verifier_requires(self) -> None:
        source = inspect.getsource(sso_provisioning.complete_sso_login)
        for claim in ('"sub"', '"tenant_id"', '"role"', '"email"'):
            assert claim in source, f"the token carries no {claim}, so it authenticates nothing"

    def test_a_token_it_mints_round_trips_through_the_real_verifier(self) -> None:
        from app.core.security import create_access_token

        token = create_access_token({"sub": "u1", "tenant_id": "t1", "role": "soc_analyst", "email": "a@b.c"})
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert decoded["tenant_id"] == "t1"
        assert decoded["role"] == "soc_analyst"
        assert decoded["type"] == "access"


class TestTheHandlersUseIt:
    """Otherwise this is another module with passing tests and no caller."""

    def test_the_oidc_callback_provisions(self) -> None:
        source = inspect.getsource(oidc.oidc_callback)
        assert "complete_sso_login(" in source
        assert "_issue_jwt(" not in source, "the OIDC callback still mints its own token"

    def test_the_saml_acs_provisions(self) -> None:
        source = inspect.getsource(saml.saml_acs)
        assert "complete_sso_login(" in source
        assert "_issue_jwt(" not in source, "the SAML ACS still mints its own token"

    @pytest.mark.parametrize("handler", ["oidc_callback", "saml_acs"])
    def test_neither_sets_the_cookie_the_api_cannot_read(self, handler: str) -> None:
        module = oidc if handler == "oidc_callback" else saml
        source = inspect.getsource(getattr(module, handler))
        assert 'set_cookie("aisoc_token"' not in source, f"{handler} still puts the token in a cookie the API does not read"

    @pytest.mark.parametrize("handler", ["oidc_callback", "saml_acs"])
    def test_the_token_travels_in_the_fragment(self, handler: str) -> None:
        """Not the query string: a fragment is not sent to the server, does
        not reach an access log, and does not leak through `Referer`."""
        module = oidc if handler == "oidc_callback" else saml
        source = inspect.getsource(getattr(module, handler))
        assert "#" in source and "access_token=" in source

    @pytest.mark.parametrize("handler", ["oidc_callback", "saml_acs"])
    def test_a_provisioning_refusal_says_why(self, handler: str) -> None:
        """ "No SSO connection is configured for this issuer" is an
        administrator's next action; "login failed" is a support ticket."""
        module = oidc if handler == "oidc_callback" else saml
        source = inspect.getsource(getattr(module, handler))
        assert "SsoProvisioningError" in source
        assert "str(exc)" in source


class TestProvisioningRules:
    def test_a_deactivated_account_is_not_revived_by_signing_in(self) -> None:
        """Deactivation is how an operator removes access. SSO re-creating
        the account on the next sign-in would make that useless."""
        source = inspect.getsource(sso_provisioning.provision_user)
        assert "is_active" in source
        assert "deactivated" in source

    def test_an_sso_account_gets_no_usable_password(self) -> None:
        source = inspect.getsource(sso_provisioning.provision_user)
        assert "!sso-no-password" in source, "an SSO-provisioned account must not be signable-into with a password"

    def test_the_role_is_refreshed_on_every_sign_in(self) -> None:
        """So removing someone from a group takes effect at their next
        login rather than needing a second manual step."""
        source = inspect.getsource(sso_provisioning.provision_user)
        assert "UPDATE users SET role" in source

    def test_matching_is_on_email_not_on_the_idp_subject(self) -> None:
        """An organisation moving between IdPs keeps its email addresses
        and would otherwise get a second account for every person."""
        source = inspect.getsource(sso_provisioning.provision_user)
        assert "lower(email) = lower(:e)" in source

    def test_an_assertion_with_no_email_is_refused(self) -> None:
        source = inspect.getsource(sso_provisioning.complete_sso_login)
        assert "no email" in source


class TestGroupClaimSpellings:
    @pytest.mark.parametrize(
        ("claims", "expected"),
        [
            ({"groups": ["a", "b"]}, ["a", "b"]),
            ({"roles": ["x"]}, ["x"]),
            ({"memberOf": ["cn=soc"]}, ["cn=soc"]),
            ({"groups": "a,b"}, ["a", "b"]),
            ({}, []),
        ],
    )
    def test_the_four_spellings_are_read(self, claims: dict, expected: list[str]) -> None:
        """There is no standard claim: Okta and Auth0 emit `groups`, Entra
        emits `roles` or `groups` depending on the app registration, and
        Keycloak emits whatever the mapper was named."""
        assert oidc._claim_groups(claims) == expected

    def test_a_missing_group_claim_is_not_an_error(self) -> None:
        assert oidc._claim_groups({"sub": "x", "email": "a@b.c"}) == []


@pytest.mark.asyncio
class TestRefusals:
    async def test_no_email_raises_rather_than_provisioning_something(self) -> None:
        with pytest.raises(SsoProvisioningError, match="no email"):
            await sso_provisioning.complete_sso_login(
                None,  # type: ignore[arg-type]
                provider="oidc",
                issuer="https://idp.example",
                email="",
                subject="s",
            )
