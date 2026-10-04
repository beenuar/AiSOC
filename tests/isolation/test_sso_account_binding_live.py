"""An unverified email claim cannot take over an existing account.

GHSA-qjjc-q2h2-56cg. Reported through private vulnerability reporting.

What was wrong
--------------
`provision_user` selected the local account with
`WHERE tenant_id = :t AND lower(email) = lower(:e)`, and nothing in the OIDC
path required `email_verified`. The word `email_verified` appeared **nowhere**
in `oidc.py` or `sso_provisioning.py`.

So an attacker who can authenticate to the tenant's configured identity
provider with an account whose *unverified* email matches an existing AiSOC
user receives an access token minted for that existing user's local id. With
database-backed RBAC the API then resolves that local user's `user_roles`, so a
low-privilege group mapping does not contain the damage: the attacker gets the
victim's permissions, not their own.

`provision_user` already accepted a `subject` parameter and never used it for
matching. Its docstring explains why, and the reason is good:

    Matching is on `(tenant_id, email)`. Not on the IdP subject, even though
    that is the stable identifier, because an organisation that moves from one
    IdP to another keeps its email addresses and would otherwise get a second
    account for every person.

The fix has to keep that true. It does, by binding the subject **per
connection**: an IdP migration is a new connection, so bindings do not carry
over and everyone re-claims their account by verified email on first sign-in --
exactly the behaviour the docstring describes. Within one connection, a second
subject presenting a bound account's email is an attack and is refused.

What this file asserts
----------------------
Real Postgres with every migration applied, driving `provision_user` directly:

* an unverified claim cannot select an existing account;
* a verified claim can, and binds;
* once bound, a different subject on the same connection is refused even with
  a verified email;
* the bound subject still resolves after the email changes at the IdP;
* a new connection re-claims by verified email, so IdP migration still works.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SSO_DSN", "").strip(),
        reason="ISOLATION_SSO_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_SSO_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_SSO_DSN is not set")
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def tenant_with_victim(engine):
    """A tenant, a privileged victim account, and two SSO connection ids."""
    from sqlalchemy import text

    tenant = uuid.uuid4()
    victim = uuid.uuid4()
    connection_a = uuid.uuid4()
    connection_b = uuid.uuid4()
    slug = f"sso-{tenant.hex[:8]}"
    victim_email = f"victim-{tenant.hex[:8]}@example.test"

    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tenant, "n": slug, "s": slug},
        )
        await conn.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
                VALUES (:id, :t, :e, :e, 'x', 'tenant_admin', true)
                """
            ),
            {"id": victim, "t": tenant, "e": victim_email},
        )
    try:
        yield {
            "tenant_id": tenant,
            "victim_id": victim,
            "victim_email": victim_email,
            "connection_a": connection_a,
            "connection_b": connection_b,
        }
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM aisoc_sso_identities WHERE tenant_id = :t"), {"t": tenant})
            await conn.execute(text("DELETE FROM users WHERE tenant_id = :t"), {"t": tenant})
            await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant})


async def _provision(engine, *, fixture, subject: str, email: str, verified: bool, connection=None):
    from app.auth.sso_provisioning import provision_user
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        result = await provision_user(
            session,
            tenant_id=fixture["tenant_id"],
            connection_id=connection or fixture["connection_a"],
            email=email,
            name="Someone",
            role="analyst",
            provider="oidc",
            subject=subject,
            email_verified=verified,
        )
        await session.commit()
        return result


class TestAnUnverifiedClaimCannotTakeOverAnAccount:
    async def test_it_is_refused(self, engine, tenant_with_victim) -> None:
        """The vulnerability. This used to return the victim's user id."""
        from app.auth.sso_provisioning import SsoProvisioningError

        with pytest.raises(SsoProvisioningError) as caught:
            await _provision(
                engine,
                fixture=tenant_with_victim,
                subject="attacker-subject",
                email=tenant_with_victim["victim_email"],
                verified=False,
            )

        assert "verif" in str(caught.value).lower(), caught.value

    async def test_an_absent_claim_is_treated_as_unverified(self, engine, tenant_with_victim) -> None:
        """OIDC makes `email_verified` optional, so absent must mean "not
        asserted" rather than "fine". Failing open on a missing claim is the
        same hole with an extra step."""
        from app.auth.sso_provisioning import SsoProvisioningError

        with pytest.raises(SsoProvisioningError):
            await _provision(
                engine,
                fixture=tenant_with_victim,
                subject="attacker-subject",
                email=tenant_with_victim["victim_email"],
                verified=None,
            )

    async def test_the_victims_account_is_untouched(self, engine, tenant_with_victim) -> None:
        """A refusal that had already rewritten the row would be worse than
        the original defect: the role refresh runs before the return."""
        from app.auth.sso_provisioning import SsoProvisioningError
        from sqlalchemy import text

        with pytest.raises(SsoProvisioningError):
            await _provision(
                engine,
                fixture=tenant_with_victim,
                subject="attacker-subject",
                email=tenant_with_victim["victim_email"],
                verified=False,
            )

        async with engine.connect() as conn:
            role = (await conn.execute(text("SELECT role FROM users WHERE id = :id"), {"id": tenant_with_victim["victim_id"]})).scalar_one()

        assert role == "tenant_admin", f"the refused sign-in rewrote the victim's role to {role!r}"


class TestAVerifiedClaimStillWorks:
    """The negative control. A guard that refused everything would pass every
    test above and make SSO unusable."""

    async def test_a_verified_claim_matches_the_existing_account(self, engine, tenant_with_victim) -> None:
        result = await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=tenant_with_victim["victim_email"],
            verified=True,
        )

        assert result["id"] == tenant_with_victim["victim_id"]
        assert result["created"] is False

    async def test_it_binds_the_subject(self, engine, tenant_with_victim) -> None:
        from sqlalchemy import text

        await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=tenant_with_victim["victim_email"],
            verified=True,
        )

        async with engine.connect() as conn:
            bound = (
                await conn.execute(
                    text("SELECT user_id FROM aisoc_sso_identities WHERE connection_id = :c AND subject = :s"),
                    {"c": tenant_with_victim["connection_a"], "s": "victim-subject"},
                )
            ).scalar_one_or_none()

        assert bound == tenant_with_victim["victim_id"]


class TestOnceBoundTheSubjectIsTheIdentity:
    async def test_a_second_subject_cannot_claim_a_bound_account(self, engine, tenant_with_victim) -> None:
        """Even with a *verified* email. Once this connection has said which
        subject owns the account, a different one presenting the same address
        is either a provider that recycles addresses or an attacker, and
        neither should silently win."""
        from app.auth.sso_provisioning import SsoProvisioningError

        await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=tenant_with_victim["victim_email"],
            verified=True,
        )

        with pytest.raises(SsoProvisioningError) as caught:
            await _provision(
                engine,
                fixture=tenant_with_victim,
                subject="attacker-subject",
                email=tenant_with_victim["victim_email"],
                verified=True,
            )

        assert "already" in str(caught.value).lower() or "bound" in str(caught.value).lower()

    async def test_the_binding_survives_an_email_change(self, engine, tenant_with_victim) -> None:
        """The reason to bind the subject at all: it is the stable identifier,
        so somebody who marries and changes address keeps their account and
        their history."""
        await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=tenant_with_victim["victim_email"],
            verified=True,
        )

        renamed = await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=f"new-{tenant_with_victim['victim_email']}",
            verified=True,
        )

        assert renamed["id"] == tenant_with_victim["victim_id"]


class TestIdpMigrationStillWorks:
    async def test_a_new_connection_re_claims_by_verified_email(self, engine, tenant_with_victim) -> None:
        """The behaviour `provision_user`'s docstring promises, and the reason
        matching is on email in the first place: an organisation moving IdP
        keeps its addresses and must not get a second account per person.

        A new connection means new subjects, so bindings do not carry over --
        and each person re-claims their own account on first sign-in.
        """
        await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="victim-subject",
            email=tenant_with_victim["victim_email"],
            verified=True,
        )

        migrated = await _provision(
            engine,
            fixture=tenant_with_victim,
            subject="entirely-different-subject-at-the-new-idp",
            email=tenant_with_victim["victim_email"],
            verified=True,
            connection=tenant_with_victim["connection_b"],
        )

        assert migrated["id"] == tenant_with_victim["victim_id"], (
            "an IdP migration created a second account, which is what matching on email exists to prevent"
        )
        assert migrated["created"] is False
