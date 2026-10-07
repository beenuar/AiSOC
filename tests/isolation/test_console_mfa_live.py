"""A second factor on the desktop console, through the real app and real Postgres.

Fix pass 4.2.

What was missing
----------------
Everything. `POST /api/v1/auth/login` verified a password and returned a
token pair, and there was no way for a user to add a second factor or for
a tenant to require one. Passkeys existed, on `/responder/*` only — the
mobile PWA — so the surface an analyst actually works from all day was
single-factor and no administrator could change that.

Why this suite is live rather than offline
-------------------------------------------
The property is "a correct password is not enough", and the only thing
that can demonstrate it is the real login route, against the real user
row, with the real password hash. A fake session that answers whatever
the handler asks cannot: it would return a user with whatever MFA state
the test wrote into the double, which is the shape that has shipped
defects in this repository before.

`ENVIRONMENT=test` and not `development`: `development` is in
`AUTH_BYPASS_ENVIRONMENTS`, so an uncredentialed request resolves to a
demo administrator — in the one suite whose whole subject is what it
takes to become a principal.

The negative controls
---------------------
Three, because the positive assertions have three different ways of
passing for the wrong reason:

* `test_a_wrong_code_is_refused` — a verifier that accepted any six
  digits would satisfy every "signs in" assertion here.
* `test_a_recovery_code_cannot_be_used_twice` — a single-use code that
  is not actually consumed is a password that never expires.
* `test_another_tenants_admin_cannot_reset_this_users_factor` — an admin
  reset is the designed way to remove somebody's second factor, so it is
  also the way to remove somebody *else's*.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_MFA_DSN", "").strip(),
        reason="ISOLATION_MFA_DSN is not set; this suite needs a live Postgres",
    ),
]

PASSWORD = "correct-horse-battery-staple-42"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_MFA_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_MFA_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _user(session, *, role: str = "infosec", tenant_id: uuid.UUID | None = None) -> dict:  # noqa: ANN001
    """A real user row with a real bcrypt hash of `PASSWORD`."""
    import sqlalchemy
    from app.core.security import get_password_hash

    await session.rollback()
    if tenant_id is None:
        tenant_id = uuid.uuid4()
        await session.execute(
            sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"mfa-{tenant_id.hex[:8]}", "s": f"mfa-{tenant_id.hex[:8]}"},
        )
    user_id = uuid.uuid4()
    email = f"u-{user_id.hex[:10]}@example.com"
    await session.execute(
        sqlalchemy.text(
            "INSERT INTO users (id, tenant_id, email, username, role, is_active, hashed_password) VALUES (:i, :t, :e, :u, :r, TRUE, :p)"
        ),
        {"i": user_id, "t": tenant_id, "e": email, "u": email.split("@")[0], "r": role, "p": get_password_hash(PASSWORD)},
    )
    await session.commit()
    return {"id": user_id, "tenant_id": tenant_id, "email": email, "role": role}


async def _password_login(client, user: dict) -> object:  # noqa: ANN001
    return await client.post("/api/v1/auth/login", json={"email": user["email"], "password": PASSWORD})


async def _bearer(client, user: dict) -> dict[str, str]:  # noqa: ANN001
    """An ordinary session for a user who has not enrolled a second factor."""
    response = await _password_login(client, user)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _code(secret: str, *, offset: int = 0) -> str:
    """A TOTP code from the production derivation.

    Deliberately the shipped function rather than a second implementation
    in the test: two implementations of RFC 6238 that agree prove they
    agree with each other, not with an authenticator app. The vectors in
    `services/api/tests/test_console_mfa.py` are RFC 6238's own and are
    what pin the derivation to the standard.
    """
    import time

    from app.services.mfa import totp_code_at

    return totp_code_at(secret, int(time.time()) + offset)


#: One 30-second step forward.
#
# The code used to confirm an enrolment is *spent*: `last_used_step` records
# it, so the same code cannot then sign the user in. That is the replay
# protection working, and it means a test that enrols and immediately signs
# in has to ask for the code the authenticator will show next — which is
# what a real user's phone does while they are typing.
NEXT_STEP = 30


async def _enrol(client, user: dict, headers: dict[str, str]) -> dict:  # noqa: ANN001
    begin = await client.post("/api/v1/auth/mfa/enroll/begin", headers=headers)
    assert begin.status_code == 200, begin.text
    secret = begin.json()["secret"]
    assert begin.json()["otpauth_uri"].startswith("otpauth://totp/")
    confirm = await client.post(
        "/api/v1/auth/mfa/enroll/confirm",
        json={"code": _code(secret)},
        headers=headers,
    )
    assert confirm.status_code == 200, confirm.text
    return {"secret": secret, "recovery_codes": confirm.json()["recovery_codes"]}


class TestTheConsoleHasASecondFactor:
    async def test_a_user_can_enrol_one(self, app_client, db) -> None:  # noqa: ANN001
        user = await _user(db)
        headers = await _bearer(app_client, user)

        status_before = await app_client.get("/api/v1/auth/mfa/status", headers=headers)
        assert status_before.status_code == 200, status_before.text
        assert status_before.json()["enrolled"] is False

        enrolment = await _enrol(app_client, user, headers)
        assert len(enrolment["recovery_codes"]) >= 8

        status_after = await app_client.get("/api/v1/auth/mfa/status", headers=headers)
        assert status_after.json()["enrolled"] is True

    async def test_a_password_alone_no_longer_completes_a_sign_in(self, app_client, db) -> None:  # noqa: ANN001
        """The item, in one assertion."""
        user = await _user(db)
        enrolment = await _enrol(app_client, user, await _bearer(app_client, user))

        challenged = await _password_login(app_client, user)
        assert challenged.status_code == 202, (
            f"a correct password returned {challenged.status_code} for a user with a confirmed second factor; body={challenged.text[:300]}"
        )
        body = challenged.json()
        assert body["mfa_required"] is True
        assert "access_token" not in body
        assert body["mfa_token"]

        completed = await app_client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": body["mfa_token"], "code": _code(enrolment["secret"], offset=NEXT_STEP)},
        )
        assert completed.status_code == 200, completed.text
        token = completed.json()["access_token"]
        me = await app_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["email"] == user["email"]

    async def test_a_recovery_code_also_completes_it(self, app_client, db) -> None:  # noqa: ANN001
        """The authenticator is on a phone, and phones are lost mid-incident."""
        user = await _user(db)
        enrolment = await _enrol(app_client, user, await _bearer(app_client, user))
        challenged = await _password_login(app_client, user)

        completed = await app_client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": challenged.json()["mfa_token"], "code": enrolment["recovery_codes"][0]},
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["access_token"]


class TestPerTenantEnforcement:
    async def test_a_tenant_admin_can_require_a_second_factor(self, app_client, db) -> None:  # noqa: ANN001
        admin = await _user(db, role="tenant_admin")
        headers = await _bearer(app_client, admin)

        updated = await app_client.put("/api/v1/auth/mfa/policy", json={"require_totp": True}, headers=headers)
        assert updated.status_code == 200, updated.text
        assert updated.json()["require_totp"] is True

        member = await _user(db, tenant_id=admin["tenant_id"])
        challenged = await _password_login(app_client, member)
        assert challenged.status_code == 202, challenged.text
        body = challenged.json()
        # Enrolment, not verification: this user has nothing to verify yet.
        assert body["mfa_enrollment_required"] is True
        assert "access_token" not in body

    async def test_an_unenrolled_user_can_enrol_from_the_challenge(self, app_client, db) -> None:  # noqa: ANN001
        """The lockout this feature would otherwise ship with.

        When an administrator turns enforcement on, every user who has not
        enrolled holds a correct password and no second factor. If the
        challenge did not let them enrol, the whole tenant would be locked
        out at once.
        """
        admin = await _user(db, role="tenant_admin")
        assert (
            await app_client.put("/api/v1/auth/mfa/policy", json={"require_totp": True}, headers=await _bearer(app_client, admin))
        ).status_code == 200

        member = await _user(db, tenant_id=admin["tenant_id"])
        challenged = await _password_login(app_client, member)
        token = challenged.json()["mfa_token"]

        begin = await app_client.post("/api/v1/auth/mfa/enroll/begin", json={"mfa_token": token})
        assert begin.status_code == 200, begin.text
        secret = begin.json()["secret"]

        confirmed = await app_client.post("/api/v1/auth/mfa/enroll/confirm", json={"mfa_token": token, "code": _code(secret)})
        assert confirmed.status_code == 200, confirmed.text
        # Signed in by the enrolment itself, rather than made to
        # authenticate a second time with a code they just proved.
        assert confirmed.json()["access_token"]
        assert len(confirmed.json()["recovery_codes"]) >= 8

    async def test_an_access_token_is_not_a_sign_in_challenge(self, app_client, db) -> None:  # noqa: ANN001
        """A session is not a second factor.

        Both halves are checked, because the token is accepted in two
        places and each would be a separate hole: presenting an access
        token at `/auth/mfa/verify` would let a live session mint another
        with no code, and presenting one as an *enrolment* challenge would
        let it enrol a factor for somebody who is mid-sign-in.
        """
        holder = await _user(db)
        access_token = (await _password_login(app_client, holder)).json()["access_token"]

        verified = await app_client.post("/api/v1/auth/mfa/verify", json={"mfa_token": access_token, "code": "123456"})
        assert verified.status_code == 401, verified.text

        enrolled = await app_client.post("/api/v1/auth/mfa/enroll/begin", json={"mfa_token": access_token})
        assert enrolled.status_code == 401, enrolled.text

    async def test_a_tenant_that_has_not_asked_is_not_forced(self, app_client, db) -> None:  # noqa: ANN001
        """Absence of a policy row means not required.

        Stated as a test because the obvious implementation — a migration
        that writes a policy row for every tenant — would change the
        meaning of every predicate that counts those rows, and this
        repository has shipped a zero-permission administrator that way.
        """
        user = await _user(db)
        assert (await _password_login(app_client, user)).status_code == 200

    async def test_a_viewer_cannot_change_the_policy(self, app_client, db) -> None:  # noqa: ANN001
        viewer = await _user(db, role="viewer")
        response = await app_client.put(
            "/api/v1/auth/mfa/policy",
            json={"require_totp": True},
            headers=await _bearer(app_client, viewer),
        )
        assert response.status_code == 403, response.text


class TestTheNegativeControls:
    async def test_a_wrong_code_is_refused(self, app_client, db) -> None:  # noqa: ANN001
        user = await _user(db)
        await _enrol(app_client, user, await _bearer(app_client, user))
        challenged = await _password_login(app_client, user)

        refused = await app_client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": challenged.json()["mfa_token"], "code": "000000"},
        )
        assert refused.status_code == 401, refused.text
        assert "access_token" not in refused.text

    async def test_a_recovery_code_cannot_be_used_twice(self, app_client, db) -> None:  # noqa: ANN001
        user = await _user(db)
        enrolment = await _enrol(app_client, user, await _bearer(app_client, user))
        code = enrolment["recovery_codes"][0]

        first = await _password_login(app_client, user)
        assert (
            await app_client.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_token": first.json()["mfa_token"], "code": code},
            )
        ).status_code == 200

        second = await _password_login(app_client, user)
        replayed = await app_client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": second.json()["mfa_token"], "code": code},
        )
        assert replayed.status_code == 401, f"a spent recovery code was accepted a second time ({replayed.status_code})"

    async def test_a_totp_code_cannot_be_replayed_within_its_window(self, app_client, db) -> None:  # noqa: ANN001
        """A 30-second step means a code stays arithmetically valid after
        use. Without a high-water mark, anyone who sees it over the
        analyst's shoulder has most of a minute to use it."""
        user = await _user(db)
        enrolment = await _enrol(app_client, user, await _bearer(app_client, user))
        code = _code(enrolment["secret"], offset=NEXT_STEP)

        first = await _password_login(app_client, user)
        assert (
            await app_client.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_token": first.json()["mfa_token"], "code": code},
            )
        ).status_code == 200

        second = await _password_login(app_client, user)
        replayed = await app_client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": second.json()["mfa_token"], "code": code},
        )
        assert replayed.status_code == 401, f"a TOTP code was accepted twice in one step ({replayed.status_code})"

    async def test_another_tenants_admin_cannot_reset_this_users_factor(self, app_client, db) -> None:  # noqa: ANN001
        victim = await _user(db)
        await _enrol(app_client, victim, await _bearer(app_client, victim))

        outsider = await _user(db, role="tenant_admin")
        response = await app_client.post(
            f"/api/v1/auth/mfa/reset/{victim['id']}",
            json={"reason": "support request"},
            headers=await _bearer(app_client, outsider),
        )
        assert response.status_code in (403, 404), response.text

        # And the factor is still there.
        still_challenged = await _password_login(app_client, victim)
        assert still_challenged.status_code == 202


class TestEnrolmentAndResetAreAudited:
    async def test_both_write_an_audit_row(self, app_client, db) -> None:  # noqa: ANN001
        import sqlalchemy

        admin = await _user(db, role="tenant_admin")
        member = await _user(db, tenant_id=admin["tenant_id"])
        await _enrol(app_client, member, await _bearer(app_client, member))

        reset = await app_client.post(
            f"/api/v1/auth/mfa/reset/{member['id']}",
            json={"reason": "lost phone, verified by voice"},
            headers=await _bearer(app_client, admin),
        )
        assert reset.status_code == 200, reset.text

        await db.rollback()
        actions = {
            row[0]
            for row in (
                await db.execute(
                    sqlalchemy.text("SELECT action FROM audit_log WHERE tenant_id = :t"),
                    {"t": admin["tenant_id"]},
                )
            ).all()
        }
        assert "mfa.enrolled" in actions, f"enrolment wrote no audit row; saw {sorted(actions)}"
        assert "mfa.reset" in actions, f"an administrative reset wrote no audit row; saw {sorted(actions)}"

        # A reset removes the factor, so the next password login succeeds
        # outright — that is the point of the reset and also what makes it
        # worth auditing.
        assert (await _password_login(app_client, member)).status_code == 200
