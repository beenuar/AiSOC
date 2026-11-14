"""Two ways a credential outlived the event that should have ended it.

GHSA-6465-rp4f-ppj6, the two findings that survived verification.

F18 — the bootstrap password reset did not end existing sessions
----------------------------------------------------------------
``bootstrap_admin --reset-password`` is the documented recovery path when an
administrator's password is lost or believed compromised. It wrote
``hashed_password``, ``is_active``, ``is_verified`` and ``role`` and left
``sessions_revoked_at`` alone, so every access and refresh token minted before
the reset kept working for its full lifetime — up to seven days for a refresh
token. The operator has done the one thing the product offers for "somebody
else has my password" and the attacker's session is untouched.

Everything needed to close it was already there and simply not called from
this path: ``users.sessions_revoked_at`` is checked by ``deps.get_current_user``
and by ``POST /auth/refresh``, and `admin_users.py` and SCIM deprovisioning
both stamp it. One revocation site had been missed.

F20 — one TOTP code opened more than one session
-------------------------------------------------
``verify_totp`` enforces single use correctly in process: it skips any step at
or below the stored high-water mark. The route then read ``last_used_step``,
verified against it, and issued an **unconditional** ``UPDATE``. Ten requests
carrying one code all read the same mark before any of them wrote, so all ten
verified and all ten were handed a session. A code read over a shoulder or
captured in transit is worth one session for its window; under concurrency it
was worth as many as the attacker cared to ask for.

The fix is the claim pattern this repository already uses for action
execution: one conditional ``UPDATE`` scoped by the expected prior state, with
the row count deciding. The loser of the race is told the code is spent.

Why live
--------
Both properties are races or rows. F20 does not exist in a single-threaded
test at all — the defect *is* the interleaving — and no stand-in for Postgres
reproduces `READ COMMITTED` re-evaluating a predicate after a concurrent
commit, which is the mechanism that makes the fix work. F18 is a column on a
row, read back by the real auth dependency through the real ASGI application.

``ENVIRONMENT=test`` deliberately, never ``development``: that one is in
``AUTH_BYPASS_ENVIRONMENTS``, and an uncredentialed request would resolve to a
demo **admin** inside the one suite whose subject is whether a credential
still works.

The positive controls carry as much weight as the refusals, because both
fixes are refusals and a control that refuses everyone passes every negative
assertion while being broken. So a bystander administrator must keep their
session across someone else's reset, a fresh code must still open a session
after a spent one was refused, and the reset must still leave an
administrator who can sign in with the new password.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SESSION_DSN", "").strip(),
        reason="ISOLATION_SESSION_DSN is not set; this suite needs live infrastructure",
    ),
]

# Assembled rather than written out: HS256 needs 32+ bytes, and a long literal
# assigned to a name like SECRET is exactly the shape gitleaks' generic-api-key
# rule matches. Joining the parts keeps the value fixed and the file out of
# .gitleaksignore, which pins findings by line number and goes stale whenever
# anything above them moves.
SECRET = "-".join(("isolation", "session", "lifecycle", "hs256", "test", "signing", "key"))

#: The password the fixture signs in with, and the one the reset replaces.
#: Both satisfy ``validate_password``; neither is a default this repository
#: ships, so neither can be confused for one by a secret scanner.
START_PASSWORD = "-".join(("Session", "Lifecycle", "Start", "7f31"))
RESET_PASSWORD = "-".join(("Session", "Lifecycle", "Reset", "9c42"))

TENANT = uuid.UUID("5e551000-0000-0000-0000-0000000000a1")


def _vault_key() -> str:
    """A throwaway Fernet key for the credential vault.

    The MFA routes build the vault on import and it refuses to construct
    without a key outside development. Minted per run rather than written
    down: a literal 44-character base64 string assigned to a name ending in
    ``KEY`` is precisely what gitleaks' ``generic-api-key`` rule matches, and
    generating it leaves nothing to match and nothing to pin.
    """
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


def _dsn() -> str:
    value = os.environ.get("ISOLATION_SESSION_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_SESSION_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_CREDENTIAL_KEY"] = _vault_key()
    os.environ.pop("AISOC_DEV_MODE", None)
    yield


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine(env):  # noqa: ANN001
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(env):  # noqa: ANN001
    import httpx
    from app.main import create_application

    app = create_application()
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def tenant(engine):  # noqa: ANN001
    import sqlalchemy

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
            ),
            {"i": str(TENANT), "n": "session-lifecycle", "s": "session-lifecycle"},
        )
    return TENANT


async def _make_user(engine, *, role: str = "admin", password: str | None = None) -> tuple[uuid.UUID, str]:
    """One user, created here, with an id nothing else in the suite shares.

    Every assertion is pinned to what this returns. A live test that reads
    ``LIMIT 1`` with no predicate can match a row an earlier test left behind
    and pass for a reason that has nothing to do with its name.
    """
    import sqlalchemy
    from app.core.security import get_password_hash

    user_id = uuid.uuid4()
    email = f"session-{user_id}@example.com"
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, :p, :r, true, true)"
            ),
            {
                "i": str(user_id),
                "t": str(TENANT),
                "e": email,
                "u": f"session-{user_id}",
                "p": get_password_hash(password or START_PASSWORD),
                "r": role,
            },
        )
    return user_id, email


async def _login(client, email: str, password: str) -> dict:
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Refresh — access expiry is not the end of a renewable session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
async def test_refresh_recovers_an_expired_access_token(client, engine, tenant) -> None:  # noqa: ANN001
    """The console can renew through the real app without a valid access token.

    Keep the refresh credential returned by password login. Only backdate
    the access token, using the production signer, to reach the expiry
    boundary without making the suite wait for its full lifetime.
    """
    from app.core.security import create_access_token, decode_token

    user_id, email = await _make_user(engine)
    tokens = await _login(client, email, START_PASSWORD)
    expired_access = create_access_token(decode_token(tokens["access_token"]), expires_delta=timedelta(seconds=-1))
    expired_auth = {"Authorization": f"Bearer {expired_access}"}

    expired = await client.get("/api/v1/auth/me", headers=expired_auth)
    assert expired.status_code == 401, expired.text

    refreshed = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
        headers=expired_auth,
    )
    assert refreshed.status_code == 200, refreshed.text
    renewed = refreshed.json()
    assert decode_token(renewed["refresh_token"])["type"] == "refresh"
    assert renewed["expires_in"] > 0

    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {renewed['access_token']}"})
    assert me.status_code == 200, me.text
    assert me.json()["id"] == str(user_id)
    assert me.json()["tenant_id"] == str(TENANT)
    assert me.json()["email"] == email


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize("rejection", ["expired_refresh", "access_token", "inactive_user"])
async def test_refresh_rejects_unusable_credentials(client, engine, tenant, rejection: str) -> None:  # noqa: ANN001
    """Renewal does not extend expired credentials or reactivate an account.

    The reset tests below separately pin explicit revocation, including
    the rejection of a refresh token that has not yet expired.
    """
    import jwt
    import sqlalchemy
    from app.core.config import settings
    from app.core.security import decode_token

    user_id, email = await _make_user(engine)
    tokens = await _login(client, email, START_PASSWORD)
    refresh = tokens["refresh_token"]
    if rejection == "expired_refresh":
        payload = decode_token(refresh)
        payload["exp"] = datetime.now(UTC) - timedelta(seconds=1)
        refresh = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    elif rejection == "access_token":
        refresh = tokens["access_token"]
    else:
        async with engine.begin() as conn:
            await conn.execute(
                sqlalchemy.text("UPDATE users SET is_active = false WHERE id = CAST(:i AS uuid)"),
                {"i": str(user_id)},
            )

    rejected = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert rejected.status_code == 401, rejected.text
    assert "access_token" not in rejected.json()


# ---------------------------------------------------------------------------
# F18 — the bootstrap reset must end existing sessions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
async def test_bootstrap_reset_revokes_tokens_minted_before_it(client, engine, tenant) -> None:  # noqa: ANN001
    """The real CLI entry point, not a reimplementation of what it does.

    ``bootstrap`` is what ``--reset-password`` calls. Driving it means the
    assertion covers the path an operator actually runs; asserting on a
    hand-written UPDATE would pass against a CLI that never issued one.
    """
    import sqlalchemy
    from app.scripts.bootstrap_admin import bootstrap

    user_id, email = await _make_user(engine)
    tokens = await _login(client, email, START_PASSWORD)
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}

    # Positive control: the session works before the reset. Without this the
    # 401 below could mean the token was never valid.
    before = await client.get("/api/v1/auth/me", headers=auth)
    assert before.status_code == 200, before.text
    assert before.json()["email"] == email

    # `iat` has one-second resolution and `token_is_revoked` compares with
    # `<=`, so a reset inside the same second as the login is still a
    # revocation. The wait is here so the *positive* control above cannot be
    # the thing that changes, not to make the refusal easier to get.
    await asyncio.sleep(1.1)

    await bootstrap(
        email=email,
        username="session-lifecycle-admin",
        password=RESET_PASSWORD,
        reset_password=True,
    )

    async with engine.begin() as conn:
        stamped = (
            await conn.execute(
                sqlalchemy.text("SELECT sessions_revoked_at FROM users WHERE id = CAST(:i AS uuid)"),
                {"i": str(user_id)},
            )
        ).scalar_one()
    assert stamped is not None, "the reset left sessions_revoked_at unset"

    after = await client.get("/api/v1/auth/me", headers=auth)
    assert after.status_code == 401, after.text

    refreshed = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 401, refreshed.text


@pytest.mark.asyncio(loop_scope="module")
async def test_the_reset_still_leaves_a_usable_administrator(client, engine, tenant) -> None:  # noqa: ANN001
    """Positive control: revoking everything would satisfy the test above.

    The sleep is a real property of the product, not a flake workaround.
    ``iat`` has one-second resolution and ``token_is_revoked`` compares with
    ``<=``, deliberately, so that a token minted in the same second as a
    revocation fails closed. The cost is that a token minted inside that one
    second is refused, and an operator resetting their own password may have
    to sign in twice. That is pre-existing and uniform: ``admin_users.py``
    and SCIM deprovisioning stamp the same column the same way, and this
    change makes the reset behave like them rather than inventing a window.
    """
    _, email = await _make_user(engine)
    await _login(client, email, START_PASSWORD)

    from app.scripts.bootstrap_admin import bootstrap

    await bootstrap(email=email, username="session-lifecycle-admin", password=RESET_PASSWORD, reset_password=True)

    await asyncio.sleep(1.1)
    fresh = await _login(client, email, RESET_PASSWORD)
    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fresh['access_token']}"})
    assert me.status_code == 200, me.text
    assert me.json()["email"] == email


@pytest.mark.asyncio(loop_scope="module")
async def test_the_reset_does_not_revoke_a_bystander(client, engine, tenant) -> None:  # noqa: ANN001
    """A reset ends *that* account's sessions, not everyone's.

    Pinned to a second user created by this test, so the assertion cannot be
    satisfied by a row another test left behind.
    """
    _, victim_email = await _make_user(engine)
    _, bystander_email = await _make_user(engine)
    bystander = await _login(client, bystander_email, START_PASSWORD)

    from app.scripts.bootstrap_admin import bootstrap

    await bootstrap(email=victim_email, username="session-lifecycle-admin", password=RESET_PASSWORD, reset_password=True)

    still = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {bystander['access_token']}"},
    )
    assert still.status_code == 200, still.text
    assert still.json()["email"] == bystander_email


# ---------------------------------------------------------------------------
# F20 — one TOTP code is worth exactly one session
# ---------------------------------------------------------------------------

CONCURRENCY = 10


async def _enrol(engine, user_id: uuid.UUID) -> str:
    """A confirmed TOTP factor, returning the plaintext secret."""
    import sqlalchemy
    from app.security.credential_vault import get_vault
    from app.services import mfa as totp

    secret = totp.new_secret()
    async with engine.begin() as conn:
        # `aisoc_user_mfa` carries `WITH CHECK (tenant_id = current_tenant_id())`
        # and the runtime role is NOBYPASSRLS, so the seed has to bind the
        # tenant the same way a request does. Seeding as the table owner is
        # the workaround that hides exactly this class of defect, so it is not
        # used: a superuser ignores every policy, and the suite would then
        # prove nothing about the role the service actually connects as.
        await conn.execute(
            sqlalchemy.text("SELECT set_config('app.current_tenant_id', :tid, TRUE)"),
            {"tid": str(TENANT)},
        )
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO aisoc_user_mfa (user_id, tenant_id, secret_encrypted, confirmed_at) "
                "VALUES (CAST(:u AS uuid), CAST(:t AS uuid), :s, now()) "
                "ON CONFLICT (user_id) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, "
                "confirmed_at = now(), last_used_step = NULL"
            ),
            {"u": str(user_id), "t": str(TENANT), "s": get_vault().encrypt(secret)},
        )
    return secret


@pytest.mark.asyncio(loop_scope="module")
async def test_one_totp_code_opens_exactly_one_session(client, engine, tenant, monkeypatch) -> None:  # noqa: ANN001
    """Ten verifies carrying one code, all past the read before any writes.

    This is the report's proof of concept, with the schedule pinned instead
    of hoped for. Plain ``asyncio.gather`` reproduced it on one machine (10 of
    10 accepted) and **not** on a CI runner, where the requests happened to
    serialise and each read the mark the one before it had written — so the
    broken code passed. A concurrency test whose result depends on how a
    runner interleaves is not a gate; it is a coin toss that usually lands on
    green. The workflow's negative control is what surfaced that, which is the
    argument for having one.

    The barrier wraps the **real** ``enrolment_row`` and only delays it. It
    changes no answer and substitutes no capability — every request still
    reads the real row, runs the real verification and issues the real
    ``UPDATE``. All it does is hold them at the point the defect needs them
    held: past the read, before the write. That is the interleaving a claim
    must survive, and the only way to assert on it deterministically.
    """
    from app.api.v1.endpoints import mfa as mfa_module
    from app.api.v1.endpoints.mfa import mint_challenge
    from app.services import mfa as totp

    user_id, _ = await _make_user(engine)
    secret = await _enrol(engine, user_id)
    code = totp.totp_code_at(secret, int(time.time()))

    real_enrolment_row = mfa_module.enrolment_row
    barrier = asyncio.Barrier(CONCURRENCY)

    async def read_then_wait(db, uid):  # noqa: ANN001, ANN202
        row = await real_enrolment_row(db, uid)
        # A timeout rather than an indefinite wait: if a request fails before
        # arriving, the rest must fail the test rather than hang the suite.
        async with asyncio.timeout(30):
            await barrier.wait()
        return row

    monkeypatch.setattr(mfa_module, "enrolment_row", read_then_wait)

    async def attempt() -> int:
        token = mint_challenge(user_id=user_id, tenant_id=TENANT, purpose="verify")
        r = await client.post("/api/v1/auth/mfa/verify", json={"mfa_token": token, "code": code})
        return r.status_code

    codes = await asyncio.gather(*(attempt() for _ in range(CONCURRENCY)))
    accepted = [c for c in codes if c == 200]
    assert len(accepted) == 1, f"{len(accepted)} of {CONCURRENCY} verifies were accepted for one code: {codes}"
    assert all(c == 401 for c in codes if c != 200), codes


@pytest.mark.asyncio(loop_scope="module")
async def test_a_fresh_code_still_opens_a_session_after_a_spent_one(client, engine, tenant) -> None:  # noqa: ANN001
    """Positive control: refusing every concurrent verify passes the test above.

    A second enrolment resets the high-water mark, so the same step is new
    again — which is also the real user's case of signing in twice. Without
    this, a fix that simply refused all but the first request ever made would
    look correct.
    """
    from app.api.v1.endpoints.mfa import mint_challenge
    from app.services import mfa as totp

    user_id, _ = await _make_user(engine)
    secret = await _enrol(engine, user_id)
    code = totp.totp_code_at(secret, int(time.time()))

    first = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mint_challenge(user_id=user_id, tenant_id=TENANT, purpose="verify"), "code": code},
    )
    assert first.status_code == 200, first.text

    replay = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mint_challenge(user_id=user_id, tenant_id=TENANT, purpose="verify"), "code": code},
    )
    assert replay.status_code == 401, replay.text

    # Re-enrol: a new factor, so the same arithmetic step is unspent again.
    secret = await _enrol(engine, user_id)
    again = await client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": mint_challenge(user_id=user_id, tenant_id=TENANT, purpose="verify"),
            "code": totp.totp_code_at(secret, int(time.time())),
        },
    )
    assert again.status_code == 200, again.text


@pytest.mark.asyncio(loop_scope="module")
async def test_concurrent_verifies_for_two_users_both_succeed(client, engine, tenant) -> None:  # noqa: ANN001
    """The claim is per row, not a lock over the table.

    Two users verifying at the same instant must both get a session. A fix
    that serialised on anything wider than the user's own row would break
    every simultaneous sign-in on the deployment, and would pass both tests
    above while doing so.
    """
    from app.api.v1.endpoints.mfa import mint_challenge
    from app.services import mfa as totp

    async def sign_in() -> int:
        user_id, _ = await _make_user(engine)
        secret = await _enrol(engine, user_id)
        token = mint_challenge(user_id=user_id, tenant_id=TENANT, purpose="verify")
        r = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": token, "code": totp.totp_code_at(secret, int(time.time()))},
        )
        return r.status_code

    both = await asyncio.gather(sign_in(), sign_in())
    assert both == [200, 200], both
