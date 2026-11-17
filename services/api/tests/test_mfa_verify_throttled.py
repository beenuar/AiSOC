"""SEC-8: the MFA verify endpoint must consult the login throttle.

`POST /auth/login` is throttled, but passing it only *issues* a challenge —
the session is minted by `/auth/mfa/verify` and `/auth/mfa/webauthn/verify`.
Those two routes consulted nothing, so a leaked `mfa_token` bought an attacker
an unthrottled sweep of the 6-digit TOTP space (a million codes, every wrong
one a free 401). The fix routes both through the shared `LoginThrottle`,
scoped per-account so the password stage's counter and the code stage's do not
collide.
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import mfa


def test_verify_endpoint_consults_the_throttle():
    src = inspect.getsource(mfa.verify)
    assert "get_login_throttle" in src, "/auth/mfa/verify does not consult the throttle"
    assert "throttle.check" in src, "/auth/mfa/verify does not check the throttle"
    assert "record_failure" in src, "/auth/mfa/verify does not count a wrong code"
    assert "record_success" in src, "/auth/mfa/verify does not reset on success"


def test_webauthn_verify_endpoint_consults_the_throttle():
    src = inspect.getsource(mfa.webauthn_verify)
    assert "get_login_throttle" in src, "/auth/mfa/webauthn/verify does not consult the throttle"
    assert "throttle.check" in src, "/auth/mfa/webauthn/verify does not check the throttle"
    assert "record_failure" in src, "/auth/mfa/webauthn/verify does not count a bad assertion"


def test_throttle_is_scoped_per_account_not_shared_with_login():
    """The MFA stage keys on the account id, not the email.

    `LoginThrottle` keys on email; a challenge token names its user by id
    inside the signed payload. Scoping the key ("mfa-account:<id>") keeps a
    wrong password from spending part of the budget for a wrong code — the two
    doors have different risk and different thresholds in practice.
    """
    import uuid

    uid = uuid.uuid4()
    key = mfa._mfa_throttle_key(uid)
    assert key == f"mfa-account:{uid}"
    assert "@" not in key, "MFA throttle key must not be email-keyed (collides with login stage)"


# ─────────────────────────────────────────────────────────────────────────────
# Behavioural coverage (added in the carry): the string assertions above pin
# the wiring's *presence*; these pin that the wiring actually locks out.
# ─────────────────────────────────────────────────────────────────────────────

import uuid as _uuid  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

import pytest  # noqa: E402
from app.services.login_throttle import LoginThrottle  # noqa: E402
from fastapi import HTTPException  # noqa: E402


def _request() -> MagicMock:
    req = MagicMock()
    req.headers = {}
    req.client = SimpleNamespace(host="203.0.113.9")
    return req


def _enrolled_row() -> dict:
    return {
        "confirmed_at": "2026-01-01T00:00:00Z",
        "tenant_id": _uuid.uuid4(),
        "secret_encrypted": "vault:v1:irrelevant",
        "last_used_step": None,
    }


@pytest.fixture
def throttled_mfa(monkeypatch: pytest.MonkeyPatch):
    """A real in-process LoginThrottle with a 3-failure budget, wired into
    the mfa module, with the crypto/db surface stubbed so only the throttle
    behaviour is under test."""
    monkeypatch.setenv("AISOC_LOGIN_FAILURE_THRESHOLD", "3")
    # Lockout is the knob under test (progressive delays are the other arm);
    # the shared env vars tune both stages, which is the PR's design.
    monkeypatch.setenv("AISOC_LOGIN_LOCKOUT_THRESHOLD", "3")
    # No base delay below the lockout, so the test exercises lockout rather
    # than sleeping through progressive delays.
    monkeypatch.setenv("AISOC_LOGIN_BASE_DELAY_SECONDS", "0")
    throttle = LoginThrottle(redis_client=None)
    monkeypatch.setattr(mfa, "get_login_throttle", lambda: throttle)

    uid = _uuid.uuid4()
    monkeypatch.setattr(mfa, "read_challenge", lambda token, expect_purpose: {"sub": str(uid), "tenant_id": str(_uuid.uuid4())})
    monkeypatch.setattr(mfa, "enrolment_row", AsyncMock(return_value=_enrolled_row()))
    monkeypatch.setattr(mfa, "set_rls_context", AsyncMock())
    monkeypatch.setattr(mfa, "_decrypt_secret", lambda blob: "JBSWY3DPEHPK3PXP")
    # Wrong code on every attempt until a test says otherwise.
    monkeypatch.setattr(mfa.totp, "verify_totp", lambda secret, code, last_used_step: None)
    monkeypatch.setattr(mfa, "_consume_recovery_code", AsyncMock(return_value=False))

    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    return throttle, uid, db


@pytest.mark.asyncio
async def test_wrong_codes_lock_the_account_out(throttled_mfa) -> None:
    """Three wrong codes are 401s; the fourth attempt is refused 429 before
    any verification happens — the unbounded TOTP sweep this fix exists for."""
    _throttle, _uid, db = throttled_mfa
    body = mfa.VerifyRequest(mfa_token="challenge", code="000000")

    for _ in range(3):
        with pytest.raises(HTTPException) as exc:
            await mfa.verify(body, db, _request())
        assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        await mfa.verify(body, db, _request())
    assert exc.value.status_code == 429
    assert "Retry-After" in (exc.value.headers or {})


@pytest.mark.asyncio
async def test_lockout_refuses_before_crypto(throttled_mfa, monkeypatch: pytest.MonkeyPatch) -> None:
    """Once locked, the verifier must not even be consulted — a flood costs
    a counter read, not an HMAC derivation per attempt."""
    _throttle, _uid, db = throttled_mfa
    body = mfa.VerifyRequest(mfa_token="challenge", code="000000")
    for _ in range(3):
        with pytest.raises(HTTPException):
            await mfa.verify(body, db, _request())

    calls = {"n": 0}

    def _counting_verify(secret, code, last_used_step):
        calls["n"] += 1
        return None

    monkeypatch.setattr(mfa.totp, "verify_totp", _counting_verify)
    with pytest.raises(HTTPException) as exc:
        await mfa.verify(body, db, _request())
    assert exc.value.status_code == 429
    assert calls["n"] == 0, "a locked-out attempt still reached the TOTP verifier"


@pytest.mark.asyncio
async def test_success_resets_the_counter(throttled_mfa, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two failures, then a success, then two more failures: no lockout —
    record_success cleared the budget, as the login stage's does."""
    _throttle, _uid, db = throttled_mfa
    body = mfa.VerifyRequest(mfa_token="challenge", code="000000")

    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            await mfa.verify(body, db, _request())
        assert exc.value.status_code == 401

    # A correct code: verify_totp returns a step, the claim UPDATE wins,
    # and the session mint is stubbed.
    monkeypatch.setattr(mfa.totp, "verify_totp", lambda secret, code, last_used_step: 12345)
    claim = MagicMock()
    claim.rowcount = 1
    db.execute = AsyncMock(return_value=claim)
    monkeypatch.setattr(
        mfa,
        "_issue_session",
        AsyncMock(return_value={"access_token": "a", "refresh_token": "r", "token_type": "bearer", "expires_in": 900}),
    )
    tokens = await mfa.verify(body, db, _request())
    assert tokens.access_token == "a"

    # Budget is fresh again: two further failures are 401, not 429.
    monkeypatch.setattr(mfa.totp, "verify_totp", lambda secret, code, last_used_step: None)
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            await mfa.verify(body, db, _request())
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_webauthn_wrong_assertions_lock_out(throttled_mfa, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle, _uid, db = throttled_mfa
    # The verifier is imported lazily inside webauthn_verify, so the patch
    # must land on its home module.
    from app.api.v1.endpoints import passkeys

    monkeypatch.setattr(passkeys, "verify_second_factor_assertion", AsyncMock(return_value=None))
    body = mfa.WebAuthnVerifyRequest(mfa_token="challenge", challenge="c", credential={})

    for _ in range(3):
        with pytest.raises(HTTPException) as exc:
            await mfa.webauthn_verify(body, db, _request())
        assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        await mfa.webauthn_verify(body, db, _request())
    assert exc.value.status_code == 429
