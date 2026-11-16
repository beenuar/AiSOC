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
