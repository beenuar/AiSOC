"""Time-based one-time passwords and recovery codes for the console.

Fix pass 4.2.

RFC 6238 is implemented here rather than pulled in, for one reason worth
stating: the derivation is twenty lines of `hmac` over a big-endian
counter, and adding a dependency to this service means regenerating a
lockfile that fourteen declaration sites are held equal against. The
vectors in `services/api/tests/test_console_mfa.py` are **RFC 6238's own
published ones**, so this is pinned to the standard rather than to itself
— which is the thing a second in-tree implementation could not give you.

What lives here and what does not
----------------------------------
Derivation, code generation, secret handling and recovery-code minting.
Policy — who must enrol, who may reset whom — is the endpoint module's,
because it is authorization and belongs next to the dependency that
enforces it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

#: Seconds per step. 30 is what every authenticator app assumes, and it is
#: not configurable for that reason.
STEP_SECONDS = 30

#: How many steps either side of now are accepted. One step is ±30 s, which
#: covers ordinary phone clock drift. Widening this widens the window an
#: observed code stays usable in, which `last_used_step` then has to bound.
DRIFT_STEPS = 1

DIGITS = 6

#: Ten codes, 20 base32 characters each (~100 bits). Long enough that a
#: fast hash is the right choice on the verification path, and short enough
#: to read off a printout.
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
_RECOVERY_GROUPS = 4
_RECOVERY_GROUP_LEN = 5


def new_secret() -> str:
    """A fresh base32 TOTP secret, 160 bits, as authenticators expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def current_step(at: int | None = None) -> int:
    return int(at if at is not None else time.time()) // STEP_SECONDS


def totp_code_at(secret: str, at: int) -> str:
    """The code this secret produces at unix time *at*."""
    return _code_for_step(secret, current_step(at))


def _code_for_step(secret: str, step: int) -> str:
    padding = "=" * (-len(secret) % 8)
    try:
        key = base64.b32decode(secret.upper() + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - a malformed secret authenticates nobody
        raise ValueError("the stored TOTP secret is not valid base32") from exc
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    # Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte
    # selects where in the digest the 31-bit integer starts.
    offset = digest[-1] & 0x0F
    (value,) = struct.unpack(">I", digest[offset : offset + 4])
    return str((value & 0x7FFF_FFFF) % (10**DIGITS)).zfill(DIGITS)


def verify_totp(secret: str, code: str, *, last_used_step: int | None = None, at: int | None = None) -> int | None:
    """The step *code* authenticated at, or `None`.

    Returns the step rather than a boolean so the caller can persist it:
    a 30-second window means a correct code stays arithmetically valid
    after it has been used, and without a high-water mark anyone who reads
    it over an analyst's shoulder has the rest of the window to replay it.

    Comparison is constant-time. The codes are short and the window is
    narrow, so a timing side channel is a thin oracle — but a thin oracle
    on a six-digit secret is not nothing, and `compare_digest` costs
    nothing.
    """
    candidate = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(candidate) != DIGITS:
        return None
    now = current_step(at)
    for step in range(now - DRIFT_STEPS, now + DRIFT_STEPS + 1):
        if last_used_step is not None and step <= last_used_step:
            # Already spent. Skipped rather than rejected outright so a
            # code from a *later* step in the same window still works,
            # which is what a user who mistypes once and retries sends.
            continue
        if hmac.compare_digest(_code_for_step(secret, step), candidate):
            return step
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The `otpauth://` URI an authenticator app scans.

    Both labels are percent-encoded. An account name is an email address
    and an issuer is operator-supplied branding; either can contain a `:`,
    which is the field separator in the label and would otherwise split it.
    """
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    query = f"secret={secret}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    return f"otpauth://totp/{label}?{query}"


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Plaintext recovery codes. The only time they exist outside a hash."""
    return [
        "-".join("".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_LEN)) for _ in range(_RECOVERY_GROUPS))
        for _ in range(count)
    ]


def normalise_recovery_code(code: str) -> str:
    """Upper-cased, with separators and whitespace removed.

    Someone reading a code off a printout types the hyphens, or does not,
    or types a space. None of that should be the difference between
    getting back into an account and not.
    """
    return "".join(ch for ch in (code or "").upper() if ch in _RECOVERY_ALPHABET)


def hash_recovery_code(code: str) -> str:
    """SHA-256 of the normalised code.

    Not bcrypt, deliberately: the code is generated entropy with no
    dictionary to slow an attacker down, and verification walks every
    unused code a user holds — ten bcrypt comparisons per attempt would be
    a second of CPU on the login path and a denial-of-service primitive.
    """
    return hashlib.sha256(normalise_recovery_code(code).encode("ascii")).hexdigest()


def recovery_code_matches(code: str, code_hash: str) -> bool:
    return hmac.compare_digest(hash_recovery_code(code), code_hash)


__all__ = [
    "DIGITS",
    "DRIFT_STEPS",
    "RECOVERY_CODE_COUNT",
    "STEP_SECONDS",
    "current_step",
    "hash_recovery_code",
    "new_recovery_codes",
    "new_secret",
    "normalise_recovery_code",
    "provisioning_uri",
    "recovery_code_matches",
    "totp_code_at",
    "verify_totp",
]
