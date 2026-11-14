"""The TOTP derivation, pinned to RFC 6238 rather than to itself.

Fix pass 4.2.

Why these vectors and not a round trip
---------------------------------------
`services/api/app/services/mfa.py` implements RFC 6238 in-tree. A test
that generates a code and then verifies it proves the two halves agree
with each other, which they would even if both were wrong — and "wrong"
here means every authenticator app in the world rejects the enrolment.

The vectors below are **RFC 6238 appendix B's own**, for the SHA-1
variant the spec defines and every app implements. They are what makes
this an implementation of the standard rather than of itself.

`tests/isolation/test_console_mfa_live.py` covers the routes, the policy
and the replay protection against real Postgres and the real application.
"""

from __future__ import annotations

import base64

import pytest
from app.services import mfa

# RFC 6238 appendix B uses the ASCII seed "12345678901234567890" for SHA-1.
# TOTP secrets travel as base32, which is what an authenticator scans.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")

# (unix time, expected 8-digit code). The RFC tabulates eight digits; this
# implementation emits six, which is what apps display, so each expectation
# is the last six.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


class TestItIsRfc6238:
    @pytest.mark.parametrize(("at", "eight_digits"), RFC_VECTORS)
    def test_the_published_vectors(self, at: int, eight_digits: str) -> None:
        assert mfa.totp_code_at(RFC_SECRET, at) == eight_digits[-6:]

    def test_the_step_is_thirty_seconds(self) -> None:
        """Not configurable, because every authenticator app assumes it."""
        assert mfa.STEP_SECONDS == 30
        assert mfa.current_step(59) == 1
        assert mfa.current_step(60) == 2


class TestVerification:
    def test_the_current_code_is_accepted_and_names_its_step(self) -> None:
        """A step, not a boolean: the caller persists it so the same code
        cannot be replayed for the rest of its 30-second window."""
        secret = mfa.new_secret()
        at = 1_700_000_000
        assert mfa.verify_totp(secret, mfa.totp_code_at(secret, at), at=at) == mfa.current_step(at)

    def test_one_step_of_drift_either_side_is_accepted(self) -> None:
        """Phone clocks are wrong. One step is ±30 s."""
        secret = mfa.new_secret()
        at = 1_700_000_000
        for offset in (-mfa.STEP_SECONDS, 0, mfa.STEP_SECONDS):
            assert mfa.verify_totp(secret, mfa.totp_code_at(secret, at + offset), at=at) is not None

    def test_two_steps_of_drift_is_not(self) -> None:
        secret = mfa.new_secret()
        at = 1_700_000_000
        assert mfa.verify_totp(secret, mfa.totp_code_at(secret, at + 2 * mfa.STEP_SECONDS), at=at) is None

    def test_a_spent_step_is_refused(self) -> None:
        """The replay window. Without this a code read over somebody's
        shoulder stays usable for the rest of its step."""
        secret = mfa.new_secret()
        at = 1_700_000_000
        code = mfa.totp_code_at(secret, at)
        step = mfa.verify_totp(secret, code, at=at)
        assert step is not None
        assert mfa.verify_totp(secret, code, last_used_step=step, at=at) is None

    def test_a_later_code_still_works_after_an_earlier_one_is_spent(self) -> None:
        """The high-water mark must not cost the user their next code — a
        user who mistypes and retries sends one from the following step."""
        secret = mfa.new_secret()
        at = 1_700_000_000
        spent = mfa.verify_totp(secret, mfa.totp_code_at(secret, at), at=at)
        later = mfa.totp_code_at(secret, at + mfa.STEP_SECONDS)
        assert mfa.verify_totp(secret, later, last_used_step=spent, at=at) is not None

    @pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "  ", None])
    def test_anything_that_is_not_six_digits_is_refused(self, code: str | None) -> None:
        assert mfa.verify_totp(mfa.new_secret(), code, at=1_700_000_000) is None  # type: ignore[arg-type]

    def test_a_malformed_stored_secret_raises_rather_than_matching(self) -> None:
        """Fails closed. A secret this service cannot decode authenticates
        nobody; returning `None` quietly would look the same as a wrong
        code and hide a corrupted row."""
        with pytest.raises(ValueError, match="base32"):
            mfa.totp_code_at("not-base32-!!!", 1_700_000_000)


class TestTheProvisioningUri:
    def test_an_authenticator_can_parse_it(self) -> None:
        uri = mfa.provisioning_uri("JBSWY3DPEHPK3PXP", account="alice@example.com", issuer="AiSOC")
        assert uri.startswith("otpauth://totp/AiSOC:alice%40example.com?")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=AiSOC" in uri
        assert "period=30" in uri and "digits=6" in uri

    def test_a_colon_in_either_label_cannot_split_the_field(self) -> None:
        """`:` separates issuer from account inside the label, so an
        operator-supplied issuer or an unusual account name would otherwise
        produce a URI an app parses as something else."""
        uri = mfa.provisioning_uri("JBSWY3DPEHPK3PXP", account="a:b@example.com", issuer="Acme: Security")
        assert uri.count(":") == 2 or "%3A" in uri
        assert "a%3Ab%40example.com" in uri


class TestRecoveryCodes:
    def test_ten_codes_of_generated_entropy(self) -> None:
        codes = mfa.new_recovery_codes()
        assert len(codes) == mfa.RECOVERY_CODE_COUNT == 10
        assert len(set(codes)) == len(codes)

    def test_the_alphabet_excludes_the_characters_people_misread(self) -> None:
        joined = "".join(mfa.new_recovery_codes(50)).replace("-", "")
        assert not (set(joined) & set("IO01"))

    @pytest.mark.parametrize("typed", ["abcde-fghij-klmno-pqrst", "ABCDE FGHIJ KLMNO PQRST", "ABCDEFGHIJKLMNOPQRST"])
    def test_separators_and_case_do_not_decide_whether_somebody_gets_back_in(self, typed: str) -> None:
        canonical = "ABCDE-FGHIJ-KLMNO-PQRST"
        assert mfa.recovery_code_matches(typed, mfa.hash_recovery_code(canonical))

    def test_a_different_code_does_not_match(self) -> None:
        assert not mfa.recovery_code_matches("ABCDE-FGHIJ-KLMNO-PQRSU", mfa.hash_recovery_code("ABCDE-FGHIJ-KLMNO-PQRST"))

    def test_an_empty_code_matches_nothing(self) -> None:
        """`normalise_recovery_code` strips to the alphabet, so an empty or
        punctuation-only input normalises to `""` — which must not hash to
        something a stored row could equal."""
        for empty in ("", "   ", "---"):
            assert not mfa.recovery_code_matches(empty, mfa.hash_recovery_code("ABCDE-FGHIJ-KLMNO-PQRST"))
