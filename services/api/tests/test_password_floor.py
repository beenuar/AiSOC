"""An empty password can neither be set nor used (GHSA-xh3r-vqgc-cv78).

``CreateUserRequest.password`` was a bare ``str``, so an explicit ``""``
passed validation, was bcrypt-hashed like any other password, and
``POST /auth/login`` accepted the empty string for that account from then on
— ``verify_password("", bcrypt(""))`` is simply true. Reported with a live
PoC by abdochtouki.

Two boundaries, because the defect has two halves:

- creation refuses anything under NIST SP 800-63B's eight characters (and
  over bcrypt's 72-byte truncation boundary), so the weak hash is never
  stored again;
- login refuses the empty string outright, so an account row created with
  an empty password *before* the floor landed is locked out rather than
  quietly serviceable forever. No legitimate credential is affected: real
  passwords are non-empty, and the SCIM / invite-pending sentinel markers
  are non-empty strings that already fail verification.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.auth import LoginRequest
from app.api.v1.endpoints.tenants import CreateUserRequest
from app.core.security import get_password_hash, verify_password
from pydantic import ValidationError


def _create(password: str) -> CreateUserRequest:
    return CreateUserRequest(email="user@example.com", username="user", password=password)


def test_an_empty_password_cannot_be_set() -> None:
    with pytest.raises(ValidationError):
        _create("")


@pytest.mark.parametrize("short", ["a", "1234567"])
def test_a_password_under_the_nist_floor_is_refused(short: str) -> None:
    with pytest.raises(ValidationError):
        _create(short)


def test_a_password_past_bcrypt_truncation_is_refused_not_cut() -> None:
    # bcrypt reads the first 72 bytes and silently ignores the rest; a
    # password the user typed and the password that verifies would differ.
    with pytest.raises(ValidationError):
        _create("x" * 73)


def test_an_ordinary_password_still_passes() -> None:
    assert _create("hunter2-but-longer").password == "hunter2-but-longer"


def test_login_refuses_the_empty_string_at_the_boundary() -> None:
    """The second half: residue accounts.

    The schema floor on creation stops new empty-password rows, but a row
    created before it carries bcrypt("") — and as the assertion below
    documents, the empty string verifies against it. The login boundary is
    therefore load-bearing, not belt-and-braces.
    """
    assert verify_password("", get_password_hash("")) is True
    with pytest.raises(ValidationError):
        LoginRequest(email="user@example.com", password="")
