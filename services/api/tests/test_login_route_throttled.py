"""The login route itself refuses repeated failures.

`test_login_throttle.py` exercises the limiter. This file exercises the
*route*, because the defect was never that no limiter existed — three of them
did, on the explain endpoint, lake queries and the public waitlist form. The
defect was that `POST /api/v1/auth/login` consulted none of them, so fifty
wrong passwords for one account inside a minute returned fifty 401s with no
delay and no lockout.

A gate on the limiter alone would pass over a route that never calls it,
which is the shape this repository keeps finding: a mechanism that exists, is
unit-tested, and has no caller on the path that needs it.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints import auth as auth_module
from app.services import login_throttle
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _tight_thresholds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LOGIN_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("AISOC_LOGIN_LOCKOUT_THRESHOLD", "50")
    monkeypatch.setenv("AISOC_LOGIN_BASE_DELAY_SECONDS", "5")
    monkeypatch.setenv("AISOC_LOGIN_MAX_DELAY_SECONDS", "60")
    monkeypatch.setenv("AISOC_LOGIN_WINDOW_SECONDS", "600")
    login_throttle.reset_login_throttle_for_tests()
    # No Redis in a unit test: the documented per-replica fallback, which is
    # the same code path the route drives.
    monkeypatch.setattr(login_throttle, "_redis_client", lambda: None)


class _NoUser:
    """A session whose every lookup finds nothing.

    That is the important case: the throttle has to engage for an address
    that does not exist, or the difference between 429 and 401 is a user
    list.
    """

    async def execute(self, *_args, **_kwargs):
        class _Result:
            @staticmethod
            def scalar_one_or_none():
                return None

        return _Result()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    app = FastAPI()
    app.include_router(auth_module.router, prefix="/api/v1")
    from app.api.v1.deps import get_db

    async def _db():
        yield _NoUser()

    app.dependency_overrides[get_db] = _db
    return TestClient(app, raise_server_exceptions=False)


def _attempt(client: TestClient) -> int:
    return client.post(
        "/api/v1/auth/login",
        json={"email": "victim@example.com", "password": "wrong"},
    ).status_code


class TestTheRouteConsultsTheThrottle:
    def test_fifty_wrong_passwords_are_not_all_401(self, client: TestClient) -> None:
        """The defect, stated as a test.

        On the pre-fix tree every one of these is a 401: no delay, no
        lockout, no counter. `SECURITY.md` pointed readers at
        `services/api/app/middleware/` for rate limiting, and that directory
        holds two files, neither of which is a limiter.
        """
        codes = [_attempt(client) for _ in range(50)]
        assert 429 in codes, f"fifty wrong passwords for one account produced no refusal at all; status codes seen: {sorted(set(codes))}"

    def test_the_first_attempts_still_answer_401(self, client: TestClient) -> None:
        """Someone who mistypes their password twice gets the ordinary
        answer, not a rate-limit page."""
        assert _attempt(client) == 401
        assert _attempt(client) == 401

    def test_the_refusal_carries_retry_after(self, client: TestClient) -> None:
        for _ in range(10):
            response = client.post(
                "/api/v1/auth/login",
                json={"email": "victim@example.com", "password": "wrong"},
            )
            if response.status_code == 429:
                assert response.headers.get("Retry-After"), "a 429 with no Retry-After is not actionable"
                assert int(response.headers["Retry-After"]) >= 1
                return
        pytest.fail("the route never refused")

    def test_an_address_that_does_not_exist_is_throttled_too(self, client: TestClient) -> None:
        """The session double finds no user for any address, so every attempt
        here is against a non-existent account — and it is still refused.

        A throttle that engaged only for real accounts would answer 429 for
        those and 401 for the rest, and that difference is a user list.
        """
        codes = [_attempt(client) for _ in range(20)]
        assert 429 in codes
