"""``GET /api/v1/alerts?limit=N`` must do something, or say it cannot.

The defect (issue #1246)
------------------------
``list_alerts`` declares pagination as ``page`` / ``page_size`` and no
``limit`` at all. FastAPI discards an undeclared query parameter without a
word, so ``?limit=1000`` neither clamped to the 200 ceiling nor answered 422 —
the default ``page_size=25`` flowed into ``.limit(page_size)`` and the caller
got 25 rows back from a request that asked for a thousand.

The response does carry ``total`` and ``pages``, so the extra rows were not
concealed. What was concealed is that the parameter was read by nobody:
``?limit=5`` also returned 25, which is the direction that bites. A script
written against the common spelling pages through a queue wrongly and a
reviewer reading the URL sees a bound that is not in force.

What is asserted here
---------------------
That the parameter has an effect and that an out-of-range value is refused
rather than absorbed. Both run through the shipped app against real
PostgreSQL, because the thing under test is how FastAPI binds a query string
to a signature — which a direct call of ``list_alerts(...)`` cannot exercise
at all, since a direct caller passes the argument by name whether or not the
route declares it.
"""

from __future__ import annotations

import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ALERT_AUDIT_PROOF_REQUIRED", "").strip() not in ("", "0", "false")

#: More than the default page of 25, so "the default is still 25" and "limit
#: took effect" are distinguishable rather than both reading as "all of them".
SEEDED_ALERTS = 40


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason="needs a live PostgreSQL with the migration chain applied",
)

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    """See ``test_alert_patch_records_what_changed`` — the application pool is
    module-level and each test gets a fresh event loop."""
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def queue():
    """A scratch tenant holding ``SEEDED_ALERTS`` alerts. Yields ``(client_token, tenant_id)``."""
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"limit-{suffix}", "s": f"limit-{suffix}"},
        )
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active, is_verified)
                VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                """
            ),
            {
                "i": user_id,
                "t": tenant_id,
                "e": f"analyst-{suffix}@example.com",
                "u": f"analyst-{suffix}",
                "h": _UNUSABLE_PASSWORD_HASH,
            },
        )
        for n in range(SEEDED_ALERTS):
            await db.execute(
                text(
                    """
                    INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, updated_at)
                    VALUES (:i, :t, :ti, 'medium', 'new', NOW() - (:n * INTERVAL '1 minute'), NOW())
                    """
                ),
                {"i": uuid.uuid4(), "t": tenant_id, "ti": f"alert {n:03d}", "n": n},
            )
        await db.commit()

    yield create_access_token({"sub": str(user_id)}), tenant_id
    await engine.dispose()


async def _list(token: str, params: dict) -> tuple[int, dict]:
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            "/api/v1/alerts",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
    return response.status_code, (response.json() if response.content else {})


class TestTheParameterHasAnEffect:
    async def test_a_limit_below_the_default_actually_shortens_the_page(self, queue) -> None:
        """The reproduction in the direction that silently returns *more* than
        asked for. Before the fix this returned 25 rows for ``limit=5``."""
        token, _tenant = queue

        code, body = await _list(token, {"limit": 5})

        assert code == 200, body
        assert len(body["items"]) == 5, f"asked for 5 and got {len(body['items'])} — the `limit` parameter is being discarded"
        assert body["page_size"] == 5, f"the response reports a page size it did not use: {body['page_size']}"

    async def test_a_limit_above_the_default_returns_more(self, queue) -> None:
        token, _tenant = queue

        code, body = await _list(token, {"limit": 40})

        assert code == 200, body
        assert len(body["items"]) == SEEDED_ALERTS
        assert body["pages"] == 1

    async def test_it_pages_with_the_page_parameter(self, queue) -> None:
        """An alias that changes the page length and not the offset is half a
        parameter — the second page has to move by the same amount."""
        token, _tenant = queue

        _code, first = await _list(token, {"limit": 10, "page": 1})
        _code, second = await _list(token, {"limit": 10, "page": 2})

        first_ids = [item["id"] for item in first["items"]]
        second_ids = [item["id"] for item in second["items"]]
        assert len(first_ids) == len(second_ids) == 10
        assert not set(first_ids) & set(second_ids), "page 2 repeated rows from page 1"
        assert first["pages"] == 4


class TestAnOutOfRangeValueIsRefused:
    async def test_the_thousand_row_request_in_the_report_is_rejected(self, queue) -> None:
        """``?limit=1000`` used to return 25 rows and status 200.

        Serving a quietly different page size is the failure being fixed, and
        clamping silently to 200 would be the same failure with a nicer
        number: the caller still cannot tell their bound was ignored.
        """
        token, _tenant = queue

        code, body = await _list(token, {"limit": 1000})

        assert code == 422, f"a limit above the 200 ceiling was accepted and answered {code}: {body}"

    async def test_zero_and_negative_are_rejected_too(self, queue) -> None:
        token, _tenant = queue

        for value in (0, -1):
            code, _body = await _list(token, {"limit": value})
            assert code == 422, f"limit={value} was accepted"


class TestTheExistingContractIsUnchanged:
    async def test_the_default_page_is_still_twenty_five(self, queue) -> None:
        token, _tenant = queue

        code, body = await _list(token, {})

        assert code == 200
        assert len(body["items"]) == 25
        assert body["page_size"] == 25
        assert body["total"] == SEEDED_ALERTS

    async def test_page_size_still_works_on_its_own(self, queue) -> None:
        token, _tenant = queue

        code, body = await _list(token, {"page_size": 7})

        assert code == 200
        assert len(body["items"]) == 7
        assert body["page_size"] == 7

    async def test_page_size_above_the_ceiling_is_still_rejected(self, queue) -> None:
        token, _tenant = queue

        code, _body = await _list(token, {"page_size": 1000})

        assert code == 422


class TestTwoSpellingsThatDisagreeAreRefused:
    async def test_a_conflicting_pair_is_a_400_rather_than_a_silent_pick(self, queue) -> None:
        """Choosing one of two contradictory bounds is the same class of bug as
        ignoring one of them: the caller is served a page size they did not
        ask for and are not told."""
        token, _tenant = queue

        code, body = await _list(token, {"limit": 5, "page_size": 50})

        assert code == 400, f"a request naming two different page sizes was served {code}: {body}"
        assert "limit" in str(body).lower()

    async def test_an_agreeing_pair_is_fine(self, queue) -> None:
        """Refusing a redundant-but-consistent request would break a client
        that sends both for compatibility."""
        token, _tenant = queue

        code, body = await _list(token, {"limit": 5, "page_size": 5})

        assert code == 200, body
        assert len(body["items"]) == 5
