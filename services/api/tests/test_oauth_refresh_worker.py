"""Unit tests for the OAuth refresh worker (Workstream 5).

These tests focus on the *pure* helpers and the per-connector refresh
state machine. The DB session is mocked because we don't want to spin
up Postgres for unit-scope coverage — the SQL itself is exercised by
the connector endpoint integration tests.

Coverage map:

* ``_parse_expires_at``         — ISO-8601 parsing, ``Z`` suffix, fallback
* ``_resolve_token_url``        — per-tenant override vs. catalog hint
* ``_record_failure``           — counter increments, alarm threshold trip
* ``_refresh_one`` happy path   — success rotates token, resets counter
* ``_refresh_one`` 4xx          — failure increments + flips unhealthy
* ``_refresh_one`` 5xx          — failure increments without alarm yet
* ``_refresh_one`` no-app-cred  — silent failure, no token POST
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.security.credential_vault import CredentialVault
from app.workers import oauth_refresh as worker
from cryptography.fernet import Fernet

# --------------------------------------------------------------- helpers


class _FakeConnector:
    """Minimal stand-in for the SQLAlchemy ``Connector`` model.

    We don't need an attached session — ``_refresh_one`` only reads
    attributes and emits ``UPDATE`` statements through the (mocked)
    session. Using a plain Python object keeps tests fast and isolated
    from ORM machinery.
    """

    def __init__(
        self,
        *,
        auth_config: dict[str, Any] | None = None,
        oauth_refresh_failures: int = 0,
        health_status: str = "healthy",
        connector_type: str = "github",
    ) -> None:
        self.id = uuid.uuid4()
        self.tenant_id = uuid.uuid4()
        self.connector_type = connector_type
        self.auth_config = auth_config or {}
        self.oauth_refresh_failures = oauth_refresh_failures
        self.health_status = health_status


class _FakeAppCredential:
    def __init__(
        self,
        *,
        client_id: str = "client-id-123",
        client_secret_vault: str = "client-secret-encrypted",
        token_url: str | None = "https://provider.example.com/oauth/token",
    ) -> None:
        self.client_id = client_id
        self.client_secret_vault = client_secret_vault
        self.token_url = token_url


def _build_vault() -> CredentialVault:
    """Hermetic vault for tests — never touches process settings."""
    return CredentialVault(Fernet.generate_key())


def _mock_db(*, app_credential: Any = None, scalars_seq: list[Any] | None = None) -> AsyncMock:
    """Build an ``AsyncSession``-shaped mock.

    ``execute`` is an ``AsyncMock`` whose awaited return is a *plain*
    ``MagicMock`` (so ``scalar_one_or_none`` and ``scalars`` stay sync —
    they're sync in real SQLAlchemy ``Result`` objects too).

    ``app_credential`` controls what ``scalar_one_or_none`` returns; if
    ``scalars_seq`` is given, ``scalars().all()`` returns it in order
    (used by ``_select_due_connectors`` tests).
    """
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = app_credential
    if scalars_seq is not None:
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = scalars_seq
        result.scalars.return_value = scalars_mock
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return db


# ------------------------------------------------------- _parse_expires_at


def test_parse_expires_at_iso_with_offset() -> None:
    parsed = worker._parse_expires_at("2026-01-01T00:00:00+00:00")
    assert parsed == datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_expires_at_iso_with_z_suffix() -> None:
    """Some providers (GitHub) emit ``Z`` instead of ``+00:00``."""
    parsed = worker._parse_expires_at("2026-01-01T00:00:00Z")
    assert parsed == datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_expires_at_naive_assumes_utc() -> None:
    """Naive timestamps shouldn't poison comparisons against ``now(UTC)``."""
    parsed = worker._parse_expires_at("2026-01-01T00:00:00")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed == datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "not-a-date", 123, []])
def test_parse_expires_at_rejects_garbage(value: Any) -> None:
    assert worker._parse_expires_at(value) is None


# ------------------------------------------------------- _resolve_token_url


def test_resolve_token_url_prefers_tenant_override() -> None:
    """Per-tenant ``token_url`` wins over catalog hints."""
    cred = _FakeAppCredential(token_url="https://override.example.com/token")
    hints = {"token_url": "https://catalog.example.com/token"}
    assert worker._resolve_token_url(cred, hints) == "https://override.example.com/token"


def test_resolve_token_url_falls_back_to_hints() -> None:
    cred = _FakeAppCredential(token_url=None)
    hints = {"token_url": "https://catalog.example.com/token"}
    assert worker._resolve_token_url(cred, hints) == "https://catalog.example.com/token"


def test_resolve_token_url_returns_none_when_unresolved() -> None:
    """Worker logs + skips rather than raising — keep loop alive."""
    cred = _FakeAppCredential(token_url=None)
    assert worker._resolve_token_url(cred, {}) is None


def test_resolve_token_url_strips_whitespace() -> None:
    cred = _FakeAppCredential(token_url="   https://provider/token   ")
    assert worker._resolve_token_url(cred, {}) == "https://provider/token"


# ------------------------------------------------------- _record_failure


@pytest.mark.asyncio
async def test_record_failure_increments_below_threshold() -> None:
    """Below the alarm threshold we bump the counter without flipping health."""
    conn = _FakeConnector(oauth_refresh_failures=0, health_status="healthy")
    db = _mock_db()

    await worker._record_failure(db, connector=conn, alarm_threshold=3, reason="http_500")

    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()

    # The .values() block we send to SQLAlchemy must increment the counter
    # but NOT overwrite health_status until threshold is reached.
    update_call = db.execute.call_args.args[0]
    compiled = update_call.compile().params
    assert compiled["oauth_refresh_failures"] == 1
    assert "health_status" not in compiled


@pytest.mark.asyncio
async def test_record_failure_trips_alarm_at_threshold() -> None:
    """At ``alarm_threshold`` consecutive failures we flip to unhealthy."""
    conn = _FakeConnector(oauth_refresh_failures=2, health_status="healthy")
    db = _mock_db()

    await worker._record_failure(db, connector=conn, alarm_threshold=3, reason="invalid_grant")

    update_call = db.execute.call_args.args[0]
    compiled = update_call.compile().params
    assert compiled["oauth_refresh_failures"] == 3
    assert compiled["health_status"] == "unhealthy"


# ------------------------------------------------------- _refresh_one


@pytest.fixture
def patched_vault(monkeypatch: pytest.MonkeyPatch) -> CredentialVault:
    """Replace the global vault with a hermetic one for every test."""
    vault = _build_vault()
    monkeypatch.setattr(worker, "get_vault", lambda: vault)
    return vault


@pytest.mark.asyncio
async def test_refresh_one_happy_path(patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful refresh rotates tokens, zeros counter, restores health."""
    # Build a connector with an encrypted refresh_token + expires_at.
    auth_payload = {
        "access_token": "old-access",
        "refresh_token": "stable-refresh",
        "expires_at": "2026-01-01T00:00:00+00:00",
    }
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
        oauth_refresh_failures=2,
        health_status="unhealthy",
    )

    # App credential lookup returns a credential whose secret decrypts cleanly.
    cred = _FakeAppCredential(
        client_secret_vault=patched_vault.encrypt("super-secret"),
    )
    db = _mock_db(app_credential=cred)

    # Bypass the catalog HTTP call.
    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={"token_url": "https://provider/token"}),
    )

    # Mock the OAuth token endpoint response.
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {
        "access_token": "fresh-access",
        "refresh_token": "rotated-refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
    }
    mock_post = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = mock_post

        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)

    assert ok is True
    mock_post.assert_awaited_once()
    # The body must use grant_type=refresh_token with the decrypted refresh.
    posted_body = mock_post.call_args.kwargs["data"]
    assert posted_body["grant_type"] == "refresh_token"
    assert posted_body["refresh_token"] == "stable-refresh"
    assert posted_body["client_id"] == cred.client_id
    assert posted_body["client_secret"] == "super-secret"

    # Two writes: app_credential SELECT happens *before* the post; the
    # success path issues exactly one UPDATE+commit.
    assert db.commit.await_count == 1


@pytest.mark.asyncio
async def test_refresh_one_4xx_records_failure(patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    """A 4xx (e.g. invalid_grant) trips the failure path with the status code."""
    auth_payload = {
        "refresh_token": "revoked-refresh",
        "expires_at": "2026-01-01T00:00:00+00:00",
    }
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
        oauth_refresh_failures=2,  # next failure trips the alarm
        health_status="healthy",
    )
    cred = _FakeAppCredential(
        client_secret_vault=patched_vault.encrypt("super-secret"),
    )
    db = _mock_db(app_credential=cred)

    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={}),
    )

    bad_response = MagicMock()
    bad_response.status_code = 400
    bad_response.text = '{"error":"invalid_grant"}'
    bad_response.raise_for_status = MagicMock(side_effect=httpx.HTTPStatusError("400", request=MagicMock(), response=bad_response))
    mock_post = AsyncMock(return_value=bad_response)

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = mock_post

        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)

    assert ok is False
    # Last UPDATE should set health_status=unhealthy because we crossed 3.
    last_update = db.execute.call_args_list[-1].args[0]
    compiled = last_update.compile().params
    assert compiled["oauth_refresh_failures"] == 3
    assert compiled["health_status"] == "unhealthy"


@pytest.mark.asyncio
async def test_refresh_one_network_error_no_alarm_yet(patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    """A transient ``ConnectError`` increments the counter without alarming."""
    auth_payload = {"refresh_token": "ok"}
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
        oauth_refresh_failures=0,
    )
    cred = _FakeAppCredential(
        client_secret_vault=patched_vault.encrypt("super-secret"),
    )
    db = _mock_db(app_credential=cred)

    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={}),
    )

    mock_post = AsyncMock(side_effect=httpx.ConnectError("dns_failed"))
    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = mock_post

        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)

    assert ok is False
    last_update = db.execute.call_args_list[-1].args[0]
    compiled = last_update.compile().params
    assert compiled["oauth_refresh_failures"] == 1
    assert "health_status" not in compiled


@pytest.mark.asyncio
async def test_refresh_one_missing_app_credential(patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    """No OAuthAppCredential row → record failure with that reason, no POST."""
    auth_payload = {"refresh_token": "ok"}
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
    )
    db = _mock_db()
    # default scalar_one_or_none returns None — simulates missing row.

    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={}),
    )

    with patch("httpx.AsyncClient") as client_cls:
        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)

    assert ok is False
    # We never reached the POST step.
    client_cls.assert_not_called()
    # We did record a failure (one execute for SELECT + one for UPDATE).
    assert db.execute.await_count >= 2
    assert db.commit.await_count == 1


@pytest.mark.asyncio
async def test_refresh_one_missing_token_url(patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    """Token URL unresolvable → failure recorded, no POST."""
    auth_payload = {"refresh_token": "ok"}
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
    )
    cred = _FakeAppCredential(
        client_secret_vault=patched_vault.encrypt("super-secret"),
        token_url=None,
    )
    db = _mock_db(app_credential=cred)

    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={}),  # no token_url anywhere
    )

    with patch("httpx.AsyncClient") as client_cls:
        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)

    assert ok is False
    client_cls.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_one_keeps_existing_refresh_token_when_provider_omits(
    patched_vault: CredentialVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Auth0-style: provider returns access_token only, we keep the old refresh."""
    auth_payload = {
        "access_token": "old",
        "refresh_token": "keep-me",
        "expires_at": "2026-01-01T00:00:00+00:00",
    }
    conn = _FakeConnector(
        auth_config=patched_vault.encrypt_dict(auth_payload),
    )
    cred = _FakeAppCredential(
        client_secret_vault=patched_vault.encrypt("super-secret"),
    )
    db = _mock_db(app_credential=cred)

    monkeypatch.setattr(
        worker._CatalogResolver,
        "hints_for",
        AsyncMock(return_value={}),
    )

    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    # No refresh_token in response → keep the old one.
    fake_response.json.return_value = {
        "access_token": "fresh",
        "expires_in": 3600,
    }
    mock_post = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = mock_post
        ok = await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3)
    assert ok is True

    # Decrypt the auth_config we wrote and verify refresh_token survived.
    last_update = db.execute.call_args_list[-1].args[0]
    new_auth_config = last_update.compile().params["auth_config"]
    decrypted = patched_vault.decrypt_dict(new_auth_config)
    assert decrypted["access_token"] == "fresh"
    assert decrypted["refresh_token"] == "keep-me"


# ------------------------------------------------------- run_forever loop


@pytest.mark.asyncio
async def test_run_forever_exits_on_stop_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``stop_event`` provides a deterministic shutdown for tests."""
    import asyncio

    monkeypatch.setattr(worker.settings, "OAUTH_REFRESH_INTERVAL_SECONDS", 5)
    monkeypatch.setattr(worker, "run_once", AsyncMock(return_value={"checked": 0, "refreshed": 0, "failed": 0}))

    stop = asyncio.Event()
    stop.set()
    await worker.run_forever(stop_event=stop)
    # If we got here, the loop exited cleanly without raising.


@pytest.mark.asyncio
async def test_run_forever_swallows_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bug in run_once must not kill the loop — durability is the point."""
    import asyncio

    monkeypatch.setattr(worker.settings, "OAUTH_REFRESH_INTERVAL_SECONDS", 5)

    call_count = {"n": 0}

    async def flaky_run_once() -> dict[str, int]:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("transient db blip")
        return {"checked": 0, "refreshed": 0, "failed": 0}

    monkeypatch.setattr(worker, "run_once", flaky_run_once)

    stop = asyncio.Event()

    async def stop_after_two_ticks() -> None:
        # Wait long enough for run_once to be called at least twice.
        while call_count["n"] < 2:
            await asyncio.sleep(0.01)
        stop.set()

    # Drive the cadence fast for the test by replacing wait_for sleep.
    real_wait_for = asyncio.wait_for

    async def fast_wait_for(awaitable: Any, timeout: float) -> Any:
        return await real_wait_for(awaitable, timeout=0.05)

    monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)

    await asyncio.gather(
        worker.run_forever(stop_event=stop),
        stop_after_two_ticks(),
    )

    # The loop survived the first-tick exception and ran again.
    assert call_count["n"] >= 2
