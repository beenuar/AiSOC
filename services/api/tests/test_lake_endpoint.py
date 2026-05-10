"""Unit tests for the lake API helpers (Workstream 7).

The lake endpoints (``POST /api/v1/lake/sql`` and ``GET /api/v1/lake/schema``)
are tested at two layers in this repo:

* The big-ticket security/correctness logic is owned by the rewriter
  (see ``test_lake_sql.py``) and the per-tenant rate limiter
  (see ``test_lake_rate_limit.py``). Those modules are pure-Python
  units and exhaustive tests live next to them.
* The endpoint module itself is mostly orchestration: it wires
  authentication, the rate limiter, the rewriter, the ClickHouse
  client, and the audit log together. Spinning the whole FastAPI app
  up for that would obscure the contract and double-cover the
  rewriter/limiter tests.

This file therefore targets the *small* helpers that live inside
``app.api.v1.endpoints.lake`` and have observable, independently
testable behaviour:

* ``_scrub_sql_for_log`` — deterministic text trimming.
* ``_acquire_or_429`` — stamps rate-limit headers on the response and
  raises 429 when the limiter denies. We assert both branches because
  the headers carry IETF semantics that operators rely on.
* ``_audit_query_attempt`` — must call :func:`emit_audit` with the
  right ``action``/``resource``/``changes`` payload, and must
  *swallow* any audit failure so a broken audit log can't 500 a real
  query.

We mock ``get_lake_rate_limiter`` and ``emit_audit`` directly to keep
the tests hermetic. This matches the pattern already established by
``test_federated_endpoint.py`` and ``test_connectors_endpoint.py``.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1.endpoints.lake import (
    _acquire_or_429,
    _audit_query_attempt,
    _scrub_sql_for_log,
)
from app.services.lake_rate_limit import RateLimitDecision
from fastapi import HTTPException, Response

# --------------------------------------------------------- _scrub_sql_for_log


def test_scrub_sql_for_log_passthrough_under_limit() -> None:
    """SQL shorter than ``max_chars`` is returned verbatim.

    The lake accepts up to 200 KB of SQL but typical queries are <1 KB,
    so the common case must be a no-op. Any mutation here would corrupt
    the structured logs operators read.
    """
    sql = "SELECT severity, count() FROM aisoc.alert_metrics GROUP BY severity"
    scrubbed = _scrub_sql_for_log(sql)
    assert scrubbed == sql


def test_scrub_sql_for_log_truncates_at_max_chars() -> None:
    """SQL above the limit is trimmed and tagged with the dropped count.

    The trailing marker tells operators reading the log "this isn't the
    full query, the rest is in the database/agent transcript". Without
    it, a debugger would see what looks like a complete-but-mysterious
    SELECT.
    """
    long_sql = "SELECT * FROM aisoc.raw_events WHERE x = '" + ("a" * 5000) + "'"
    scrubbed = _scrub_sql_for_log(long_sql, max_chars=4_000)

    assert len(scrubbed) > 4_000  # because the marker adds bytes
    assert scrubbed.startswith("SELECT * FROM aisoc.raw_events")
    assert "…<truncated" in scrubbed
    # The truncation marker reports the number of dropped characters.
    expected_dropped = len(long_sql) - 4_000
    assert f"truncated {expected_dropped} chars" in scrubbed


def test_scrub_sql_for_log_handles_exact_boundary() -> None:
    """At exactly ``max_chars`` we still pass through unchanged.

    Off-by-one bugs here would either drop the last character of an
    almost-full SQL string or unnecessarily mark a fitting query as
    truncated. Neither is acceptable.
    """
    sql = "x" * 4_000
    assert _scrub_sql_for_log(sql, max_chars=4_000) == sql


def test_scrub_sql_for_log_empty_input() -> None:
    """Empty SQL is returned as-is — defensive but cheap.

    The endpoint validates ``sql`` is non-empty via Pydantic, but the
    helper might be called from log paths that observe partial data.
    """
    assert _scrub_sql_for_log("") == ""


# ------------------------------------------------------------- _acquire_or_429


@pytest.mark.asyncio
async def test_acquire_or_429_allowed_stamps_headers() -> None:
    """The allowed path must stamp ``X-RateLimit-*`` headers and return.

    Headers are how clients implement client-side back-off; a missing
    header means the SDK can't tell when it's safe to retry.
    """
    decision = RateLimitDecision(
        allowed=True,
        remaining=42.0,
        capacity=60.0,
        retry_after_seconds=0.0,
    )
    limiter = MagicMock()
    limiter.acquire = AsyncMock(return_value=decision)

    response = Response()
    tenant_id = uuid.uuid4()

    with patch(
        "app.api.v1.endpoints.lake.get_lake_rate_limiter",
        return_value=limiter,
    ):
        # Should not raise.
        await _acquire_or_429(response=response, tenant_id=tenant_id, cost=1.0)

    limiter.acquire.assert_awaited_once_with(tenant_id, cost=1.0)
    assert response.headers["X-RateLimit-Limit"] == "60"
    assert response.headers["X-RateLimit-Remaining"] == "42"
    # The allowed path MUST NOT advertise Retry-After — that header is
    # specifically for the throttled path and would confuse SDKs.
    assert "retry-after" not in {k.lower() for k in response.headers.keys()}


@pytest.mark.asyncio
async def test_acquire_or_429_denied_raises_with_headers() -> None:
    """Denied: headers stamped on response *and* propagated on the 429.

    Two reasons for the redundancy: (1) some FastAPI middlewares strip
    headers from error responses, so we belt-and-brace; (2) the
    HTTPException's ``headers`` arg is what FastAPI actually serialises
    into the 429 envelope, while ``response.headers`` is what observers
    of the request lifecycle see.
    """
    decision = RateLimitDecision(
        allowed=False,
        remaining=0.0,
        capacity=60.0,
        retry_after_seconds=2.5,
    )
    limiter = MagicMock()
    limiter.acquire = AsyncMock(return_value=decision)

    response = Response()
    tenant_id = uuid.uuid4()

    with patch(
        "app.api.v1.endpoints.lake.get_lake_rate_limiter",
        return_value=limiter,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _acquire_or_429(
                response=response,
                tenant_id=tenant_id,
                cost=1.0,
            )

    exc = exc_info.value
    assert exc.status_code == 429
    assert "rate limit" in exc.detail.lower()
    # Retry-After is rounded UP per RFC 7231 — 2.5s becomes 3.
    assert exc.headers["Retry-After"] == "3"
    assert exc.headers["X-RateLimit-Limit"] == "60"
    # Response.headers also got the stamp so middlewares observing the
    # request can react identically to allowed and throttled flows.
    assert response.headers["X-RateLimit-Limit"] == "60"
    assert response.headers["Retry-After"] == "3"


@pytest.mark.asyncio
async def test_acquire_or_429_passes_cost_through() -> None:
    """Cost is policy that lives in the endpoint, not the limiter.

    We assert it flows through verbatim because changing it without
    realising silently makes the bucket charge wrong, with no test
    failure.
    """
    decision = RateLimitDecision(
        allowed=True,
        remaining=59.5,
        capacity=60.0,
        retry_after_seconds=0.0,
    )
    limiter = MagicMock()
    limiter.acquire = AsyncMock(return_value=decision)

    with patch(
        "app.api.v1.endpoints.lake.get_lake_rate_limiter",
        return_value=limiter,
    ):
        await _acquire_or_429(
            response=Response(),
            tenant_id=uuid.uuid4(),
            cost=0.25,  # the schema endpoint's discount cost
        )

    args, kwargs = limiter.acquire.call_args
    assert kwargs == {"cost": 0.25}


# ---------------------------------------------------------- _audit_query_attempt


def _build_request(
    *,
    headers: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
) -> Any:
    """Build a minimal FastAPI Request stand-in for audit tests.

    The audit helper only reads ``request.headers`` and ``request.client``;
    we don't need the full ASGI scope. A MagicMock with those two
    attributes set is enough.
    """
    req = MagicMock()
    req.headers = headers or {}
    req.client = MagicMock()
    req.client.host = client_host
    return req


@pytest.mark.asyncio
async def test_audit_query_attempt_emits_with_full_payload() -> None:
    """Successful audit emission carries the structured changes dict.

    The audit log is the compliance evidence that a tenant's queries
    happened — getting the schema right matters more here than for
    operational logs.
    """
    db = MagicMock()
    request = _build_request()
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    with patch(
        "app.api.v1.endpoints.lake.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        await _audit_query_attempt(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            user_email="alice@example.com",
            request=request,
            outcome="ok",
            referenced_tables=["aisoc.alert_metrics"],
            row_count=12,
            elapsed_ms=345,
            row_cap=1000,
        )

    mock_emit.assert_awaited_once()
    kwargs = mock_emit.call_args.kwargs
    assert kwargs["db"] is db
    assert kwargs["tenant_id"] == tenant_id
    assert kwargs["actor_id"] == user_id
    assert kwargs["actor_email"] == "alice@example.com"
    assert kwargs["action"] == "lake.query"
    assert kwargs["resource"] == "lake"
    assert kwargs["resource_id"] is None
    assert kwargs["request"] is request

    changes = kwargs["changes"]
    assert changes["outcome"] == "ok"
    assert changes["reason"] is None
    assert changes["referenced_tables"] == ["aisoc.alert_metrics"]
    assert changes["row_count"] == 12
    assert changes["elapsed_ms"] == 345
    assert changes["row_cap"] == 1000


@pytest.mark.asyncio
async def test_audit_query_attempt_normalises_missing_tables_to_empty_list() -> None:
    """Failure paths often have no rewriter result — we must still log.

    Forbidden / syntax error / not-configured paths all call this
    helper without a referenced_tables list. The audit log column is
    JSON not nullable in spirit, so we normalise ``None`` to ``[]``.
    """
    with patch(
        "app.api.v1.endpoints.lake.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        await _audit_query_attempt(
            db=MagicMock(),
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_email="alice@example.com",
            request=_build_request(),
            outcome="forbidden",
            reason="DROP TABLE not allowed",
        )

    changes = mock_emit.call_args.kwargs["changes"]
    assert changes["outcome"] == "forbidden"
    assert changes["reason"] == "DROP TABLE not allowed"
    assert changes["referenced_tables"] == []
    assert changes["row_count"] is None
    assert changes["elapsed_ms"] is None
    assert changes["row_cap"] is None


@pytest.mark.asyncio
async def test_audit_query_attempt_swallows_emit_failure() -> None:
    """Audit emission failure must never propagate.

    If the audit log table is locked / down, the user-facing query
    should still succeed. We assert this by raising from the mocked
    ``emit_audit`` and verifying the helper completes normally — any
    propagation here would surface as a 500 on every lake call during
    an audit outage.
    """
    with patch(
        "app.api.v1.endpoints.lake.emit_audit",
        new=AsyncMock(side_effect=RuntimeError("audit table locked")),
    ):
        # Should NOT raise.
        await _audit_query_attempt(
            db=MagicMock(),
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_email="alice@example.com",
            request=_build_request(),
            outcome="ok",
            referenced_tables=["aisoc.alert_metrics"],
            row_count=1,
            elapsed_ms=2,
            row_cap=100,
        )


@pytest.mark.asyncio
async def test_audit_query_attempt_uses_request_for_ip_and_ua() -> None:
    """The request object is forwarded verbatim to ``emit_audit``.

    ``emit_audit`` itself extracts IP/user-agent from headers; here
    we only need to confirm the helper passes the same Request through
    without rewrapping it (which would lose ASGI scope context).
    """
    request = _build_request(
        headers={"x-forwarded-for": "203.0.113.7", "user-agent": "agent/1.0"},
    )
    with patch(
        "app.api.v1.endpoints.lake.emit_audit",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        await _audit_query_attempt(
            db=MagicMock(),
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_email="alice@example.com",
            request=request,
            outcome="ok",
            referenced_tables=[],
            row_count=0,
            elapsed_ms=1,
            row_cap=10,
        )
    assert mock_emit.call_args.kwargs["request"] is request
