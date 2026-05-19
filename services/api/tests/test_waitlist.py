"""Tests for the managed-instance waitlist endpoints — T6.1.

Mirrors the in-memory-fixture approach used by `test_business_context.py`:
each test stubs the AsyncSession + AuthUser directly and drives the
endpoint coroutine through ``_run`` on a fresh event loop. No live DB
required.

Coverage map
~~~~~~~~~~~~

Signup payload
    * Pydantic normalises email casing + trims fields.
    * Invalid email rejected.
    * soc_stack is de-duped, trimmed, and capped at 20.

Signup endpoint
    * Net-new email persists, returns entry_id, fires Slack.
    * Repeat email is idempotent (no insert, same response shape).
    * Rate limiter exhaustion → 429 with Retry-After header.
    * Slack failure does NOT break the signup (logged + swallowed).

Admin endpoints
    * GET filters by status; rejects unknown statuses with 400.
    * GET 403s when caller lacks admin scope.
    * PATCH transitions status + stamps contacted_at / onboarded_at.
    * PATCH 404 when entry missing.

Slack message
    * build_signup_message renders the Block Kit shape we expect.

The signup endpoint and the rate limiter are exercised through the
real classes; only the AsyncSession is mocked.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1.endpoints import waitlist as endpoint
from app.models.waitlist import (
    WAITLIST_STATUS_CONTACTED,
    WAITLIST_STATUS_DECLINED,
    WAITLIST_STATUS_NEW,
    WAITLIST_STATUS_ONBOARDED,
    WaitlistEntry,
)
from app.services.waitlist import (
    SignupRateLimiter,
    SlackNotifier,
    build_signup_message,
)
from fastapi import HTTPException, Request, Response
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _run(coro):  # type: ignore[no-untyped-def]
    """Drive an async endpoint coroutine to completion in a fresh loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _admin_user(*, allow: bool = True) -> SimpleNamespace:
    """Mock the AuthUser dependency.

    The endpoint calls ``user.has_permission_db(perm, db)`` twice
    (admin:waitlist then settings:write fallback); the stub returns
    ``allow`` for both unless overridden.
    """

    async def _check(_perm: str, _db: Any) -> bool:
        return allow

    return SimpleNamespace(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="tenant_admin",
        email="admin@aisoc.dev",
        has_permission_db=_check,
    )


def _mock_request(*, xff: str | None = None, client_host: str = "127.0.0.1") -> Request:
    """Construct a Request stub with controllable client + headers.

    We don't go through FastAPI's TestClient because the rest of the
    endpoint suite uses direct-call style. A SimpleNamespace shaped
    like Request is enough for the endpoint's ``_client_ip`` helper.
    """
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return SimpleNamespace(  # type: ignore[return-value]
        headers=headers,
        client=SimpleNamespace(host=client_host),
    )


class _MockSession:
    """AsyncSession-shaped fake backed by an in-memory dict.

    Implements just enough of the SQLAlchemy AsyncSession surface for
    the waitlist endpoint to exercise the full happy + race paths.
    """

    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, WaitlistEntry] = {}
        self.commit_calls: int = 0
        self.rollback_calls: int = 0
        self.add_calls: list[WaitlistEntry] = []

    async def execute(self, stmt: Any, params: Any = None) -> Any:
        # We sniff the statement's compiled SQL for the columns we care
        # about. The endpoint uses ``select(WaitlistEntry).where(...)``,
        # ``select(WaitlistEntry).where(...).order_by(...).limit(...)``,
        # and that's it — so a narrow matcher is enough.
        sql = str(stmt).lower()
        if "from aisoc_waitlist_entries" not in sql:
            raise RuntimeError(f"unexpected SQL in mock session: {sql}")

        rows = list(self.rows.values())

        # WHERE id = :id
        for _clause in getattr(stmt, "whereclause", None) and [stmt.whereclause] or []:
            pass  # SQLAlchemy compiled expressions don't easily yield bind values
        # Easier: walk the stmt._where_criteria.
        # We'll just inspect the compiled clause string.
        # For simplicity, match by binding inspection:
        compiled = stmt.compile(compile_kwargs={"literal_binds": False})
        params_map: dict[str, Any] = dict(compiled.params)
        # id filter
        for key, value in params_map.items():
            if "id_1" in key and isinstance(value, uuid.UUID):
                rows = [r for r in rows if r.id == value]
            elif "email_1" in key and isinstance(value, str):
                rows = [r for r in rows if r.email == value]
            elif "status_1" in key and isinstance(value, str):
                rows = [r for r in rows if r.status == value]

        # Apply ORDER BY created_at DESC + LIMIT if present
        if "order by" in sql:
            rows = sorted(rows, key=lambda r: r.created_at, reverse=True)
        if "limit" in sql:
            for key, value in params_map.items():
                if "param_1" in key and isinstance(value, int):
                    rows = rows[:value]

        return _MockExecuteResult(rows)

    def add(self, entry: WaitlistEntry) -> None:
        if entry.id is None:
            entry.id = uuid.uuid4()
        if entry.created_at is None:
            entry.created_at = datetime.now(UTC)
        self.add_calls.append(entry)
        self.rows[entry.id] = entry

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1

    async def refresh(self, entry: WaitlistEntry) -> None:
        if entry.id in self.rows:
            stored = self.rows[entry.id]
            entry.created_at = stored.created_at


class _MockExecuteResult:
    def __init__(self, rows: list[WaitlistEntry]) -> None:
        self._rows = rows

    def scalar_one_or_none(self) -> WaitlistEntry | None:
        return self._rows[0] if self._rows else None

    def scalars(self) -> _MockExecuteResult:
        return self

    def all(self) -> list[WaitlistEntry]:
        return list(self._rows)


class _RecordingNotifier(SlackNotifier):
    """Captures calls instead of hitting the network."""

    def __init__(self, *, succeed: bool = True, raise_on_post: bool = False) -> None:
        super().__init__(webhook_url="http://recording.invalid")
        self.calls: list[dict] = []
        self._succeed = succeed
        self._raise = raise_on_post

    def post(self, payload: dict) -> bool:  # type: ignore[override]
        self.calls.append(payload)
        if self._raise:
            raise RuntimeError("simulated notifier crash")
        return self._succeed


# ---------------------------------------------------------------------------
# Pydantic payload tests
# ---------------------------------------------------------------------------


class TestSignupRequestValidation:
    def test_email_is_normalized_and_trimmed(self) -> None:
        payload = endpoint.WaitlistSignupRequest(
            email="  Alice@Acme.IO  ",
            company="Acme",
            role="SOC Manager",
            soc_stack=["splunk"],
            motivation="We want it.",
        )
        assert payload.email == "alice@acme.io"
        assert payload.company == "Acme"
        assert payload.role == "SOC Manager"

    def test_invalid_email_rejected(self) -> None:
        with pytest.raises(ValidationError):
            endpoint.WaitlistSignupRequest(
                email="not-an-email",
                company="Acme",
                role="SOC Manager",
                soc_stack=[],
                motivation="We want it.",
            )

    def test_soc_stack_dedup_trim_and_cap(self) -> None:
        payload = endpoint.WaitlistSignupRequest(
            email="bob@acme.io",
            company="Acme",
            role="Analyst",
            soc_stack=[
                "splunk",
                "  splunk  ",  # dup after trim
                "",  # dropped
                "crowdstrike",
                *[f"vendor-{i}" for i in range(30)],  # over the cap
            ],
            motivation="We want it.",
        )
        assert payload.soc_stack[0] == "splunk"
        assert "crowdstrike" in payload.soc_stack
        assert payload.soc_stack.count("splunk") == 1
        assert len(payload.soc_stack) <= 20

    def test_blank_motivation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            endpoint.WaitlistSignupRequest(
                email="c@acme.io",
                company="Acme",
                role="Analyst",
                soc_stack=[],
                motivation="   ",
            )


# ---------------------------------------------------------------------------
# Signup endpoint
# ---------------------------------------------------------------------------


class TestSignupEndpoint:
    def test_new_signup_persists_and_notifies(self) -> None:
        session = _MockSession()
        notifier = _RecordingNotifier()
        limiter = SignupRateLimiter(capacity=5, refill_per_hour=10)
        req = _mock_request(xff="203.0.113.5")
        resp = Response()

        result = _run(
            endpoint.signup(
                endpoint.WaitlistSignupRequest(
                    email="founder@acme.io",
                    company="Acme",
                    role="CISO",
                    soc_stack=["splunk", "crowdstrike"],
                    motivation="Migrating off in-house scripts.",
                ),
                req,  # type: ignore[arg-type]
                resp,
                db=session,  # type: ignore[arg-type]
                rate_limiter=limiter,
                notifier=notifier,
            )
        )

        assert result.ok is True
        assert result.entry_id is not None
        assert session.commit_calls == 1
        assert len(session.add_calls) == 1
        assert session.add_calls[0].email == "founder@acme.io"
        assert session.add_calls[0].status == WAITLIST_STATUS_NEW
        assert notifier.calls, "expected slack notification"
        # Rate-limit headers should be on the response.
        assert resp.headers.get("X-RateLimit-Limit") == "5"

    def test_repeat_email_is_idempotent_no_op(self) -> None:
        session = _MockSession()
        # Pre-seed an existing entry.
        existing_id = uuid.uuid4()
        session.rows[existing_id] = WaitlistEntry(
            id=existing_id,
            email="founder@acme.io",
            company="Acme",
            role="CISO",
            soc_stack=[],
            motivation="prior",
            status=WAITLIST_STATUS_NEW,
            created_at=datetime.now(UTC),
        )
        notifier = _RecordingNotifier()
        limiter = SignupRateLimiter(capacity=5, refill_per_hour=10)
        result = _run(
            endpoint.signup(
                endpoint.WaitlistSignupRequest(
                    email="Founder@acme.io",  # casing differs
                    company="Acme",
                    role="CISO",
                    soc_stack=[],
                    motivation="Trying again.",
                ),
                _mock_request(),  # type: ignore[arg-type]
                Response(),
                db=session,  # type: ignore[arg-type]
                rate_limiter=limiter,
                notifier=notifier,
            )
        )
        assert result.entry_id == str(existing_id)
        # No new row was inserted.
        assert session.add_calls == []
        assert notifier.calls == []

    def test_rate_limit_exhaustion_returns_429(self) -> None:
        session = _MockSession()
        notifier = _RecordingNotifier()
        limiter = SignupRateLimiter(capacity=1, refill_per_hour=1)
        req = _mock_request(xff="198.51.100.7")
        # First call consumes the only token.
        _run(
            endpoint.signup(
                endpoint.WaitlistSignupRequest(
                    email="a@acme.io",
                    company="Acme",
                    role="Analyst",
                    soc_stack=[],
                    motivation="m",
                ),
                req,  # type: ignore[arg-type]
                Response(),
                db=session,  # type: ignore[arg-type]
                rate_limiter=limiter,
                notifier=notifier,
            )
        )
        # Second call from the same IP gets refused.
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.signup(
                    endpoint.WaitlistSignupRequest(
                        email="b@acme.io",
                        company="Acme",
                        role="Analyst",
                        soc_stack=[],
                        motivation="m",
                    ),
                    req,  # type: ignore[arg-type]
                    Response(),
                    db=session,  # type: ignore[arg-type]
                    rate_limiter=limiter,
                    notifier=notifier,
                )
            )
        assert exc_info.value.status_code == 429
        assert "Retry-After" in exc_info.value.headers

    def test_slack_failure_does_not_break_signup(self) -> None:
        session = _MockSession()
        # Notifier that raises (despite the contract); the endpoint must
        # swallow this so the prospect still sees a success.
        notifier = _RecordingNotifier(raise_on_post=True)
        limiter = SignupRateLimiter(capacity=5, refill_per_hour=10)
        result = _run(
            endpoint.signup(
                endpoint.WaitlistSignupRequest(
                    email="x@acme.io",
                    company="Acme",
                    role="Analyst",
                    soc_stack=[],
                    motivation="m",
                ),
                _mock_request(),  # type: ignore[arg-type]
                Response(),
                db=session,  # type: ignore[arg-type]
                rate_limiter=limiter,
                notifier=notifier,
            )
        )
        assert result.ok is True
        assert result.entry_id is not None


# ---------------------------------------------------------------------------
# Admin list endpoint
# ---------------------------------------------------------------------------


class TestAdminListEndpoint:
    def _seed(self, session: _MockSession) -> tuple[uuid.UUID, uuid.UUID]:
        a_id = uuid.uuid4()
        b_id = uuid.uuid4()
        session.rows[a_id] = WaitlistEntry(
            id=a_id,
            email="a@acme.io",
            company="A",
            role="r",
            soc_stack=["splunk"],
            motivation="m",
            status=WAITLIST_STATUS_NEW,
            created_at=datetime(2026, 5, 13, 9, 0, tzinfo=UTC),
        )
        session.rows[b_id] = WaitlistEntry(
            id=b_id,
            email="b@acme.io",
            company="B",
            role="r",
            soc_stack=[],
            motivation="m",
            status=WAITLIST_STATUS_CONTACTED,
            created_at=datetime(2026, 5, 14, 9, 0, tzinfo=UTC),
        )
        return a_id, b_id

    def test_list_returns_all_entries_for_admin(self) -> None:
        session = _MockSession()
        self._seed(session)
        user = _admin_user()
        result = _run(endpoint.list_entries(session, user))  # type: ignore[arg-type]
        assert result.total == 2
        # Ordered by created_at DESC — most recent first.
        assert result.entries[0].email == "b@acme.io"
        assert result.entries[1].email == "a@acme.io"

    def test_list_filters_by_status(self) -> None:
        session = _MockSession()
        self._seed(session)
        user = _admin_user()
        result = _run(
            endpoint.list_entries(
                session,  # type: ignore[arg-type]
                user,
                status_filter="contacted",
            )
        )
        assert result.total == 1
        assert result.entries[0].status == WAITLIST_STATUS_CONTACTED

    def test_list_rejects_unknown_status(self) -> None:
        session = _MockSession()
        user = _admin_user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.list_entries(
                    session,  # type: ignore[arg-type]
                    user,
                    status_filter="bogus-state",
                )
            )
        assert exc_info.value.status_code == 400

    def test_list_forbidden_for_non_admin(self) -> None:
        session = _MockSession()
        self._seed(session)
        user = _admin_user(allow=False)
        with pytest.raises(HTTPException) as exc_info:
            _run(endpoint.list_entries(session, user))  # type: ignore[arg-type]
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Admin PATCH endpoint
# ---------------------------------------------------------------------------


class TestAdminPatchEndpoint:
    def test_patch_to_contacted_stamps_contacted_at(self) -> None:
        session = _MockSession()
        entry_id = uuid.uuid4()
        session.rows[entry_id] = WaitlistEntry(
            id=entry_id,
            email="c@acme.io",
            company="C",
            role="r",
            soc_stack=[],
            motivation="m",
            status=WAITLIST_STATUS_NEW,
            created_at=datetime.now(UTC),
        )
        user = _admin_user()
        result = _run(
            endpoint.patch_entry(
                entry_id,
                endpoint.WaitlistPatchRequest(status="contacted"),
                session,  # type: ignore[arg-type]
                user,
            )
        )
        assert result.status == WAITLIST_STATUS_CONTACTED
        assert result.contacted_at is not None
        assert session.rows[entry_id].contacted_at is not None

    def test_patch_to_onboarded_stamps_onboarded_at(self) -> None:
        session = _MockSession()
        entry_id = uuid.uuid4()
        session.rows[entry_id] = WaitlistEntry(
            id=entry_id,
            email="o@acme.io",
            company="O",
            role="r",
            soc_stack=[],
            motivation="m",
            status=WAITLIST_STATUS_CONTACTED,
            created_at=datetime.now(UTC),
            contacted_at=datetime.now(UTC),
        )
        user = _admin_user()
        result = _run(
            endpoint.patch_entry(
                entry_id,
                endpoint.WaitlistPatchRequest(status="onboarded"),
                session,  # type: ignore[arg-type]
                user,
            )
        )
        assert result.status == WAITLIST_STATUS_ONBOARDED
        assert result.onboarded_at is not None

    def test_patch_to_declined_is_terminal(self) -> None:
        session = _MockSession()
        entry_id = uuid.uuid4()
        session.rows[entry_id] = WaitlistEntry(
            id=entry_id,
            email="d@acme.io",
            company="D",
            role="r",
            soc_stack=[],
            motivation="m",
            status=WAITLIST_STATUS_NEW,
            created_at=datetime.now(UTC),
        )
        user = _admin_user()
        result = _run(
            endpoint.patch_entry(
                entry_id,
                endpoint.WaitlistPatchRequest(status="declined"),
                session,  # type: ignore[arg-type]
                user,
            )
        )
        assert result.status == WAITLIST_STATUS_DECLINED
        # Declined doesn't stamp contacted_at / onboarded_at.
        assert result.contacted_at is None
        assert result.onboarded_at is None

    def test_patch_missing_entry_404(self) -> None:
        session = _MockSession()
        user = _admin_user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.patch_entry(
                    uuid.uuid4(),
                    endpoint.WaitlistPatchRequest(status="contacted"),
                    session,  # type: ignore[arg-type]
                    user,
                )
            )
        assert exc_info.value.status_code == 404

    def test_patch_invalid_status_rejected_at_payload_layer(self) -> None:
        with pytest.raises(ValidationError):
            endpoint.WaitlistPatchRequest(status="nope")


# ---------------------------------------------------------------------------
# Slack message builder
# ---------------------------------------------------------------------------


class TestSlackMessageShape:
    def test_block_kit_payload_includes_company_and_email(self) -> None:
        payload = build_signup_message(
            email="x@acme.io",
            company="Acme Inc",
            role="CISO",
            soc_stack=["splunk", "crowdstrike"],
            motivation="Want to evaluate.",
            entry_id="abc-123",
        )
        assert "Acme Inc" in payload["text"]
        assert payload["blocks"][0]["type"] == "header"
        fields = payload["blocks"][1]["fields"]
        joined = " ".join(f["text"] for f in fields)
        assert "Acme Inc" in joined
        assert "CISO" in joined
        assert "splunk" in joined
        # Entry id surfaces in the context block for triage.
        assert "abc-123" in payload["blocks"][3]["elements"][0]["text"]

    def test_empty_soc_stack_renders_as_not_specified(self) -> None:
        payload = build_signup_message(
            email="x@acme.io",
            company="Acme",
            role="Analyst",
            soc_stack=[],
            motivation="Want to evaluate.",
            entry_id="abc-123",
        )
        joined = " ".join(f["text"] for f in payload["blocks"][1]["fields"])
        assert "not specified" in joined

    def test_long_motivation_is_truncated(self) -> None:
        payload = build_signup_message(
            email="x@acme.io",
            company="Acme",
            role="Analyst",
            soc_stack=[],
            motivation="x" * 800,
            entry_id="abc-123",
        )
        block_text = payload["blocks"][2]["text"]["text"]
        assert block_text.endswith("...")
        assert len(block_text) < 800


# ---------------------------------------------------------------------------
# Client IP resolution
# ---------------------------------------------------------------------------


class TestClientIpResolution:
    def test_x_forwarded_for_first_address_wins(self) -> None:
        ip = endpoint._client_ip(
            _mock_request(xff="203.0.113.10, 198.51.100.1, 192.0.2.5")  # type: ignore[arg-type]
        )
        assert ip == "203.0.113.10"

    def test_falls_back_to_socket(self) -> None:
        ip = endpoint._client_ip(_mock_request(client_host="10.0.0.1"))  # type: ignore[arg-type]
        assert ip == "10.0.0.1"

    def test_unknown_when_no_client(self) -> None:
        req = SimpleNamespace(headers={}, client=None)
        ip = endpoint._client_ip(req)  # type: ignore[arg-type]
        assert ip == "unknown"
