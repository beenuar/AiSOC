"""The sweep that gives ``shadow_reconcile`` a schedule.

Gap-closure Phase 2.1, closing D15.

The defect being closed is precisely "exists and nothing calls it": the
matcher was complete, had eleven tests, and had no caller, so a tenant whose
analysts close their queue in their own SIEM accumulated no track record and
the only symptom was a scorecard that never filled in. A test asserting the
sweep is registered by the *deployed* lifespan rather than by one this file
built is therefore the point of the file, and it is the last test here.

The rest cover the properties a scheduled sweep against somebody else's API
has to have: it must tell a condition that will never resolve from one that
might, it must not re-read the same window forever, it must not poll faster
than it said it would, and it must record the quiet passes so that a sweep
which stopped is distinguishable from one with nothing to do.
"""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.db.cross_tenant import CrossTenantPreconditionError
from app.security.credential_vault import CredentialVaultError
from app.workers import shadow_reconcile
from app.workers.shadow_reconcile import run_once

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
CONNECTOR = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
OTHER_CONNECTOR = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000002")

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


def _row(**overrides: Any) -> dict[str, Any]:
    """One candidate as the SQL returns it."""
    row: dict[str, Any] = {
        "connector_id": CONNECTOR,
        "tenant_id": TENANT,
        "connector_type": "splunk",
        "auth_config": {"base_url": "https://splunk.example.com:8089", "token": "vault:v1:x"},
        "connector_config": {"saved_search": "my notables"},
        "connector_updated_at": NOW - timedelta(days=30),
        "measuring_since": NOW - timedelta(days=3),
        "watermark_at": None,
        "last_run_at": None,
        "retry_after": None,
        "blocked_reason": None,
        "blocked_connector_updated_at": None,
        "consecutive_failures": 0,
    }
    row.update(overrides)
    return row


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one(self) -> Any:
        return self._value

    def mappings(self) -> _Result:
        return self

    def all(self) -> Any:
        return self._value if isinstance(self._value, list) else []


class FakeSession:
    """Records every statement, so what the sweep wrote can be asserted."""

    def __init__(self, rows: list[dict[str, Any]], *, measuring: int = 1, bound_tenant: str | None = None) -> None:
        self._rows = rows
        self._measuring = measuring
        self._bound_tenant = bound_tenant
        self.statements: list[tuple[str, dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False

    async def scalar(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        self.statements.append((str(stmt), dict(params or {})))
        return self._bound_tenant

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(stmt)
        self.statements.append((sql, dict(params or {})))
        if "COUNT(DISTINCT tenant_id)" in sql:
            return _Result(self._measuring)
        if "FROM connectors c" in sql:
            return _Result(self._rows)
        return _Result(None)

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def close(self) -> None:  # pragma: no cover - session is injected
        pass

    def writes(self) -> list[dict[str, Any]]:
        return [p for sql, p in self.statements if "INSERT INTO aisoc_shadow_reconcile_state" in sql]


@pytest.fixture(autouse=True)
def _vault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A vault that decrypts. Tests that want a missing key override this."""

    class _Vault:
        def decrypt_dict(self, value: dict[str, Any]) -> dict[str, Any]:
            return {k: (v.replace("vault:v1:", "") if isinstance(v, str) else v) for k, v in value.items()}

    monkeypatch.setattr(shadow_reconcile, "get_vault", lambda: _Vault())


def _respond(monkeypatch: pytest.MonkeyPatch, response: httpx.Response | BaseException) -> list[dict[str, Any]]:
    """Stand in for the actions service. Returns the payloads it was sent."""
    sent: list[dict[str, Any]] = []

    class _Client:
        def __init__(self, **_kw: Any) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_exc: Any) -> None:
            return None

        async def post(self, url: str, headers: dict[str, str] | None = None, json: Any = None) -> httpx.Response:
            sent.append({"url": url, "headers": headers or {}, "json": json})
            if isinstance(response, BaseException):
                raise response
            return response

    monkeypatch.setattr(shadow_reconcile.httpx, "AsyncClient", _Client)
    return sent


def _ok(**body: Any) -> httpx.Response:
    payload = {
        "vendor": "splunk",
        "count": 0,
        "labelled": 0,
        "unlabeled": 0,
        "considered": 0,
        "matched": 0,
        "unmatched": 0,
        "already_resolved": 0,
        "skipped_no_key": 0,
        "latest_closed_at": None,
    }
    payload.update(body)
    return httpx.Response(200, json=payload, request=httpx.Request("POST", "http://actions/api/v1/shadow/reconcile"))


def _refused(code: int, detail: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        code,
        json={"detail": detail},
        headers=headers or {},
        request=httpx.Request("POST", "http://actions/api/v1/shadow/reconcile"),
    )


class TestItActuallyPolls:
    @pytest.mark.asyncio
    async def test_a_due_connector_is_polled_and_its_watermark_advances(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed_at = (NOW - timedelta(minutes=20)).isoformat()
        sent = _respond(monkeypatch, _ok(count=4, considered=4, matched=3, unmatched=1, latest_closed_at=closed_at))
        db = FakeSession([_row()])

        run = await run_once(db=db, now=NOW)

        assert run.count("ok") == 1
        assert len(sent) == 1
        assert sent[0]["url"].endswith("/api/v1/shadow/reconcile")
        assert sent[0]["json"]["vendor"] == "splunk"
        write = db.writes()[0]
        assert write["last_status"] == "ok"
        assert write["matched"] == 3
        # Advanced to the latest closure seen, not to the end of the window.
        assert write["watermark_at"] == datetime.fromisoformat(closed_at)

    @pytest.mark.asyncio
    async def test_the_tenant_travels_on_the_header_not_in_the_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The receiving route takes its tenant from the credential.

        A tenant in the body would be a value the caller chose that nothing
        checked, which is the shape every cross-tenant leak in this codebase
        has had.
        """
        sent = _respond(monkeypatch, _ok())

        await run_once(db=FakeSession([_row()]), now=NOW)

        assert sent[0]["headers"]["X-AiSOC-Tenant-ID"] == str(TENANT)
        assert not [k for k in sent[0]["json"] if "tenant" in k]

    @pytest.mark.asyncio
    async def test_credentials_are_translated_into_the_readers_key_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The connector stores ``base_url``; the reader wants ``splunk_url``.

        A key that lands under the wrong name does not raise. The factory
        returns None and the read is refused as "no usable credentials", which
        reads to an operator as a problem on their side.
        """
        sent = _respond(monkeypatch, _ok())

        await run_once(db=FakeSession([_row()]), now=NOW)

        credentials = sent[0]["json"]["credentials"]
        assert credentials["splunk_url"] == "https://splunk.example.com:8089"
        assert credentials["splunk_token"] == "x"
        # The saved search a deployment renamed reaches the reader too.
        assert sent[0]["json"]["search_override"] == "my notables"


class TestPermanentIsNotTransient:
    """The property the whole design rests on, asserted from both sides."""

    @pytest.mark.asyncio
    async def test_a_refused_credential_blocks_and_names_the_action(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _respond(
            monkeypatch,
            _refused(422, "splunk: the vendor refused the stored credentials with HTTP 401. Re-authorise this connector in Settings"),
        )
        db = FakeSession([_row()])

        run = await run_once(db=db, now=NOW)

        assert run.count("blocked") == 1
        write = db.writes()[0]
        assert write["last_status"] == "blocked"
        assert "Re-authorise" in write["blocked_reason"]
        # Recorded against the connector as it stands now, which is what makes
        # re-saving it the one event that resumes polling.
        assert write["blocked_connector_updated_at"] == NOW - timedelta(days=30)

    @pytest.mark.asyncio
    async def test_a_blocked_connector_is_not_polled_again(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sent = _respond(monkeypatch, _ok())
        db = FakeSession(
            [
                _row(
                    blocked_reason="splunk: the vendor refused the stored credentials with HTTP 401",
                    blocked_connector_updated_at=NOW - timedelta(days=30),
                    last_run_at=NOW - timedelta(days=2),
                )
            ]
        )

        run = await run_once(db=db, now=NOW)

        assert sent == [], "a revoked credential must not be retried on a timer"
        assert run.count("idle") == 0, "a blocked connector is not counted as polled"
        # Still written, so the state is visible rather than merely absent.
        assert db.writes()[0]["last_status"] == "idle"

    @pytest.mark.asyncio
    async def test_saving_the_connector_resumes_polling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The one event that could have fixed it is the only one that clears it."""
        sent = _respond(monkeypatch, _ok())
        db = FakeSession(
            [
                _row(
                    blocked_reason="splunk: the vendor refused the stored credentials with HTTP 401",
                    blocked_connector_updated_at=NOW - timedelta(days=30),
                    connector_updated_at=NOW - timedelta(minutes=1),
                    last_run_at=NOW - timedelta(days=2),
                )
            ]
        )

        run = await run_once(db=db, now=NOW)

        assert len(sent) == 1
        assert run.count("ok") == 1
        assert db.writes()[0]["blocked_reason"] is None

    @pytest.mark.asyncio
    async def test_an_undecryptable_credential_blocks_before_the_vendor_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Vault:
            def decrypt_dict(self, _value: dict[str, Any]) -> dict[str, Any]:
                raise CredentialVaultError("no key in the keyring")

        monkeypatch.setattr(shadow_reconcile, "get_vault", lambda: _Vault())
        sent = _respond(monkeypatch, _ok())
        db = FakeSession([_row()])

        run = await run_once(db=db, now=NOW)

        assert sent == []
        assert run.count("blocked") == 1
        assert "Re-save this connector" in db.writes()[0]["blocked_reason"]

    @pytest.mark.asyncio
    async def test_an_unreachable_actions_service_is_transient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _respond(monkeypatch, httpx.ConnectError("refused"))
        db = FakeSession([_row()])

        run = await run_once(db=db, now=NOW)

        assert run.count("transient") == 1
        write = db.writes()[0]
        assert write["last_status"] == "transient"
        assert write["blocked_reason"] is None, "a transient fault must never block"
        assert write["consecutive_failures"] == 1

    @pytest.mark.asyncio
    async def test_consecutive_transient_failures_accumulate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """So a fault that has outlived a transient explanation is visible as one."""
        _respond(monkeypatch, httpx.ReadTimeout("slow"))
        db = FakeSession([_row(consecutive_failures=6, last_run_at=NOW - timedelta(days=1))])

        await run_once(db=db, now=NOW)

        assert db.writes()[0]["consecutive_failures"] == 7

    @pytest.mark.asyncio
    async def test_a_transient_failure_leaves_the_watermark_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failure must not look like progress and must not skip a window."""
        _respond(monkeypatch, httpx.ConnectError("refused"))
        db = FakeSession([_row(watermark_at=NOW - timedelta(hours=2), last_run_at=NOW - timedelta(days=1))])

        await run_once(db=db, now=NOW)

        assert db.writes()[0]["watermark_at"] is None, "the upsert keeps the stored value when the pass wrote none"

    @pytest.mark.asyncio
    async def test_a_deployment_refusal_halts_the_pass_instead_of_blaming_every_connector(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A wrong service token is not fifty connectors each needing a re-save."""
        _respond(monkeypatch, _refused(401, "invalid or missing service token"))
        db = FakeSession([_row(), _row(connector_id=OTHER_CONNECTOR)])

        run = await run_once(db=db, now=NOW)

        assert run.halted_reason is not None
        assert "401" in run.halted_reason
        assert db.rolled_back is True
        assert db.writes() == [] or not db.committed


class TestRateLimitingAndTheWatermark:
    @pytest.mark.asyncio
    async def test_a_vendors_retry_after_is_stored_and_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _respond(monkeypatch, _refused(429, "splunk asked us to slow down", {"Retry-After": "600"}))
        db = FakeSession([_row()])

        await run_once(db=db, now=NOW)

        assert db.writes()[0]["retry_after"] == NOW + timedelta(seconds=600)

    @pytest.mark.asyncio
    async def test_a_connector_inside_its_retry_after_is_not_polled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sent = _respond(monkeypatch, _ok())
        db = FakeSession([_row(retry_after=NOW + timedelta(minutes=5), last_run_at=NOW - timedelta(days=1))])

        await run_once(db=db, now=NOW)

        assert sent == []
        assert "asked us to wait" in db.writes()[0]["last_detail"]

    @pytest.mark.asyncio
    async def test_a_recently_polled_connector_is_left_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The per-connector floor, so a short tick cadence is not a poll storm."""
        sent = _respond(monkeypatch, _ok())
        db = FakeSession([_row(last_run_at=NOW - timedelta(minutes=5))])

        await run_once(db=db, now=NOW)

        assert sent == []
        assert db.writes()[0]["last_detail"] == "polled recently"

    @pytest.mark.asyncio
    async def test_the_window_starts_at_the_watermark_less_the_overlap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A vendor's search index lags its own close events.

        A window beginning exactly where the last one ended steps over anything
        indexed late, and the overlap is free of consequence because an
        already-graded finding comes back as ``already_resolved``.
        """
        sent = _respond(monkeypatch, _ok())
        watermark = NOW - timedelta(hours=2)
        db = FakeSession([_row(watermark_at=watermark, last_run_at=NOW - timedelta(days=1))])

        await run_once(db=db, now=NOW)

        since = datetime.fromisoformat(sent[0]["json"]["since"])
        assert since == watermark - timedelta(seconds=shadow_reconcile.settings.SHADOW_RECONCILE_OVERLAP_SECONDS)

    @pytest.mark.asyncio
    async def test_a_first_pass_starts_when_measurement_started(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reaching back further would grade closures with nothing to grade them against."""
        sent = _respond(monkeypatch, _ok())
        measuring_since = NOW - timedelta(days=2)
        db = FakeSession([_row(measuring_since=measuring_since)])

        await run_once(db=db, now=NOW)

        assert datetime.fromisoformat(sent[0]["json"]["since"]) == measuring_since

    @pytest.mark.asyncio
    async def test_one_window_is_capped_so_a_long_gap_catches_up_in_steps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Asking a customer's SIEM for a month in one search is the request
        least likely to succeed, so it is never made."""
        sent = _respond(monkeypatch, _ok())
        db = FakeSession([_row(measuring_since=NOW - timedelta(days=90))])

        await run_once(db=db, now=NOW)

        since = datetime.fromisoformat(sent[0]["json"]["since"])
        until = datetime.fromisoformat(sent[0]["json"]["until"])
        assert until - since <= timedelta(hours=shadow_reconcile.settings.SHADOW_RECONCILE_MAX_WINDOW_HOURS)
        assert until < NOW, "the pass stops short of now and resumes next tick"

    @pytest.mark.asyncio
    async def test_an_empty_window_still_advances_the_watermark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Otherwise the sweep re-reads the same quiet hours forever."""
        _respond(monkeypatch, _ok())
        db = FakeSession([_row(watermark_at=NOW - timedelta(hours=4), last_run_at=NOW - timedelta(days=1))])

        await run_once(db=db, now=NOW)

        advanced = db.writes()[0]["watermark_at"]
        assert advanced is not None
        assert advanced > NOW - timedelta(hours=4)
        # But not past the overlap, so nothing indexed inside it is skipped.
        assert advanced <= NOW - timedelta(seconds=shadow_reconcile.settings.SHADOW_RECONCILE_OVERLAP_SECONDS)

    @pytest.mark.asyncio
    async def test_a_pass_is_capped_per_tick(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sent = _respond(monkeypatch, _ok())
        monkeypatch.setattr(shadow_reconcile, "_max_per_tick", lambda: 2)
        rows = [_row(connector_id=uuid.UUID(int=i)) for i in range(1, 6)]

        run = await run_once(db=FakeSession(rows), now=NOW)

        assert len(sent) == 2
        assert run.candidates == 5


class TestTheQuietCasesAreRecorded:
    """A sweep that stopped and a sweep with nothing to do look identical from
    outside unless the quiet case is written down."""

    @pytest.mark.asyncio
    async def test_no_measuring_tenant_is_a_recorded_state_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _respond(monkeypatch, _ok())

        run = await run_once(db=FakeSession([], measuring=0), now=NOW)

        assert run.measuring_tenants == 0
        assert run.candidates == 0
        assert run.halted_reason is None

    @pytest.mark.asyncio
    async def test_measuring_with_no_replayable_connector_is_distinguishable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Somebody asked to be measured and has nothing this can poll.

        Reported apart from "nobody asked", because only one of the two is
        worth telling an operator about.
        """
        _respond(monkeypatch, _ok())

        run = await run_once(db=FakeSession([], measuring=3), now=NOW)

        assert run.measuring_tenants == 3
        assert run.candidates == 0

    @pytest.mark.asyncio
    async def test_reading_closures_and_matching_none_is_reported_as_a_wiring_fault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Not as a successful quiet pass. The join key is not arriving."""
        _respond(monkeypatch, _ok(count=12, considered=12, matched=0, unmatched=12))
        db = FakeSession([_row()])

        await run_once(db=db, now=NOW)

        detail = db.writes()[0]["last_detail"]
        assert "matched none" in detail
        assert "external_id" in detail

    @pytest.mark.asyncio
    async def test_the_sweep_refuses_a_session_bound_to_one_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A cross-tenant sweep that quietly sees one tenant is worse than one
        that stops, because it reports success."""
        _respond(monkeypatch, _ok())
        db = FakeSession([_row()], bound_tenant=str(TENANT))

        with pytest.raises(CrossTenantPreconditionError):
            await run_once(db=db, now=NOW)


class TestOnlyReplayableConnectorsAreAsked:
    def test_the_candidate_query_filters_on_the_shared_vendor_table(self) -> None:
        """One definition of "has a reader", shared with replay evaluation.

        A second list here would go stale the first time a sixth reader landed,
        and the symptom would be a tenant whose connector is supported and is
        never polled.
        """
        from app.services.replay_evaluation.vendors import replayable_connector_ids  # noqa: PLC0415

        assert ":replayable" in shadow_reconcile._CANDIDATES_SQL
        assert replayable_connector_ids(), "the shared table is empty; this test is stale"

    def test_only_tenants_with_shadow_mode_on_are_candidates(self) -> None:
        assert "aisoc_shadow_mode" in shadow_reconcile._CANDIDATES_SQL
        assert "enabled IS TRUE" in shadow_reconcile._CANDIDATES_SQL


def test_the_deployed_lifespan_registers_the_sweep() -> None:
    """The failure this whole change closes is "exists and nothing calls it".

    So the assertion is against ``app/main.py`` as it ships, not against a
    scheduler a test assembled. Read off the source with an AST pass rather
    than imported, for the same reason the Phase 1.2 sink test is: importing
    ``app.main`` pulls in the service's whole startup graph, and a test that
    has to boot the service to check a registration gets deleted the first
    time it is slow.

    Three things are checked, because any one of them alone would pass over a
    worker that never runs: the module is imported, a task is created for it,
    and the task's ``worker=`` is the sweep's ``run_forever`` rather than
    something that merely mentions it.
    """
    source = Path(__file__).resolve().parents[1] / "app" / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "app.workers.shadow_reconcile"
        for alias in node.names
    }
    assert imported, "app/main.py no longer imports the shadow-reconciliation worker"

    guarded = [
        call
        for call in ast.walk(tree)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_run_guarded_scheduler_worker"
    ]
    assert guarded, "app/main.py no longer registers guarded scheduler workers; this test is stale"

    registered = [
        call
        for call in guarded
        for kw in call.keywords
        if kw.arg == "worker" and isinstance(kw.value, ast.Name) and kw.value.id in imported
    ]
    assert registered, (
        "the shadow-reconciliation sweep is imported by app/main.py but never passed to "
        "_run_guarded_scheduler_worker, so nothing would call it on a schedule. That is the exact "
        "defect D15 recorded, one layer up."
    )

    job_names = {
        kw.value.value for call in registered for kw in call.keywords if kw.arg == "job_name" and isinstance(kw.value, ast.Constant)
    }
    assert "shadow_reconcile" in job_names, (
        f"the sweep is registered under {job_names or 'no job name'}; the Redis scheduler lease is keyed on "
        f"the job name, so two names means two replicas can sweep the same vendor at once"
    )


def test_the_sweep_is_off_by_default_and_says_so() -> None:
    """A feature that reaches a third party's API ships off.

    Paired with the assertion that the disabled case is announced, because the
    state this change closes is an operator reading an empty scorecard and
    being unable to tell a sweep that is off from one that is broken.
    """
    from app.core.config import Settings  # noqa: PLC0415

    assert Settings.model_fields["SHADOW_RECONCILE_ENABLED"].default is False

    source = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text(encoding="utf-8")
    assert "shadow_reconcile worker disabled" in source
