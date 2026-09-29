"""The operator door onto a DLQ replay (deferral 5b).

Fusion owns whether a message is safe to replay. This half owns whether the
*action* is safe to take, and the three properties below are what that means:
the attempt is recorded before it is made, a failure says why instead of
returning zeros that read like success, and the bound is enforced here as
well as downstream.
"""

from __future__ import annotations

import uuid

import pytest
from app.services.dlq_replay_gateway import (
    MAX_REPLAY_MESSAGES,
    DlqReplayRequest,
    run_replay,
)
from pydantic import ValidationError


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value


class _RecordingSession:
    """Captures the statements a replay writes, in order."""

    def __init__(self, replay_id: uuid.UUID | None = None) -> None:
        self.replay_id = replay_id or uuid.uuid4()
        self.statements: list[tuple[str, dict]] = []
        self.commits = 0

    async def execute(self, statement: object, params: dict | None = None) -> _FakeResult:
        self.statements.append((str(statement).strip().split()[0].upper(), params or {}))
        return _FakeResult(self.replay_id)

    async def commit(self) -> None:
        self.commits += 1


def _request(**overrides: object) -> DlqReplayRequest:
    base: dict = {"topic": "aisoc.raw_events", "partition": 0, "start_offset": 42, "max_messages": 10}
    return DlqReplayRequest(**{**base, **overrides})


class TestTheRequestShapeIsSafeByDefault:
    def test_execute_defaults_to_a_dry_run(self) -> None:
        """The dangerous direction is a caller who omits the field."""
        assert _request().execute is False

    @pytest.mark.parametrize(
        "overrides",
        [
            {"max_messages": 0},
            {"max_messages": MAX_REPLAY_MESSAGES + 1},
            {"partition": -1},
            {"start_offset": -1},
            {"topic": ""},
        ],
    )
    def test_an_unbounded_or_negative_request_is_refused_by_the_model(self, overrides: dict) -> None:
        with pytest.raises(ValidationError):
            _request(**overrides)

    def test_the_cap_matches_the_one_fusion_and_the_migration_enforce(self) -> None:
        """Three layers, and they must be the same number.

        A bound that lives only in a request model is a bound a
        service-to-service caller skips, so it is restated in fusion and as a
        CHECK constraint. If they ever disagree, the weakest one is the real
        one — which is why this reads the migration rather than trusting it.
        """
        from pathlib import Path

        migration = Path(__file__).resolve().parents[1] / "migrations" / "075_dead_letter_replay.sql"
        assert f"max_messages <= {MAX_REPLAY_MESSAGES}" in migration.read_text(encoding="utf-8")


class TestTheAttemptIsRecordedBeforeItIsMade:
    @pytest.mark.asyncio
    async def test_the_row_is_inserted_and_committed_before_fusion_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A replay that hangs must still have left evidence it started."""
        session = _RecordingSession()
        monkeypatch.delenv("FUSION_SERVICE_URL", raising=False)
        monkeypatch.delenv("FUSION_URL", raising=False)

        await run_replay(session, tenant_id=uuid.uuid4(), requested_by=uuid.uuid4(), request=_request())

        assert session.statements[0][0] == "INSERT"
        assert session.commits >= 1

    @pytest.mark.asyncio
    async def test_the_actor_is_stamped_on_the_row(self) -> None:
        session = _RecordingSession()
        actor = uuid.uuid4()

        await run_replay(session, tenant_id=uuid.uuid4(), requested_by=actor, request=_request())

        assert session.statements[0][1]["requested_by"] == str(actor)


class TestAFailureSaysWhy:
    @pytest.mark.asyncio
    async def test_an_unconfigured_fusion_reports_the_reason_not_an_empty_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`produced: 0` with no reason reads exactly like 'nothing to do'.

        That reading is how an operator concludes a queue was drained when
        the replay never ran at all.
        """
        monkeypatch.delenv("FUSION_SERVICE_URL", raising=False)
        monkeypatch.delenv("FUSION_URL", raising=False)
        session = _RecordingSession()

        response = await run_replay(session, tenant_id=uuid.uuid4(), requested_by=None, request=_request())

        assert response.status == "failed"
        assert response.error is not None
        assert "FUSION_SERVICE_URL" in response.error
        assert response.produced == 0

    @pytest.mark.asyncio
    async def test_the_failure_is_written_back_to_the_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FUSION_SERVICE_URL", raising=False)
        monkeypatch.delenv("FUSION_URL", raising=False)
        session = _RecordingSession()

        await run_replay(session, tenant_id=uuid.uuid4(), requested_by=None, request=_request())

        kinds = [kind for kind, _ in session.statements]
        assert kinds == ["INSERT", "UPDATE"]
        assert session.statements[-1][1]["status"] == "failed"
        assert session.statements[-1][1]["error"]


class TestASuccessfulReplayIsRecordedFaithfully:
    @pytest.mark.asyncio
    async def test_the_counts_fusion_reported_reach_both_the_row_and_the_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx
        from app.services import dlq_replay_gateway

        monkeypatch.setenv("FUSION_SERVICE_URL", "http://fusion.test")
        body = {
            "executed": True,
            "messages_read": 7,
            "would_pass": 5,
            "refused": 2,
            "produced": 5,
            "refusals": {"missing or non-object 'ocsf_event'": 2},
            "produced_offsets": [10, 11, 12, 13, 14],
        }

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def post(self, *_args, **_kwargs):
                return httpx.Response(200, json=body)

        monkeypatch.setattr(dlq_replay_gateway.httpx, "AsyncClient", lambda **_kw: _Client())
        session = _RecordingSession()

        response = await run_replay(session, tenant_id=uuid.uuid4(), requested_by=None, request=_request(execute=True))

        assert response.status == "completed"
        assert (response.messages_read, response.would_pass, response.refused, response.produced) == (7, 5, 2, 5)
        # The refusal reasons survive to the operator: "two failed for the
        # same reason" is the finding, not the list of offsets.
        assert response.refusals == {"missing or non-object 'ocsf_event'": 2}
        assert session.statements[-1][1]["produced"] == 5
