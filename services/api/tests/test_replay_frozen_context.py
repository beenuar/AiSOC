"""The replay sends the context production triages with, frozen at the split.

Fix pass 3.1. A replay grades the agent against closed findings, and the
report it produces is read as "this is how triage would have done". That
reading is only true if the replay runs with what production runs with.

Two halves were missing, and both flatter or distort the result rather than
erroring:

* `job.py` sent a context block **only** when a caller passed tenant skills,
  so an ordinary replay sent none at all. Organisation memory
  (`aisoc_context_statements`), outcome priors
  (`aisoc_institutional_memory`, `outcome:` keys) and the tenant's
  business-context rule set were never captured, while production reads all
  three on every alert. `replay.md`, `triage-context.md` and
  `tenant-skills.md` all describe a replay that carries them.
* The agents-side runner was constructed with no `business_context`, while
  `main.py` constructs a `BusinessContextApplier` whenever the feature is
  enabled -- which is by default.

The direction of the error matters. Organisation memory and priors mostly
*suppress*, so a replay without them re-raises alerts production would have
closed and scores the agent against a world it does not run in.

What is deliberately **not** sent: anything recorded after the split. The
capture here reads rows with their recorded time attached and the agents
side drops the late ones (`capture_context` in
`services/agents/app/replay/shadow.py`), so the filtering happens in one
place rather than being re-implemented on each side of the call.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from app.services.replay_evaluation import job as job_module

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


class _RecordingStore:
    def __init__(self) -> None:
        self.failure: str | None = None
        self.result: dict[str, Any] | None = None

    async def mark_running(self, db: Any, **_: Any) -> None:
        return None

    async def fail_evaluation(self, db: Any, *, error: str, **_: Any) -> None:
        self.failure = error

    async def store_result(self, db: Any, **fields: Any) -> None:
        self.result = fields


class _Connector:
    connector_type = "splunk"
    auth_config = {"base_url": "https://splunk:8089", "token": "t"}
    connector_config = {"ssl_verify": True}


class _ContextSession:
    """A session that answers the three context reads and the connector read.

    Routed on the SQL text rather than on call order: the job is free to
    reorder its reads, and a positional stub would then answer the wrong
    query while still passing.
    """

    def __init__(self, *, statements: list[dict[str, Any]], priors: list[Any], rule_set: Any) -> None:
        self._statements = statements
        self._priors = priors
        self._rule_set = rule_set
        self.queries: list[str] = []
        self.savepoints = 0
        self.savepoint_rollbacks = 0

    async def begin_nested(self) -> Any:
        """A SAVEPOINT, recorded so a test can assert one was actually taken."""
        self.savepoints += 1
        session = self

        class _Savepoint:
            async def rollback(self) -> None:
                session.savepoint_rollbacks += 1

            async def commit(self) -> None:
                return None

        return _Savepoint()

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        sql = str(statement)
        self.queries.append(sql)
        rows: list[Any] = []
        scalar: Any = None
        if "aisoc_context_statements" in sql:
            rows = self._statements
        elif "aisoc_institutional_memory" in sql:
            rows = self._priors
        elif "aisoc_business_context_rule_sets" in sql:
            rows = [self._rule_set] if self._rule_set is not None else []
        else:
            scalar = _Connector()

        class _Result:
            def scalar_one_or_none(self) -> Any:
                return scalar

            def mappings(self) -> Any:
                return rows

            def __iter__(self) -> Any:
                return iter(rows)

        return _Result()

    async def rollback(self) -> None:
        return None


def _request(**overrides: Any) -> job_module.ReplayRequest:
    defaults: dict[str, Any] = {
        "tenant_id": TENANT,
        "evaluation_id": uuid.uuid4(),
        "connector_row_id": uuid.uuid4(),
        "connector_type": "splunk",
        "vendor": "splunk",
        "window_start": datetime(2026, 3, 1, tzinfo=UTC),
        "window_end": datetime(2026, 6, 1, tzinfo=UTC),
        "train_fraction": 0.7,
        "limit": 1000,
        "bootstrap_seed": 20260926,
        "bootstrap_resamples": 50,
    }
    return job_module.ReplayRequest(**{**defaults, **overrides})


@pytest.fixture
def no_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Vault:
        def decrypt_dict(self, value: dict[str, Any]) -> dict[str, Any]:
            return dict(value)

    monkeypatch.setattr(job_module, "get_vault", lambda: _Vault())


@pytest.fixture
def recording_store(monkeypatch: pytest.MonkeyPatch) -> _RecordingStore:
    stub = _RecordingStore()
    monkeypatch.setattr(job_module.store, "mark_running", stub.mark_running)
    monkeypatch.setattr(job_module.store, "fail_evaluation", stub.fail_evaluation)
    monkeypatch.setattr(job_module.store, "store_result", stub.store_result)
    return stub


def _capture_replay_payload(monkeypatch: pytest.MonkeyPatch, sink: dict[str, Any]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/replay/history"):
            return httpx.Response(
                200,
                json={"vendor": "splunk", "count": 2, "labelled": 2, "unlabeled": 0, "findings": [{"x": 1}, {"x": 2}]},
            )
        import json as _json

        sink.update(_json.loads(request.content.decode()))
        return httpx.Response(
            200,
            json={
                "decisions": [
                    {"finding_id": "a", "predicted": "malicious", "actual": "malicious", "split": "test"},
                    {"finding_id": "b", "predicted": "benign", "actual": "benign", "split": "test"},
                ],
                "method": {},
            },
        )

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        job_module.httpx,
        "AsyncClient",
        lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )


def _session() -> _ContextSession:
    return _ContextSession(
        statements=[
            {
                "statement": "deploy-bot opens change tickets; its bulk edits are expected",
                "reason_code": "expected_automation",
                "scope": "actor",
                "scope_value": "deploy-bot",
                "observations": 12,
                "updated_at": datetime(2026, 2, 1, tzinfo=UTC),
            }
        ],
        priors=[
            {
                "key": "outcome:sig-benign-backup",
                "value": {
                    "disposition": "benign",
                    "author": "human",
                    "confidence": 1.0,
                    "last_seen": "2026-02-10T00:00:00+00:00",
                },
            }
        ],
        rule_set={
            "yaml_text": "rules:\n  - name: crown jewels\n    when: {host: db-prod-1}\n    then: {severity: critical}\n",
            "enabled": True,
            "updated_at": datetime(2026, 1, 20, tzinfo=UTC),
        },
    )


@pytest.mark.asyncio
class TestTheReplayCarriesProductionContext:
    async def test_organisation_memory_is_sent(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """Statements in `aisoc_context_statements` reach the agents service.

        Pre-fix this list was absent: the payload carried no `context` key at
        all unless a caller passed skills.
        """
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        await job_module.run_evaluation(_session(), _request())

        assert recording_store.failure is None, recording_store.failure
        statements = sent.get("context", {}).get("statements") or []
        assert [s["statement"] for s in statements] == ["deploy-bot opens change tickets; its bulk edits are expected"]

    async def test_outcome_priors_are_sent_keyed_by_signature(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """Priors travel under the bare signature, not the `outcome:` storage key.

        The agents side looks a prior up by signature; sending the storage
        key would put every prior somewhere nothing reads, which is the
        silent-miss shape `human_priors.py` documents.
        """
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        await job_module.run_evaluation(_session(), _request())

        priors = sent.get("context", {}).get("priors") or {}
        assert list(priors) == ["sig-benign-backup"]
        assert priors["sig-benign-backup"]["author"] == "human"

    async def test_the_business_context_rule_set_is_sent(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """Production applies the tenant's rules on every alert; a replay must too."""
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        await job_module.run_evaluation(_session(), _request())

        rules = sent.get("context", {}).get("business_context") or {}
        assert rules.get("enabled") is True
        assert "crown jewels" in (rules.get("yaml_text") or "")
        # Carries its own recorded time so the agents side can drop a rule set
        # edited after the split, the same way it drops a late statement.
        assert rules.get("updated_at")

    async def test_a_context_block_is_sent_even_with_no_skills(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """The ordinary replay path is the one that was running bare."""
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        await job_module.run_evaluation(_session(), _request())

        assert "context" in sent
        assert sent["context"].get("skills") == []

    async def test_a_context_read_that_fails_does_not_fail_the_replay(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """Fail-soft, and say so in the method note rather than silently.

        A replay that dies because institutional memory was briefly
        unreadable is worse than one that runs with less context and records
        which part it could not read.
        """
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        class _Broken(_ContextSession):
            async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
                if "aisoc_context_statements" in str(statement):
                    raise RuntimeError("relation does not exist")
                return await super().execute(statement, *args, **kwargs)

        session = _Broken(statements=[], priors=[], rule_set=None)
        await job_module.run_evaluation(session, _request())

        assert recording_store.failure is None, recording_store.failure
        assert recording_store.result is not None
        unread = (recording_store.result.get("method") or {}).get("frozen_context_unread") or []
        assert "statements" in unread

    async def test_a_failed_read_is_confined_to_a_savepoint(
        self, monkeypatch: pytest.MonkeyPatch, recording_store: _RecordingStore, no_vault: None
    ) -> None:
        """Catching the exception is not enough on PostgreSQL.

        A failed statement aborts the **whole** transaction and the engine
        refuses everything after it with `current transaction is aborted,
        commands ignored until end of transaction block` -- so a plain
        try/except around a context read does not isolate the failure, it
        poisons the write that stores the report. The replay then scores
        correctly and dies on its own `UPDATE`, which reads as a storage
        bug rather than as a missing table.

        That is not hypothetical: it is what the live four-service replay
        job reported before this was confined, while every offline test
        passed, because a stub session has no transaction to poison.
        """
        sent: dict[str, Any] = {}
        _capture_replay_payload(monkeypatch, sent)

        class _Broken(_ContextSession):
            async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
                if "aisoc_institutional_memory" in str(statement):
                    raise RuntimeError("relation does not exist")
                return await super().execute(statement, *args, **kwargs)

        session = _Broken(statements=[], priors=[], rule_set=None)
        await job_module.run_evaluation(session, _request())

        assert session.savepoints >= 3, "each optional read must take its own savepoint"
        assert session.savepoint_rollbacks == 1, "only the failed read should have rolled back"
        assert recording_store.failure is None, recording_store.failure
