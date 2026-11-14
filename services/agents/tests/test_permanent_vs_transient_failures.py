"""Two loops that reported a permanent condition as a transient one.

Both are the same mistake with different blast radius, and the repository
already has the rule: a retry loop must be able to tell a condition that
will never resolve from one that might, and say which.

* `/contextual/action/stream` answered **"Streaming failed. Please try
  again."** to every failure, including the commonest one — this deployment
  has no model, so there is nothing a retry can reach. Advising a retry for
  a permanent condition is how a misconfiguration gets mistaken for
  flakiness.
* The hunt scheduler re-dialled ClickHouse on every 60-second tick on the
  CORE profile, where ClickHouse legitimately does not exist. Each attempt
  printed twelve lines of Python stack from `clickhouse_driver`'s own
  connect path plus a one-line warning, forever.
"""

from __future__ import annotations

import json

import pytest
from app.api import contextual
from app.hunt import scheduler


def _frames(chunks: list[bytes]) -> list[dict]:
    out: list[dict] = []
    for chunk in chunks:
        for line in chunk.decode().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


async def _drain(response) -> list[dict]:
    chunks = [chunk async for chunk in response.body_iterator]
    return _frames([c if isinstance(c, bytes) else c.encode() for c in chunks])


class TestTheStreamSaysWhetherARetryCanWork:
    @pytest.mark.asyncio
    async def test_no_model_configured_is_reported_as_permanent(self, monkeypatch):
        """Fails pre-fix: every failure answered "Please try again"."""

        async def _boom(*_a, **_kw):
            raise RuntimeError("no provider")
            yield  # pragma: no cover - makes this an async generator

        monkeypatch.setattr(contextual, "_stream_llm", _boom)
        monkeypatch.setattr(contextual, "resolve_api_key", lambda _m: "")

        req = contextual.ContextualActionRequest(page="alerts", action="explain", entity_id="a1")
        frames = await _drain(await contextual.run_action_stream(req))

        error = next(f for f in frames if "error" in f)
        assert error["retryable"] is False
        assert "try again" not in error["error"].lower()
        assert "retrying will not help" in error["error"].lower()

    @pytest.mark.asyncio
    async def test_a_model_that_broke_mid_answer_is_reported_as_retryable(self, monkeypatch):
        async def _boom(*_a, **_kw):
            raise RuntimeError("connection reset")
            yield  # pragma: no cover

        monkeypatch.setattr(contextual, "_stream_llm", _boom)
        monkeypatch.setattr(contextual, "resolve_api_key", lambda _m: "sk-present")

        req = contextual.ContextualActionRequest(page="alerts", action="explain", entity_id="a1")
        frames = await _drain(await contextual.run_action_stream(req))

        error = next(f for f in frames if "error" in f)
        assert error["retryable"] is True
        assert "retrying may work" in error["error"].lower()
        # And it does not hand the caller the exception text. An exception
        # string from a model client carries gateway hostnames and request
        # ids; the stack belongs in the service log, which has it.
        assert "connection reset" not in error["error"]


class TestTheSchedulerStopsRedialingALakeThatIsNotThere:
    @pytest.fixture(autouse=True)
    def _fresh_backoff(self, monkeypatch):
        monkeypatch.setattr(scheduler, "_lake_backoff", scheduler._LakeBackoff())

    def test_a_failure_opens_a_window_in_which_no_call_is_made(self, monkeypatch):
        """Fails pre-fix: every tick called through and the driver logged a stack."""
        calls = {"n": 0}

        def _unreachable(_tenant):
            calls["n"] += 1
            raise OSError("Connection refused to clickhouse:9000")

        monkeypatch.setattr("app.hunt.lake_source.fetch_recent_events", _unreachable)
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "lake")

        for _ in range(10):
            assert scheduler._load_telemetry("tenant-1") == []

        assert calls["n"] == 1, f"dialled an unreachable lake {calls['n']} times across 10 ticks"

    def test_the_window_grows_and_is_capped(self):
        backoff = scheduler._LakeBackoff()
        waits = [backoff.record_failure() for _ in range(12)]
        assert waits[0] == backoff.MIN_SECONDS
        assert waits[1] == backoff.MIN_SECONDS * 2
        assert max(waits) == backoff.MAX_SECONDS
        assert waits[-1] == backoff.MAX_SECONDS

    def test_only_the_first_failure_is_loud(self):
        backoff = scheduler._LakeBackoff()
        backoff.record_failure()
        assert backoff.first_failure is True
        backoff.record_failure()
        assert backoff.first_failure is False

    def test_recovery_clears_the_window(self, monkeypatch):
        """A lake that comes back is read again, and the recovery is announced.

        Without this, a window that only ever grows turns a slow start into
        a silent outage — and leaves the log claiming an outage that ended.
        """
        state = {"fail": True}

        def _flaky(_tenant):
            if state["fail"]:
                raise OSError("Connection refused")
            return [{"host": "ws-1"}]

        monkeypatch.setattr("app.hunt.lake_source.fetch_recent_events", _flaky)
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "lake")

        assert scheduler._load_telemetry("tenant-1") == []
        assert scheduler._lake_backoff.suppressed() is True

        # The window elapses and the lake is back.
        state["fail"] = False
        scheduler._lake_backoff._next_attempt = 0.0
        assert scheduler._load_telemetry("tenant-1") == [{"host": "ws-1"}]
        assert scheduler._lake_backoff.suppressed() is False

    def test_an_unreachable_lake_never_substitutes_the_fixture_corpus(self, monkeypatch):
        """The standing rule, re-pinned because the backoff is a new branch.

        A hunt that quietly reports findings from synthetic telemetry is
        worse than one that reports nothing.
        """

        def _unreachable(_tenant):
            raise OSError("Connection refused")

        monkeypatch.setattr("app.hunt.lake_source.fetch_recent_events", _unreachable)
        monkeypatch.setenv("HUNT_TELEMETRY_PROVIDER", "lake")

        assert scheduler._load_telemetry("tenant-1") == []
        # And the suppressed tick is empty too, not a fixture read.
        assert scheduler._load_telemetry("tenant-1") == []
