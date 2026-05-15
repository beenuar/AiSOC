"""Unit tests for ``app.workers.hunt_scheduler._execute_hunt`` — Track 3, T3.4.

We isolate ``_execute_hunt`` from Elasticsearch, the database session, and the
``SavedHunt`` ORM by:

* Faking the hunt object with a minimal attribute bag — only ``id`` and
  ``translated_query`` are read.
* Monkeypatching the two collaborators imported at module scope into the
  worker — ``resolve_es_credentials`` and ``run_esql_query`` — so we can drive
  every branch from pure-Python doubles.

Why test it this way? The scheduler's value comes from how it *composes*
those collaborators (skip cleanly when nothing is configured, surface real
errors so ``run_once`` can retry, return the row count on success). Wiring up
a real ``AsyncSession`` would test ``AsyncSession`` — not the composition.

The four branches we lock in:

#. Hunt missing translated ES|QL → quiet skip, returns ``0``.
#. ES creds missing → quiet skip, returns ``0``.
#. Happy path → returns ``len(rows)``.
#. Transport / air-gap / value errors → propagated so ``run_once`` skips
   ``last_run_at`` bump and retries on the next sweep.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.airgap import AirgapViolation
from app.services.esql_runner import ESQLExecutionError, ESQLNotConfigured, ESQLResult
from app.workers import hunt_scheduler


def _make_hunt(translated: Any = None) -> Any:
    """Return a stand-in for :class:`app.models.saved_hunt.SavedHunt`.

    Only the two attributes ``_execute_hunt`` actually touches need to be
    populated. We use a ``MagicMock`` rather than the SQLAlchemy model so the
    test file doesn't pull in a live DB engine.
    """
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.translated_query = translated
    return hunt


@pytest.fixture
def fake_db() -> Any:
    """A throw-away DB session — ``_execute_hunt`` doesn't touch it today."""
    return MagicMock()


class TestExecuteHuntSkipPaths:
    """Branches where the worker logs and returns ``0`` instead of raising.

    Both are *expected* in production:

    * A NL hunt saved as a draft has no translated ES|QL yet — re-translating
      is the API endpoint's job, not the scheduler's.
    * Self-hosted dev installs frequently run the API without ES wired up; we
      want the scheduler to keep running quietly, not spam ``exception``.
    """

    async def test_skips_when_no_translated_query(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated=None)
        # If we reach the runner we've failed — pin a tripwire.
        called = AsyncMock(side_effect=AssertionError("runner should not be called"))
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", called)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        called.assert_not_called()

    async def test_skips_when_translated_query_missing_esql_key(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``translated_query`` may exist but carry only KQL/SPL — that's a skip."""
        hunt = _make_hunt(translated={"kql": "event.code:4625", "spl": "index=foo"})
        called = AsyncMock(side_effect=AssertionError("runner should not be called"))
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", called)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        called.assert_not_called()

    async def test_skips_when_translated_query_is_not_a_dict(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defensive: a malformed row shouldn't crash the sweep."""
        hunt = _make_hunt(translated="just a string somehow")  # type: ignore[arg-type]
        called = AsyncMock(side_effect=AssertionError("runner should not be called"))
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", called)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        called.assert_not_called()

    async def test_skips_when_es_credentials_not_configured(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(side_effect=ESQLNotConfigured("no ES_URL")),
        )
        called = AsyncMock(side_effect=AssertionError("runner should not be called"))
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", called)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        called.assert_not_called()


class TestExecuteHuntHappyPath:
    """When everything is wired up, return the row count the runner produced."""

    async def test_returns_row_count_from_runner(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs | WHERE event.code == 4625"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(return_value=("http://es.local:9200", "test-key")),
        )
        runner = AsyncMock(
            return_value=ESQLResult(
                columns=["@timestamp", "event.code"],
                rows=[
                    ["2026-05-15T00:00:00Z", 4625],
                    ["2026-05-15T00:01:00Z", 4625],
                    ["2026-05-15T00:02:00Z", 4625],
                ],
                took_ms=42,
            )
        )
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", runner)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 3
        runner.assert_awaited_once()
        # Validate that the runner sees the ES|QL we stored, not a re-translation.
        call_kwargs = runner.await_args.kwargs
        assert call_kwargs["esql"] == "FROM logs | WHERE event.code == 4625"
        assert call_kwargs["es_url"] == "http://es.local:9200"
        assert call_kwargs["es_api_key"] == "test-key"

    async def test_returns_zero_when_runner_returns_empty(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(return_value=("http://es.local:9200", "test-key")),
        )
        runner = AsyncMock(
            return_value=ESQLResult(columns=[], rows=[], took_ms=5)
        )
        monkeypatch.setattr(hunt_scheduler, "run_esql_query", runner)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0


class TestExecuteHuntErrorPropagation:
    """Errors the scheduler *cannot recover from on its own* must propagate.

    ``run_once`` catches the exception, logs it, and skips the
    ``last_run_at`` bump so the hunt retries on the next tick. If we
    swallowed errors here we would silently mark broken hunts as "ran" and
    they would never retry.
    """

    async def test_airgap_violation_propagates(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(return_value=("http://es.local:9200", "test-key")),
        )
        monkeypatch.setattr(
            hunt_scheduler,
            "run_esql_query",
            AsyncMock(side_effect=AirgapViolation("egress blocked")),
        )

        with pytest.raises(AirgapViolation):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_value_error_propagates(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSRF guard mismatch surfaces as ``ValueError`` — must bubble up."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(return_value=("http://es.local:9200", "test-key")),
        )
        monkeypatch.setattr(
            hunt_scheduler,
            "run_esql_query",
            AsyncMock(side_effect=ValueError("host mismatch")),
        )

        with pytest.raises(ValueError, match="host mismatch"):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_esql_execution_error_propagates(
        self, fake_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_es_credentials",
            MagicMock(return_value=("http://es.local:9200", "test-key")),
        )
        monkeypatch.setattr(
            hunt_scheduler,
            "run_esql_query",
            AsyncMock(side_effect=ESQLExecutionError("ES 500")),
        )

        with pytest.raises(ESQLExecutionError):
            await hunt_scheduler._execute_hunt(fake_db, hunt)
