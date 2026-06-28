"""Unit tests for ``app.workers.hunt_scheduler._execute_hunt`` — Track 3, T3.4.

Phase 4.5 update: the worker now routes execution through the
:mod:`app.services.event_warehouse` provider registry instead of
calling :func:`run_esql_query` directly. These tests therefore exercise
the *new* composition surface — the scheduler picks a provider, the
provider raises/returns, the scheduler responds.

The four behavioural contracts we lock in are unchanged from before:

#. Hunt has no provider-recognisable translation → quiet skip, ``0``.
#. Provider raises :class:`HuntNotConfigured` → quiet skip, ``0``.
#. Happy path → returns the provider's hit count.
#. Transport / air-gap / value errors → propagated so ``run_once``
   skips the ``last_run_at`` bump and retries on the next sweep.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.core.airgap import AirgapViolation
from app.services.event_warehouse import (
    HuntExecutionError,
    HuntNotConfigured,
    UnsupportedTranslation,
)
from app.workers import hunt_scheduler


def _make_hunt(translated: Any = None) -> Any:
    """Return a stand-in for :class:`app.models.saved_hunt.SavedHunt`."""
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.translated_query = translated
    # `getattr(hunt, 'warehouse_provider', None)` must return None so
    # the registry doesn't think this hunt has an override.
    del hunt.warehouse_provider
    return hunt


@pytest.fixture
def fake_db() -> Any:
    """A throw-away DB session — ``_execute_hunt`` doesn't touch it today."""
    return MagicMock()


def _stub_provider(name: str = "elasticsearch", *, run: AsyncMock | None = None) -> Any:
    """Build a provider double the registry can return."""
    provider = MagicMock()
    provider.name = name
    provider.translated_query_key = "esql"
    provider.run_hunt = run or AsyncMock(return_value=0)
    return provider


class TestExecuteHuntSkipPaths:
    """Branches where the worker logs and returns ``0`` instead of raising."""

    async def test_skips_when_no_translated_query(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated=None)
        # If we reach a provider we've failed — pin a tripwire.
        provider = _stub_provider(run=AsyncMock(side_effect=AssertionError("provider should not be called")))
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_provider",
            MagicMock(side_effect=UnsupportedTranslation("no provider for hunt")),
        )

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        provider.run_hunt.assert_not_called()

    async def test_skips_when_translated_query_missing_esql_key(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """``translated_query`` may exist but carry only KQL/SPL — that's a skip."""
        hunt = _make_hunt(translated={"kql": "event.code:4625", "spl": "index=foo"})
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_provider",
            MagicMock(side_effect=UnsupportedTranslation("no live driver for kql/spl")),
        )

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0

    async def test_skips_when_translated_query_is_not_a_dict(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Defensive: a malformed row shouldn't crash the sweep."""
        hunt = _make_hunt(translated="just a string somehow")  # type: ignore[arg-type]
        monkeypatch.setattr(
            hunt_scheduler,
            "resolve_provider",
            MagicMock(side_effect=UnsupportedTranslation("hunt has no translated_query dict")),
        )

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0

    async def test_skips_when_provider_reports_not_configured(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """ES creds missing → :class:`HuntNotConfigured` → soft skip."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=HuntNotConfigured("no ES_URL")))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        provider.run_hunt.assert_awaited_once()


class TestExecuteHuntHappyPath:
    """When everything is wired up, return the hit count the provider produced."""

    async def test_returns_provider_hit_count(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs | WHERE event.code == 4625"})
        provider = _stub_provider(run=AsyncMock(return_value=3))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 3
        provider.run_hunt.assert_awaited_once_with(hunt, max_rows=500)

    async def test_returns_zero_when_provider_returns_empty(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(return_value=0))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0


class TestExecuteHuntErrorPropagation:
    """Errors the scheduler cannot recover from on its own must propagate."""

    async def test_airgap_violation_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=AirgapViolation("egress blocked")))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        with pytest.raises(AirgapViolation):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_value_error_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSRF guard mismatch surfaces as ``ValueError`` — must bubble up."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=ValueError("host mismatch")))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        with pytest.raises(ValueError, match="host mismatch"):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_hunt_execution_error_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=HuntExecutionError("ES 500")))
        monkeypatch.setattr(hunt_scheduler, "resolve_provider", MagicMock(return_value=provider))

        with pytest.raises(HuntExecutionError):
            await hunt_scheduler._execute_hunt(fake_db, hunt)
