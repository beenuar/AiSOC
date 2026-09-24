"""Unit tests for ``app.workers.hunt_scheduler._execute_hunt``.

The worker routes execution through the :mod:`app.services.event_warehouse`
provider registry: it asks which warehouses the hunt's tenant has
connected, picks a provider, resolves that tenant's vault-encrypted
credentials, and hands both to the driver.

The behavioural contracts locked in here:

#. Hunt has no provider-recognisable translation → quiet skip, ``0``.
#. Tenant has connected no warehouse → quiet skip, ``0``.
#. Credentials missing or undecryptable → quiet skip, ``0``.
#. Happy path → returns the provider's hit count, and the driver is
   handed the tenant's credentials.
#. Transport / air-gap / value errors → propagated so ``run_once``
   skips the ``last_run_at`` bump and retries on the next sweep.
#. A failed *connector lookup* propagates rather than reporting zero,
   because "we could not read your connectors" is not "your hunt found
   nothing".

Regression note
~~~~~~~~~~~~~~~

``test_passes_tenant_credentials_to_provider`` and
``test_looks_up_connectors_for_the_hunts_tenant`` are the cases the previous
implementation could not satisfy. ``_execute_hunt`` ignored its ``db``
argument entirely (``_ = db  # unused``) and the providers read
``settings.ES_URL`` / ``SPLUNK_URL``, which are not declared fields on
``Settings`` — so no tenant's stored credentials ever reached a driver and
every scheduled hunt returned zero hits.
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
    WarehouseCredentials,
)
from app.workers import hunt_scheduler


def _make_hunt(translated: Any = None, tenant_id: uuid.UUID | None = None) -> Any:
    """Return a stand-in for :class:`app.models.saved_hunt.SavedHunt`."""
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.tenant_id = tenant_id or uuid.uuid4()
    hunt.translated_query = translated
    # `getattr(hunt, 'warehouse_provider', None)` must return None so
    # the registry doesn't think this hunt has an override.
    del hunt.warehouse_provider
    return hunt


@pytest.fixture
def fake_db() -> Any:
    return MagicMock()


def _credentials(connector_type: str = "elastic") -> WarehouseCredentials:
    return WarehouseCredentials(
        connector_id=uuid.uuid4(),
        connector_type=connector_type,
        connector_name="prod cluster",
        auth={"base_url": "https://es.example.com:9200", "api_key": "k"},
        config={},
    )


def _stub_provider(name: str = "elasticsearch", *, run: AsyncMock | None = None) -> Any:
    """Build a provider double the registry can return."""
    provider = MagicMock()
    provider.name = name
    provider.translated_query_key = "esql"
    provider.connector_types = ("elastic",)
    provider.run_hunt = run or AsyncMock(return_value=0)
    return provider


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider: Any = None,
    connected: set[str] | None = None,
    credentials: Any = None,
    resolve_error: Exception | None = None,
    connected_error: Exception | None = None,
) -> dict[str, Any]:
    """Patch the three collaborators ``_execute_hunt`` calls.

    Returns the mocks so a test can assert on the arguments they received.
    """
    connected_mock = AsyncMock(
        return_value=connected if connected is not None else {"elastic"},
        side_effect=connected_error,
    )
    monkeypatch.setattr(hunt_scheduler, "connected_warehouse_types", connected_mock)

    if resolve_error is not None:
        resolve_mock = MagicMock(side_effect=resolve_error)
    else:
        resolve_mock = MagicMock(return_value=provider or _stub_provider())
    monkeypatch.setattr(hunt_scheduler, "resolve_provider", resolve_mock)

    creds_mock = AsyncMock(return_value=credentials if credentials is not None else _credentials())
    if isinstance(credentials, Exception):
        creds_mock = AsyncMock(side_effect=credentials)
    monkeypatch.setattr(hunt_scheduler, "resolve_tenant_warehouse", creds_mock)

    return {"connected": connected_mock, "resolve": resolve_mock, "credentials": creds_mock}


class TestExecuteHuntSkipPaths:
    """Branches where the worker logs and returns ``0`` instead of raising."""

    async def test_skips_when_no_translated_query(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated=None)
        provider = _stub_provider(run=AsyncMock(side_effect=AssertionError("provider should not be called")))
        _wire(monkeypatch, provider=provider, resolve_error=UnsupportedTranslation("no provider for hunt"))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        provider.run_hunt.assert_not_called()

    async def test_skips_when_translated_query_missing_esql_key(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """``translated_query`` may exist but carry only a dialect no connected
        warehouse speaks — that's a skip."""
        hunt = _make_hunt(translated={"kql": "event.code:4625"})
        _wire(monkeypatch, resolve_error=UnsupportedTranslation("no live driver for kql"))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0

    async def test_skips_when_translated_query_is_not_a_dict(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Defensive: a malformed row shouldn't crash the sweep."""
        hunt = _make_hunt(translated="just a string somehow")  # type: ignore[arg-type]
        _wire(monkeypatch, resolve_error=UnsupportedTranslation("hunt has no translated_query dict"))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0

    async def test_skips_when_tenant_has_connected_no_warehouse(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """A tenant who never connected a SIEM is a soft skip, not an error."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(
            monkeypatch,
            connected=set(),
            resolve_error=UnsupportedTranslation("no enabled connector of type ['elastic', 'splunk']"),
        )

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0

    async def test_skips_when_credentials_cannot_be_resolved(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Connector row exists but its secret will not decrypt → soft skip."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=AssertionError("provider should not be called")))
        _wire(
            monkeypatch,
            provider=provider,
            credentials=HuntNotConfigured("stored credentials could not be decrypted"),
        )

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        provider.run_hunt.assert_not_called()

    async def test_skips_when_provider_reports_not_configured(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Connector saved without a URL → :class:`HuntNotConfigured` → soft skip."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = _stub_provider(run=AsyncMock(side_effect=HuntNotConfigured("connector has no cluster URL")))
        _wire(monkeypatch, provider=provider)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0
        provider.run_hunt.assert_awaited_once()


class TestExecuteHuntTenantScoping:
    """The credentials a driver receives belong to the hunt's own tenant."""

    async def test_looks_up_connectors_for_the_hunts_tenant(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        tenant_id = uuid.uuid4()
        hunt = _make_hunt(translated={"esql": "FROM logs"}, tenant_id=tenant_id)
        mocks = _wire(monkeypatch, provider=_stub_provider(run=AsyncMock(return_value=1)))

        await hunt_scheduler._execute_hunt(fake_db, hunt)

        args, kwargs = mocks["connected"].await_args
        assert args[0] is fake_db
        assert args[1] == tenant_id
        assert set(kwargs["candidate_types"]) == {"elastic", "splunk"}

    async def test_passes_tenant_credentials_to_provider(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """The regression: ``_execute_hunt`` used to ignore ``db`` entirely and
        the drivers read process settings, so no stored credential ever
        reached a warehouse."""
        tenant_id = uuid.uuid4()
        hunt = _make_hunt(translated={"esql": "FROM logs"}, tenant_id=tenant_id)
        creds = _credentials()
        run = AsyncMock(return_value=7)
        mocks = _wire(monkeypatch, provider=_stub_provider(run=run), credentials=creds)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 7
        run.assert_awaited_once_with(hunt, credentials=creds, max_rows=500)
        args, kwargs = mocks["credentials"].await_args
        assert args[1] == tenant_id
        assert kwargs["connector_types"] == ("elastic",)

    async def test_selection_is_scoped_by_what_the_tenant_connected(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs", "spl": "index=foo"})
        mocks = _wire(monkeypatch, connected={"splunk"})

        await hunt_scheduler._execute_hunt(fake_db, hunt)

        _, kwargs = mocks["resolve"].call_args
        assert kwargs["connected_types"] == {"splunk"}


class TestExecuteHuntHappyPath:
    """When everything is wired up, return the hit count the provider produced."""

    async def test_returns_provider_hit_count(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs | WHERE event.code == 4625"})
        provider = _stub_provider(run=AsyncMock(return_value=3))
        _wire(monkeypatch, provider=provider)

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 3

    async def test_returns_zero_when_provider_returns_empty(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(monkeypatch, provider=_stub_provider(run=AsyncMock(return_value=0)))

        hits = await hunt_scheduler._execute_hunt(fake_db, hunt)

        assert hits == 0


class TestExecuteHuntErrorPropagation:
    """Errors the scheduler cannot recover from on its own must propagate."""

    async def test_airgap_violation_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(monkeypatch, provider=_stub_provider(run=AsyncMock(side_effect=AirgapViolation("egress blocked"))))

        with pytest.raises(AirgapViolation):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_value_error_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSRF guard mismatch surfaces as ``ValueError`` — must bubble up."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(monkeypatch, provider=_stub_provider(run=AsyncMock(side_effect=ValueError("host mismatch"))))

        with pytest.raises(ValueError, match="host mismatch"):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_hunt_execution_error_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(monkeypatch, provider=_stub_provider(run=AsyncMock(side_effect=HuntExecutionError("ES 500"))))

        with pytest.raises(HuntExecutionError):
            await hunt_scheduler._execute_hunt(fake_db, hunt)

    async def test_connector_lookup_failure_propagates(self, fake_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """A database error reading connectors must not be reported as zero hits."""
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        _wire(monkeypatch, connected_error=RuntimeError("connection pool exhausted"))

        with pytest.raises(RuntimeError, match="connection pool exhausted"):
            await hunt_scheduler._execute_hunt(fake_db, hunt)
