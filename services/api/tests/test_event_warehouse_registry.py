"""Tests for the event-warehouse provider registry — Phase 4.5.

The registry is the routing layer between the hunt scheduler and the
per-warehouse drivers. These tests pin the contract the scheduler
relies on:

* Elasticsearch is the default provider — any hunt carrying ``esql``
  goes there.
* The chain is walked in priority order; an ES-only hunt is never
  handed to Splunk just because Splunk happens to be registered.
* Hunts with no recognised translation raise
  :class:`UnsupportedTranslation` so the scheduler skips them rather
  than spamming a hard failure.
* ``register_provider`` lets a downstream / test add a custom driver
  without forking the registry module.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from app.services.event_warehouse import (
    EventWarehouseProvider,
    UnsupportedTranslation,
    available_providers,
    register_provider,
    resolve_provider,
)
from app.services.event_warehouse.registry import SUPPORTED_PROVIDERS


def _make_hunt(translated: Any = None, override: str | None = None) -> Any:
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.translated_query = translated
    if override is None:
        del hunt.warehouse_provider
    else:
        hunt.warehouse_provider = override
    return hunt


class FakeProvider:
    """Standalone provider for register_provider tests."""

    name = "fake-warehouse"
    translated_query_key = "fake_dsl"

    async def run_hunt(self, hunt: Any, *, max_rows: int = 500) -> int:
        return 0


class TestDefaults:
    """Built-in providers are the ones the scheduler ships with today."""

    def test_elasticsearch_is_first(self) -> None:
        # The priority order matters: we want ES picked when both ES
        # and another translation are present.
        assert available_providers()[0] == "elasticsearch"

    def test_available_providers_contains_scaffolded_drivers(self) -> None:
        names = available_providers()
        assert {"elasticsearch", "splunk", "chronicle"}.issubset(set(names))


class TestResolveProvider:
    def test_picks_elasticsearch_when_esql_present(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = resolve_provider(hunt)
        assert provider.name == "elasticsearch"

    def test_picks_first_match_when_multiple_translations(self) -> None:
        """ES wins over SPL when both are present (priority order)."""
        hunt = _make_hunt(translated={"esql": "FROM logs", "spl": "index=foo"})
        provider = resolve_provider(hunt)
        assert provider.name == "elasticsearch"

    def test_skips_to_next_when_first_provider_key_is_empty(self) -> None:
        """Empty ES string but present SPL → Splunk picked."""
        hunt = _make_hunt(translated={"esql": "", "spl": "index=foo"})
        provider = resolve_provider(hunt)
        assert provider.name == "splunk"

    def test_raises_when_no_translation_recognised(self) -> None:
        """A hunt with only an unknown DSL key has no provider."""
        hunt = _make_hunt(translated={"unknown_dsl": "SELECT *"})
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt)

    def test_raises_when_translated_query_is_not_a_dict(self) -> None:
        hunt = _make_hunt(translated="raw string")  # type: ignore[arg-type]
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt)

    def test_raises_when_translated_query_is_none(self) -> None:
        hunt = _make_hunt(translated=None)
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt)

    def test_per_hunt_override_pins_named_provider(self) -> None:
        """``hunt.warehouse_provider`` overrides priority order entirely."""
        hunt = _make_hunt(translated={"esql": "FROM logs"}, override="splunk")
        provider = resolve_provider(hunt)
        assert provider.name == "splunk"

    def test_unknown_override_raises_unsupported(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"}, override="not-a-provider")
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt)


class TestRegisterProvider:
    """A custom provider can be added without forking the registry module."""

    @pytest.fixture(autouse=True)
    def _clean_registry(self) -> Any:
        original = list(SUPPORTED_PROVIDERS)
        yield
        SUPPORTED_PROVIDERS.clear()
        SUPPORTED_PROVIDERS.extend(original)

    def test_register_provider_appends_to_chain(self) -> None:
        register_provider(FakeProvider())
        assert "fake-warehouse" in available_providers()

    def test_registered_provider_is_picked_up_by_resolve(self) -> None:
        register_provider(FakeProvider())
        hunt = _make_hunt(translated={"fake_dsl": "RUN this"})
        provider = resolve_provider(hunt)
        assert provider.name == "fake-warehouse"

    def test_registered_providers_respect_protocol(self) -> None:
        fake = FakeProvider()
        assert isinstance(fake, EventWarehouseProvider)
