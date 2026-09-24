"""Tests for the event-warehouse provider registry.

The registry is the routing layer between the hunt scheduler and the
per-warehouse drivers. These tests pin the contract the scheduler relies
on:

* Selection is driven by what the tenant *connected*, then by what the
  hunt was translated into — not by registry order alone.
* The chain is walked in priority order only to break ties when a tenant
  has connected more than one warehouse.
* Hunts with no recognised translation, and tenants with no connected
  warehouse, both raise :class:`UnsupportedTranslation` so the scheduler
  skips them rather than spamming a hard failure — but with messages that
  say which of the two happened.
* ``register_provider`` lets a downstream / test add a custom driver
  without forking the registry module.

Regression note
~~~~~~~~~~~~~~~

``test_splunk_only_tenant_is_not_routed_to_elasticsearch`` is the case the
previous implementation got wrong. ``resolve_provider`` used to return the
first provider whose ``translated_query_key`` appeared in the hunt, and the
natural-language translator emits ES|QL, SPL *and* KQL for every question.
``esql`` was therefore always present and Elasticsearch was always chosen,
including for tenants who run only Splunk.
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
    candidate_connector_types,
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
    connector_types = ("fake_connector",)

    async def run_hunt(self, hunt: Any, *, credentials: Any, max_rows: int = 500) -> int:
        return 0


class TestDefaults:
    """Built-in providers are the ones the scheduler ships with today."""

    def test_elasticsearch_is_first(self) -> None:
        # Priority order only breaks ties between warehouses a tenant has
        # both connected.
        assert available_providers()[0] == "elasticsearch"

    def test_registry_ships_two_live_drivers(self) -> None:
        assert set(available_providers()) == {"elasticsearch", "splunk"}

    def test_chronicle_scaffold_is_gone(self) -> None:
        """It read a ``udm`` translation nothing emits, gated on settings that
        were never fields, and reported itself as a supported warehouse."""
        assert "chronicle" not in available_providers()

    def test_candidate_connector_types_covers_every_driver(self) -> None:
        assert set(candidate_connector_types()) == {"elastic", "splunk"}


class TestResolveProvider:
    def test_picks_elasticsearch_when_tenant_has_elastic(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"})
        provider = resolve_provider(hunt, connected_types={"elastic"})
        assert provider.name == "elasticsearch"

    def test_splunk_only_tenant_is_not_routed_to_elasticsearch(self) -> None:
        """The regression. The translator emits every dialect, so a Splunk-only
        tenant used to be handed to the Elasticsearch driver and skipped."""
        hunt = _make_hunt(translated={"esql": "FROM logs", "spl": "index=foo"})
        provider = resolve_provider(hunt, connected_types={"splunk"})
        assert provider.name == "splunk"

    def test_priority_breaks_ties_when_both_connected(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs", "spl": "index=foo"})
        provider = resolve_provider(hunt, connected_types={"elastic", "splunk"})
        assert provider.name == "elasticsearch"

    def test_skips_to_next_when_first_provider_key_is_empty(self) -> None:
        """Empty ES string but present SPL → Splunk picked."""
        hunt = _make_hunt(translated={"esql": "", "spl": "index=foo"})
        provider = resolve_provider(hunt, connected_types={"elastic", "splunk"})
        assert provider.name == "splunk"

    def test_raises_when_tenant_has_connected_nothing(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs", "spl": "index=foo"})
        with pytest.raises(UnsupportedTranslation) as excinfo:
            resolve_provider(hunt, connected_types=set())
        # The message has to distinguish this from "never translated", because
        # the scheduler turns both into a soft skip.
        assert "no enabled connector" in str(excinfo.value)

    def test_raises_when_no_translation_recognised(self) -> None:
        """A hunt with only an unknown DSL key has no provider."""
        hunt = _make_hunt(translated={"unknown_dsl": "SELECT *"})
        with pytest.raises(UnsupportedTranslation) as excinfo:
            resolve_provider(hunt, connected_types={"elastic"})
        assert "no translated query" in str(excinfo.value)

    def test_raises_when_translated_query_is_not_a_dict(self) -> None:
        hunt = _make_hunt(translated="raw string")  # type: ignore[arg-type]
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt, connected_types={"elastic"})

    def test_raises_when_translated_query_is_none(self) -> None:
        hunt = _make_hunt(translated=None)
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt, connected_types={"elastic"})

    def test_per_hunt_override_pins_named_provider(self) -> None:
        """``hunt.warehouse_provider`` overrides priority order entirely."""
        hunt = _make_hunt(translated={"esql": "FROM logs"}, override="splunk")
        provider = resolve_provider(hunt, connected_types={"elastic"})
        assert provider.name == "splunk"

    def test_unknown_override_raises_unsupported(self) -> None:
        hunt = _make_hunt(translated={"esql": "FROM logs"}, override="not-a-provider")
        with pytest.raises(UnsupportedTranslation):
            resolve_provider(hunt, connected_types={"elastic"})


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
        provider = resolve_provider(hunt, connected_types={"fake_connector"})
        assert provider.name == "fake-warehouse"

    def test_registered_provider_widens_candidate_types(self) -> None:
        register_provider(FakeProvider())
        assert "fake_connector" in candidate_connector_types()

    def test_registered_providers_respect_protocol(self) -> None:
        fake = FakeProvider()
        assert isinstance(fake, EventWarehouseProvider)
