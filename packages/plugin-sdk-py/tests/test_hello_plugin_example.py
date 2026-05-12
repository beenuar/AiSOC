"""Smoke test for the ``plugins/community/_examples/hello-plugin`` tutorial.

This test pins the contract that the hello-plugin tutorial documents in
``apps/docs/docs/plugins/hello-plugin.md``. If the tutorial drifts from
the reference implementation, this test will fail and force the docs to
be updated in lockstep.

It deliberately avoids importing the example as a Python module — the
tutorial loads it through ``load_plugin_from_directory`` exactly the way
the AiSOC plugin runtime would, which doubles as proof that the
manifest + entry-point shape on disk is loadable in production.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aisoc_plugin_sdk import (
    EnricherPlugin,
    EnrichmentRequest,
    PluginContext,
    PluginRegistry,
)
from aisoc_plugin_sdk.loader import load_plugin_from_directory

REPO_ROOT = Path(__file__).resolve().parents[3]
HELLO_PLUGIN_DIR = REPO_ROOT / "plugins" / "community" / "_examples" / "hello-plugin"


# ── Sanity: the example exists where the docs say it does ────────────────────


def test_hello_plugin_example_files_exist() -> None:
    """The tutorial points at concrete files; make sure they survive renames."""

    assert HELLO_PLUGIN_DIR.is_dir(), (
        f"Expected hello-plugin example at {HELLO_PLUGIN_DIR}. "
        "If this directory moved, update apps/docs/docs/plugins/hello-plugin.md."
    )
    assert (HELLO_PLUGIN_DIR / "aisoc-plugin.yaml").is_file()
    assert (HELLO_PLUGIN_DIR / "plugin.py").is_file()
    assert (HELLO_PLUGIN_DIR / "README.md").is_file()


def test_hello_plugin_is_excluded_from_marketplace() -> None:
    """Examples under ``_examples/`` must never ship in the marketplace.

    The marketplace builder (``scripts/build_marketplace.py``) discovers
    plugins by walking ``plugins/community/<id>/plugin.yaml``. The tutorial
    avoids both signals on purpose: it lives one directory deeper, and its
    manifest is named ``aisoc-plugin.yaml`` (the SDK loader filename), not
    ``plugin.yaml`` (the marketplace filename). If anyone "fixes" either
    of those, this test will catch it.
    """

    assert HELLO_PLUGIN_DIR.parent.name == "_examples", (
        "Tutorial example must stay under plugins/community/_examples/ so the "
        "marketplace builder ignores it."
    )
    assert not (HELLO_PLUGIN_DIR / "plugin.yaml").exists(), (
        "Tutorial example must NOT define a plugin.yaml — that would make "
        "scripts/build_marketplace.py index it and ship it to real tenants."
    )


# ── Loader contract ──────────────────────────────────────────────────────────


def test_hello_plugin_loads_via_loader() -> None:
    """Walks the same code path the runtime uses to load real plugins."""

    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)

    assert isinstance(plugin, EnricherPlugin)
    assert plugin.manifest.id == "aisoc.hello-plugin"
    assert plugin.manifest.plugin_type == "enricher"
    assert plugin.manifest.version == "1.0.0"
    assert "tutorial" in plugin.manifest.tags


# ── Lifecycle hook ───────────────────────────────────────────────────────────


@pytest.fixture
def ctx() -> PluginContext:
    return PluginContext(
        api_base_url="http://localhost:8000",
        api_token="test-token",
        config={},
    )


async def test_on_load_defaults_to_sha256(ctx: PluginContext) -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)

    await plugin.on_load(ctx)

    # The tutorial promises the default algorithm is sha256.
    assert getattr(plugin, "_algorithm") == "sha256"


async def test_on_load_accepts_configured_algorithm() -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    ctx = PluginContext(
        api_base_url="http://localhost:8000",
        api_token="test-token",
        config={"algorithm": "sha512"},
    )

    await plugin.on_load(ctx)

    assert getattr(plugin, "_algorithm") == "sha512"


async def test_on_load_rejects_unknown_algorithm() -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    ctx = PluginContext(
        api_base_url="http://localhost:8000",
        api_token="test-token",
        config={"algorithm": "definitely-not-a-real-hash"},
    )

    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        await plugin.on_load(ctx)


# ── Enrichment is deterministic ──────────────────────────────────────────────


async def test_enrich_is_deterministic(ctx: PluginContext) -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    await plugin.on_load(ctx)

    request = EnrichmentRequest(
        indicator_type="ip",
        indicator_value="203.0.113.42",
    )

    expected_digest = hashlib.sha256(b"203.0.113.42").hexdigest()

    result_a = await plugin.enrich(request, ctx)
    result_b = await plugin.enrich(request, ctx)

    assert result_a.indicator_value == "203.0.113.42"
    assert result_a.enrichments["hello_plugin.algorithm"] == "sha256"
    assert result_a.enrichments["hello_plugin.digest"] == expected_digest
    assert result_a.enrichments["hello_plugin.length"] == len(expected_digest)
    assert "hello-plugin" in result_a.tags
    assert result_a.malicious is None  # tutorial enricher has no opinion
    assert result_a.confidence is None
    # Same input must always yield the same enrichment — this is the
    # property the docs page leans on for snapshot examples.
    assert result_a.model_dump() == result_b.model_dump()


async def test_enrich_uses_configured_algorithm() -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    ctx = PluginContext(
        api_base_url="http://localhost:8000",
        api_token="test-token",
        config={"algorithm": "sha512"},
    )
    await plugin.on_load(ctx)

    request = EnrichmentRequest(indicator_type="domain", indicator_value="example.com")
    result = await plugin.enrich(request, ctx)

    assert result.enrichments["hello_plugin.algorithm"] == "sha512"
    assert result.enrichments["hello_plugin.digest"] == hashlib.sha512(
        b"example.com"
    ).hexdigest()


# ── Registry integration ─────────────────────────────────────────────────────


async def test_hello_plugin_registers_as_enricher(ctx: PluginContext) -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    registry = PluginRegistry()
    registry.register(plugin)

    await registry.load_all(ctx)

    assert len(registry) == 1
    enrichers = registry.enrichers()
    assert len(enrichers) == 1
    assert enrichers[0].manifest.id == "aisoc.hello-plugin"
    # Lookup by ID works the same way the runtime resolves enrichers.
    assert registry.get("aisoc.hello-plugin") is plugin
