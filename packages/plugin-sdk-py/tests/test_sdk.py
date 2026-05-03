"""Unit tests for the AiSOC Python plugin SDK."""

import pytest

from aisoc_plugin_sdk import (
    PluginManifest,
    PluginContext,
    EnricherPlugin,
    EnrichmentRequest,
    EnrichmentResult,
    ActionPlugin,
    ActionRequest,
    ActionResult,
    PluginRegistry,
    enricher,
    action,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx() -> PluginContext:
    return PluginContext(
        api_base_url="http://localhost:8000",
        api_token="test-token",
        config={},
    )


# ── Enricher tests ────────────────────────────────────────────────────────────

class MockEnricher(EnricherPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="test.mock-enricher",
            name="Mock Enricher",
            version="1.0.0",
            plugin_type="enricher",
        )

    async def enrich(self, request: EnrichmentRequest, ctx: PluginContext) -> EnrichmentResult:
        return EnrichmentResult(
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            enrichments={"source": "mock"},
            malicious=False,
        )


@pytest.mark.asyncio
async def test_enricher_basic(ctx: PluginContext) -> None:
    plugin = MockEnricher()
    req = EnrichmentRequest(indicator_type="ip", indicator_value="1.2.3.4")
    result = await plugin.enrich(req, ctx)
    assert result.indicator_value == "1.2.3.4"
    assert result.malicious is False
    assert result.enrichments["source"] == "mock"


def test_enricher_manifest() -> None:
    plugin = MockEnricher()
    assert plugin.manifest.plugin_type == "enricher"
    assert plugin.manifest.id == "test.mock-enricher"


# ── Action tests ──────────────────────────────────────────────────────────────

class MockAction(ActionPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="test.mock-action",
            name="Mock Action",
            version="1.0.0",
            plugin_type="action",
        )

    def supported_actions(self) -> list[str]:
        return ["mock_action"]

    async def execute(self, request: ActionRequest, ctx: PluginContext) -> ActionResult:
        if request.dry_run:
            return ActionResult(
                action_id=request.action_id,
                success=True,
                dry_run=True,
                summary="Would execute mock_action",
            )
        return ActionResult(
            action_id=request.action_id,
            success=True,
            summary="Executed mock_action",
            details={"params": request.params},
        )


@pytest.mark.asyncio
async def test_action_execute(ctx: PluginContext) -> None:
    plugin = MockAction()
    req = ActionRequest(action_id="mock_action", params={"target": "host1"})
    result = await plugin.execute(req, ctx)
    assert result.success
    assert not result.dry_run
    assert result.details["params"]["target"] == "host1"


@pytest.mark.asyncio
async def test_action_dry_run(ctx: PluginContext) -> None:
    plugin = MockAction()
    req = ActionRequest(action_id="mock_action", dry_run=True)
    result = await plugin.execute(req, ctx)
    assert result.dry_run
    assert "Would" in result.summary


# ── Registry tests ────────────────────────────────────────────────────────────

def test_registry_register_and_lookup() -> None:
    registry = PluginRegistry()
    enricher_plugin = MockEnricher()
    action_plugin = MockAction()

    registry.register(enricher_plugin)
    registry.register(action_plugin)

    assert len(registry) == 2
    assert len(registry.enrichers()) == 1
    assert len(registry.actions()) == 1
    assert registry.get("test.mock-enricher") is enricher_plugin


def test_registry_unregister() -> None:
    registry = PluginRegistry()
    registry.register(MockEnricher())
    registry.unregister("test.mock-enricher")
    assert len(registry) == 0


# ── Decorator tests ───────────────────────────────────────────────────────────

@enricher(id="test.fn-enricher", name="Function Enricher")
async def fn_enricher(request: EnrichmentRequest, ctx: PluginContext) -> EnrichmentResult:
    return EnrichmentResult(
        indicator_type=request.indicator_type,
        indicator_value=request.indicator_value,
        enrichments={"fn": True},
    )


@pytest.mark.asyncio
async def test_enricher_decorator(ctx: PluginContext) -> None:
    plugin = fn_enricher()
    assert plugin.manifest.id == "test.fn-enricher"
    req = EnrichmentRequest(indicator_type="domain", indicator_value="evil.com")
    result = await plugin.enrich(req, ctx)
    assert result.enrichments["fn"] is True


@action(id="test.fn-action", name="Function Action", actions=["fn_action"])
async def fn_action(request: ActionRequest, ctx: PluginContext) -> ActionResult:
    return ActionResult(action_id=request.action_id, success=True, summary="fn done")


@pytest.mark.asyncio
async def test_action_decorator(ctx: PluginContext) -> None:
    plugin = fn_action()
    assert "fn_action" in plugin.supported_actions()
    req = ActionRequest(action_id="fn_action")
    result = await plugin.execute(req, ctx)
    assert result.success
