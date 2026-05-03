# aisoc-plugin-sdk · Python

The official Python SDK for building AiSOC plugins — custom enrichers,
response actions, and data-source connectors.

## Installation

```bash
pip install aisoc-plugin-sdk
```

Or during development:

```bash
pip install -e "packages/plugin-sdk-py[dev]"
```

## Quick Start

### Enricher (function style)

```python
from aisoc_plugin_sdk import enricher, EnrichmentRequest, EnrichmentResult, PluginContext

@enricher(id="myorg.virustotal", name="VirusTotal Enricher", author="myorg")
async def vt_enrich(request: EnrichmentRequest, ctx: PluginContext) -> EnrichmentResult:
    # call VirusTotal API here …
    return EnrichmentResult(
        indicator_type=request.indicator_type,
        indicator_value=request.indicator_value,
        enrichments={"vt_score": 72},
        malicious=True,
        confidence=0.9,
    )
```

### Response Action (class style)

```python
from aisoc_plugin_sdk import ActionPlugin, ActionRequest, ActionResult, PluginManifest, PluginContext

class BlockIPAction(ActionPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="myorg.block-ip",
            name="Block IP on Firewall",
            version="1.0.0",
            plugin_type="action",
        )

    def supported_actions(self) -> list[str]:
        return ["block_ip", "unblock_ip"]

    async def execute(self, request: ActionRequest, ctx: PluginContext) -> ActionResult:
        ip = request.params.get("ip")
        if request.dry_run:
            return ActionResult(action_id=request.action_id, success=True, dry_run=True,
                                summary=f"Would block {ip}")
        # … firewall API call …
        return ActionResult(action_id=request.action_id, success=True,
                            summary=f"Blocked {ip}")
```

### Connector

```python
from typing import AsyncIterator, Any
from aisoc_plugin_sdk import ConnectorPlugin, ConnectorConfig, PluginManifest, PluginContext
from aisoc_plugin_sdk.decorators import connector

@connector(id="myorg.splunk-connector", name="Splunk Connector")
class SplunkConnector(ConnectorPlugin):
    async def test_connection(self, ctx: PluginContext) -> bool:
        # ping Splunk …
        return True

    async def fetch_events(
        self, ctx: PluginContext, since: str | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        # query Splunk and yield normalised events …
        yield {"event_type": "alert", "source": "splunk", …}
```

## Plugin Registry

```python
from aisoc_plugin_sdk import PluginRegistry, PluginContext

registry = PluginRegistry()
registry.register(BlockIPAction())
registry.register(SplunkConnector())

ctx = PluginContext(api_base_url="http://api:8000", api_token="…")
await registry.load_all(ctx)
```

## Development

```bash
cd packages/plugin-sdk-py
pip install -e ".[dev]"
pytest
mypy src
ruff check src
```

## License

MIT — see [LICENSE](../../LICENSE).
