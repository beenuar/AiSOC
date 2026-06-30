---
sidebar_position: 2
---

# Python Plugin SDK

## Installation

:::info Status — monorepo today, PyPI in v8.0
`aisoc-plugin-sdk` ships from this monorepo today. The PyPI release lands with v8.0. Use the source-install path below until then — the import path (`aisoc_plugin_sdk`) and API surface stay identical.
:::

```bash
# Today (monorepo source install):
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC && pip install -e packages/plugin-sdk-py

# v8.0+ (once aisoc-plugin-sdk is on PyPI):
pip install aisoc-plugin-sdk
```

The PyPI distribution will be `aisoc-plugin-sdk`; the import path is
`aisoc_plugin_sdk`. The source lives in `packages/plugin-sdk-py/`.

## Quick Start: Enricher

```python
from aisoc_plugin_sdk import EnricherPlugin, PluginManifest, PluginType
from aisoc_plugin_sdk.enricher import EnrichmentRequest, EnrichmentResult

class VirusTotalEnricher(EnricherPlugin):
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="myorg.virustotal",
            name="VirusTotal Enricher",
            version="1.0.0",
            plugin_type=PluginType.ENRICHER,
        )

    async def enrich(
        self, request: EnrichmentRequest, context
    ) -> EnrichmentResult:
        # Call VirusTotal API here
        return EnrichmentResult(
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            enrichments={"vt_score": 72},
            malicious=True,
            confidence=0.95,
        )
```

### Using the decorator

```python
from aisoc_plugin_sdk import enricher

@enricher(
    id="myorg.virustotal",
    name="VirusTotal Enricher",
    version="1.0.0",
)
async def vt_enrich(request, context):
    return EnrichmentResult(...)
```

## Quick Start: Action

```python
from aisoc_plugin_sdk import ActionPlugin, PluginManifest, PluginType
from aisoc_plugin_sdk.action import ActionRequest, ActionResult

class BlockIPAction(ActionPlugin):
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="myorg.block-ip",
            name="Block IP",
            version="1.0.0",
            plugin_type=PluginType.ACTION,
        )

    def supported_actions(self) -> list[str]:
        return ["block_ip"]

    async def execute(
        self, request: ActionRequest, context
    ) -> ActionResult:
        if request.dry_run:
            return ActionResult(
                action_id=request.action_id, success=True,
                dry_run=True, summary=f"Would block {request.params['ip']}"
            )
        # firewall API call here
        return ActionResult(action_id=request.action_id, success=True)
```

## Plugin Registry

```python
from aisoc_plugin_sdk import PluginRegistry, PluginContext

registry = PluginRegistry()
registry.register(VirusTotalEnricher())
registry.register(BlockIPAction())

ctx = PluginContext(api_base_url="http://localhost:8000", api_token="...")
await registry.load_all(ctx)
```

## Development

```bash
cd packages/plugin-sdk-py
pip install -e ".[dev]"
pytest
mypy src/
ruff check src/
```
