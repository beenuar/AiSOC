"""AiSOC Plugin SDK for Python."""

from .action import ActionPlugin, ActionRequest, ActionResult
from .client import AiSOCClient, AiSOCClientError
from .connector import ConnectorConfig, ConnectorPlugin
from .decorators import action, connector, enricher
from .enricher import EnricherPlugin, EnrichmentRequest, EnrichmentResult
from .loader import PluginLoadError, load_manifest, load_plugin_from_directory
from .plugin import AiSOCPlugin, PluginContext, PluginManifest, PluginResult
from .registry import PluginRegistry

__version__ = "0.1.0"

__all__ = [
    # Core
    "AiSOCPlugin",
    "PluginManifest",
    "PluginContext",
    "PluginResult",
    # Enricher
    "EnricherPlugin",
    "EnrichmentRequest",
    "EnrichmentResult",
    # Action
    "ActionPlugin",
    "ActionRequest",
    "ActionResult",
    # Connector
    "ConnectorPlugin",
    "ConnectorConfig",
    # Decorators
    "enricher",
    "action",
    "connector",
    # Registry
    "PluginRegistry",
    # Client
    "AiSOCClient",
    "AiSOCClientError",
    # Loader
    "load_manifest",
    "load_plugin_from_directory",
    "PluginLoadError",
]
