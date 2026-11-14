"""AiSOC Plugin SDK for Python."""

from .plugin import AiSOCPlugin, PluginManifest, PluginContext, PluginResult
from .enricher import EnricherPlugin, EnrichmentRequest, EnrichmentResult
from .action import ActionPlugin, ActionRequest, ActionResult
from .connector import ConnectorPlugin, ConnectorConfig
from .decorators import enricher, action, connector
from .registry import PluginRegistry
from .client import AiSOCClient, AiSOCClientError
from .loader import load_manifest, load_plugin_from_directory, PluginLoadError

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
