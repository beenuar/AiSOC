"""Cyble AiSOC Connector SDK.

This package is the single integration boundary between the agent platform
and external security tooling (Splunk, Microsoft Sentinel, CrowdStrike
Falcon, SentinelOne, Okta, Microsoft 365 / Entra ID, etc.).

Design goals:

1. **Per-tenant routing**: every tool call resolves the connector for the
   *current tenant*. Tenant A's Splunk and Tenant B's Splunk are isolated
   instances with isolated credentials.
2. **Mock-when-unconfigured**: if a tenant has no credentials registered
   for an integration, the SDK returns a deterministic mock connector
   that reproduces the demo data the platform shipped with. This keeps
   `make demo` working out of the box without any vendor accounts.
3. **One file per vendor**: adding a new connector is a single module
   under `app/connectors/<vendor>/connector.py` plus a one-line
   registration in `app/connectors/sdk/builtin.py`.
4. **Typed, async, resilient**: every connector uses the shared
   `AsyncHttpClient` (timeout, retry, structured errors) and exposes
   high-level typed methods, not raw HTTP.

Public API:

    from app.connectors import get_connector, ConnectorKind
    siem = await get_connector(tenant_id, ConnectorKind.SIEM)
    events = await siem.search_events(entity="HR-42", entity_type="host", minutes=60)

The tool-layer handlers in `app/tools/*.py` call this — they do *not*
hit vendor SDKs directly.
"""
from __future__ import annotations

from app.connectors.sdk.base import (
    BaseConnector,
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
    ConnectorRateLimitError,
    ConnectorTimeoutError,
)
from app.connectors.sdk.registry import (
    get_connector,
    list_registered_factories,
    register_connector_factory,
    reset_connector_cache,
)

__all__ = [
    "BaseConnector",
    "ConnectorAuthError",
    "ConnectorConfig",
    "ConnectorError",
    "ConnectorKind",
    "ConnectorRateLimitError",
    "ConnectorTimeoutError",
    "get_connector",
    "list_registered_factories",
    "register_connector_factory",
    "reset_connector_cache",
]
