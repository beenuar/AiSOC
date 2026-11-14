"""Connector SDK internals (base classes, HTTP client, registry, builtins)."""
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
from app.connectors.sdk.http import (
    ApiKeyAuth,
    AsyncHttpClient,
    BasicAuth,
    BearerAuth,
    ConnectorAuth,
    OAuthClientCredentials,
)
from app.connectors.sdk.protocols import (
    BaseEdrConnector,
    BaseEmailConnector,
    BaseIdpConnector,
    BaseSiemConnector,
)

__all__ = [
    "ApiKeyAuth",
    "AsyncHttpClient",
    "BaseConnector",
    "BaseEdrConnector",
    "BaseEmailConnector",
    "BaseIdpConnector",
    "BaseSiemConnector",
    "BasicAuth",
    "BearerAuth",
    "ConnectorAuth",
    "ConnectorAuthError",
    "ConnectorConfig",
    "ConnectorError",
    "ConnectorKind",
    "ConnectorRateLimitError",
    "ConnectorTimeoutError",
    "OAuthClientCredentials",
]
