"""Built-in connector factory registrations.

This module is imported lazily by ``ConnectorRegistry`` the first time
``get_connector()`` is called (see ``_ensure_builtins_loaded`` in
``registry.py``). Importing it eagerly would create a circular import
with ``registry.py``.

Adding a new vendor:
  1. Implement ``app/connectors/<vendor>/connector.py`` with a class that
     inherits from the appropriate ``Base*Connector`` protocol.
  2. Import it below and call ``register_connector_factory`` with the
     vendor string used by the admin API (e.g. ``"splunk"``, ``"okta"``).
  3. The vendor name registered here is what tenants pass when they
     POST to ``/api/connectors`` — keep them stable, they are user-facing.

The ``"mock"`` vendor is special: the registry falls back to it whenever
a tenant has no row configured or the row is disabled. Every supported
``ConnectorKind`` MUST have a mock registered or the tool layer will
break for unconfigured tenants.
"""
from __future__ import annotations

from app.connectors.crowdstrike import make_crowdstrike_edr
from app.connectors.m365 import make_m365_email
from app.connectors.okta import make_okta_idp
from app.connectors.sdk.base import ConnectorKind
from app.connectors.sdk.mocks import (
    make_mock_cloud,
    make_mock_edr,
    make_mock_email,
    make_mock_forensics,
    make_mock_idp,
    make_mock_saas,
    make_mock_siem,
)
from app.connectors.sdk.registry import register_connector_factory
from app.connectors.sentinel import make_sentinel_siem
from app.connectors.sentinelone import make_sentinelone_edr
from app.connectors.splunk import make_splunk_siem
from app.connectors.velociraptor import make_velociraptor_forensics


def register_builtin_factories() -> None:
    """Register the built-in mock factories for every supported kind.

    Called exactly once by ``_ensure_builtins_loaded`` in the registry.
    Idempotent — the registry guards re-entry, but registering the same
    ``(kind, vendor)`` twice would simply overwrite the prior factory
    (last-writer wins), not raise.
    """

    # Mock fallbacks. The registry uses ``vendor="mock"`` whenever a
    # tenant has no row or the row is ``enabled=False``.
    register_connector_factory(kind=ConnectorKind.SIEM, vendor="mock")(make_mock_siem)
    register_connector_factory(kind=ConnectorKind.EDR, vendor="mock")(make_mock_edr)
    register_connector_factory(kind=ConnectorKind.IDP, vendor="mock")(make_mock_idp)
    register_connector_factory(kind=ConnectorKind.EMAIL, vendor="mock")(make_mock_email)
    register_connector_factory(kind=ConnectorKind.CLOUD, vendor="mock")(make_mock_cloud)
    register_connector_factory(kind=ConnectorKind.SAAS, vendor="mock")(make_mock_saas)
    register_connector_factory(kind=ConnectorKind.FORENSICS, vendor="mock")(make_mock_forensics)

    # Real vendors. Each maps a vendor string (the one tenants pass to
    # ``POST /api/connectors``) to its factory.
    register_connector_factory(kind=ConnectorKind.SIEM, vendor="splunk")(make_splunk_siem)
    register_connector_factory(kind=ConnectorKind.SIEM, vendor="sentinel")(make_sentinel_siem)
    register_connector_factory(kind=ConnectorKind.EDR, vendor="crowdstrike")(make_crowdstrike_edr)
    register_connector_factory(kind=ConnectorKind.EDR, vendor="sentinelone")(make_sentinelone_edr)
    register_connector_factory(kind=ConnectorKind.IDP, vendor="okta")(make_okta_idp)
    register_connector_factory(kind=ConnectorKind.EMAIL, vendor="m365")(make_m365_email)
    register_connector_factory(kind=ConnectorKind.FORENSICS, vendor="velociraptor")(make_velociraptor_forensics)


# Run at import time so the registry only needs to import this module.
register_builtin_factories()


__all__ = ["register_builtin_factories"]
