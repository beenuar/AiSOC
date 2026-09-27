"""Which connectors can be replayed, and how their credentials reach the readers.

Gap-closure Phase 1.4.

Two vocabularies meet here and neither is wrong.

A **connector** stores credentials under the field names its setup wizard
collects: Splunk's is ``base_url``, QRadar's is ``console_url``, Elastic's is
``base_url`` again. Those names are part of a saved row and a rendered form,
and renaming them would invalidate every stored connector.

A **client** in ``services/actions`` reads a flat, vendor-prefixed mapping:
``splunk_url``, ``qradar_url``, ``elastic_url``. Those names are shared with
the writeback path and with playbook parameters, and renaming them would
break every playbook that names one.

So there is a translation, and this module is the only place it is written
down. It is pure: no database, no HTTP, no vault. Every mapping can therefore
be driven in a test without a running anything, which matters because the
failure mode is silent. A key that lands under the wrong name does not raise;
the factory returns ``None`` and the read is refused as "no usable
credentials", which reads to an operator as a configuration problem on their
side.

Why a table and not a convention
--------------------------------
Three of the five pairs would fit a rule like "prefix the field with the
vendor". ``base_url`` to ``splunk_url`` does not, and neither does
``sec_token`` to ``qradar_token``. A convention with exceptions is a table
with extra steps, so it is a table.

Defender is reached through the ``azure_defender`` connector
------------------------------------------------------------
There is no separate Defender XDR connector in this tree. ``azure_defender``
collects exactly the three credentials the Defender reader needs, and its own
description names the Defender products it covers, so it is the connector that
maps to the ``defender`` reader rather than a sixth one being invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "REPLAYABLE_CONNECTORS",
    "ReplayableConnector",
    "UnsupportedConnector",
    "credentials_for",
    "is_replayable",
    "replayable_connector_ids",
    "vendor_for",
]


class UnsupportedConnector(Exception):
    """This connector type has no closed-finding reader.

    Raised rather than returning an empty history, because "AiSOC cannot read
    this vendor's closed findings" and "this vendor's analysts closed nothing"
    are different answers and only one of them is about the product.
    """


@dataclass(frozen=True)
class ReplayableConnector:
    """One connector type that can be replayed, and how to translate it."""

    connector_type: str
    #: The reader arm on ``services/actions``.
    vendor: str
    label: str
    #: Connector ``auth_config`` field name to the credential key the client
    #: factory in ``app.executors.siem`` reads.
    auth_map: dict[str, str]
    #: Connector ``connector_config`` field name to the same. Kept apart
    #: because ``connector_config`` is not secret and is not vault-encrypted,
    #: so a mapping that pulled from the wrong one would either leak a secret
    #: into a non-secret column or fail to decrypt.
    config_map: dict[str, str]


#: The five vendors Phase 1.1 wrote readers for, keyed by the connector type
#: a tenant actually saves. Anything absent here is refused by name.
REPLAYABLE_CONNECTORS: dict[str, ReplayableConnector] = {
    "splunk": ReplayableConnector(
        connector_type="splunk",
        vendor="splunk",
        label="Splunk Enterprise Security",
        auth_map={
            "base_url": "splunk_url",
            "token": "splunk_token",
            "username": "splunk_username",
            "password": "splunk_password",
        },
        # The saved search is where a deployment keeps its notables, and
        # deployments rename it. Hardcoding one returns nothing on a site that
        # did, which is a zero-row window rather than an error.
        config_map={"ssl_verify": "splunk_verify_ssl", "saved_search": "search_override"},
    ),
    "microsoft_sentinel": ReplayableConnector(
        connector_type="microsoft_sentinel",
        vendor="sentinel",
        label="Microsoft Sentinel",
        auth_map={
            "tenant_id": "sentinel_tenant_id",
            "client_id": "sentinel_client_id",
            "client_secret": "sentinel_client_secret",
            "subscription_id": "sentinel_subscription_id",
            "resource_group": "sentinel_resource_group",
            "workspace": "sentinel_workspace_name",
        },
        config_map={},
    ),
    "elastic": ReplayableConnector(
        connector_type="elastic",
        vendor="elastic",
        label="Elastic Security",
        auth_map={
            "base_url": "elastic_url",
            "api_key": "elastic_api_key",
            "username": "elastic_username",
            "password": "elastic_password",
        },
        config_map={"index": "index"},
    ),
    "qradar": ReplayableConnector(
        connector_type="qradar",
        vendor="qradar",
        label="IBM QRadar",
        auth_map={"console_url": "qradar_url", "sec_token": "qradar_token"},
        config_map={"verify_tls": "qradar_verify_ssl"},
    ),
    "azure_defender": ReplayableConnector(
        connector_type="azure_defender",
        vendor="defender",
        label="Microsoft Defender XDR",
        auth_map={
            "tenant_id": "mde_tenant_id",
            "client_id": "mde_client_id",
            "client_secret": "mde_client_secret",
        },
        config_map={},
    ),
}


def replayable_connector_ids() -> list[str]:
    """Connector types with a closed-finding reader, sorted."""
    return sorted(REPLAYABLE_CONNECTORS)


def is_replayable(connector_type: str) -> bool:
    return connector_type in REPLAYABLE_CONNECTORS


def vendor_for(connector_type: str) -> str:
    """The reader arm for a connector type, or refuse by name."""
    entry = REPLAYABLE_CONNECTORS.get(connector_type)
    if entry is None:
        raise UnsupportedConnector(
            f"'{connector_type}' has no closed-finding reader. Replay evaluation supports {', '.join(replayable_connector_ids())}."
        )
    return entry.vendor


def credentials_for(
    connector_type: str,
    auth_config: dict[str, Any],
    connector_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate one connector's stored settings into the reader's credential keys.

    ``auth_config`` arrives already decrypted; this function never touches the
    vault, so a test can drive every mapping with plain strings.

    A field the connector did not store is omitted rather than set to ``None``.
    The factories test truthiness, so an explicit ``None`` and an absent key
    behave the same for them, but an omitted key keeps the forwarded payload to
    what the tenant actually configured.
    """
    entry = REPLAYABLE_CONNECTORS.get(connector_type)
    if entry is None:
        raise UnsupportedConnector(
            f"'{connector_type}' has no closed-finding reader. Replay evaluation supports {', '.join(replayable_connector_ids())}."
        )

    credentials: dict[str, Any] = {}
    for source, target in entry.auth_map.items():
        value = auth_config.get(source)
        if value not in (None, ""):
            credentials[target] = value
    for source, target in entry.config_map.items():
        value = (connector_config or {}).get(source)
        # Booleans are copied even when False: ``ssl_verify: false`` is a
        # deliberate choice for an internal CA, and dropping it would silently
        # re-enable verification against a certificate that will not validate.
        if isinstance(value, bool) or value not in (None, ""):
            credentials[target] = value
    return credentials
