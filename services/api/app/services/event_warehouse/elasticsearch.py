"""Elasticsearch event-warehouse provider — Phase 4.5.

A thin shim over :mod:`app.services.esql_runner` so the scheduler can talk
to all warehouses through the same provider interface. The runner stays the
single source of truth for SSRF / air-gap guards + the ``| LIMIT`` row cap.

Credentials come from the tenant's own ``elastic`` connector row, resolved
and vault-decrypted by the caller. The field names read below are exactly
the ones :meth:`ElasticConnector.schema` declares in the connectors
microservice — ``base_url``, ``api_key``, ``username``, ``password`` — so
what the user typed into the console wizard is what the hunt runs against.
"""

from __future__ import annotations

import base64
import logging

from app.core.airgap import AirgapViolation
from app.models.saved_hunt import SavedHunt
from app.services.esql_runner import (
    ESQLExecutionError,
    run_esql_query,
)

from .base import (
    HuntExecutionError,
    HuntNotConfigured,
    _BaseProvider,
)
from .credentials import WarehouseCredentials

logger = logging.getLogger(__name__)


def elastic_auth_header(credentials: WarehouseCredentials) -> str:
    """Build the Authorization header from whichever auth the user saved.

    The Elastic connector accepts an API key *or* a username/password pair,
    and its own ``_headers()`` picks between them the same way. Refusing
    early with a clear message beats sending ``ApiKey None`` and reporting
    Elasticsearch's 401 as if the cluster were misconfigured.
    """
    api_key = credentials.get("api_key")
    if api_key:
        return f"ApiKey {api_key}"

    username = credentials.get("username")
    password = credentials.get("password")
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    raise HuntNotConfigured(
        f"connector {credentials.connector_name!r} has neither an API key nor a "
        "username/password pair — re-save it in the console with credentials"
    )


class ElasticsearchProvider(_BaseProvider):
    """Run ES|QL hunts against the tenant's own Elasticsearch cluster."""

    name = "elasticsearch"
    translated_query_key = "esql"
    connector_types = ("elastic",)

    async def run_hunt(
        self,
        hunt: SavedHunt,
        *,
        credentials: WarehouseCredentials,
        max_rows: int = 500,
    ) -> int:
        esql = self._read_translated(hunt)

        es_url = credentials.get("base_url", "url", "endpoint")
        if not es_url:
            raise HuntNotConfigured(
                f"connector {credentials.connector_name!r} has no cluster URL — "
                "re-save it in the console with the Elasticsearch endpoint"
            )

        auth_header = elastic_auth_header(credentials)

        try:
            result = await run_esql_query(
                esql=esql,
                es_url=es_url,
                # The header is fully formed above; the runner only falls back
                # to the ApiKey form when no header is supplied.
                es_api_key="",
                auth_header=auth_header,
                # The SSRF allow-list is the connector's own endpoint, so this
                # tenant's hunt can reach that cluster and nothing else.
                allowed_url=es_url,
                max_rows=max_rows,
            )
        except (AirgapViolation, ValueError):
            # Re-raise unchanged — the scheduler has dedicated handling
            # for air-gap and SSRF/validation errors.
            raise
        except ESQLExecutionError as exc:
            raise HuntExecutionError(str(exc)) from exc

        return len(result.rows)
