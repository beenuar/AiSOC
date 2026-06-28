"""Elasticsearch event-warehouse provider — Phase 4.5.

This is a thin shim over :mod:`app.services.esql_runner` so the
scheduler can talk to all warehouses through the same provider
interface. The runner stays the single source of truth for SSRF /
air-gap guards + the ``| LIMIT`` row cap.
"""

from __future__ import annotations

import logging

from app.core.airgap import AirgapViolation
from app.models.saved_hunt import SavedHunt
from app.services.esql_runner import (
    ESQLExecutionError,
    ESQLNotConfigured,
    resolve_es_credentials,
    run_esql_query,
)

from .base import (
    HuntExecutionError,
    HuntNotConfigured,
    _BaseProvider,
)

logger = logging.getLogger(__name__)


class ElasticsearchProvider(_BaseProvider):
    """Run ES|QL hunts against the configured Elasticsearch cluster."""

    name = "elasticsearch"
    translated_query_key = "esql"

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        esql = self._read_translated(hunt)

        try:
            es_url, es_api_key = resolve_es_credentials()
        except ESQLNotConfigured as exc:
            raise HuntNotConfigured(str(exc)) from exc

        try:
            result = await run_esql_query(
                esql=esql,
                es_url=es_url,
                es_api_key=es_api_key,
                max_rows=max_rows,
            )
        except (AirgapViolation, ValueError):
            # Re-raise unchanged — the scheduler has dedicated handling
            # for air-gap and SSRF/validation errors.
            raise
        except ESQLExecutionError as exc:
            raise HuntExecutionError(str(exc)) from exc

        return len(result.rows)
