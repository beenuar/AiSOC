"""Google Chronicle event-warehouse provider — Phase 4.5 scaffold.

Reads YARA-L / UDM search out of ``hunt.translated_query["udm"]`` and
would run it against the configured Chronicle backend. Stub today —
see the Splunk provider for the same pattern (advertise the contract,
fail with :class:`HuntNotConfigured` so the scheduler walks the chain).
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.models.saved_hunt import SavedHunt

from .base import HuntNotConfigured, _BaseProvider

logger = logging.getLogger(__name__)


class ChronicleProvider(_BaseProvider):
    """Run UDM hunts against the configured Chronicle backend."""

    name = "chronicle"
    translated_query_key = "udm"

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        _ = self._read_translated(hunt)
        _ = max_rows
        if not getattr(settings, "CHRONICLE_PROJECT_ID", None) or not getattr(settings, "CHRONICLE_SERVICE_ACCOUNT_JSON", None):
            raise HuntNotConfigured("chronicle: CHRONICLE_PROJECT_ID or CHRONICLE_SERVICE_ACCOUNT_JSON not configured")
        logger.info(
            "event_warehouse.chronicle.run_hunt_not_yet_live hunt_id=%s",
            hunt.id,
        )
        raise HuntNotConfigured("chronicle: provider scaffolded but live UDM execution not yet shipped")
