"""Splunk event-warehouse provider — Phase 4.5 scaffold.

Reads SPL out of ``hunt.translated_query["spl"]`` and would run it
against the configured Splunk search head. The driver itself is the
``NotImplemented`` path today: it advertises the contract and the
credential keys so an operator wiring Splunk credentials sees a clear
"driver not yet shipped" error instead of a silent skip.

Adding the live implementation is a one-PR change once we land a
splunk-sdk dep:

1. Resolve ``SPLUNK_URL`` + ``SPLUNK_HMAC_TOKEN`` (or the Splunk SDK
   session form) via settings.
2. POST the SPL to ``/services/search/jobs`` with ``exec_mode=oneshot``.
3. Count rows in the result set, return the hit count.
4. Add the SSRF guard mirroring :func:`_validate_es_url`.

Until then this provider raises :class:`HuntNotConfigured` so the
scheduler walks to the next provider in the chain.
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.models.saved_hunt import SavedHunt

from .base import HuntNotConfigured, _BaseProvider

logger = logging.getLogger(__name__)


class SplunkProvider(_BaseProvider):
    """Run SPL hunts against the configured Splunk search head."""

    name = "splunk"
    translated_query_key = "spl"

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        _ = self._read_translated(hunt)
        _ = max_rows
        if not getattr(settings, "SPLUNK_URL", None) or not getattr(settings, "SPLUNK_HMAC_TOKEN", None):
            raise HuntNotConfigured("splunk: SPLUNK_URL or SPLUNK_HMAC_TOKEN not configured")
        # Live wire pending — see module docstring.
        logger.info(
            "event_warehouse.splunk.run_hunt_not_yet_live hunt_id=%s",
            hunt.id,
        )
        raise HuntNotConfigured("splunk: provider scaffolded but live SPL execution not yet shipped")
