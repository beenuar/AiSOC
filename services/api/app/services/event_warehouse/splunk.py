"""Splunk event-warehouse provider.

Runs the SPL the platform's translator already produced for a saved hunt
against the tenant's own Splunk search head, using the credentials stored
on their ``splunk`` connector row.

This driver previously raised :class:`HuntNotConfigured` unconditionally —
it checked ``settings.SPLUNK_URL`` and ``settings.SPLUNK_HMAC_TOKEN``,
neither of which is a declared field on ``Settings``, and then raised
"scaffolded but live SPL execution not yet shipped" even if they had been.
The SPL translation was produced for every hunt and then discarded.
"""

from __future__ import annotations

import logging

from app.core.airgap import AirgapViolation
from app.models.saved_hunt import SavedHunt
from app.services.spl_runner import SPLExecutionError, run_spl_query

from .base import HuntExecutionError, HuntNotConfigured, _BaseProvider
from .credentials import WarehouseCredentials

logger = logging.getLogger(__name__)


class SplunkProvider(_BaseProvider):
    """Run SPL hunts against the tenant's own Splunk search head."""

    name = "splunk"
    translated_query_key = "spl"
    connector_types = ("splunk",)

    async def run_hunt(
        self,
        hunt: SavedHunt,
        *,
        credentials: WarehouseCredentials,
        max_rows: int = 500,
    ) -> int:
        spl = self._read_translated(hunt)

        base_url = credentials.get("base_url", "url", "endpoint")
        if not base_url:
            raise HuntNotConfigured(
                f"connector {credentials.connector_name!r} has no Splunk URL — "
                "re-save it in the console with the management endpoint (port 8089)"
            )

        token = credentials.get("token", "hec_token", "api_token")
        username = credentials.get("username")
        password = credentials.get("password")
        if not token and not (username and password):
            raise HuntNotConfigured(
                f"connector {credentials.connector_name!r} has neither a token nor a "
                "username/password pair — re-save it in the console with credentials"
            )

        # The connector schema defaults this to True and only a private
        # deployment with a self-signed certificate should turn it off, so a
        # missing key must read as "verify", never as "skip verification".
        verify_ssl = credentials.get("ssl_verify", default=True)

        try:
            result = await run_spl_query(
                spl=spl,
                base_url=base_url,
                token=token,
                username=username,
                password=password,
                max_rows=max_rows,
                verify_ssl=bool(verify_ssl),
            )
        except (AirgapViolation, ValueError):
            # Re-raise unchanged — the scheduler distinguishes air-gap and
            # SSRF/validation refusals from warehouse errors.
            raise
        except SPLExecutionError as exc:
            raise HuntExecutionError(str(exc)) from exc

        return len(result.rows)
