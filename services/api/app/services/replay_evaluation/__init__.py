"""Replay evaluation: triage measured against a tenant's own closed findings.

Gap-closure Phase 1.4. Three modules, kept apart so two of them need no
database and no network to test:

``vendors``
    Which connector types have a closed-finding reader, and how their stored
    field names translate into the credential keys the readers expect. Pure.
``store``
    Reading and writing the two tenant-scoped tables migration 065 creates.
``job``
    The orchestration across ``services/actions``, ``services/agents`` and the
    vendored scorer, and the only module that makes an outbound call.
"""

from __future__ import annotations

from app.services.replay_evaluation.vendors import (
    REPLAYABLE_CONNECTORS,
    ReplayableConnector,
    UnsupportedConnector,
    credentials_for,
    is_replayable,
    replayable_connector_ids,
    vendor_for,
)

__all__ = [
    "REPLAYABLE_CONNECTORS",
    "ReplayableConnector",
    "UnsupportedConnector",
    "credentials_for",
    "is_replayable",
    "replayable_connector_ids",
    "vendor_for",
]
