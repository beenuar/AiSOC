"""Extract connector / OCSF provenance from an ingest ``raw_events`` envelope.

Issue #568: the fusion spine dropped the connector instance id, connector type,
and OCSF class on the floor when promoting/detecting alerts, so every persisted
row rendered as source "unknown" and downstream agents could not resolve the
originating connector (needed by the Splunk evidence tool in #570). This helper
recovers that provenance from the envelope the Go ingest service publishes.

The ingest ``NormalizedEvent`` carries ``connector_id`` at the top level and,
inside ``ocsf_event``, both ``source_connector_id`` and ``metadata.product``.
``connector_type`` is not always on the wire, so we fall back to the OCSF
product vendor/name for a human-meaningful provenance label; the canonical
connector *instance* id is what downstream resolution actually keys on.
"""

from __future__ import annotations

import uuid
from typing import Any


def _parse_uuid(value: Any) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _product_label(ocsf: dict[str, Any]) -> str | None:
    meta = ocsf.get("metadata") if isinstance(ocsf, dict) else None
    product = meta.get("product") if isinstance(meta, dict) else None
    if not isinstance(product, dict):
        return None
    vendor = product.get("vendor_name")
    name = product.get("name")
    parts = [p for p in (vendor, name) if isinstance(p, str) and p]
    return " ".join(parts) or None


def extract_provenance(
    message: dict[str, Any],
    ocsf: dict[str, Any] | None = None,
) -> tuple[uuid.UUID | None, str | None, int | None]:
    """Return ``(connector_id, connector_type, ocsf_class_uid)`` for a message.

    Never raises — a malformed envelope yields ``(None, None, None)`` so the
    consumer keeps flowing.
    """
    ocsf = ocsf if isinstance(ocsf, dict) else (message.get("ocsf_event") if isinstance(message, dict) else None)
    ocsf = ocsf if isinstance(ocsf, dict) else {}

    connector_id = _parse_uuid(message.get("connector_id")) or _parse_uuid(ocsf.get("source_connector_id"))
    connector_type = message.get("connector_type") if isinstance(message.get("connector_type"), str) else None
    if not connector_type:
        connector_type = _product_label(ocsf)

    class_uid_raw = ocsf.get("class_uid")
    class_uid = class_uid_raw if isinstance(class_uid_raw, int) else None

    return connector_id, connector_type, class_uid
