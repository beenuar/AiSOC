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

import re
import uuid
from typing import Any


def _parse_uuid(value: Any) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _says_the_same_thing(whole: str, part: str) -> bool:
    """Whether ``part`` already appears inside ``whole`` as whole words.

    Word boundaries, not a plain substring test: "AWS" must not be swallowed
    by a product called "Lawsuit Monitor", and the join exists to name a
    vendor, not to pattern-match one.
    """
    return re.search(rf"(?<!\w){re.escape(part)}(?!\w)", whole, re.IGNORECASE) is not None


def product_label(ocsf: dict[str, Any]) -> str | None:
    """Vendor + product, deduplicated.

    Most connectors set `vendor_name` and `name` to the same string, so a
    naive join produced `connector_type = "crowdstrike crowdstrike"` on every
    alert. Verified on a live stack.

    Exact equality was not enough. Four of the ten profiles in
    `services/ingest/internal/normalizer/normalizer.go` name the vendor inside
    the product — `Okta` / `Okta System Log`, `Splunk` / `Splunk Enterprise`,
    `Kubernetes` / `Kubernetes Audit`, `Email` / `Forwarded Email` — so the
    alert queue, the Investigation Rail and every entity chip read "Okta Okta
    System Log". Observed on a live CORE stack against real pushed telemetry.
    A part that another part already says is dropped; the longer one wins,
    which leaves "CrowdStrike Falcon" and "AWS Security Hub" untouched because
    neither names the other.

    This is the single implementation. `promoter._source()` delegates here;
    there used to be two copies of the join and only one of them was fixed,
    which is why the doubled label survived the first repair.
    """
    meta = ocsf.get("metadata") if isinstance(ocsf, dict) else None
    product = meta.get("product") if isinstance(meta, dict) else None
    if not isinstance(product, dict):
        return None
    parts: list[str] = []
    for value in (product.get("vendor_name"), product.get("name")):
        if not isinstance(value, str) or not value.strip():
            continue
        cleaned = value.strip()
        if any(cleaned.lower() == seen.lower() for seen in parts):
            continue
        parts.append(cleaned)
    kept = [
        part
        for index, part in enumerate(parts)
        if not any(len(other) > len(part) and _says_the_same_thing(other, part) for other in parts[:index] + parts[index + 1 :])
    ]
    return " ".join(kept) or None


#: Retained so existing imports keep working.
_product_label = product_label


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
