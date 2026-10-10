"""One decoder for the connector payload ``services/ingest`` attaches.

``raw_data`` is a JSON **string**, not a dict:
``normalizer.go`` runs ``json.Marshal(raw.Payload)`` and stores the result as
``ocsf["raw_data"]``. Two fusion modules need the payload back — the detection
engine, to build the field namespace a rule matches against, and the promoter,
to find the vendor's own description — and before issue #1244 only the
detection engine knew the shape. The promoter guarded its branch with
``isinstance(raw, dict)``, which no ingest event satisfies, so the vendor's
description was dropped on every event that carried one.

A dict is accepted as well as a string. Some producers (the API's direct
``/alerts/submit`` path, fixtures written before ingest serialised) hand the
payload through unserialised, and refusing it would trade one dead branch for
another.
"""

from __future__ import annotations

import json
from typing import Any


def decode_raw_data(ocsf: dict[str, Any]) -> dict[str, Any] | None:
    """The connector's own payload, or ``None`` when there isn't one.

    ``None`` rather than ``{}`` so a caller can distinguish "no payload" from
    "an empty payload" and apply its own fallback — the detection engine falls
    back to the OCSF top level, the promoter does not.
    """
    raw = ocsf.get("raw_data")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            # Malformed JSON in raw_data. The caller decides what to do with
            # nothing; one bad payload must not raise out of the hot path.
            return None
        if isinstance(parsed, dict):
            return parsed
    return None
