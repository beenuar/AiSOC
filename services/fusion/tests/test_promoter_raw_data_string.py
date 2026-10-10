"""The promoter reads ``raw_data`` in the shape ingest actually writes it.

Issue #1244. ``services/ingest`` serialises the connector payload before it
attaches it::

    if rawBytes, err := json.Marshal(raw.Payload); err == nil {
        ocsf["raw_data"] = string(rawBytes)
    }

so ``raw_data`` on every ingest-normalized event is a JSON **string**. The
promoter's description resolver guarded its only vendor-description branch
with ``isinstance(raw, dict)``, which that value can never satisfy, so the
branch was unreachable on the production path and a supplied description was
dropped. Execution fell through to ``ocsf["message"]`` — the same key
``_title`` reads first — so title and description came back identical.

The existing coverage in ``test_promoter_alert_text.py`` passes ``raw_data``
as a dict, which is the shape no ingest event has: the double was more
capable than the real thing, so the tests passed while the path was dead.
Every case here uses the serialised string.
"""

from __future__ import annotations

import json
import uuid

from app.services.promoter import _description, promote_normalized_event

_TENANT = str(uuid.uuid4())


def _ingest_event(payload: dict) -> dict:
    """An OCSF event shaped the way ``services/ingest`` emits one."""
    return {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "severity_id": 4,
        "message": payload.get("title", ""),
        "metadata": {"product": {"vendor_name": "CrowdStrike", "name": "Falcon"}},
        "raw_data": json.dumps(payload),
        "tenant_uid": _TENANT,
    }


def test_a_serialized_raw_data_still_yields_the_vendors_description() -> None:
    """The defect: this returned the title, because the dict branch was dead."""
    ocsf = _ingest_event(
        {
            "title": "Credential dumping detected",
            "description": "lsass.exe memory read by rundll32.exe (comsvcs.dll MiniDump)",
            "host": "WIN-FIN-01",
        }
    )
    assert _description(ocsf) == "lsass.exe memory read by rundll32.exe (comsvcs.dll MiniDump)"


def test_description_and_title_are_not_the_same_string() -> None:
    """The symptom an analyst sees: two panes showing one sentence."""
    alert = promote_normalized_event(
        {
            "tenant_id": _TENANT,
            "ocsf_event": _ingest_event(
                {
                    "title": "Credential dumping detected",
                    "description": "lsass.exe memory read by rundll32.exe",
                }
            ),
        }
    )
    assert alert is not None
    assert alert.title == "Credential dumping detected"
    assert alert.description == "lsass.exe memory read by rundll32.exe"


def test_a_title_is_not_repeated_as_the_description() -> None:
    """With no description supplied, the slot is empty rather than a copy.

    Restating the title adds nothing an analyst can act on and it reads as if
    the vendor wrote two sentences. The console renders the raw event either
    way.
    """
    alert = promote_normalized_event(
        {
            "tenant_id": _TENANT,
            "ocsf_event": _ingest_event({"title": "Suspicious PowerShell"}),
        }
    )
    assert alert is not None
    assert alert.title == "Suspicious PowerShell"
    assert alert.description is None or alert.description == ""


def test_the_other_human_keys_are_reached_through_the_string_too() -> None:
    for key in ("message", "summary", "detail", "reason"):
        ocsf = _ingest_event({"title": "Alert", key: f"human sentence via {key}"})
        assert _description(ocsf) == f"human sentence via {key}", key


def test_a_malformed_raw_data_string_does_not_raise() -> None:
    """A truncated payload degrades to the existing fallbacks, never an error."""
    ocsf = _ingest_event({"title": "Alert"})
    ocsf["raw_data"] = '{"description": "truncated'
    assert _description(ocsf) == "Alert"
    assert promote_normalized_event({"tenant_id": _TENANT, "ocsf_event": ocsf}) is not None


def test_a_serialized_payload_is_never_the_description() -> None:
    """The property that matters, now stated against the real shape."""
    ocsf = _ingest_event({"command_line": "whoami", "host": "WIN-01", "pid": 4242})
    result = _description(ocsf)
    assert not result.startswith("{"), f"description is a serialized payload: {result[:60]}"
    assert "4242" not in result
