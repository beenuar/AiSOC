"""``POST /connectors/{id}/normalize``: the production mapping, over HTTP.

Gap-closure Phase 1.2. Replay evaluation lives in ``services/agents`` and
cannot import a connector, because both services package their code as
top-level ``app``. This route is how it reaches the real mapping instead of
carrying a copy that would drift.

The handler is driven directly rather than through a test client, which is how
this suite already exercises router-level code. Authentication is a
router-wide dependency (``require_console_or_service_auth``) covered by
``test_tenant_scope.py`` and by ``scripts/check_route_auth.py``; repeating it
here would test FastAPI's wiring rather than this route's behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.api.router import MAX_NORMALIZE_ROWS, NormalizeRequest, normalize_rows
from app.connectors import CONNECTOR_REGISTRY
from fastapi import HTTPException

#: A Splunk ES closed notable, in the shape ``list_closed_notables`` returns.
#: Synthetic, and recorded against the field names that SPL selects.
_NOTABLE: dict[str, Any] = {
    "event_id": "ES-1",
    "rule_id": "rule-42",
    "search_name": "Suspicious PowerShell",
    "urgency": "high",
    "disposition": "disposition:1",
    "src": "192.0.2.10",
    "host": "WS-01",
    "_time": "1772323200",
}

pytestmark = pytest.mark.asyncio


async def test_the_route_returns_the_connectors_own_mapping() -> None:
    body = await normalize_rows("splunk", NormalizeRequest(rows=[_NOTABLE]))

    assert body["connector_id"] == "splunk"
    assert body["row_count"] == 1
    envelope = body["rows"][0]
    assert envelope["source"] == "splunk"
    assert envelope["title"] == "Suspicious PowerShell"
    assert envelope["src_ip"] == "192.0.2.10"
    assert envelope["hostname"] == "WS-01"
    # The untouched vendor row travels with it, which is what lets replay hand
    # fields the connector did not lift to the same triage production sees.
    assert envelope["raw_event"] == _NOTABLE


async def test_the_route_matches_the_connector_called_directly() -> None:
    """The claim is "the same mapping", so it is compared against the class itself."""
    cls = CONNECTOR_REGISTRY["splunk"]
    direct = cls.normalize(cls.__new__(cls), dict(_NOTABLE))

    body = await normalize_rows("splunk", NormalizeRequest(rows=[_NOTABLE]))

    assert body["rows"][0] == direct


async def test_order_is_preserved_so_a_caller_can_pair_rows_with_findings() -> None:
    rows = [{**_NOTABLE, "event_id": f"ES-{index}"} for index in range(5)]

    body = await normalize_rows("splunk", NormalizeRequest(rows=rows))

    assert [e["external_id"] for e in body["rows"]] == [f"ES-{index}" for index in range(5)]


async def test_an_unknown_connector_is_a_404() -> None:
    with pytest.raises(HTTPException) as caught:
        await normalize_rows("not-a-connector", NormalizeRequest(rows=[{}]))

    assert caught.value.status_code == 404


async def test_an_oversized_batch_is_refused_rather_than_truncated() -> None:
    """A short list reads as "these are all of them" and would shrink the window."""
    rows = [dict(_NOTABLE) for _ in range(MAX_NORMALIZE_ROWS + 1)]

    with pytest.raises(HTTPException) as caught:
        await normalize_rows("splunk", NormalizeRequest(rows=rows))

    assert caught.value.status_code == 422
    assert "exceeds" in str(caught.value.detail)


async def test_the_request_model_carries_no_credential_field() -> None:
    """Structural half of "this route cannot call a customer's SIEM".

    The behavioural half is that the handler builds the connector with
    ``__new__`` and never runs ``__init__``, so there is nothing configured to
    call out with even if a credential were supplied.
    """
    assert set(NormalizeRequest.model_fields) == {"rows"}


@pytest.mark.parametrize("connector_id", sorted(CONNECTOR_REGISTRY))
async def test_every_registered_connector_either_normalizes_or_says_why(connector_id: str) -> None:
    """No connector may half-map a row and return it looking complete.

    A connector whose ``normalize`` reaches for instance state must produce a
    422 naming itself. The failure this forbids is a partially-populated
    envelope flowing into replay indistinguishable from a real one.
    """
    try:
        body = await normalize_rows(connector_id, NormalizeRequest(rows=[_NOTABLE]))
    except HTTPException as exc:
        assert exc.status_code == 422, exc.detail
        assert connector_id in str(exc.detail)
        return
    assert body["row_count"] == 1
