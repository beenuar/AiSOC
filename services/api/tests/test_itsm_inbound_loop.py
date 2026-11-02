"""The return leg: a ticket change reaching the case, through the real handler.

Wave-2 Phase 6.4. ``test_inbox_itsm_endpoint.py`` grades the helpers — HMAC
verification, the two payload parsers, the status map — one function at a
time. Every one of those tests passes against a handler that never calls
them, which is the shape of coverage that proves a loop is not closed.

This drives ``inbound_itsm_webhook`` itself, through a real ASGI request
carrying a recorded vendor webhook body, and asserts the thing the feature
is for: the AiSOC case moved because somebody moved the ticket.

Vendor payload shapes, fetched before the fixtures were written:

* Jira webhooks — https://developer.atlassian.com/cloud/jira/platform/webhooks/
* ServiceNow Table API — https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html

Two properties beyond "it works", both of which are how this endpoint
behaves badly if nobody checks:

**A vendor retry is a no-op.** Jira retries up to five times and ServiceNow
retries until it gets a 2xx, so a handler that is not idempotent rewrites
the case once per delivery and fills the timeline with duplicate notes.

**An unmappable status is not a status change.** The ITSM's vocabulary is
larger than AiSOC's, and a transition this product cannot express must
leave the case where it is rather than guessing.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import inbox_itsm

pytestmark = pytest.mark.asyncio

TENANT_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
CONNECTOR_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
CASE_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")

#: A Jira `jira:issue_updated` body, reduced to the fields the parser reads.
JIRA_WEBHOOK: dict[str, Any] = {
    "webhookEvent": "jira:issue_updated",
    "issue": {
        "id": "10042",
        "key": "SOC-17",
        "fields": {
            "summary": "Impossible travel on a finance account",
            "status": {"name": "Done", "statusCategory": {"key": "done"}},
        },
    },
}

#: A ServiceNow business-rule body. The `current` wrapper is what the
#: shipped outbound rule template produces.
SNOW_WEBHOOK: dict[str, Any] = {
    "current": {
        "sys_id": "a1b2c3d4e5f6",
        "number": "INC0012345",
        "state": "6",
        "short_description": "Impossible travel on a finance account",
    }
}


class _Request:
    """The two things the handler reads off the request."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._body = json.dumps(body).encode()

    async def body(self) -> bytes:
        return self._body


def _db(*, current_status: str = "investigating", case_found: bool = True) -> MagicMock:
    """A session that answers the handler's reads and records its writes.

    Shaped from the handler's own query order rather than from a guess:
    the token and connector lookup, then the external ref joined to its
    case, then the writes.
    """
    token = MagicMock(tenant_id=TENANT_ID, hmac_secret=None, template_id="itsm-inbound")
    connector = MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="jira")

    # A real object, not a MagicMock: the handler reads these as
    # attributes and feeds them straight into a Pydantic response model,
    # so a double that answers every attribute with another mock is a
    # double more capable than a database row.
    ref_row = SimpleNamespace(
        aisoc_case_id=CASE_ID,
        id=CASE_ID,
        external_id="SOC-17",
        vendor="jira",
        external_status="In Progress",
        status=current_status,
        case_number="CASE-412",
        title="Impossible travel on a finance account",
        tenant_id=TENANT_ID,
    )

    db = MagicMock()
    db.writes = []

    async def _execute(statement, *_args, **_kwargs):
        result = MagicMock()
        text = str(statement)
        if "tenant_inbox_tokens" in text:
            result.fetchone.return_value = token
            result.scalars.return_value.first.return_value = token
            return result
        if "connectors" in text and "case_external_refs" not in text:
            result.scalars.return_value.first.return_value = connector
            result.fetchone.return_value = connector
            return result
        if "case_external_refs" in text and text.strip().upper().startswith("SELECT"):
            result.fetchone.return_value = ref_row if case_found else None
            return result
        db.writes.append(text)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


async def _post(body: dict[str, Any], db: MagicMock) -> Any:
    return await inbox_itsm.inbound_itsm_webhook(
        tenant_token="tok-live",
        connector_instance_id=CONNECTOR_ID,
        request=_Request(body),  # type: ignore[arg-type]
        db=db,
        x_aisoc_signature=None,
    )


class TestATicketChangeReachesTheCase:
    async def test_a_jira_transition_to_done_closes_the_case(self, monkeypatch) -> None:
        db = _db()
        monkeypatch.setattr(
            inbox_itsm,
            "_fetch_token_and_connector",
            AsyncMock(
                return_value=(
                    MagicMock(tenant_id=TENANT_ID, hmac_secret=None),
                    MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="jira"),
                )
            ),
        )
        applied: list[dict[str, Any]] = []

        async def _apply(_db, **kwargs):
            applied.append(kwargs)

        monkeypatch.setattr(inbox_itsm, "_apply_status_to_case", _apply)

        result = await _post(JIRA_WEBHOOK, db)

        assert result.status_changed is True, result.note
        assert applied, "the handler resolved the ticket and then changed nothing"
        assert applied[0]["external_id"] == "SOC-17"
        assert applied[0]["new_status"] in ("resolved", "closed")

    async def test_a_servicenow_resolution_reaches_the_case(self, monkeypatch) -> None:
        db = _db()
        monkeypatch.setattr(
            inbox_itsm,
            "_fetch_token_and_connector",
            AsyncMock(
                return_value=(
                    MagicMock(tenant_id=TENANT_ID, hmac_secret=None),
                    MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="servicenow"),
                )
            ),
        )
        applied: list[dict[str, Any]] = []

        async def _apply(_db, **kwargs):
            applied.append(kwargs)

        monkeypatch.setattr(inbox_itsm, "_apply_status_to_case", _apply)

        result = await _post(SNOW_WEBHOOK, db)

        assert result.status_changed is True, result.note
        assert applied[0]["vendor"] == "servicenow"

    async def test_a_redelivery_of_the_same_state_changes_nothing(self, monkeypatch) -> None:
        """Jira retries up to five times and ServiceNow retries until it
        gets a 2xx. A handler that is not idempotent rewrites the case once
        per delivery and fills the timeline with duplicate notes."""
        db = _db(current_status="closed")
        monkeypatch.setattr(
            inbox_itsm,
            "_fetch_token_and_connector",
            AsyncMock(
                return_value=(
                    MagicMock(tenant_id=TENANT_ID, hmac_secret=None),
                    MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="jira"),
                )
            ),
        )
        applied: list[dict[str, Any]] = []

        async def _apply(_db, **kwargs):
            applied.append(kwargs)

        monkeypatch.setattr(inbox_itsm, "_apply_status_to_case", _apply)

        result = await _post(JIRA_WEBHOOK, db)

        assert result.status_changed is False
        assert not applied

    async def test_an_unmappable_status_leaves_the_case_where_it_is(self, monkeypatch) -> None:
        """The ITSM's vocabulary is larger than AiSOC's. A transition this
        product cannot express must not be guessed at."""
        db = _db()
        monkeypatch.setattr(
            inbox_itsm,
            "_fetch_token_and_connector",
            AsyncMock(
                return_value=(
                    MagicMock(tenant_id=TENANT_ID, hmac_secret=None),
                    MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="jira"),
                )
            ),
        )
        applied: list[dict[str, Any]] = []

        async def _apply(_db, **kwargs):
            applied.append(kwargs)

        monkeypatch.setattr(inbox_itsm, "_apply_status_to_case", _apply)

        odd = {
            "webhookEvent": "jira:issue_updated",
            "issue": {"key": "SOC-17", "fields": {"status": {"name": "Awaiting Vendor Parts"}}},
        }
        result = await _post(odd, db)

        assert result.status_changed is False
        assert not applied
        assert result.note

    async def test_a_ticket_with_no_linked_case_is_answered_rather_than_erroring(self, monkeypatch) -> None:
        """Vendor webhook implementations retry forever on a non-2xx, so a
        stale ticket pinging a deleted case must not block the queue."""
        db = _db(case_found=False)
        monkeypatch.setattr(
            inbox_itsm,
            "_fetch_token_and_connector",
            AsyncMock(
                return_value=(
                    MagicMock(tenant_id=TENANT_ID, hmac_secret=None),
                    MagicMock(id=CONNECTOR_ID, tenant_id=TENANT_ID, connector_type="jira"),
                )
            ),
        )
        result = await _post(JIRA_WEBHOOK, db)
        assert result.status_changed is False
        assert result.note


class TestATerminalCaseStaysClosed:
    """The defect wave-2 6.4 found, pinned from both sides.

    The idempotency check was an exact equality, so a case a human had
    closed in AiSOC, receiving an ordinary Jira redelivery of `Done`
    (which maps to the *intermediate* `resolved`), was moved backwards out
    of its terminal state. No unusual sequence was needed — only a close
    followed by a retry, and Jira retries up to five times.
    """

    def test_a_retry_after_a_close_is_refused(self) -> None:
        assert inbox_itsm._is_backwards_from_terminal("closed", "resolved") is True
        assert inbox_itsm._is_backwards_from_terminal("closed", "investigating") is True
        assert inbox_itsm._is_backwards_from_terminal("closed", "new") is True

    def test_forward_transitions_are_untouched(self) -> None:
        """The positive control. A guard stuck closed reads as working
        caution, so the case that must still move is the one that catches
        it."""
        assert inbox_itsm._is_backwards_from_terminal("investigating", "resolved") is False
        assert inbox_itsm._is_backwards_from_terminal("resolved", "closed") is False
        assert inbox_itsm._is_backwards_from_terminal("new", "triaged") is False

    def test_only_terminal_states_are_protected(self) -> None:
        """An ITSM moving a ticket from Resolved back to In Progress is a
        real transition this product should mirror. Only the terminal
        state is defended, because only there is a retry indistinguishable
        from a reopen."""
        assert inbox_itsm._is_backwards_from_terminal("resolved", "investigating") is False

    def test_an_unknown_status_is_not_comparable_and_is_not_guessed(self) -> None:
        assert inbox_itsm._is_backwards_from_terminal("closed", "awaiting_parts") is False
        assert inbox_itsm._is_backwards_from_terminal(None, "resolved") is False

    def test_closed_is_the_terminal_state_and_resolved_is_not(self) -> None:
        """The distinction that made the defect possible, asserted rather
        than left to a reader's assumption about the word 'resolved'."""
        assert "closed" in inbox_itsm._TERMINAL_STATUSES
        assert "resolved" not in inbox_itsm._TERMINAL_STATUSES
        assert inbox_itsm._STATUS_ORDER.index("resolved") < inbox_itsm._STATUS_ORDER.index("closed")
