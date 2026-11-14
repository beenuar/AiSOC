"""
Tests for ``app.commands``.

We unit-test the dispatcher by stubbing out :class:`AisocApiClient` and
:class:`AisocActionsClient` with simple async fakes that record the calls
they received. This keeps the suite hermetic and fast — no respx, no Bolt.

The contract the dispatcher must hold is small but important:

* unknown / empty input → ephemeral help block (private to the user)
* upstream client errors → ephemeral error block (no traceback leaks)
* successful list/explain/investigate → ``in_channel`` (visible to the team)
  except for ``list`` which we keep ephemeral by design
* approval-required actions → in_channel approval card with action+case
  routing tokens encoded in the button values
* auto-approved actions → in_channel confirmation, no buttons

We also check the parser handles quoted reasons correctly so analysts can
include free-text rationale without breaking the command.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.commands import handle_aisoc_command
from app.services.aisoc_clients import AisocClientError

WEB_BASE = "https://app.aisoc.test"


class FakeApiClient:
    """In-memory stand-in for :class:`AisocApiClient`."""

    def __init__(
        self,
        *,
        cases: list[dict[str, Any]] | None = None,
        case: dict[str, Any] | None = None,
        investigation: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
        raise_on: str | None = None,
    ) -> None:
        self._cases = cases or []
        self._case = case or {"id": "c-1", "case_number": "AISOC-1", "title": "x"}
        self._investigation = investigation or {"run_id": "run-xyz"}
        self._summary = summary or {"summary": "ok"}
        self._raise_on = raise_on
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _maybe_raise(self, name: str) -> None:
        if self._raise_on == name:
            raise AisocClientError("upstream boom", status_code=502)

    async def list_open_cases(self, *, limit: int = 10, severity: str | None = None) -> list[dict[str, Any]]:
        self._maybe_raise("list_open_cases")
        self.calls.append(("list_open_cases", {"limit": limit, "severity": severity}))
        return self._cases

    async def get_case(self, case_id: str) -> dict[str, Any]:
        self._maybe_raise("get_case")
        self.calls.append(("get_case", {"case_id": case_id}))
        return self._case

    async def launch_investigation(self, case_id: str, *, alert_summary: str = "") -> dict[str, Any]:
        self._maybe_raise("launch_investigation")
        self.calls.append(("launch_investigation", {"case_id": case_id, "alert_summary": alert_summary}))
        return self._investigation

    async def get_case_summary(self, case_id: str) -> dict[str, Any]:
        self._maybe_raise("get_case_summary")
        self.calls.append(("get_case_summary", {"case_id": case_id}))
        return self._summary


class FakeActionsClient:
    """In-memory stand-in for :class:`AisocActionsClient`."""

    def __init__(
        self,
        *,
        action: dict[str, Any] | None = None,
        raise_on: str | None = None,
    ) -> None:
        self._action = action or {
            "id": "act-1",
            "status": "awaiting_approval",
            "action_type": "isolate_host",
            "target": "host-1",
            "blast_radius": "high",
        }
        self._raise_on = raise_on
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _maybe_raise(self, name: str) -> None:
        if self._raise_on == name:
            raise AisocClientError("actions boom", status_code=500)

    async def submit_action(self, **kwargs: Any) -> dict[str, Any]:
        self._maybe_raise("submit_action")
        self.calls.append(("submit_action", kwargs))
        return self._action


def _flatten(blocks: list[dict[str, Any]]) -> str:
    return str(blocks)


def _has_action_buttons(blocks: list[dict[str, Any]]) -> bool:
    return any(b.get("type") == "actions" for b in blocks)


# ────────────────────────────────────────────────────────────────────────────
# help / unknown
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_text_returns_help_ephemeral():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(text="", user_id="U1", api_client=api, actions_client=actions, web_base=WEB_BASE)
    assert res["response_type"] == "ephemeral"
    assert "AiSOC Slack commands" in _flatten(res["blocks"])


@pytest.mark.asyncio
async def test_unknown_subcommand_returns_help_with_ephemeral_visibility():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(text="frobnicate", user_id="U1", api_client=api, actions_client=actions, web_base=WEB_BASE)
    assert res["response_type"] == "ephemeral"
    assert "AiSOC Slack commands" in _flatten(res["blocks"])


# ────────────────────────────────────────────────────────────────────────────
# list
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_passes_severity_filter_and_uses_titled_header():
    api = FakeApiClient(cases=[{"id": "c-1", "case_number": "AISOC-1", "title": "t", "severity": "high", "status": "investigating"}])
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="list high",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert ("list_open_cases", {"limit": 10, "severity": "high"}) in api.calls
    assert "High" in _flatten(res["blocks"])


@pytest.mark.asyncio
async def test_list_rejects_unknown_severity_with_ephemeral_error():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="list bogus",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Unknown severity" in _flatten(res["blocks"])
    # The bad severity must short-circuit before calling the API.
    assert api.calls == []


@pytest.mark.asyncio
async def test_list_translates_upstream_error_to_ephemeral_error():
    api = FakeApiClient(raise_on="list_open_cases")
    actions = FakeActionsClient()
    res = await handle_aisoc_command(text="list", user_id="U1", api_client=api, actions_client=actions, web_base=WEB_BASE)
    assert res["response_type"] == "ephemeral"
    assert "Could not load cases" in _flatten(res["blocks"])


# ────────────────────────────────────────────────────────────────────────────
# investigate
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_investigate_requires_case_id():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="investigate",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Usage" in _flatten(res["blocks"])


@pytest.mark.asyncio
async def test_investigate_calls_get_case_then_launch_and_returns_in_channel():
    api = FakeApiClient(
        case={"id": "c-9", "case_number": "AISOC-9"},
        investigation={"run_id": "run-42"},
    )
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="investigate AISOC-9",
        user_id="U777",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "in_channel"
    assert ("get_case", {"case_id": "AISOC-9"}) in api.calls
    # alert_summary mentions the requesting Slack user so the case timeline
    # records who fired the run.
    launch_call = next(c for c in api.calls if c[0] == "launch_investigation")
    assert "U777" in launch_call[1]["alert_summary"]
    assert "run-42" in _flatten(res["blocks"])


@pytest.mark.asyncio
async def test_investigate_translates_upstream_error_to_ephemeral_error():
    api = FakeApiClient(raise_on="launch_investigation")
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="investigate AISOC-9",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Investigation failed" in _flatten(res["blocks"])


# ────────────────────────────────────────────────────────────────────────────
# explain
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_explain_returns_in_channel_with_summary_and_recommendations():
    api = FakeApiClient(
        case={"id": "c-1", "case_number": "AISOC-1", "title": "t", "severity": "high", "status": "investigating"},
        summary={"summary": "DNS tunnelling suspected.", "recommendations": ["Isolate"]},
    )
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="explain AISOC-1",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "in_channel"
    rendered = _flatten(res["blocks"])
    assert "DNS tunnelling suspected." in rendered
    assert "Isolate" in rendered


@pytest.mark.asyncio
async def test_explain_requires_case_id():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="explain",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Usage" in _flatten(res["blocks"])


# ────────────────────────────────────────────────────────────────────────────
# isolate / block — shared "approval required" path
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_isolate_with_quoted_reason_parses_target_and_rationale():
    api = FakeApiClient(case={"id": "case-7", "case_number": "AISOC-7"})
    actions = FakeActionsClient(
        action={
            "id": "act-1",
            "status": "awaiting_approval",
            "action_type": "isolate_host",
            "target": "host-42",
            "blast_radius": "high",
        }
    )
    res = await handle_aisoc_command(
        text='isolate host-42 AISOC-7 "confirmed beacon to known bad C2"',
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "in_channel"
    # approval card emits an actions block with approve/deny buttons
    assert _has_action_buttons(res["blocks"])
    submitted = next(c for c in actions.calls if c[0] == "submit_action")[1]
    assert submitted["action_type"] == "isolate_host"
    assert submitted["target"] == "host-42"
    assert submitted["case_id"] == "case-7"
    assert submitted["rationale"] == "confirmed beacon to known bad C2"
    assert submitted["requested_by"] == "U1"


@pytest.mark.asyncio
async def test_block_dispatches_block_ip_action_type():
    api = FakeApiClient(case={"id": "case-7", "case_number": "AISOC-7"})
    actions = FakeActionsClient(
        action={
            "id": "act-2",
            "status": "awaiting_approval",
            "action_type": "block_ip",
            "target": "1.2.3.4",
            "blast_radius": "medium",
        }
    )
    res = await handle_aisoc_command(
        text="block 1.2.3.4 AISOC-7",
        user_id="U99",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "in_channel"
    assert _has_action_buttons(res["blocks"])
    submitted = next(c for c in actions.calls if c[0] == "submit_action")[1]
    assert submitted["action_type"] == "block_ip"
    assert submitted["target"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_isolate_requires_target_and_case():
    api = FakeApiClient()
    actions = FakeActionsClient()
    res = await handle_aisoc_command(
        text="isolate host-only",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Usage" in _flatten(res["blocks"])
    assert actions.calls == []  # never submitted to actions service


@pytest.mark.asyncio
async def test_auto_approved_action_renders_confirmation_without_buttons():
    api = FakeApiClient(case={"id": "case-7", "case_number": "AISOC-7"})
    actions = FakeActionsClient(
        action={
            "id": "act-3",
            "status": "approved",  # low-blast, no approval needed
            "action_type": "isolate_host",
            "target": "host-low",
            "blast_radius": "low",
        }
    )
    res = await handle_aisoc_command(
        text="isolate host-low AISOC-7 routine",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "in_channel"
    assert not _has_action_buttons(res["blocks"])
    assert "submitted" in _flatten(res["blocks"]).lower()


@pytest.mark.asyncio
async def test_isolate_translates_upstream_error_to_ephemeral_error():
    api = FakeApiClient(case={"id": "case-7"})
    actions = FakeActionsClient(raise_on="submit_action")
    res = await handle_aisoc_command(
        text="isolate host-1 AISOC-7",
        user_id="U1",
        api_client=api,
        actions_client=actions,
        web_base=WEB_BASE,
    )
    assert res["response_type"] == "ephemeral"
    assert "Action submission failed" in _flatten(res["blocks"])
