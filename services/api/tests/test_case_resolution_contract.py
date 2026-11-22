"""A case reaches `resolved` only through the resolution contract (WS7.2).

What was wrong
--------------
`resolved` was a free transition: the PATCH gate checked only the status
ladder, and three other writers never checked anything — the war-room chat
"resolve" decision wrote `status='resolved'` directly, an inbound Jira or
ServiceNow webhook could jump any open case straight to `resolved`, and the
hourly auto-close sweep then made it effectively terminal. Nothing required
containment to have been verified, eradication or recovery to be recorded,
a root cause to exist, or the customer to have been told.

What this asserts
-----------------
* One shared checker (`case_resolution.compute_gaps`) owns the contract, the
  way `case_status` owns the vocabulary. Its requirements: containment
  verified by a named probe/action reference or waived with a reason;
  eradication and recovery steps recorded; root cause **determined or
  undetermined-with-reason** (a hypothesis does not satisfy — that is the
  point of WS7.1's statuses); at least one affected entity recorded; the
  customer notified with channel and time.
* **Per-tenant policy, off by default**: no policy row (or `enforce=false`)
  means no gaps — existing deployments keep their workflow until a tenant
  turns the contract on. Rule 14: new enforcement is opt-in.
* The PATCH route refuses `… → resolved` with a 422 that lists every unmet
  requirement by name (the console surfaces `detail` verbatim in a toast).
* The war-room "resolve" decision consults the same checker and, on gaps,
  refuses with the gaps posted to the channel instead of writing status.
* The inbound ITSM mirror cannot 422 a vendor webhook, so a vendor-side
  `resolved` that fails the contract lands as `contained` with a system
  note naming the gaps — never silently `resolved`.
* Facts are validated at write: `containment_state='verified'` requires the
  verification reference; `'not_required'` requires the reason; a notified
  claim requires channel and time together.

The live-Postgres half (RLS, one-facts-row-per-case upsert, policy row
semantics) lives in `tests/isolation/test_case_resolution_live.py`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services import case_resolution as svc
from app.services.case_resolution import (
    ResolutionFactsIn,
    ResolutionPolicy,
    compute_gaps,
)
from fastapi import HTTPException

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
CASE_ID = uuid.UUID("cccccccc-0000-0000-0000-00000000000c")


def _policy(**overrides: Any) -> ResolutionPolicy:
    payload: dict[str, Any] = {
        "enforce": True,
        "require_containment": True,
        "require_eradication_recovery": True,
        "require_root_cause": True,
        "require_entities": True,
        "require_notification": True,
    }
    payload.update(overrides)
    return ResolutionPolicy(**payload)


def _facts(**overrides: Any) -> ResolutionFactsIn:
    payload: dict[str, Any] = {
        "containment_state": "verified",
        "containment_reference": "action 7f3a… isolate_host verified by probe at 09:41Z",
        "containment_reason": None,
        "eradication": "Removed the loader from fin-ws-07; revoked the OAuth grant.",
        "recovery": "Restored the mailbox rule set; user re-enabled after reset.",
        "customer_notified_channel": "war-room #inc-412",
        "customer_notified_at": datetime(2026, 11, 21, 10, 5, tzinfo=UTC),
    }
    payload.update(overrides)
    return ResolutionFactsIn(**payload)


class TestFactsValidation:
    def test_verified_containment_requires_the_reference(self) -> None:
        with pytest.raises(svc.ResolutionValidationError, match="reference"):
            svc.validate_facts(_facts(containment_reference=None))

    def test_waived_containment_requires_the_reason(self) -> None:
        with pytest.raises(svc.ResolutionValidationError, match="reason"):
            svc.validate_facts(
                _facts(
                    containment_state="not_required",
                    containment_reference=None,
                    containment_reason=None,
                )
            )

    def test_notification_requires_channel_and_time_together(self) -> None:
        with pytest.raises(svc.ResolutionValidationError, match="channel and time"):
            svc.validate_facts(_facts(customer_notified_at=None))

    def test_complete_facts_pass(self) -> None:
        svc.validate_facts(_facts())
        svc.validate_facts(
            _facts(
                containment_state="not_required",
                containment_reference=None,
                containment_reason="No containment surface: the account was already disabled by HR offboarding.",
            )
        )


class TestComputeGaps:
    def test_no_policy_means_no_gaps(self) -> None:
        assert compute_gaps(None, None, root_cause_status=None, entity_count=0) == []

    def test_enforce_false_means_no_gaps(self) -> None:
        assert compute_gaps(_policy(enforce=False), None, root_cause_status=None, entity_count=0) == []

    def test_everything_missing_names_every_requirement(self) -> None:
        gaps = compute_gaps(_policy(), None, root_cause_status=None, entity_count=0)
        joined = " | ".join(gaps)
        assert "containment" in joined
        assert "eradication" in joined
        assert "root cause" in joined
        assert "affected entit" in joined
        assert "customer" in joined
        assert len(gaps) == 5

    def test_a_hypothesis_does_not_satisfy_root_cause(self) -> None:
        gaps = compute_gaps(_policy(), _facts(), root_cause_status="hypothesis", entity_count=3)
        assert len(gaps) == 1
        assert "root cause" in gaps[0]
        assert "hypothesis" in gaps[0]

    def test_determined_and_undetermined_both_satisfy(self) -> None:
        for status in ("determined", "undetermined"):
            assert compute_gaps(_policy(), _facts(), root_cause_status=status, entity_count=1) == []

    def test_waived_containment_satisfies(self) -> None:
        facts = _facts(
            containment_state="not_required",
            containment_reference=None,
            containment_reason="already offboarded",
        )
        assert compute_gaps(_policy(), facts, root_cause_status="determined", entity_count=1) == []

    def test_toggled_off_requirements_do_not_gap(self) -> None:
        policy = _policy(require_notification=False, require_entities=False)
        facts = _facts(customer_notified_channel=None, customer_notified_at=None)
        assert compute_gaps(policy, facts, root_cause_status="determined", entity_count=0) == []


@pytest.mark.asyncio
class TestPatchEnforcement:
    async def test_resolved_transition_is_refused_with_the_gaps_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api.v1.endpoints import cases as cases_ep

        async def _gaps(db: Any, tenant_id: Any, case_id: Any) -> list[str]:
            return ["containment is neither verified nor waived", "no root-cause record"]

        monkeypatch.setattr(cases_ep.case_resolution, "resolution_gaps", _gaps)

        existing = MagicMock()
        existing.id = CASE_ID
        existing.status = "contained"
        db = AsyncMock()
        first = MagicMock()
        first.fetchone.return_value = existing
        db.execute = AsyncMock(return_value=first)

        user = MagicMock()
        user.tenant_id = TENANT
        body = MagicMock()
        body.status = "resolved"

        with pytest.raises(HTTPException) as exc:
            await cases_ep._enforce_resolution_contract(db=db, user=user, existing=existing, target_status="resolved")
        assert exc.value.status_code == 422
        detail = str(exc.value.detail)
        assert "containment" in detail
        assert "root-cause" in detail

    async def test_other_transitions_do_not_consult_the_contract(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api.v1.endpoints import cases as cases_ep

        called = {"n": 0}

        async def _gaps(db: Any, tenant_id: Any, case_id: Any) -> list[str]:
            called["n"] += 1
            return ["anything"]

        monkeypatch.setattr(cases_ep.case_resolution, "resolution_gaps", _gaps)
        existing = MagicMock()
        existing.id = CASE_ID
        user = MagicMock()
        user.tenant_id = TENANT

        await cases_ep._enforce_resolution_contract(db=AsyncMock(), user=user, existing=existing, target_status="contained")
        assert called["n"] == 0


@pytest.mark.asyncio
class TestWarRoomEnforcement:
    async def test_resolve_decision_refuses_and_posts_the_gaps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services import war_room

        async def _gaps(db: Any, tenant_id: Any, case_id: Any) -> list[str]:
            return ["eradication and recovery steps are not recorded"]

        monkeypatch.setattr(war_room.case_resolution, "resolution_gaps", _gaps)

        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock())

        changed = await war_room.apply_channel_decision(
            db,
            tenant_id=TENANT,
            war_room={"case_id": str(CASE_ID), "channel_id": "C1", "platform": "slack"},
            decision="resolve",
            actor="analyst@aisoc.internal",
            note="",
        )
        assert changed.get("status") != "resolved"
        assert "refused" in str(changed).lower() or "gap" in str(changed).lower()
        # No status UPDATE reached the database.
        for call in db.execute.await_args_list:
            sql = str(call.args[0])
            assert "status = 'resolved'" not in sql


@pytest.mark.asyncio
class TestItsmEnforcement:
    async def test_vendor_resolved_lands_as_contained_when_gaps_exist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api.v1.endpoints import inbox_itsm

        async def _gaps(db: Any, tenant_id: Any, case_id: Any) -> list[str]:
            return ["no root-cause record"]

        monkeypatch.setattr(inbox_itsm.case_resolution, "resolution_gaps", _gaps)

        target, note = await inbox_itsm.resolve_contract_target(
            AsyncMock(),
            tenant_id=TENANT,
            case_id=CASE_ID,
            vendor_status="resolved",
        )
        assert target == "contained"
        assert "no root-cause record" in (note or "")

    async def test_vendor_resolved_passes_through_when_contract_satisfied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api.v1.endpoints import inbox_itsm

        async def _gaps(db: Any, tenant_id: Any, case_id: Any) -> list[str]:
            return []

        monkeypatch.setattr(inbox_itsm.case_resolution, "resolution_gaps", _gaps)

        target, note = await inbox_itsm.resolve_contract_target(
            AsyncMock(),
            tenant_id=TENANT,
            case_id=CASE_ID,
            vendor_status="resolved",
        )
        assert target == "resolved"
        assert note is None
