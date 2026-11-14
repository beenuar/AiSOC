"""An author cannot approve their own detection rule.

Gap-closure wave 9.

`detection_rule_proposals.proposed_by_id` was written at creation and
compared against nothing, so the author of a rule could approve it —
on the one surface in this product that writes executable code into
the detection engine. Every other governed surface separates the two:
action approval, playbook dispatch, MSSP overrides.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import detection_proposals as dp
from fastapi import HTTPException

AUTHOR = uuid.UUID("11111111-1111-1111-1111-111111111111")
REVIEWER = uuid.UUID("22222222-2222-2222-2222-222222222222")
TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")


def _proposal(proposed_by: uuid.UUID | None) -> SimpleNamespace:
    """A proposal that has already passed its fixture gate, so the only
    thing left that can refuse it is the duty check."""
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        status="eval_passed",
        proposed_by_id=proposed_by,
        eval_result={"candidate_rule": {"passed": True}},
        decided_by_id=None,
        decision_comment=None,
        decided_at=None,
        # The response model validates from this object, so the double
        # has to carry every field it reads. A shorter namespace failed
        # with fifteen validation errors rather than exercising the
        # check under test.
        base_rule_id=None,
        promoted_rule_id=None,
        name="candidate",
        description=None,
        rule_language="sigma",
        rule_body="detection: {}",
        category="endpoint",
        severity="medium",
        confidence=50,
        mitre_tactics=[],
        mitre_techniques=[],
        tags=[],
        positive_fixtures=[],
        negative_fixtures=[],
        review_comments=[],
        github_pr_url=None,
        created_at=now,
        updated_at=now,
    )


def _user(user_id: uuid.UUID) -> SimpleNamespace:
    return SimpleNamespace(user_id=user_id, tenant_id=TENANT, email="x@example.com", role="admin", scopes=["*"])


async def _decide(monkeypatch: pytest.MonkeyPatch, proposal, caller, decision: str = "approve"):  # noqa: ANN001, ANN202
    monkeypatch.setattr(dp, "_ensure_dac_enabled", lambda: None)

    async def _load(_db, _pid, _tenant):  # noqa: ANN001, ANN202
        return proposal

    monkeypatch.setattr(dp, "_load_proposal", _load)

    class _DB:
        """Accepts the writes the handler makes and records nothing.

        Docstring bodies rather than `...`, which CodeQL reads as an
        ineffectual statement — the convention this repository already
        uses for Protocol and abstract bodies.
        """

        async def commit(self) -> None:
            """No-op."""

        async def refresh(self, *_a) -> None:
            """No-op."""

        def add(self, *_a) -> None:
            """No-op."""

    return await dp.decide_proposal(
        proposal.id,
        dp.DecisionRequest(decision=decision),
        caller,
        _DB(),
    )


@pytest.mark.asyncio
class TestSeparationOfDuties:
    async def test_the_author_cannot_approve_their_own_rule(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(dp, "_SEPARATION_OF_DUTIES_ENFORCED", True)
        with pytest.raises(HTTPException) as caught:
            await _decide(monkeypatch, _proposal(AUTHOR), _user(AUTHOR))
        assert caught.value.status_code == 403
        assert "cannot approve" in str(caught.value.detail)

    async def test_a_second_person_can(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The negative control. A check that refused everyone would
        satisfy the test above and make the product unusable."""
        monkeypatch.setattr(dp, "_SEPARATION_OF_DUTIES_ENFORCED", True)
        result = await _decide(monkeypatch, _proposal(AUTHOR), _user(REVIEWER))
        assert result is not None

    async def test_the_author_may_still_reject_their_own(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rejecting your own proposal is withdrawing it, which needs no
        second person — and forcing one would strand bad proposals."""
        monkeypatch.setattr(dp, "_SEPARATION_OF_DUTIES_ENFORCED", True)
        result = await _decide(monkeypatch, _proposal(AUTHOR), _user(AUTHOR), decision="reject")
        assert result is not None

    async def test_a_proposal_with_no_author_is_not_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rules imported from the shipped corpus have no proposer, and
        refusing them would make the catalogue unapprovable."""
        monkeypatch.setattr(dp, "_SEPARATION_OF_DUTIES_ENFORCED", True)
        result = await _decide(monkeypatch, _proposal(None), _user(REVIEWER))
        assert result is not None

    async def test_it_can_be_turned_off_for_a_single_analyst_deployment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A control that forces people to disable it entirely is worse
        than one that is off by choice and recorded."""
        monkeypatch.setattr(dp, "_SEPARATION_OF_DUTIES_ENFORCED", False)
        result = await _decide(monkeypatch, _proposal(AUTHOR), _user(AUTHOR))
        assert result is not None

    async def test_it_is_on_by_default(self) -> None:
        """Read from the module rather than the environment, so this
        fails if somebody flips the default rather than the override."""
        import importlib

        reloaded = importlib.reload(dp)
        assert reloaded._SEPARATION_OF_DUTIES_ENFORCED is True
