"""Depth 2 Phase 1.2 reproduction: nothing compares granted with used.

1.1 made "what can this identity do" answerable and recorded, per principal,
which granted actions were exercised in a trailing window. Neither is a
review. A reviewer's questions are comparative — who holds admin they never
use, which human has a long-lived cloud key, which outside collaborator has
admin on a repository, which admin has been dormant — and no module in the
tree asks any of them.

Fails on the pre-change tree for that reason. Kept afterwards as the guard,
including the two tests that pin the honesty properties, because the failure
mode here is not an absent finding but a confident wrong one: a review built
on unmeasured usage recommends revoking every permission in the estate.
"""

from __future__ import annotations

import pytest


def test_an_access_review_module_exists() -> None:
    from app.services import access_review

    assert hasattr(access_review, "review_principal")
    assert hasattr(access_review, "FINDING_KINDS")


def test_every_finding_kind_the_plan_names_is_implemented() -> None:
    """The four the plan lists, plus the posture findings the same scan surfaces.

    Named individually rather than counted: a count passes when one kind is
    renamed and another silently dropped.
    """
    from app.services.access_review import FINDING_KINDS

    required = {
        "human_with_long_lived_key",
        "unused_write_access",
        "outside_collaborator_admin",
        "dormant_admin",
        "fork_reachable_workflow_secret",
        "org_member_without_mfa",
    }
    assert required <= set(FINDING_KINDS), f"missing: {sorted(required - set(FINDING_KINDS))}"


def test_unmeasured_usage_produces_no_usage_finding() -> None:
    """The property the whole item turns on.

    An install with no event lake cannot know which permissions were
    exercised. A review that reads that as "used nothing" recommends
    revoking the estate, and it recommends it with exactly the confidence of
    a correct finding.
    """
    from app.services.access_review import review_principal
    from app.services.identity_privilege import IdentityPrivilege, PrivilegeTags
    from app.services.identity_privilege_store import UsageOverlay

    privilege = IdentityPrivilege(
        tier="admin",
        tags=PrivilegeTags(can_escalate=True),
        provider="aws",
        principal_id="arn:aws:iam::1:user/alice",
        evidence={"can_escalate": ["iam:PutUserPolicy"]},
        action_count=40,
    )
    result = review_principal(privilege=privilege, usage=UsageOverlay(measured=False, used={}))

    kinds = {f.kind for f in result.findings}
    assert "unused_write_access" not in kinds
    assert "dormant_admin" not in kinds
    assert result.usage_measured is False
    # And it must say so, rather than returning a short list that reads as
    # a clean bill of health.
    assert result.unmeasured_reason


def test_a_review_with_no_inventory_is_not_a_clean_bill() -> None:
    """Zero findings over zero principals is "nothing reviewed"."""
    from app.services.access_review import summarise

    summary = summarise([])
    assert summary["reviewed_principals"] == 0
    assert summary["state"] == "nothing_reviewed"
    assert summary["findings"] == 0


def test_best_fit_role_is_only_offered_when_usage_was_measured() -> None:
    """A right-sizing recommendation on unmeasured usage is a guess."""
    from app.services.access_review import best_fit_role
    from app.services.identity_privilege_store import UsageOverlay

    unmeasured = best_fit_role(
        provider="aws",
        granted={"s3:GetObject", "s3:PutObject", "iam:PutUserPolicy"},
        usage=UsageOverlay(measured=False, used={}),
    )
    assert unmeasured is None


@pytest.mark.parametrize("kind", ["human_with_long_lived_key", "outside_collaborator_admin"])
def test_every_finding_names_the_object_to_change(kind: str) -> None:
    """Read-only means the finding has to be actionable by a human.

    "Nothing may change vendor state" is only workable if the finding says
    precisely which object a person should go and change.
    """
    from app.services.access_review import FINDING_KINDS

    spec = FINDING_KINDS[kind]
    assert spec.object_hint, f"{kind} does not name the object to change"
    assert spec.recommendation
