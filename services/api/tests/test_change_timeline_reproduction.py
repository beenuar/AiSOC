"""Depth 2 Phase 1.5 reproduction: nothing answers "what changed before this".

The question an analyst asks first about an identity alert is what changed
in the days before it: a role granted, a policy edited, an OAuth app
consented to, an MFA factor replaced, a share opened, a key created. Both
halves of the answer are already in the platform — versioned posture
snapshots since migration 103, and the audit events the lake holds — and
nothing joins them.

Fails on the pre-change tree for that reason, and keeps two honesty
properties afterwards: a window with no recorded change must be
distinguishable from a window nobody could read, and every change returned
must carry the source it came from so the ledger citation can be checked.
"""

from __future__ import annotations


def test_a_change_timeline_module_exists() -> None:
    from app.services import change_timeline

    assert hasattr(change_timeline, "changes_before")
    assert hasattr(change_timeline, "CHANGE_KINDS")


def test_every_change_kind_the_plan_names_is_covered() -> None:
    from app.services.change_timeline import CHANGE_KINDS

    required = {
        "role_or_group_grant",
        "policy_edit",
        "oauth_consent",
        "mfa_factor_change",
        "sharing_change",
        "key_creation",
    }
    assert required <= set(CHANGE_KINDS), f"missing: {sorted(required - set(CHANGE_KINDS))}"


def test_the_typed_pivot_is_registered() -> None:
    """A tool nobody is offered is not a tool."""
    from app.services import investigation_tools

    assert "changes_before_alert" in investigation_tools.TOOLS


def test_no_changes_is_distinguishable_from_could_not_read() -> None:
    """The two readings call for opposite conclusions.

    "Nothing changed in the window" is evidence. "We could not read the
    window" is a gap. A result shape that renders both as an empty list
    turns the second into the first, and an investigation closes on it.
    """
    from app.services.change_timeline import ChangeTimeline

    quiet = ChangeTimeline(changes=[], sources_read=("posture", "audit"))
    blind = ChangeTimeline(changes=[], sources_read=())

    assert quiet.measured is True
    assert blind.measured is False
    assert blind.as_dict()["reason"]


def test_every_change_names_its_source() -> None:
    """A citation whose target nobody can find is not a citation."""
    from app.services.change_timeline import IdentityChange

    change = IdentityChange(
        kind="policy_edit",
        at="2026-10-01T00:00:00+00:00",
        subject="arn:aws:iam::1:user/alice",
        summary="policy p1 edited",
        source="posture_snapshot",
        source_ref="snapshot:abc123",
    )
    assert change.source and change.source_ref
    assert change.as_dict()["source_ref"] == "snapshot:abc123"
