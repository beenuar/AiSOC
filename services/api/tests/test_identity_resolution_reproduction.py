"""Depth 2 Phase 3.1 reproduction: one person is six unrelated strings.

An alert names `alice@example.com` from Okta, `ALICE` from an EDR device
login, `arn:aws:iam::1:user/alice` from CloudTrail and `alice-gh` from a code
platform, and the platform treats them as four people. Nothing in the tree
links them, so a story cannot be built across sources and a privilege answer
about one does not reach an alert about another.

The failure mode to design against is not "no links", it is **wrong links**:
merging two people because their local-parts match destroys the thing the
feature exists to provide. So the shape has to carry a confidence and an
evidence list, and a low-confidence link must be visible and never used to
merge.

Fails on the pre-change tree. Kept afterwards as the guard.
"""

from __future__ import annotations

import pytest


def test_an_identity_resolution_module_exists() -> None:
    from app.services import identity_resolution

    assert hasattr(identity_resolution, "resolve_links")
    assert hasattr(identity_resolution, "LINK_RULES")


def test_every_source_the_plan_names_is_covered() -> None:
    from app.services.identity_resolution import SOURCE_KINDS

    required = {"idp", "edr_device_user", "proxy_user", "cloud_principal", "code_platform", "workspace"}
    assert required <= set(SOURCE_KINDS), f"missing: {sorted(required - set(SOURCE_KINDS))}"


def test_a_link_carries_confidence_and_evidence() -> None:
    from app.services.identity_resolution import IdentityLink

    link = IdentityLink(
        left="okta:alice@example.com",
        right="aws:arn:aws:iam::1:user/alice",
        confidence=0.95,
        rule="verified_email_match",
        evidence=["both principals carry the verified address alice@example.com"],
    )
    assert 0.0 <= link.confidence <= 1.0
    assert link.evidence
    assert link.as_dict()["rule"] == "verified_email_match"


def test_a_low_confidence_link_is_shown_but_never_merged() -> None:
    """The property the whole item turns on.

    A weak link is useful to an analyst looking at a story and dangerous to
    anything that merges. Both halves have to be true at once: visible, and
    not acted on.
    """
    from app.services.identity_resolution import MERGE_THRESHOLD, resolve_links

    result = resolve_links(
        [
            {"source": "idp", "id": "alice@example.com", "display_name": "Alice Smith"},
            # Same local part, different domain, no other corroboration. This
            # is the canonical wrong merge: `alice@contoso.com` is routinely
            # a different person.
            {"source": "workspace", "id": "alice@contoso.com"},
        ]
    )
    weak = [link for link in result.links if link.confidence < MERGE_THRESHOLD]
    assert weak, "the weak link was dropped entirely; it must be shown"
    assert all(not link.merged for link in weak)
    assert result.clusters_for_merge() == [], "a low-confidence link was used to merge"


def test_a_strong_link_does_merge() -> None:
    """The positive control for the test above.

    Without it, a resolver that linked nothing at all would pass the
    low-confidence assertion perfectly.
    """
    from app.services.identity_resolution import resolve_links

    result = resolve_links(
        [
            {"source": "idp", "id": "alice@example.com", "email": "alice@example.com", "email_verified": True},
            {
                "source": "cloud_principal",
                "id": "arn:aws:iam::1:user/alice",
                "email": "alice@example.com",
                "email_verified": True,
            },
        ]
    )
    assert any(link.merged for link in result.links)
    assert len(result.clusters_for_merge()) == 1


@pytest.mark.parametrize(
    "ids",
    [
        ["svc-deploy", "svc-deploy"],
        ["admin", "admin"],
    ],
)
def test_shared_generic_names_never_merge(ids: list[str]) -> None:
    """`admin` on two systems is two accounts, not one person.

    This is the merge that would silently join every tenant's local
    administrator into one identity and take the whole estate's alerts
    with it.
    """
    from app.services.identity_resolution import resolve_links

    result = resolve_links(
        [
            {"source": "edr_device_user", "id": ids[0]},
            {"source": "idp", "id": ids[1]},
        ]
    )
    assert result.clusters_for_merge() == []
