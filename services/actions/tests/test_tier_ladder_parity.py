"""The L0-L4 ladder is spelled in two places. They may not disagree.

``MaturityTier`` is the enum the dispatcher and the gate pass around.
``approval_rules`` repeats the same ladder as plain strings, because it may
not import ``app.services.maturity`` — that module is reached through the
dispatcher and importing it back would close the loop — and because the copy
``services/api`` vendors has no enum to reach at all.

A repetition nobody compares is a disagreement waiting to happen, and this one
decides whether a containment verb runs unattended. So compare it, in both
directions: a member added to the enum and a tier added to the tuple each have
to fail here.

The env parsing is checked the same way. Three readers answer "which tier did
the operator ask for": the dispatcher, the tenant-policy fallback, and now the
console through the vendored copy. ``tenant_policy`` keeps its own
implementation — it is imported *by* the dispatcher, so reaching into
``live_actions`` from it would be a cycle — which is exactly the arrangement
that needs a test rather than a convention.
"""

from __future__ import annotations

import pytest
from app.live_actions.approval_rules import (
    DEFAULT_TIER,
    EARNED_TIER_CEILING_LABEL,
    TIER_FULL_NAMES,
    TIER_LABELS,
    TIER_ORDER,
    tier_from_env_value,
)
from app.live_actions.dispatcher import EARNED_TIER_CEILING, configured_tier
from app.services.maturity import MaturityTier
from app.services.tenant_policy import UNREADABLE_POLICY_FLOOR, _env_tier

#: Every spelling the dispatcher has always accepted, plus the ways an
#: operator gets it wrong. A typo must never grant autonomy nobody asked for,
#: so the unrecognised cases are here deliberately.
ENV_VALUES = (
    "",
    "   ",
    "L0",
    "L1",
    "L2",
    "L3",
    "L4",
    "l2",
    " l3 ",
    "L0_OBSERVE",
    "L1_NOTIFY",
    "L2_CONTAIN",
    "L3_REMEDIATE",
    "L4_AUTOMATE",
    "0",
    "1",
    "2",
    "3",
    "4",
    "L5",
    "5",
    "TOTALLY_AUTONOMOUS",
    "AUTOMATE",
)


def test_the_two_ladders_have_the_same_tiers() -> None:
    assert len(TIER_ORDER) == len(TIER_FULL_NAMES) == len(MaturityTier)
    assert tuple(member.name for member in MaturityTier) == TIER_FULL_NAMES
    assert tuple(member.name.split("_")[0] for member in MaturityTier) == TIER_ORDER


def test_a_tier_index_is_its_enum_value() -> None:
    """``MaturityTier(TIER_ORDER.index(t))`` is how the dispatcher converts."""
    for index, short in enumerate(TIER_ORDER):
        assert MaturityTier(index).name.split("_")[0] == short
        assert MaturityTier[TIER_FULL_NAMES[index]].value == index


def test_the_labels_are_the_enum_labels() -> None:
    assert set(TIER_LABELS) == set(TIER_ORDER)
    for member in MaturityTier:
        assert TIER_LABELS[member.name.split("_")[0]] == member.label


@pytest.mark.parametrize("raw", ENV_VALUES)
def test_every_reader_of_the_tier_variable_agrees(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_MATURITY_TIER", raw)
    shared, _recognised = tier_from_env_value(raw)

    assert configured_tier().name.split("_")[0] == shared
    assert _env_tier().name.split("_")[0] == shared


def test_an_unparseable_value_falls_back_rather_than_up() -> None:
    for raw in ("L5", "5", "TOTALLY_AUTONOMOUS", "AUTOMATE"):
        tier, recognised = tier_from_env_value(raw)
        assert recognised is False
        assert tier == DEFAULT_TIER


def test_the_default_and_the_unreadable_floor_are_the_same_tier() -> None:
    """Both mean "notify, do not act". Two literals would let one move."""
    assert DEFAULT_TIER == "L1"
    assert UNREADABLE_POLICY_FLOOR.name.split("_")[0] == DEFAULT_TIER


def test_the_earned_ceiling_label_is_the_dispatcher_ceiling() -> None:
    """A grant may lift a verb to L3 and no further, wherever it is read."""
    assert EARNED_TIER_CEILING.name.split("_")[0] == EARNED_TIER_CEILING_LABEL
    assert EARNED_TIER_CEILING is MaturityTier.L3_REMEDIATE
