"""UEBA must baseline non-human principals, not just people.

A service account or an AI agent runs continuously with standing credentials.
That is exactly the profile an attacker wants and exactly what nobody watches,
so these are the entities most in need of behavioural baselining rather than
least.

Only the HTTP scoring route constrained the value, to `^(user|device|ip)$`.
The constraint was also inconsistent with the rest of the service: the schema
column is a plain `String(32)` with no CHECK constraint, the Welford
statistics never inspect the type (it is an opaque partition key), and the
Kafka path already accepted any string — so an agent baseline could be created
by publishing to Kafka but not by calling the API.

The degenerate-variance handling added in v8.0 is what makes admitting them
safe, and its absence is why doing so earlier would have been actively
misleading. `compute_z_score` returns None rather than 0.0 when a feature has
no variance, and names the reason: a constant stream collapses the standard
deviation to zero, after which every subsequent value — however extreme — sits
zero deviations from the mean. Without that, every non-human principal would
have read as permanently normal.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.routes import ENTITY_TYPES, ScoreEventRequest
from pydantic import ValidationError


def _payload(entity_type: str) -> dict:
    return {
        "tenant_id": str(uuid.uuid4()),
        "entity_type": entity_type,
        "entity_id": "svc-nightly-backup",
        "event_type": "authentication",
        "features": {"hour_of_day": 3.0},
    }


# ── the regression ────────────────────────────────────────────────────────


@pytest.mark.parametrize("entity_type", ["service_account", "ai_agent", "mcp_server"])
def test_non_human_principals_are_accepted(entity_type: str):
    assert ScoreEventRequest(**_payload(entity_type)).entity_type == entity_type


@pytest.mark.parametrize("entity_type", ["user", "device", "ip"])
def test_the_original_types_still_work(entity_type: str):
    assert ScoreEventRequest(**_payload(entity_type)).entity_type == entity_type


def test_an_unknown_entity_type_is_still_refused():
    """The list widened; it did not become a free-text field.

    An unconstrained type would let a typo create a parallel baseline that
    silently accumulates nothing useful, which is worse than a 422.
    """
    with pytest.raises(ValidationError):
        ScoreEventRequest(**_payload("kitchen_sink"))


def test_the_pattern_is_derived_from_the_list():
    """So adding a kind to ENTITY_TYPES cannot forget to update the regex."""
    for entity_type in ENTITY_TYPES:
        assert ScoreEventRequest(**_payload(entity_type)).entity_type == entity_type


# ── the statistics must actually hold up for these entities ───────────────


def test_a_constant_stream_does_not_read_as_normal():
    """The property that makes non-human baselining meaningful at all.

    A service account authenticating at 03:00 every night has zero variance on
    `hour_of_day`. Returning 0.0 there would mean no observation could ever be
    anomalous; None means "unknown", which the caller excludes.
    """
    from app.services.baseline import compute_z_score

    # Enough samples to clear the minimum, but no variance at all.
    degenerate = {"hour_of_day": {"mean": 3.0, "std": 0.0, "count": 500}}
    assert compute_z_score(degenerate, "hour_of_day", 3.0) is None
    # And a wildly different value against the same degenerate baseline is
    # still unknown rather than confidently zero.
    assert compute_z_score(degenerate, "hour_of_day", 17.0) is None


def test_a_real_deviation_is_still_scored():
    from app.services.baseline import compute_z_score

    stats = {"hour_of_day": {"mean": 3.0, "std": 1.0, "count": 500}}
    score = compute_z_score(stats, "hour_of_day", 17.0)
    assert score is not None
    assert score > 3.0
