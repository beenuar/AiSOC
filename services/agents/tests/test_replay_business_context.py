"""A replay applies the tenant's business-context rules, as production does.

Fix pass 3.1, agents half. `main.py` constructs a `BusinessContextApplier`
whenever the feature is enabled -- which is the default -- and hands it to
the triage worker, so every production verdict is reached with the tenant's
rules applied. The replay route constructed `ReplayRunner` with no
`business_context` at all, so a replay graded the agent in an estate with no
crown jewels, no known-noisy hosts and no suppressions.

That is not a neutral omission. Business-context rules mostly raise or lower
severity on specific assets, so a replay without them scores a different
agent than the one the tenant runs, and the report does not say so.

The rules travel in the frozen context rather than being read live, for the
same reason every other part of that snapshot does: a rule set edited after
the split must not decide a verdict about a window that closed before it.
`capture_context` applies the filter, so the route only has to hand the rows
over with their recorded time intact.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.api.replay_router import FrozenContext, _business_context_applier

#: The grammar the production worker parses: `id`, `when`, `then`. Written
#: out rather than built by a helper so a change to the grammar breaks this
#: test instead of silently passing an empty rule list.
_YAML = """
rules:
  - id: crown-jewels
    when:
      host: db-prod-1
    then:
      set_severity: critical
"""


class TestTheRunnerGetsTheTenantsRules:
    def test_an_enabled_rule_set_becomes_an_applier(self) -> None:
        context = FrozenContext(
            business_context={
                "yaml_text": _YAML,
                "enabled": True,
                "updated_at": "2026-01-20T00:00:00+00:00",
            }
        )

        applier = _business_context_applier(context, split_at=datetime(2026, 3, 1, tzinfo=UTC))

        assert applier is not None

    def test_no_rule_set_means_no_applier(self) -> None:
        """Absent is not the same as empty, and neither invents rules."""
        assert _business_context_applier(FrozenContext(), split_at=datetime(2026, 3, 1, tzinfo=UTC)) is None

    def test_a_disabled_rule_set_is_not_applied(self) -> None:
        """A tenant who turned their rules off is not silently opted back in."""
        context = FrozenContext(business_context={"yaml_text": _YAML, "enabled": False, "updated_at": "2026-01-20T00:00:00+00:00"})

        assert _business_context_applier(context, split_at=datetime(2026, 3, 1, tzinfo=UTC)) is None

    def test_a_rule_set_edited_after_the_split_is_dropped(self) -> None:
        """The same leakage rule every other part of the snapshot follows.

        A rule authored with hindsight about the window being graded would
        make the score a statement about the author, not the agent.
        """
        split = datetime(2026, 3, 1, tzinfo=UTC)
        context = FrozenContext(
            business_context={
                "yaml_text": _YAML,
                "enabled": True,
                "updated_at": (split + timedelta(days=5)).isoformat(),
            }
        )

        assert _business_context_applier(context, split_at=split) is None

    def test_an_undated_rule_set_is_kept(self) -> None:
        """Matches how `capture_context` treats an undated statement.

        Dropping it would silently under-apply context, which is the error
        this item exists to fix; keeping it is recorded behaviour rather
        than an accident.
        """
        context = FrozenContext(business_context={"yaml_text": _YAML, "enabled": True})

        assert _business_context_applier(context, split_at=datetime(2026, 3, 1, tzinfo=UTC)) is not None

    def test_unparseable_yaml_does_not_break_the_replay(self) -> None:
        """A bad rule set applies none, exactly as the worker does."""
        context = FrozenContext(business_context={"yaml_text": "rules: [[[", "enabled": True, "updated_at": "2026-01-20T00:00:00+00:00"})

        assert _business_context_applier(context, split_at=datetime(2026, 3, 1, tzinfo=UTC)) is None


@pytest.mark.parametrize("field", ["statements", "priors", "business_context"])
def test_the_frozen_context_model_carries_every_part(field: str) -> None:
    """The wire contract the API half of 3.1 writes to."""
    assert field in FrozenContext.model_fields
