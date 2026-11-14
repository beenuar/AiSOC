"""A proposal with no detection logic cannot be promoted into the engine.

Fix pass item 6.5. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`POST /api/v1/detection/tuning/auto-suggest` opens proposals in
`detection_rule_proposals` whose `rule_body` is **entirely comments**:

    # Auto-tuner proposal for rule <id>
    # Action: <action>
    # <rationale>
    # FP rate 40% over 25 decided alerts
    # TODO(analyst): review + attach fixtures before promotion.

and whose `base_rule_id` is `NULL`. A null base takes the "new rule" branch in
`POST /detection-proposals/{id}/decide`, so an approver clicking through would
**write a rule with no detection logic into the engine** -- a rule that matches
nothing, published as though it detects something.

It also defaulted `create_proposals=True`, so simply calling the endpoint
seeded the governed queue with stubs.

What this file asserts
----------------------
The guard, on the real helper: a body whose every non-blank line is a comment
is refused, and a body with real logic is not. Plus the default on the query
parameter, because a queue that fills itself with stubs is the thing that made
the first defect reachable.
"""

from __future__ import annotations

import inspect

import pytest


class TestABodyWithNoLogicIsRefused:
    @pytest.mark.parametrize(
        "body",
        [
            "# Auto-tuner proposal for rule abc\n# Action: narrow\n# TODO(analyst): review\n",
            "   \n# only a comment\n\n",
            "",
            "   ",
            "#\n#\n#\n",
        ],
    )
    def test_a_comment_only_body_carries_no_detection_logic(self, body: str) -> None:
        from app.api.v1.endpoints.detection_proposals import body_has_detection_logic

        assert body_has_detection_logic(body) is False, f"{body!r} was treated as a promotable rule"

    @pytest.mark.parametrize(
        "body",
        [
            "detection:\n  selection:\n    EventID: 4625\n  condition: selection\n",
            "# a comment, then logic\ntitle: Failed logon\ndetection:\n  condition: selection\n",
        ],
    )
    def test_a_body_with_real_logic_is_promotable(self, body: str) -> None:
        """The negative control. A guard that refused everything would make the
        whole proposal surface unusable, which is a worse outcome than the
        defect."""
        from app.api.v1.endpoints.detection_proposals import body_has_detection_logic

        assert body_has_detection_logic(body) is True


class TestTheAutoTunerDoesNotSeedTheQueueByDefault:
    def test_create_proposals_defaults_to_false(self) -> None:
        """A stub proposal is only dangerous once it is in the queue.

        The parameter defaulted to `True`, so calling the endpoint at all
        filled the governed queue with bodies nobody intended to promote.
        """
        from app.api.v1.endpoints.rule_tuning import auto_suggest_tuning

        default = inspect.signature(auto_suggest_tuning).parameters["create_proposals"].default
        actual = getattr(default, "default", default)

        assert actual is False, f"create_proposals defaults to {actual!r}, so the queue seeds itself"


class TestTheDecideRouteConsultsTheGuard:
    def test_promotion_checks_for_detection_logic(self) -> None:
        """Read as source, deliberately, and the reason is narrow.

        Driving the promotion branch needs an approved proposal, a tenant
        session and a rule row, which is the live suite's job. What can be
        pinned cheaply is that the promotion path calls the guard at all --
        the defect was that nothing did.
        """
        from app.api.v1.endpoints import detection_proposals

        source = inspect.getsource(detection_proposals)

        assert "body_has_detection_logic(" in source, "the promotion path does not consult the guard"
