"""
Unit tests for playbook engine correctness fixes.

These tests pin down behavior of the helper functions and ``PlaybookEngine.run``
that were silently broken before ``fix/playbook-engine-correctness``:

1. Expression-string conditions were silently always-true (only field/op/value
   were evaluated).
2. ``gt``/``lt`` crashed on non-numeric values via ``float(value or 0)``.
3. ``contains`` couldn't express list-membership (``severity in [...]``).
4. Context flattening used ``setdefault``, so later steps couldn't refine
   values set earlier (e.g. enrichment overwriting a placeholder ``user_id``).
5. ``_resolve_field`` couldn't traverse list indices (``entities.0.name``).

Tests avoid any network I/O by stubbing ``_emit`` so the realtime POST never
fires.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.playbook import engine as engine_mod
from app.playbook.engine import (
    PlaybookEngine,
    RunStatus,
    StepStatus,
    _evaluate_condition,
    _evaluate_expression,
    _resolve_field,
    _to_float,
)
from app.playbook.models import Playbook, PlaybookStep, StepCondition, StepType

# ---------------------------------------------------------------------------
# _resolve_field
# ---------------------------------------------------------------------------


class TestResolveField:
    def test_returns_none_for_empty_field(self) -> None:
        assert _resolve_field({"a": 1}, "") is None

    def test_top_level_key(self) -> None:
        assert _resolve_field({"severity": "high"}, "severity") == "high"

    def test_nested_dict_path(self) -> None:
        ctx = {"alert": {"severity": "high"}}
        assert _resolve_field(ctx, "alert.severity") == "high"

    def test_missing_key_returns_none(self) -> None:
        assert _resolve_field({"alert": {}}, "alert.severity") is None

    def test_traverses_list_index(self) -> None:
        ctx = {"entities": [{"name": "alice"}, {"name": "bob"}]}
        assert _resolve_field(ctx, "entities.0.name") == "alice"
        assert _resolve_field(ctx, "entities.1.name") == "bob"

    def test_negative_list_index(self) -> None:
        ctx = {"entities": ["a", "b", "c"]}
        assert _resolve_field(ctx, "entities.-1") == "c"

    def test_out_of_range_list_index_returns_none(self) -> None:
        ctx = {"entities": ["a"]}
        assert _resolve_field(ctx, "entities.5") is None

    def test_non_numeric_index_on_list_returns_none(self) -> None:
        ctx = {"entities": ["a", "b"]}
        assert _resolve_field(ctx, "entities.name") is None

    def test_traversal_into_scalar_returns_none(self) -> None:
        # Can't drill into a string with a dot-path.
        assert _resolve_field({"name": "alice"}, "name.first") is None


# ---------------------------------------------------------------------------
# _to_float
# ---------------------------------------------------------------------------


class TestToFloat:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (None, 0.0),
            ("", 0.0),
            (0, 0.0),
            (42, 42.0),
            (3.14, 3.14),
            ("7", 7.0),
            ("7.5", 7.5),
            (True, 1.0),
            (False, 0.0),
        ],
    )
    def test_coerces(self, value: Any, expected: float) -> None:
        assert _to_float(value) == expected

    @pytest.mark.parametrize("value", ["abc", "1.2.3", [1, 2], {"a": 1}, object()])
    def test_returns_none_for_non_numeric(self, value: Any) -> None:
        assert _to_float(value) is None


# ---------------------------------------------------------------------------
# _evaluate_condition — structured form
# ---------------------------------------------------------------------------


class TestEvaluateConditionStructured:
    def test_empty_condition_passes(self) -> None:
        # No field, no expression → treated as "no gate".
        assert _evaluate_condition(StepCondition(), {}) is True

    def test_eq(self) -> None:
        cond = StepCondition(field="severity", operator="eq", value="high")
        assert _evaluate_condition(cond, {"severity": "high"}) is True
        assert _evaluate_condition(cond, {"severity": "low"}) is False

    def test_ne(self) -> None:
        cond = StepCondition(field="severity", operator="ne", value="low")
        assert _evaluate_condition(cond, {"severity": "high"}) is True
        assert _evaluate_condition(cond, {"severity": "low"}) is False

    def test_exists_true_for_present_value(self) -> None:
        cond = StepCondition(field="user_id", operator="exists")
        assert _evaluate_condition(cond, {"user_id": "u1"}) is True

    def test_exists_false_for_missing_value(self) -> None:
        cond = StepCondition(field="user_id", operator="exists")
        assert _evaluate_condition(cond, {}) is False

    def test_contains_substring(self) -> None:
        cond = StepCondition(field="message", operator="contains", value="error")
        assert _evaluate_condition(cond, {"message": "fatal error: boom"}) is True
        assert _evaluate_condition(cond, {"message": "all good"}) is False

    def test_contains_supports_list_membership(self) -> None:
        # This is the SOAR-classic case: ``severity in ["high","critical"]``.
        # Pre-fix this returned False because ``["high","critical"] in
        # str(value)`` raised TypeError or always coerced to False.
        cond = StepCondition(field="severity", operator="contains", value=["high", "critical"])
        assert _evaluate_condition(cond, {"severity": "high"}) is True
        assert _evaluate_condition(cond, {"severity": "critical"}) is True
        assert _evaluate_condition(cond, {"severity": "low"}) is False

    def test_contains_missing_field_is_false(self) -> None:
        cond = StepCondition(field="severity", operator="contains", value=["high"])
        assert _evaluate_condition(cond, {}) is False

    def test_gt_lt_numeric(self) -> None:
        gt = StepCondition(field="score", operator="gt", value=50)
        lt = StepCondition(field="score", operator="lt", value=50)
        assert _evaluate_condition(gt, {"score": 80}) is True
        assert _evaluate_condition(gt, {"score": 20}) is False
        assert _evaluate_condition(lt, {"score": 20}) is True
        assert _evaluate_condition(lt, {"score": 80}) is False

    def test_gt_lt_does_not_crash_on_non_numeric(self) -> None:
        # Pre-fix: ``float("abc" or 0)`` → ValueError. Now: False.
        cond = StepCondition(field="score", operator="gt", value=10)
        assert _evaluate_condition(cond, {"score": "not-a-number"}) is False

        cond = StepCondition(field="score", operator="lt", value="also-not-a-number")
        assert _evaluate_condition(cond, {"score": 50}) is False

    def test_gt_lt_missing_field_treated_as_zero(self) -> None:
        # Historical "missing means zero" semantics for numeric comparisons.
        cond = StepCondition(field="score", operator="gt", value=-1)
        assert _evaluate_condition(cond, {}) is True
        cond = StepCondition(field="score", operator="lt", value=1)
        assert _evaluate_condition(cond, {}) is True

    def test_unknown_operator_is_false(self) -> None:
        # Pydantic's Literal blocks construction, so bypass with model_construct.
        cond = StepCondition.model_construct(field="x", operator="weird", value=1)
        assert _evaluate_condition(cond, {"x": 1}) is False


# ---------------------------------------------------------------------------
# _evaluate_condition — expression form (the silently-always-true regression)
# ---------------------------------------------------------------------------


class TestEvaluateConditionExpressionForm:
    def test_expression_takes_precedence_over_blank_field(self) -> None:
        # Pre-fix this branch was never taken — expression was ignored entirely
        # and the (empty field, eq, None) form silently evaluated to True
        # because ``None == None``.
        cond = StepCondition(expression="severity == 'high'")
        assert _evaluate_condition(cond, {"severity": "high"}) is True
        assert _evaluate_condition(cond, {"severity": "low"}) is False

    def test_expression_false_path_actually_fires(self) -> None:
        cond = StepCondition(expression="score > 100")
        assert _evaluate_condition(cond, {"score": 5}) is False


# ---------------------------------------------------------------------------
# _evaluate_expression
# ---------------------------------------------------------------------------


class TestEvaluateExpression:
    @pytest.mark.parametrize(
        "expr,ctx,expected",
        [
            ("severity == 'high'", {"severity": "high"}, True),
            ('severity == "critical"', {"severity": "critical"}, True),
            ("severity != 'low'", {"severity": "high"}, True),
            ("score > 10", {"score": 50}, True),
            ("score >= 50", {"score": 50}, True),
            ("score <= 50", {"score": 50}, True),
            ("score < 10", {"score": 50}, False),
            ("severity in ['high','critical']", {"severity": "critical"}, True),
            ("severity in ['high','critical']", {"severity": "low"}, False),
            ("severity not in ['low','info']", {"severity": "high"}, True),
            ("severity not in ['low','info']", {"severity": "low"}, False),
        ],
    )
    def test_common_operators(self, expr: str, ctx: dict, expected: bool) -> None:
        assert _evaluate_expression(expr, ctx) is expected

    def test_is_null_sugar(self) -> None:
        assert _evaluate_expression("user_id is null", {}) is True
        assert _evaluate_expression("user_id is null", {"user_id": "u1"}) is False

    def test_is_not_null_sugar(self) -> None:
        assert _evaluate_expression("user_id is not null", {"user_id": "u1"}) is True
        assert _evaluate_expression("user_id is not null", {}) is False

    def test_equality_against_null_literal(self) -> None:
        assert _evaluate_expression("user_id == null", {}) is True
        assert _evaluate_expression("user_id != null", {"user_id": "u1"}) is True

    def test_dot_path_resolution(self) -> None:
        ctx = {"alert": {"severity": "high"}}
        assert _evaluate_expression("alert.severity == 'high'", ctx) is True

    def test_list_index_resolution(self) -> None:
        ctx = {"entities": [{"name": "alice"}]}
        assert _evaluate_expression("entities.0.name == 'alice'", ctx) is True

    def test_numeric_literal_int_and_float(self) -> None:
        assert _evaluate_expression("score == 42", {"score": 42}) is True
        assert _evaluate_expression("score == 3.14", {"score": 3.14}) is True

    def test_bool_literal(self) -> None:
        assert _evaluate_expression("flag == true", {"flag": True}) is True
        assert _evaluate_expression("flag == false", {"flag": False}) is True

    def test_malformed_returns_false(self) -> None:
        assert _evaluate_expression("this is not an expression", {}) is False
        assert _evaluate_expression("", {}) is False
        assert _evaluate_expression(None, {}) is False  # type: ignore[arg-type]

    def test_gt_on_non_numeric_returns_false(self) -> None:
        assert _evaluate_expression("severity > 'low'", {"severity": "high"}) is False


# ---------------------------------------------------------------------------
# PlaybookEngine.run — context-flattening override behavior
# ---------------------------------------------------------------------------


def _make_playbook(steps: list[PlaybookStep]) -> Playbook:
    return Playbook(name="test-pb", steps=steps)


@pytest.fixture(autouse=True)
def _silence_realtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub out ``_emit`` so engine.run() never tries to POST to the realtime
    service during tests."""
    monkeypatch.setattr(engine_mod, "_emit", AsyncMock(return_value=None))


@pytest.fixture
def patch_handlers():
    """Helper to temporarily inject handlers into ``_HANDLERS``."""

    saved: dict = {}

    def _install(mapping: dict) -> None:
        for k, v in mapping.items():
            saved[k] = engine_mod._HANDLERS.get(k)
            engine_mod._HANDLERS[k] = v

    yield _install

    for k, v in saved.items():
        if v is None:
            engine_mod._HANDLERS.pop(k, None)
        else:
            engine_mod._HANDLERS[k] = v


class TestEngineContextFlattening:
    @pytest.mark.asyncio
    async def test_later_step_can_override_earlier_flattened_value(self, patch_handlers) -> None:
        """An enrichment step should be able to refine a placeholder value set
        by an earlier step. Pre-fix, ``setdefault`` froze the first writer."""

        async def enrich_handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
            # Second step "resolves" the user_id placeholder.
            return {"user_id": "u-canonical-123"}

        # First step writes a placeholder via its handler.
        async def placeholder_handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
            return {"user_id": "u-placeholder"}

        patch_handlers(
            {
                StepType.HTTP: placeholder_handler,
                StepType.ENRICH: enrich_handler,
            }
        )

        pb = _make_playbook(
            [
                PlaybookStep(id="s1", name="placeholder", type=StepType.HTTP),
                PlaybookStep(id="s2", name="enrich", type=StepType.ENRICH),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={})

        assert run.status == RunStatus.COMPLETED
        # The second step's value wins.
        assert run.context["user_id"] == "u-canonical-123"
        # Namespaced keys preserve per-step history.
        assert run.context["_step_s1"]["user_id"] == "u-placeholder"
        assert run.context["_step_s2"]["user_id"] == "u-canonical-123"

    @pytest.mark.asyncio
    async def test_underscore_keys_are_not_auto_flattened(self, patch_handlers) -> None:
        async def handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
            return {"public": "yes", "_private": "no"}

        patch_handlers({StepType.HTTP: handler})

        pb = _make_playbook([PlaybookStep(id="s1", name="h", type=StepType.HTTP)])
        run = await PlaybookEngine().run(pb, trigger_context={})

        assert run.context["public"] == "yes"
        assert "_private" not in run.context  # bookkeeping keys stay namespaced
        assert run.context["_step_s1"]["_private"] == "no"


class TestEngineConditionGate:
    """Round-trip the expression-form fix through the engine to confirm a
    falsy expression actually skips a step (previously it silently always
    passed)."""

    @pytest.mark.asyncio
    async def test_expression_condition_skips_step_when_false(self, patch_handlers) -> None:
        called = {"hit": False}

        async def handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
            called["hit"] = True
            return {"ok": True}

        patch_handlers({StepType.NOTIFY: handler})

        pb = _make_playbook(
            [
                PlaybookStep(
                    id="s1",
                    name="notify-on-critical",
                    type=StepType.NOTIFY,
                    condition=StepCondition(expression="severity == 'critical'"),
                ),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={"severity": "low"})

        assert called["hit"] is False
        assert run.step_results[0]["status"] == StepStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_expression_condition_runs_step_when_true(self, patch_handlers) -> None:
        called = {"hit": False}

        async def handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
            called["hit"] = True
            return {"ok": True}

        patch_handlers({StepType.NOTIFY: handler})

        pb = _make_playbook(
            [
                PlaybookStep(
                    id="s1",
                    name="notify-on-critical",
                    type=StepType.NOTIFY,
                    condition=StepCondition(expression="severity == 'critical'"),
                ),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={"severity": "critical"})

        assert called["hit"] is True
        assert run.step_results[0]["status"] == StepStatus.SUCCESS


# ---------------------------------------------------------------------------
# PlaybookEngine.run — step types the engine cannot run must not report success
# ---------------------------------------------------------------------------
#
# Twelve of the twenty-two StepType members had no entry in ``_HANDLERS``.
# The run loop answered those with ``{"skipped": True}`` and left
# ``step_status`` at its SUCCESS default, so a playbook containing them ran to
# RunStatus.COMPLETED having done nothing that it said it did.
#
# ``approval`` is the one that matters most: it is a human decision point, it
# appears in 14 steps across the shipped packs, and it passed on its own —
# the run continued straight into the action an analyst was meant to
# authorise. "Unverifiable means not autonomous" applies to a gate that
# cannot be evaluated as much as to an action that cannot be verified.


class TestUnimplementedStepTypesFailClosed:
    @pytest.mark.asyncio
    async def test_an_approval_gate_the_engine_cannot_honour_halts_the_run(self) -> None:
        """Fails against the pre-change tree, which reported SUCCESS/COMPLETED."""
        pb = _make_playbook(
            [
                PlaybookStep(id="gate", name="Analyst approves isolation", type=StepType.APPROVAL),
                PlaybookStep(id="act", name="Isolate the host", type=StepType.ISOLATE_HOST),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={})

        assert run.step_results[0]["status"] == StepStatus.FAILED
        assert run.step_results[0]["result"]["unimplemented"] is True
        assert "approval" in run.step_results[0]["result"]["error"]
        assert run.status == RunStatus.FAILED
        # The whole point: the step behind the gate must not have run.
        assert len(run.step_results) == 1, "execution continued past a gate that was never granted"

    @pytest.mark.asyncio
    async def test_no_step_type_reports_success_without_a_handler(self) -> None:
        """Every StepType with no handler, not just the one that hurt most."""
        unimplemented = [st for st in StepType if st not in engine_mod._HANDLERS and st != StepType.CONDITION]
        assert unimplemented, "fixture assumption broken: expected some StepType to lack a handler"

        for step_type in unimplemented:
            pb = _make_playbook([PlaybookStep(id="s1", name=f"step {step_type.value}", type=step_type)])
            run = await PlaybookEngine().run(pb, trigger_context={})

            result = run.step_results[0]
            assert result["status"] == StepStatus.FAILED, f"{step_type.value} reported {result['status']} with no handler"
            assert result["result"].get("unimplemented") is True
            assert run.status == RunStatus.FAILED

    @pytest.mark.asyncio
    async def test_a_missing_handler_is_not_retried(self) -> None:
        """A handler that does not exist will not exist next attempt either;
        retrying just delays the failure by up to 2**retry_max seconds."""
        pb = _make_playbook([PlaybookStep(id="s1", name="scan", type=StepType.RUN_AV_SCAN, retry_max=3)])

        run = await PlaybookEngine().run(pb, trigger_context={})

        assert run.step_results[0]["status"] == StepStatus.FAILED
        assert run.step_results[0]["result"]["_elapsed_ms"] == 0

    @pytest.mark.asyncio
    async def test_on_failure_continue_lets_the_run_proceed_without_calling_it_completed(self) -> None:
        """``continue`` decides whether the run keeps going, not what it is called.

        346 of the 380 steps in the shipped packs carry ``on_failure:
        continue``, so treating it as "report this run as completed" would put
        a green tick over a containment that never happened — which is the
        same fake success, moved up one level from the step to the run.
        """
        pb = _make_playbook(
            [
                PlaybookStep(id="s1", name="best-effort scan", type=StepType.RUN_AV_SCAN, on_failure="continue"),
                PlaybookStep(id="s2", name="second step", type=StepType.RUN_SCRIPT, on_failure="continue"),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={})

        assert len(run.step_results) == 2, "the author said continue; both steps must be attempted"
        assert all(r["status"] == StepStatus.FAILED for r in run.step_results)
        assert run.status == RunStatus.FAILED
        assert run.error and "2 of 2 steps failed" in run.error

    @pytest.mark.asyncio
    async def test_a_dry_run_says_which_steps_would_fail(self) -> None:
        """A dry run exists to tell the author what would happen. Reporting a
        bare ``dry_run: true`` for a step that cannot execute would imply it
        is fine."""
        pb = _make_playbook(
            [
                PlaybookStep(id="s1", name="notify", type=StepType.NOTIFY),
                PlaybookStep(id="s2", name="gate", type=StepType.APPROVAL),
            ]
        )

        run = await PlaybookEngine().run(pb, trigger_context={}, dry_run=True)

        assert run.status == RunStatus.COMPLETED
        assert run.step_results[0]["result"].get("unimplemented") is None
        assert run.step_results[1]["result"]["unimplemented"] is True
        assert run.step_results[1]["result"]["would_fail"] is True
