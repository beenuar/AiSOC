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
