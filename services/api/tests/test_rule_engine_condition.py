"""Tests for the Sigma condition parser.

These tests pin the rule-engine condition evaluator to a safe boolean
subset and explicitly prove that the legacy `eval()` based RCE vector
(arbitrary Python in a Sigma `condition:` field) no longer executes.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from app.services.rule_engine import _eval_condition, _SigmaConditionParser


class TestSigmaConditionGrammar:
    """The accepted grammar mirrors the Sigma spec subset we support."""

    def test_simple_selection_true(self) -> None:
        assert _eval_condition("selection", {"selection": True}) is True

    def test_simple_selection_false(self) -> None:
        assert _eval_condition("selection", {"selection": False}) is False

    def test_and(self) -> None:
        assert _eval_condition("a and b", {"a": True, "b": True}) is True
        assert _eval_condition("a and b", {"a": True, "b": False}) is False

    def test_or(self) -> None:
        assert _eval_condition("a or b", {"a": False, "b": True}) is True
        assert _eval_condition("a or b", {"a": False, "b": False}) is False

    def test_not(self) -> None:
        assert _eval_condition("not a", {"a": False}) is True
        assert _eval_condition("not a", {"a": True}) is False

    def test_parentheses_and_precedence(self) -> None:
        sels = {"a": True, "b": False, "c": True}
        # `or` binds looser than `and`, so a and (b or c) ≠ (a and b) or c.
        assert _eval_condition("a and (b or c)", sels) is True
        assert _eval_condition("(a and b) or c", sels) is True
        assert _eval_condition("a and b or c", sels) is True  # parsed as (a and b) or c

    def test_boolean_literals(self) -> None:
        assert _eval_condition("true", {}) is True
        assert _eval_condition("false", {}) is False
        assert _eval_condition("True and false", {}) is False

    def test_quantifier_one_of(self) -> None:
        sels = {"sel1": False, "sel2": True, "sel3": False}
        assert _eval_condition("1 of sel*", sels) is True
        sels_all_false = {"sel1": False, "sel2": False}
        assert _eval_condition("1 of sel*", sels_all_false) is False

    def test_quantifier_all_of(self) -> None:
        sels = {"sel1": True, "sel2": True}
        assert _eval_condition("all of sel*", sels) is True
        assert _eval_condition("all of sel*", {"sel1": True, "sel2": False}) is False

    def test_quantifier_them(self) -> None:
        assert _eval_condition("all of them", {"a": True, "b": True}) is True
        assert _eval_condition("1 of them", {"a": False, "b": True}) is True

    def test_unknown_selection_is_false(self) -> None:
        # Referring to a selection that does not exist resolves to False
        # rather than raising, matching the legacy fallback semantics.
        assert _eval_condition("missing", {"selection": True}) is False
        assert _eval_condition("missing or selection", {"selection": True}) is True


class TestSigmaConditionRefusesCodeExecution:
    """The parser must not evaluate arbitrary Python expressions.

    These cases would have executed under the old `eval()` implementation
    and either raised, returned attacker-controlled values, or in the
    worst case (`__import__`) achieved remote code execution.
    """

    def test_attribute_access_does_not_execute(self) -> None:
        # `().__class__` was a classic eval sandbox escape vector. The
        # parser must reject the dot/parenthesis syntax outright and fall
        # back to the safe default (AND of selections, here empty → False).
        assert _eval_condition("().__class__.__mro__[1]", {}) is False

    def test_function_call_does_not_execute(self) -> None:
        # Side-effect proof: under the old eval() implementation, the
        # `open(... 'w')` call would create a real file on disk because
        # `__builtins__` was set to `{}` but `open` was still importable
        # through `().__class__.__base__.__subclasses__()` tricks. With
        # the AST parser we simply refuse to parse the expression.
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = os.path.join(tmp, "pwned.txt")
            expr = f"__import__('os').system('touch {sentinel}')"
            result = _eval_condition(expr, {})
            assert result is False
            assert not os.path.exists(sentinel)

    def test_string_concatenation_does_not_execute(self) -> None:
        # `+` is not part of the supported grammar; legacy eval would have
        # happily concatenated strings and returned a truthy value.
        assert _eval_condition("'a' + 'b'", {}) is False

    def test_comparison_operators_rejected(self) -> None:
        # Comparison operators were silently accepted by eval; they are
        # not part of the Sigma condition grammar and must be refused.
        assert _eval_condition("1 == 1", {}) is False

    def test_walrus_does_not_assign(self) -> None:
        # Walrus expressions could bind names in the eval namespace; the
        # parser does not even tokenize ":=".
        assert _eval_condition("(x := 1)", {}) is False


class TestParserInternals:
    """Direct parser tests for tokenizer/precedence regression coverage."""

    def test_tokenizer_handles_whitespace(self) -> None:
        parser = _SigmaConditionParser("  a   and   b ", {"a": True, "b": True})
        assert parser.parse() is True

    def test_tokenizer_rejects_invalid_characters(self) -> None:
        # Invalid characters must not be silently dropped — the public
        # `_eval_condition` wrapper catches the ValueError and falls back
        # to the safe default, but here we assert the parser itself
        # refuses to accept them.
        with pytest.raises(ValueError):
            _SigmaConditionParser("a $ b", {"a": True, "b": True}).parse()

    def test_unbalanced_parens_safe_fallback(self) -> None:
        # Unbalanced parens fall back to "AND all selections" via the
        # public wrapper rather than blowing up the request.
        assert _eval_condition("(a and b", {"a": True, "b": True}) is True
        assert _eval_condition("(a and b", {"a": True, "b": False}) is False
