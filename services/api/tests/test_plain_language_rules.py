"""Plain-language business-context rules compile to the schema that runs.

Wave 2, Phase 4.3.

Two properties are under test, and they are different claims:

1. **The sentence compiles to the structured rule an author meant.** Asserted
   by round-tripping every compiled rule through
   :func:`~app.services.business_context.models.load_rules_from_yaml` — the
   *real* parser both engines read, not a copy of it. A compiler whose output
   only its own test accepts is the "two producers compared against each
   other" shape; this compares against the consumer.

2. **An ambiguous or unsupported sentence is refused, not approximated.** The
   failure this guards is the `neq` one from the engines: a rule that parses,
   saves, and silently never matches. Here the equivalents are a comparator
   with no evaluator behind it, a mixed and/or that has two readings, and a
   field name that is not a field path.

No model is involved anywhere in this path, which is the plan's hard
constraint for the item: a tenant's free text cannot become an instruction if
nothing ever sends it to a model.
"""

from __future__ import annotations

import pytest
from app.services.business_context.models import (
    ALLOWED_OPS,
    ALLOWED_SEVERITIES,
    RuleParseError,
    load_rules_from_yaml,
)
from app.services.business_context.plain_language import (
    PlainLanguageError,
    compile_plain_language,
    operator_phrase_targets,
    unsupported_phrase_targets,
)

try:  # pragma: no cover - exercised by whichever branch the environment takes
    import yaml as _yaml
except ModuleNotFoundError:  # pragma: no cover
    _yaml = None  # type: ignore[assignment]


def _round_trip(compiled) -> None:
    """The compiled rule must survive the parser the engines actually use."""
    if _yaml is None:  # pragma: no cover
        pytest.skip("PyYAML not installed in this environment")
    rules = load_rules_from_yaml(_yaml.safe_dump({"rules": [compiled.rule]}))
    assert len(rules) == 1
    assert rules[0].id == compiled.rule["id"]


# ── The grammar produces only comparators that exist ────────────────────────


def test_every_phrase_maps_to_a_real_operator():
    """A phrase pointing at a comparator no evaluator implements is a rule
    that saves and never fires — exactly the `neq` defect, one layer up."""
    assert operator_phrase_targets() <= set(ALLOWED_OPS)


def test_neq_is_not_reachable_from_any_phrase():
    """`neq` is the recorded trap: not an operator, silently never matches."""
    assert "neq" not in operator_phrase_targets()
    assert "neq" not in ALLOWED_OPS


def test_unsupported_phrases_are_declared_rather_than_silently_missing():
    """Phrases that read as English but have no comparator are named.

    "does not contain" is the motivating case: refusing it with "not
    understood" sends an author hunting for a typo that is not there.
    """
    assert unsupported_phrase_targets()
    assert unsupported_phrase_targets().isdisjoint(set(ALLOWED_OPS))


# ── Compiling ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("sentence", "expected_op", "expected_value"),
    [
        ("if severity is critical then route to tier3", "eq", "critical"),
        ("when severity is not critical then tag noisy", "ne", "critical"),
        ("if risk_score is at least 80 then set severity to high", "gte", 80),
        ("if risk_score is more than 80 then set severity to high", "gt", 80),
        ("if risk_score is less than 10 then suppress", "lt", 10),
        ("if host.name starts with prod- then set severity to high", "startswith", "prod-"),
        ("if host.name ends with .internal then tag internal", "endswith", ".internal"),
        ("if message contains ransomware then set severity to critical", "contains", "ransomware"),
        ("if user.department is one of finance, legal then route to tier3", "in", ["finance", "legal"]),
        ("if user.department is none of finance, legal then route to tier1", "not_in", ["finance", "legal"]),
        ("if host.owner exists then tag owned", "exists", None),
        ("if host.owner is missing then tag unowned", "not_exists", None),
    ],
)
def test_sentences_compile_to_the_expected_leaf(sentence, expected_op, expected_value):
    compiled = compile_plain_language(sentence, rule_id="test-rule")
    leaf = compiled.rule["when"]
    assert leaf["op"] == expected_op
    if expected_value is None:
        assert "value" not in leaf
    else:
        assert leaf["value"] == expected_value
    _round_trip(compiled)


def test_the_article_in_front_of_a_field_is_tolerated():
    """An author writes "the host is ..."; refusing that is pedantry."""
    compiled = compile_plain_language("if the severity is critical then suppress", rule_id="test-rule")
    assert compiled.rule["when"]["field"] == "severity"


def test_quoted_values_stay_strings():
    """Quoting is how an author says "literally this", including digits."""
    compiled = compile_plain_language('if asset.tag is "2024" then tag legacy', rule_id="test-rule")
    assert compiled.rule["when"]["value"] == "2024"


def test_and_compiles_to_all():
    compiled = compile_plain_language(
        "if severity is critical and user.department is finance then route to tier3",
        rule_id="test-rule",
    )
    assert set(compiled.rule["when"]) == {"all"}
    assert len(compiled.rule["when"]["all"]) == 2
    _round_trip(compiled)


def test_or_compiles_to_any():
    compiled = compile_plain_language(
        "if severity is critical or severity is high then route to tier2",
        rule_id="test-rule",
    )
    assert set(compiled.rule["when"]) == {"any"}
    _round_trip(compiled)


def test_negation_compiles_to_not():
    compiled = compile_plain_language(
        "if not (message contains backup) then set severity to high",
        rule_id="test-rule",
    )
    assert set(compiled.rule["when"]) == {"not"}
    _round_trip(compiled)


def test_multiple_actions_compile_together():
    compiled = compile_plain_language(
        "if severity is critical then set severity to high and tag downgraded",
        rule_id="test-rule",
    )
    assert compiled.rule["then"]["set_severity"] == "high"
    assert compiled.rule["then"]["tag"] == "downgraded"
    _round_trip(compiled)


def test_fields_referenced_are_reported_for_the_preview():
    """The preview's answer to "will this ever match?".

    Fields are not a closed set — they depend on a tenant's connectors — so
    the compiler reports them and the route measures their coverage against
    real alerts, rather than a hardcoded list refusing valid paths.
    """
    compiled = compile_plain_language(
        "if user.department is finance and host.name starts with prod- then route to tier3",
        rule_id="test-rule",
    )
    assert compiled.fields_referenced == ("user.department", "host.name")


def test_suppress_with_another_action_warns_rather_than_silently_winning():
    compiled = compile_plain_language("if severity is low then suppress and tag ignored", rule_id="test-rule")
    assert compiled.rule["then"]["suppress"] is True
    assert any("dropped before triage" in w for w in compiled.warnings)


# ── Refusals ────────────────────────────────────────────────────────────────


def test_or_inside_a_list_is_refused_with_the_comma_form_named():
    """`or` is the boolean joiner, so "is one of a or b" is two conditions.

    Found by the round-trip test rather than by reading: the sentence split
    into a condition and the bare word "legal", which failed downstream with
    "no comparison found" — true, and useless to the author.
    """
    with pytest.raises(PlainLanguageError, match="commas"):
        compile_plain_language(
            "if user.department is one of finance or legal then route to tier3",
            rule_id="test-rule",
        )


def test_mixed_and_or_is_refused_rather_than_guessed():
    """ "a and b or c" has two readings; picking one silently is how a rule
    comes to mean something its author did not write."""
    with pytest.raises(PlainLanguageError, match="ambiguous"):
        compile_plain_language(
            "if severity is critical and user.department is finance or host.name is db1 then suppress",
            rule_id="test-rule",
        )


def test_does_not_contain_is_refused_with_the_workaround_named():
    with pytest.raises(PlainLanguageError, match="no 'does not contain' comparator"):
        compile_plain_language("if message does not contain backup then set severity to high", rule_id="test-rule")


def test_an_unknown_severity_is_refused_with_the_vocabulary():
    with pytest.raises(PlainLanguageError) as exc:
        compile_plain_language("if severity is critical then set severity to urgent", rule_id="test-rule")
    assert all(level in str(exc.value) for level in ALLOWED_SEVERITIES)


def test_an_unknown_route_is_refused_with_the_vocabulary():
    with pytest.raises(PlainLanguageError, match="not a routing destination"):
        compile_plain_language("if severity is critical then route to nowhere", rule_id="test-rule")


def test_a_field_that_is_not_a_path_is_refused():
    with pytest.raises(PlainLanguageError, match="not a field path"):
        compile_plain_language('if "some free text" is critical then suppress', rule_id="test-rule")


def test_a_missing_then_clause_is_refused():
    with pytest.raises(PlainLanguageError, match="'then' clause"):
        compile_plain_language("if severity is critical", rule_id="test-rule")


def test_a_missing_opener_is_refused():
    with pytest.raises(PlainLanguageError, match="start with"):
        compile_plain_language("severity is critical then suppress", rule_id="test-rule")


def test_an_action_the_schema_cannot_express_is_refused():
    """Not approximated into the nearest supported action."""
    with pytest.raises(PlainLanguageError, match="not one the schema can express"):
        compile_plain_language("if severity is critical then page the on-call engineer", rule_id="test-rule")


def test_a_unary_comparator_with_a_value_is_refused():
    with pytest.raises(PlainLanguageError, match="takes no value"):
        compile_plain_language("if host.owner exists bob then tag owned", rule_id="test-rule")


def test_empty_input_is_refused():
    with pytest.raises(PlainLanguageError):
        compile_plain_language("   ", rule_id="test-rule")


def test_an_oversized_sentence_is_refused():
    with pytest.raises(PlainLanguageError, match="too long"):
        compile_plain_language("if severity is " + "x" * 2100 + " then suppress", rule_id="test-rule")


# ── The compiled rule is the rule that saves ────────────────────────────────


def test_a_compiled_rule_is_accepted_by_the_real_parser_verbatim():
    """The preview and the save cannot drift, because they are one dict."""
    compiled = compile_plain_language(
        "if user.department is finance and severity is critical then route to tier3",
        rule_id="finance-critical",
    )
    _round_trip(compiled)


def test_a_compiled_rule_with_no_action_cannot_be_produced():
    """The schema rejects a no-op `then`; the compiler must never emit one."""
    if _yaml is None:  # pragma: no cover
        pytest.skip("PyYAML not installed in this environment")
    compiled = compile_plain_language("if severity is critical then suppress", rule_id="test-rule")
    # Prove the parser would have caught it, so the compiler's own refusal is
    # a second line of defence rather than the only one.
    with pytest.raises(RuleParseError):
        load_rules_from_yaml(_yaml.safe_dump({"rules": [{**compiled.rule, "then": {}}]}))
