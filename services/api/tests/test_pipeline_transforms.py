"""Wave 5 (W5.3/W5.2) - the field-extraction / transform DSL."""

from __future__ import annotations

import pytest
from app.services.pipeline_transforms import (
    TransformError,
    apply_transforms,
    validate_transforms,
)


def test_rename_moves_and_removes_source():
    out = apply_transforms({"src": "v"}, [{"op": "rename", "from": "src", "to": "dst"}])
    assert out.event == {"dst": "v"}


def test_dotted_paths_nest():
    out = apply_transforms(
        {"user": "alice"},
        [{"op": "rename", "from": "user", "to": "actor.name"}],
    )
    assert out.event["actor"]["name"] == "alice"


def test_set_default_only_when_missing():
    out = apply_transforms(
        {"sev": "high"},
        [
            {"op": "set_default", "field": "sev", "value": "low"},
            {"op": "set_default", "field": "conf", "value": 50},
        ],
    )
    assert out.event["sev"] == "high"
    assert out.event["conf"] == 50


def test_lowercase_and_coalesce():
    out = apply_transforms(
        {"a": None, "b": "HELLO"},
        [
            {"op": "coalesce", "fields": ["a", "b"], "to": "greeting"},
            {"op": "lowercase", "field": "greeting"},
        ],
    )
    assert out.event["greeting"] == "hello"


def test_regex_extract_named_groups():
    out = apply_transforms(
        {"msg": "user=bob action=login src=10.0.0.1"},
        [{"op": "regex_extract", "field": "msg", "pattern": r"user=(?P<user>\w+).*src=(?P<src_ip>[\d.]+)"}],
    )
    assert out.event["user"] == "bob"
    assert out.event["src_ip"] == "10.0.0.1"


def test_bad_op_warns_but_does_not_drop_event():
    # 'from' present but no 'to' → the op raises, is caught as a warning, and
    # the rest of the event survives (fail-open per op, never drop the event).
    out = apply_transforms({"keep": "me", "src": "v"}, [{"op": "rename", "from": "src"}])
    assert out.event["keep"] == "me"
    assert out.warnings


def test_validate_rejects_unknown_op():
    with pytest.raises(TransformError):
        validate_transforms([{"op": "rm -rf"}])


def test_validate_rejects_bad_regex():
    with pytest.raises(TransformError):
        validate_transforms([{"op": "regex_extract", "field": "m", "pattern": "(unclosed"}])


def test_validate_rejects_too_many_ops():
    with pytest.raises(TransformError):
        validate_transforms([{"op": "drop", "field": "x"}] * 200)


def test_validate_rejects_redos_nested_quantifier():
    for evil in (r"(a+)+$", r"(a*)*b", r"(x+)*"):
        with pytest.raises(TransformError):
            validate_transforms([{"op": "regex_extract", "field": "m", "pattern": evil}])


def test_regex_input_is_length_bounded():
    # A huge input is truncated before matching (ReDoS bound); still extracts.
    out = apply_transforms(
        {"m": "x" * 10000 + " user=zed"},
        [{"op": "regex_extract", "field": "m", "pattern": r"user=(?P<user>\w+)"}],
    )
    # The match target beyond the cap is dropped, so the trailing token is not found.
    assert "user" not in out.event


def test_original_event_is_not_mutated():
    original = {"src": "v"}
    apply_transforms(original, [{"op": "rename", "from": "src", "to": "dst"}])
    assert original == {"src": "v"}
