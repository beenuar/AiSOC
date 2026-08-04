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


def test_extract_named_groups():
    out = apply_transforms(
        {"msg": "user=bob action=login src=10.0.0.1"},
        [{"op": "extract", "field": "msg", "template": "user=%{WORD:user} action=%{WORD:action} src=%{IP:src_ip}"}],
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


def test_validate_rejects_unknown_grok_token():
    with pytest.raises(TransformError):
        validate_transforms([{"op": "extract", "field": "m", "template": "x=%{NOPE:v}"}])


def test_validate_rejects_too_many_ops():
    with pytest.raises(TransformError):
        validate_transforms([{"op": "drop", "field": "x"}] * 200)


def test_extract_literals_are_escaped_not_regex():
    # Regex metacharacters in the template's literal text are matched literally,
    # never interpreted — so no user data becomes a regex operator (ReDoS-proof).
    out = apply_transforms(
        {"m": "a.b=hello"},
        [{"op": "extract", "field": "m", "template": "a.b=%{WORD:v}"}],
    )
    assert out.event["v"] == "hello"
    # The literal "a.b" must not match "axb" (the dot is escaped).
    out2 = apply_transforms(
        {"m": "axb=hello"},
        [{"op": "extract", "field": "m", "template": "a.b=%{WORD:v}"}],
    )
    assert "v" not in out2.event


def test_extract_input_is_length_bounded():
    out = apply_transforms(
        {"m": "x" * 10000 + " user=zed"},
        [{"op": "extract", "field": "m", "template": "user=%{WORD:user}"}],
    )
    assert "user" not in out.event  # trailing token beyond the cap is dropped


def test_original_event_is_not_mutated():
    original = {"src": "v"}
    apply_transforms(original, [{"op": "rename", "from": "src", "to": "dst"}])
    assert original == {"src": "v"}
