"""The shared extractor must survive prose on both sides of the JSON.

It trimmed everything before the first ``{`` and nothing after the last ``}``,
so a model that answered correctly and then added a closing pleasantry was
scored unparseable. Small local models do this constantly.

The module also advertised itself as the replacement for the agents' ad-hoc
parsers while nothing in production imported it. These tests pin both halves:
the extraction behaviour, and that auto-triage actually calls it.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from app.llm.structured_output import extract_json_block, parse_structured

AGENT_SOURCE = Path(__file__).resolve().parent.parent / "app" / "agents" / "auto_triage_agent.py"


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ('{"a": 1}', {"a": 1}),
        ('{"a": 1}\n\nHope that helps!', {"a": 1}),
        ('Sure! Here is the verdict:\n{"a": 1}\nLet me know.', {"a": 1}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('```json\n{"a": 1}\n```\nAnything else?', {"a": 1}),
        ('[{"a": 1}]\ntrailing', [{"a": 1}]),
        # A brace inside a string is not the end of the object.
        ('{"note": "he typed }"}\nbye', {"note": "he typed }"}),
        # An escaped quote must not end the string scan early.
        ('{"note": "say \\"hi\\" }"}\nbye', {"note": 'say "hi" }'}),
        # Nesting.
        ('{"o": {"i": [1, 2]}}\nthanks', {"o": {"i": [1, 2]}}),
    ],
)
def test_extracts_the_body_whatever_surrounds_it(reply: str, expected: object) -> None:
    assert json.loads(extract_json_block(reply)) == expected
    assert parse_structured(reply).ok


def test_an_unclosed_object_is_left_for_the_parser_to_report() -> None:
    """Truncation must surface as a parse failure, not a silent trim.

    Returning the remainder means json reports where it ran out; trimming to
    the last balanced point would invent an object the model never closed.
    """
    result = parse_structured('{"a": 1, "b": "unterminated')
    assert not result.ok
    assert "invalid JSON" in result.error


def test_prose_with_no_json_at_all_still_fails() -> None:
    assert not parse_structured("I think this alert is fine, honestly").ok


def test_auto_triage_uses_the_shared_extractor() -> None:
    """The wiring, read from source.

    The module documented itself as the single parser while having no
    production caller. This fails if auto-triage goes back to its own
    fence-stripping.
    """
    tree = ast.parse(AGENT_SOURCE.read_text())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "app.llm.structured_output"
        for alias in node.names
    }
    assert "extract_json_block" in imported, "auto-triage no longer shares the extractor"
