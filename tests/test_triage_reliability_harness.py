"""The reliability harness must measure the settings production actually uses.

``scripts/measure_triage_reliability.py`` published a measured reliability
figure for auto-triage — 44 of 50 replies usable before constraining the reply
to a JSON object, 50 of 50 after. That number only describes production while
the harness runs production's settings, and the harness holds its own copies of
them as module constants.

The script's comment already said they "are asserted against it in
tests/test_triage_reliability_harness.py". The file did not exist, so the
constants were free to drift from the call site and the published figure would
have quietly started describing a configuration nobody runs. Reading both out
of the tree and comparing them is what the comment claimed all along.

Parsed rather than imported: ``auto_triage_agent`` pulls in the agents service's
dependency tree, which is not installed for the repository-level gates, and a
test that skips when an import fails is a test that stops running the day the
environment changes.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "scripts" / "measure_triage_reliability.py"
AGENT = REPO / "services" / "agents" / "app" / "agents" / "auto_triage_agent.py"

#: The production call: `make_chat_model("triage", temperature=..., max_tokens=...)`.
_CALL = re.compile(r"make_chat_model\(\s*[\"']triage[\"']\s*,([^)]*)\)", re.S)


def _harness_constant(name: str) -> float | int:
    tree = ast.parse(HARNESS.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    pytest.fail(f"{HARNESS.name} no longer defines {name}")


def _production_kwargs() -> dict[str, float | int]:
    match = _CALL.search(AGENT.read_text(encoding="utf-8"))
    if match is None:
        pytest.fail(f'no make_chat_model("triage", ...) call found in {AGENT.name}')
    kwargs: dict[str, float | int] = {}
    for part in match.group(1).split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        try:
            kwargs[key.strip()] = ast.literal_eval(value.strip())
        except (ValueError, SyntaxError):
            continue
    return kwargs


def test_harness_temperature_matches_production():
    assert _harness_constant("TEMPERATURE") == _production_kwargs()["temperature"]


def test_harness_max_tokens_matches_production():
    assert _harness_constant("MAX_TOKENS") == _production_kwargs()["max_tokens"]


def test_production_triage_still_requests_json():
    """The measured improvement came from constraining the reply's grammar.

    Dropping `json_output` would restore the defect the figure was published
    about while the figure stayed on the page.
    """
    match = _CALL.search(AGENT.read_text(encoding="utf-8"))
    assert match is not None
    assert "json_output=True" in match.group(1).replace(" ", "")
