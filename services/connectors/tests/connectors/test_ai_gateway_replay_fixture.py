"""Keep the fusion rule-pack fixtures equal to the gateway connector's output.

`services/fusion` cannot import `services/connectors` — both package their
application as `app` — so the AI rule pack is replayed in fusion against
committed artefacts, and this regenerates them and fails if they drift.
Two directions, the same arrangement as the vendored narrative.

Nothing here is synthesized from a rule. A fixture generated from the rule
it tests carries the rule's own clause key, which is why 1 of 12 GitHub
rules fired on real connector output while all twelve passed their own
replay.

Run with `AISOC_REGENERATE_FIXTURES=1` after a deliberate change to
`normalize()`.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest
from app.connectors.ai_gateway import AIGatewayConnector

FIXTURES = pathlib.Path(__file__).resolve().parents[3] / "fusion" / "tests" / "fixtures" / "ai_gateway"

GW = {"base_url": "https://gw.example.com", "api_key": "k"}


def _span(**overrides) -> dict:
    """One gateway span in the vendor's documented spend-record shape."""
    base = {
        "id": "req-1",
        "timestamp": "2026-11-01T09:00:00Z",
        "agent_id": "release-bot",
        "agent_name": "release-bot",
        "model": "claude-opus-5-5",
        "custom_llm_provider": "anthropic",
        "key_alias": "release-bot-key",
        "tool": "search_notes",
        "status": "success",
        "spend": 0.02,
        "total_tokens": 100,
        "prompt_tokens": 20,
        "completion_tokens": 80,
        "end_user": "alice@example.com",
    }
    base.update(overrides)
    return base


#: Each pair differs in exactly ONE decisive field. The baseline history is
#: built from the `_routine` fixture in the fusion replay, so the twins here
#: differ only in what the rule clauses on.
CASES: dict[str, dict] = {
    "routine.json": _span(),
    # The high-risk tool. Everything else identical to routine.
    "high_risk_tool.json": _span(id="req-2", tool="execute_command"),
    # A tool the agent has never used that is NOT on the high-risk list:
    # novel, and deliberately not a finding.
    "novel_benign_tool.json": _span(id="req-3", tool="summarise_page"),
    "guardrail_blocked.json": _span(id="req-4", status="blocked"),
    "expensive.json": _span(id="req-5", spend=40.0),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_matches_the_connector_output(name: str):
    rendered = AIGatewayConnector(**GW).normalize(CASES[name])
    path = FIXTURES / name

    if os.environ.get("AISOC_REGENERATE_FIXTURES") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")

    assert path.exists(), f"{path} is missing — regenerate with AISOC_REGENERATE_FIXTURES=1"
    assert json.loads(path.read_text()) == rendered, (
        f"{name} no longer matches AIGatewayConnector.normalize(). The fusion rule-pack "
        "replay reads this file; regenerate it rather than editing it by hand."
    )
