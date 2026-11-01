"""The gateway names the key and the cost, and the connector drops both.

Depth plan wave 2, Phase 7.3 / 7.4.

The gap
-------
`AIGatewayConnector.normalize()` reads `api_key_alias` — but only as the
third fallback for `agent_id`, and then discards it. `key_alias`, `key_name`
and `spend` never reach the event at all.

That matters for two reasons and the second is the one that bites:

1. The engine flattens `raw_event` exactly one level, so a vendor field the
   connector reads and discards is invisible to every rule that clauses on
   it. This is the measured Okta shape: `outcome["result"]` was read to pick
   a severity, never lifted, and seven shipped rules could not fire.
2. "Token-spend anomalies **per key** and per agent" has no subject without
   a key identifier on the usage record. A baseline keyed on a field nothing
   emits is a published signal structurally incapable of firing — exactly
   what `RARITY_FIELDS` documents as the trap.

The payload below is the gateway vendor's own published spend record,
field for field, from
https://docs.litellm.ai/docs/proxy/cost_tracking (fetched, 200).
"""

from __future__ import annotations

import pytest
from app.connectors.ai_gateway import AIGatewayConnector

#: The vendor's documented spend-log record. `key_name` is masked by the
#: vendor itself; `key_alias` is the human-readable name an operator sets.
SPEND_RECORD = {
    "id": "req-1",
    "request_id": "req-1",
    "timestamp": "2026-11-01T09:00:00Z",
    "model": "claude-opus-5-5",
    "custom_llm_provider": "anthropic",
    "api_key": "efcafbb6350240db25ed534b4ec6011b3e1ba1006eb4f903461fd36f6",
    "key_name": "sk-...KE_A",
    "key_alias": "release-bot-key",
    "spend": 0.000002,
    "total_tokens": 100,
    "completion_tokens": 80,
    "prompt_tokens": 20,
    "end_user": "alice@example.com",
    "agent_id": "release-bot",
}


@pytest.fixture
def connector() -> AIGatewayConnector:
    return AIGatewayConnector(base_url="https://gw.example.com", api_key="k")


def test_the_key_the_request_was_billed_to_reaches_the_event(connector: AIGatewayConnector):
    """Without this there is no subject for a per-key spend baseline.

    The connector already reads `api_key_alias` as an `agent_id` fallback,
    so the value was in its hands and went nowhere.
    """
    event = connector.normalize(SPEND_RECORD)
    assert event.get("gateway_key") == "release-bot-key"


def test_the_masked_key_name_is_used_when_no_alias_is_set():
    """An unaliased key is the common case on a new deployment.

    Falling back to nothing would make every unaliased key share one empty
    subject, which is a baseline over an aggregate rather than over a key.
    """
    c = AIGatewayConnector(base_url="https://gw.example.com", api_key="k")
    record = dict(SPEND_RECORD)
    record.pop("key_alias")
    assert c.normalize(record).get("gateway_key") == "sk-...KE_A"


def test_the_raw_hashed_key_is_never_used_as_the_subject(connector: AIGatewayConnector):
    """The hash is a credential identifier, not a name.

    The vendor masks `key_name` for exactly this reason. `gateway_key` is
    the subject a baseline is keyed on, an alert titles and a console row
    renders, so the full hash must not be it.

    Asserted on `gateway_key` rather than on the whole event: `raw_event`
    carries the vendor's payload verbatim by design, the same as every
    other connector, and that is a separate decision from what this
    connector elects to promote to a named field.
    """
    event = connector.normalize(SPEND_RECORD)
    assert event.get("gateway_key") != SPEND_RECORD["api_key"]


def test_a_record_with_no_key_at_all_promotes_nothing(connector: AIGatewayConnector):
    """An in-house proxy need not have the concept of a key.

    Inventing a placeholder would give every such deployment one shared
    subject, and a baseline over "unknown" is a baseline over the whole
    estate wearing a key's name.
    """
    record = {k: v for k, v in SPEND_RECORD.items() if k not in {"key_alias", "key_name", "api_key_alias"}}
    event = connector.normalize(record)
    assert not event.get("gateway_key")


def test_the_cost_of_the_request_reaches_the_event(connector: AIGatewayConnector):
    """`spend` is the vendor's own figure in dollars.

    Recomputing it here from token counts and a price table would be a
    second meter disagreeing with the gateway's — the thing that is
    actually billed.
    """
    event = connector.normalize(SPEND_RECORD)
    assert event.get("request_cost_usd") == pytest.approx(0.000002)


def test_total_tokens_reaches_the_event(connector: AIGatewayConnector):
    """Carried rather than summed from the two halves.

    A provider that reports a total including reasoning or cached tokens
    would disagree with `prompt + completion`, and the vendor's own total
    is the one its billing uses.
    """
    assert connector.normalize(SPEND_RECORD).get("total_tokens") == 100


def test_a_record_with_no_cost_reports_nothing_rather_than_zero(connector: AIGatewayConnector):
    """A missing cost is unknown, and `0.0` is a measurement.

    A spend baseline fed zeros for every record a gateway did not price
    would learn that this agent costs nothing and then never flag anything.
    """
    record = {k: v for k, v in SPEND_RECORD.items() if k != "spend"}
    event = connector.normalize(record)
    assert "request_cost_usd" not in event or event["request_cost_usd"] is None
