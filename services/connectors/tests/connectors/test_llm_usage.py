"""Phase D2 — AI/LLM-usage audit connector tests.

Pins schema + registry, provider selection, the event-type severity floors, and
that the emitted top-level ``event_type`` is the dotted form the llm-* detection
rules match on.
"""

from __future__ import annotations

import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.llm_usage import LlmUsageConnector


def test_registered_and_schema():
    assert CONNECTOR_REGISTRY["llm_usage"] is LlmUsageConnector
    s = LlmUsageConnector.schema()
    assert s.category == "saas"
    assert {"provider", "api_key"} <= {f.name for f in s.fields}
    assert next(f for f in s.fields if f.name == "api_key").type == "secret"
    assert Capability.PULL_AUDIT in LlmUsageConnector.capabilities()


def test_bad_provider_rejected():
    with pytest.raises(ValueError):
        LlmUsageConnector(provider="gemini", api_key="k")


def test_api_key_created_is_high():
    c = LlmUsageConnector(provider="openai", api_key="k")
    out = c.normalize({"id": "log_1", "type": "api_key.created", "actor": {"email": "a@corp.com"}})
    assert out["severity"] == "high"
    assert out["event_type"] == "openai.api_key.created"
    assert out["actor_email"] == "a@corp.com"


def test_logging_disabled_is_critical():
    c = LlmUsageConnector(provider="openai", api_key="k")
    out = c.normalize({"id": "log_2", "type": "logging.setting.updated"})
    assert out["severity"] == "critical"
    assert out["event_type"] == "openai.logging.setting.updated"


def test_routine_event_is_info():
    c = LlmUsageConnector(provider="openai", api_key="k")
    out = c.normalize({"id": "log_3", "type": "login.succeeded"})
    assert out["severity"] == "info"


def test_anthropic_provider_prefix():
    c = LlmUsageConnector(provider="anthropic", api_key="k")
    out = c.normalize({"id": "a1", "action": "member.added"})
    assert out["event_type"] == "anthropic.member.added"
    assert out["severity"] == "high"


def test_emitted_event_type_matches_llm_detection_shape():
    # The llm-* detection rules match on event_type endswith .api_key.created
    # etc. — assert the emitted dotted form supports that.
    c = LlmUsageConnector(provider="openai", api_key="k")
    out = c.normalize({"id": "x", "type": "api_key.created", "key_scope": "admin"})
    assert out["event_type"].endswith(".api_key.created")
