"""Shared agents-test fixtures.

Wave 1 introduced two process-wide singletons that carry state across calls:
the CostGovernor (verdict dedup cache + per-tenant spend) and the LLM
ResponseCache. Reset both before every test so a verdict/response recorded by
one test can't leak into the next (e.g. a reused alert hitting DEDUPLICATED, or
a cached LLM response shadowing a test's mocked one).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_agent_singletons():
    from app.core.cost_governor import reset_governor
    from app.llm.contract import _RESPONSE_CACHE

    reset_governor()
    _RESPONSE_CACHE.clear()
    yield
    reset_governor()
    _RESPONSE_CACHE.clear()
