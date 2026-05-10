"""
Memory Recall Eval — Three-Tier Fidelity Gate
==============================================
Cross-cutting eval for the AiSOC capability roadmap (2026 H2): the agent's
three-tier memory (session → working → institutional) must store values
faithfully, return them on recall, respect tier priority ordering, and
maintain cross-tenant isolation.

The suite is intentionally deterministic — no LLM calls, no external
services.  Session uses in-process LRU, working falls back to its
in-process dict (no Redis), and institutional falls back to its in-process
dict (no PostgreSQL).  This keeps CI fast and dependency-free.

Gates (all must pass):
    1. Write-then-recall round-trip per tier
    2. Recall priority: session > working > institutional
    3. Cross-tenant isolation: tenant A cannot read tenant B data
    4. Session eviction after clear()
    5. Structured-value fidelity (dict/list round-trip)
    6. Override ingestion end-to-end
    7. institutional search by tag

Metrics:
    * recall_accuracy — fraction of test cases where recalled value matches
      the written value exactly.  Floor: 1.0 (all cases must pass).
    * isolation_score — fraction of cross-tenant probes that return None.
      Floor: 1.0 (perfect isolation required).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTS_ROOT))

os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("REDIS_URL", "")

from app.memory import MemoryManager  # noqa: E402
from app.memory.institutional import _FALLBACK as _INSTITUTIONAL_FALLBACK  # noqa: E402
from app.memory.models import OverrideFeedback  # noqa: E402
from app.memory.session import _session_caches  # noqa: E402
from app.memory.working import _FALLBACK as _WORKING_FALLBACK  # noqa: E402

RECALL_ACCURACY_FLOOR = 1.0
ISOLATION_FLOOR = 1.0


def _clear_all_fallbacks() -> None:
    _session_caches.clear()
    _WORKING_FALLBACK.clear()
    _INSTITUTIONAL_FALLBACK.clear()


@pytest.fixture(autouse=True)
def _clean_state():
    _clear_all_fallbacks()
    yield
    _clear_all_fallbacks()


# ------------------------------------------------------------------
# 1. Write-then-recall per tier
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_round_trip():
    mgr = await MemoryManager.create(tenant_id="t-recall", run_id="run-1")
    await mgr.write_session("key_a", "value_a")
    assert await mgr.recall("key_a", tiers=("session",)) == "value_a"


@pytest.mark.asyncio
async def test_working_round_trip():
    mgr = await MemoryManager.create(tenant_id="t-recall", run_id="run-1")
    await mgr.write_working("key_b", {"nested": True})
    result = await mgr.recall("key_b", tiers=("working",))
    assert result == {"nested": True}


@pytest.mark.asyncio
async def test_institutional_round_trip():
    mgr = await MemoryManager.create(tenant_id="t-recall", run_id="run-1")
    await mgr.write_institutional("key_c", [1, 2, 3], tags=["test"])
    result = await mgr.recall("key_c", tiers=("institutional",))
    assert result == [1, 2, 3]


# ------------------------------------------------------------------
# 2. Recall priority: session > working > institutional
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recall_priority_session_wins():
    mgr = await MemoryManager.create(tenant_id="t-prio", run_id="run-p")
    await mgr.write_session("shared_key", "from_session")
    await mgr.write_working("shared_key", "from_working")
    await mgr.write_institutional("shared_key", "from_institutional")
    result = await mgr.recall("shared_key")
    assert result == "from_session"


@pytest.mark.asyncio
async def test_recall_priority_working_wins_without_session():
    mgr = await MemoryManager.create(tenant_id="t-prio2", run_id="run-p2")
    await mgr.write_working("shared_key", "from_working")
    await mgr.write_institutional("shared_key", "from_institutional")
    result = await mgr.recall("shared_key")
    assert result == "from_working"


@pytest.mark.asyncio
async def test_recall_priority_institutional_fallback():
    mgr = await MemoryManager.create(tenant_id="t-prio3", run_id="run-p3")
    await mgr.write_institutional("only_inst", "from_institutional")
    result = await mgr.recall("only_inst")
    assert result == "from_institutional"


# ------------------------------------------------------------------
# 3. Cross-tenant isolation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_tenant_isolation_working():
    mgr_a = await MemoryManager.create(tenant_id="tenant-A", run_id="r1")
    mgr_b = await MemoryManager.create(tenant_id="tenant-B", run_id="r2")
    await mgr_a.write_working("secret", "tenant-A-data")
    result = await mgr_b.recall("secret", tiers=("working",))
    assert result is None


@pytest.mark.asyncio
async def test_cross_tenant_isolation_institutional():
    mgr_a = await MemoryManager.create(tenant_id="tenant-C", run_id="r3")
    mgr_b = await MemoryManager.create(tenant_id="tenant-D", run_id="r4")
    await mgr_a.write_institutional("classified", "tenant-C-only")
    result = await mgr_b.recall("classified", tiers=("institutional",))
    assert result is None


# ------------------------------------------------------------------
# 4. Session eviction after clear()
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_clear_evicts():
    mgr = await MemoryManager.create(tenant_id="t-clear", run_id="run-clear")
    await mgr.write_session("ephemeral", "gone-soon")
    assert await mgr.recall("ephemeral", tiers=("session",)) == "gone-soon"
    await mgr.clear_session()
    assert await mgr.recall("ephemeral", tiers=("session",)) is None


# ------------------------------------------------------------------
# 5. Structured-value fidelity
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_structured_value_fidelity():
    mgr = await MemoryManager.create(tenant_id="t-struct", run_id="run-struct")
    complex_val = {
        "alert_id": "ALT-001",
        "iocs": ["10.0.0.1", "evil.com"],
        "mitre": {"tactic": "TA0001", "technique": "T1566.001"},
        "score": 0.87,
    }
    await mgr.write_working("case_context", complex_val)
    recalled = await mgr.recall("case_context", tiers=("working",))
    assert recalled == complex_val


# ------------------------------------------------------------------
# 6. Override ingestion end-to-end
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_ingestion():
    mgr = await MemoryManager.create(tenant_id="t-override", run_id="run-ov")
    feedback = OverrideFeedback(
        tenant_id="t-override",
        run_id="run-ov",
        alert_id="ALT-999",
        original_verdict="benign",
        corrected_verdict="true_positive",
        analyst_id="analyst-42",
        reason="Confirmed C2 callback after manual PCAP review",
    )
    await mgr.ingest_override(feedback)
    result = await mgr.recall(f"analyst_override:{feedback.alert_id}", tiers=("institutional",))
    assert result is not None
    assert result["corrected_verdict"] == "true_positive"
    assert result["analyst_id"] == "analyst-42"


# ------------------------------------------------------------------
# 7. Institutional search by tag
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_institutional_search_by_tag():
    mgr = await MemoryManager.create(tenant_id="t-search", run_id="run-s")
    await mgr.write_institutional("fp-1", {"rule": "sigma-001"}, tags=["known_fp"])
    await mgr.write_institutional("fp-2", {"rule": "sigma-002"}, tags=["known_fp"])
    await mgr.write_institutional("other", {"rule": "sigma-003"}, tags=["playbook"])
    results = await mgr.search_institutional(tags=["known_fp"])
    keys = [r["key"] for r in results]
    assert "fp-1" in keys
    assert "fp-2" in keys


# ------------------------------------------------------------------
# 8. Missing key returns None
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_key_returns_none():
    mgr = await MemoryManager.create(tenant_id="t-miss", run_id="run-miss")
    assert await mgr.recall("nonexistent") is None


# ------------------------------------------------------------------
# 9. Delete removes from tier
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_removes_from_working():
    mgr = await MemoryManager.create(tenant_id="t-del", run_id="run-del")
    await mgr.write_working("to_delete", "temp")
    assert await mgr.recall("to_delete", tiers=("working",)) == "temp"
    await mgr.delete("to_delete", "working")
    assert await mgr.recall("to_delete", tiers=("working",)) is None


# ------------------------------------------------------------------
# Aggregate runner for the eval harness
# ------------------------------------------------------------------


def run_evaluation() -> dict[str, Any]:
    """Execute all memory-recall checks and return a JSON-serializable report.

    Called by ``scripts/run_evals.py`` for the unified evaluation runner.
    """
    _clear_all_fallbacks()

    cases: list[dict] = []

    async def _run_case(name: str, coro):
        try:
            await coro
            cases.append({"name": name, "passed": True})
        except AssertionError as exc:
            cases.append({"name": name, "passed": False, "error": str(exc)})

    async def _run_all():
        await _run_case("session_round_trip", test_session_round_trip())
        await _run_case("working_round_trip", test_working_round_trip())
        await _run_case("institutional_round_trip", test_institutional_round_trip())
        await _run_case("recall_priority_session_wins", test_recall_priority_session_wins())
        await _run_case(
            "recall_priority_working_wins",
            test_recall_priority_working_wins_without_session(),
        )
        await _run_case(
            "recall_priority_institutional_fallback",
            test_recall_priority_institutional_fallback(),
        )
        await _run_case("cross_tenant_working", test_cross_tenant_isolation_working())
        await _run_case(
            "cross_tenant_institutional",
            test_cross_tenant_isolation_institutional(),
        )
        await _run_case("session_clear", test_session_clear_evicts())
        await _run_case("structured_fidelity", test_structured_value_fidelity())
        await _run_case("override_ingestion", test_override_ingestion())
        await _run_case("search_by_tag", test_institutional_search_by_tag())
        await _run_case("missing_key_none", test_missing_key_returns_none())
        await _run_case("delete_from_working", test_delete_removes_from_working())

    asyncio.run(_run_all())

    passed = sum(1 for c in cases if c["passed"])
    total = len(cases)
    accuracy = passed / total if total else 0.0

    isolation_cases = [c for c in cases if "cross_tenant" in c["name"]]
    isolation_passed = sum(1 for c in isolation_cases if c["passed"])
    isolation_total = len(isolation_cases)
    isolation_score = isolation_passed / isolation_total if isolation_total else 1.0

    _clear_all_fallbacks()

    return {
        "passed": accuracy >= RECALL_ACCURACY_FLOOR and isolation_score >= ISOLATION_FLOOR,
        "recall_accuracy": round(accuracy, 4),
        "recall_accuracy_floor": RECALL_ACCURACY_FLOOR,
        "isolation_score": round(isolation_score, 4),
        "isolation_floor": ISOLATION_FLOOR,
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": [c for c in cases if not c["passed"]],
    }
