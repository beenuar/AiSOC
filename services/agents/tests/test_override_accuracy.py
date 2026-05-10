"""
Override Accuracy Eval — Analyst Feedback Fidelity Gate
=======================================================
Cross-cutting eval for the AiSOC capability roadmap (2026 H2): when an
analyst overrides an agent verdict, the correction must be faithfully
stored, retrievable, and applied to future similar alerts.

This suite tests the complete analyst-override lifecycle:

    1. **Ingestion fidelity**: OverrideFeedback objects are stored in
       institutional memory with all fields intact.
    2. **Retrieval accuracy**: overrides are retrievable by alert ID and
       searchable by the ``analyst_override`` tag.
    3. **Multi-override consistency**: multiple overrides for different
       alerts from different analysts coexist without collision.
    4. **Idempotent upsert**: re-ingesting an override for the same alert
       updates rather than duplicates.
    5. **Override fields preserved**: analyst_id, reason, corrected_verdict,
       original_verdict, and created_at survive the round-trip.

Like the memory-recall suite, this runs fully offline against in-process
fallbacks — no PostgreSQL, no Redis, no LLM.

Metric:
    * override_accuracy — fraction of test assertions that pass.
      Floor: 1.0 (every assertion must hold).
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

OVERRIDE_ACCURACY_FLOOR = 1.0


def _clear_all_fallbacks() -> None:
    _session_caches.clear()
    _WORKING_FALLBACK.clear()
    _INSTITUTIONAL_FALLBACK.clear()


@pytest.fixture(autouse=True)
def _clean_state():
    _clear_all_fallbacks()
    yield
    _clear_all_fallbacks()


def _make_feedback(
    *,
    tenant_id: str = "t-ov",
    run_id: str = "run-ov",
    alert_id: str = "ALT-001",
    original: str = "benign",
    corrected: str = "true_positive",
    analyst_id: str = "analyst-1",
    reason: str = "Confirmed via PCAP",
) -> OverrideFeedback:
    return OverrideFeedback(
        tenant_id=tenant_id,
        run_id=run_id,
        alert_id=alert_id,
        original_verdict=original,
        corrected_verdict=corrected,
        analyst_id=analyst_id,
        reason=reason,
    )


# ------------------------------------------------------------------
# 1. Ingestion fidelity
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_ingestion_stores_all_fields():
    mgr = await MemoryManager.create(tenant_id="t-ov", run_id="run-ov")
    fb = _make_feedback(alert_id="ALT-100", reason="DNS exfil confirmed")
    await mgr.ingest_override(fb)

    result = await mgr.recall("analyst_override:ALT-100", tiers=("institutional",))
    assert result is not None
    assert result["alert_id"] == "ALT-100"
    assert result["original_verdict"] == "benign"
    assert result["corrected_verdict"] == "true_positive"
    assert result["analyst_id"] == "analyst-1"
    assert result["reason"] == "DNS exfil confirmed"
    assert result["run_id"] == "run-ov"


# ------------------------------------------------------------------
# 2. Retrieval via search by analyst_override tag
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_searchable_by_tag():
    mgr = await MemoryManager.create(tenant_id="t-ov2", run_id="run-ov2")
    fb1 = _make_feedback(tenant_id="t-ov2", alert_id="ALT-201")
    fb2 = _make_feedback(tenant_id="t-ov2", alert_id="ALT-202")
    await mgr.ingest_override(fb1)
    await mgr.ingest_override(fb2)

    results = await mgr.search_institutional(tags=["analyst_override"])
    keys = [r["key"] for r in results]
    assert "analyst_override:ALT-201" in keys
    assert "analyst_override:ALT-202" in keys


# ------------------------------------------------------------------
# 3. Multi-override consistency (different alerts, different analysts)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_override_no_collision():
    mgr = await MemoryManager.create(tenant_id="t-multi", run_id="run-m")
    overrides = [
        _make_feedback(
            tenant_id="t-multi",
            alert_id=f"ALT-30{i}",
            analyst_id=f"analyst-{i}",
            corrected="true_positive" if i % 2 == 0 else "false_positive",
            reason=f"Reason {i}",
        )
        for i in range(5)
    ]
    for fb in overrides:
        await mgr.ingest_override(fb)

    for i, fb in enumerate(overrides):
        result = await mgr.recall(f"analyst_override:{fb.alert_id}", tiers=("institutional",))
        assert result is not None
        assert result["analyst_id"] == f"analyst-{i}"
        expected = "true_positive" if i % 2 == 0 else "false_positive"
        assert result["corrected_verdict"] == expected


# ------------------------------------------------------------------
# 4. Idempotent upsert (re-ingest same alert → update, not duplicate)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_upsert_idempotent():
    mgr = await MemoryManager.create(tenant_id="t-upsert", run_id="run-u")
    fb_v1 = _make_feedback(
        tenant_id="t-upsert",
        alert_id="ALT-UPSERT",
        corrected="true_positive",
        reason="First assessment",
    )
    await mgr.ingest_override(fb_v1)

    fb_v2 = _make_feedback(
        tenant_id="t-upsert",
        alert_id="ALT-UPSERT",
        corrected="false_positive",
        reason="Revised after deeper analysis",
    )
    await mgr.ingest_override(fb_v2)

    result = await mgr.recall("analyst_override:ALT-UPSERT", tiers=("institutional",))
    assert result is not None
    assert result["corrected_verdict"] == "false_positive"
    assert result["reason"] == "Revised after deeper analysis"


# ------------------------------------------------------------------
# 5. Cross-tenant override isolation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_cross_tenant_isolation():
    mgr_a = await MemoryManager.create(tenant_id="t-iso-A", run_id="r-a")
    mgr_b = await MemoryManager.create(tenant_id="t-iso-B", run_id="r-b")
    fb = _make_feedback(tenant_id="t-iso-A", alert_id="ALT-ISO")
    await mgr_a.ingest_override(fb)

    result_b = await mgr_b.recall("analyst_override:ALT-ISO", tiers=("institutional",))
    assert result_b is None

    result_a = await mgr_a.recall("analyst_override:ALT-ISO", tiers=("institutional",))
    assert result_a is not None


# ------------------------------------------------------------------
# 6. Override verdicts span — cover real SOC correction patterns
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_verdict_patterns():
    """Test realistic SOC correction scenarios."""
    mgr = await MemoryManager.create(tenant_id="t-patterns", run_id="run-p")
    patterns = [
        ("ALT-P1", "benign", "true_positive", "Missed lateral movement"),
        ("ALT-P2", "true_positive", "false_positive", "Scheduled scan, not attack"),
        ("ALT-P3", "true_positive", "benign", "Test traffic from pentest team"),
        ("ALT-P4", "suspicious", "true_positive", "Confirmed ransomware C2"),
    ]
    for alert_id, orig, corrected, reason in patterns:
        fb = _make_feedback(
            tenant_id="t-patterns",
            alert_id=alert_id,
            original=orig,
            corrected=corrected,
            reason=reason,
        )
        await mgr.ingest_override(fb)

    for alert_id, orig, corrected, reason in patterns:
        result = await mgr.recall(f"analyst_override:{alert_id}", tiers=("institutional",))
        assert result is not None
        assert result["original_verdict"] == orig
        assert result["corrected_verdict"] == corrected
        assert result["reason"] == reason


# ------------------------------------------------------------------
# Aggregate runner for the eval harness
# ------------------------------------------------------------------


def run_evaluation() -> dict[str, Any]:
    """Execute all override-accuracy checks and return a JSON-serializable
    report.  Called by ``scripts/run_evals.py``."""
    _clear_all_fallbacks()

    cases: list[dict] = []

    async def _run_case(name: str, coro):
        try:
            await coro
            cases.append({"name": name, "passed": True})
        except AssertionError as exc:
            cases.append({"name": name, "passed": False, "error": str(exc)})

    async def _run_all():
        await _run_case("ingestion_fidelity", test_override_ingestion_stores_all_fields())
        await _run_case("searchable_by_tag", test_override_searchable_by_tag())
        await _run_case("multi_override_consistency", test_multi_override_no_collision())
        await _run_case("upsert_idempotent", test_override_upsert_idempotent())
        await _run_case("cross_tenant_isolation", test_override_cross_tenant_isolation())
        await _run_case("verdict_patterns", test_override_verdict_patterns())

    asyncio.run(_run_all())

    passed = sum(1 for c in cases if c["passed"])
    total = len(cases)
    accuracy = passed / total if total else 0.0

    _clear_all_fallbacks()

    return {
        "passed": accuracy >= OVERRIDE_ACCURACY_FLOOR,
        "override_accuracy": round(accuracy, 4),
        "override_accuracy_floor": OVERRIDE_ACCURACY_FLOOR,
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": [c for c in cases if not c["passed"]],
    }
