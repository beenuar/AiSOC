"""Autonomy must rest on measured performance, not on the model's self-report.

`state.confidence` is the number the model put in its own `confidence` field,
coerced and clamped. It is the sole numeric gate on autonomous closure —
`closure_policy.decide` compares it to a threshold and nothing else — and it
is not evidence of anything. A model that reports 0.97 on every reply closes
every alert, and nothing in the system has ever checked whether the 0.97 was
earned.

`app.confidence.eligibility` is the missing input: whether *this* model, on
*this* prompt version, for *this* tenant context and alert class, has a
separately measured auto-closure precision over a minimum sample, recent
enough to still describe the configuration in front of it.

Three states, not two, and the middle one is the whole design:

* a measurement exists and clears the bar — eligible;
* a measurement exists and does not — **blocked**, which is new safety that
  costs nothing today because no measurement exists yet;
* no measurement at all — **unmeasured**, which does not block by default and
  blocks under `AISOC_AUTONOMY_REQUIRE_MEASURED=1`.

The default is the additive one deliberately, and the record file ships with
zero rows because there is no funded provider to produce one. Enforcing
deny-by-default today would turn off auto-closure on every deployment on the
strength of a measurement nobody has taken, which is a product change nobody
asked for; shipping it unenforceable would be decoration. So the mechanism
runs on every closure and records its verdict, the strict posture is one
documented flag, and the measurement itself is marked PENDING.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.confidence import eligibility
from app.confidence.eligibility import Eligibility, PerformanceRecord, evaluate_eligibility, load_records

RECORD_PATH = Path(eligibility.__file__).resolve().parent / "autonomy_performance.json"


def _record(**overrides: object) -> PerformanceRecord:
    base = {
        "model": "llama3.1:8b-instruct-q4_K_M",
        "prompt_name": "triage.system",
        "prompt_version": "2",
        "prompt_sha256": "a" * 64,
        "tenant_context": "default",
        "alert_class": "cloud",
        "samples": 400,
        "auto_close_precision": 0.98,
        "corpus_digest": "sha256:" + "b" * 64,
        "code_revision": "c" * 40,
        "measured_at": "2026-10-20T00:00:00+00:00",
        "measured_by": "scripts/run_verdict_eval.py",
        "is_synthetic": True,
    }
    base.update(overrides)
    return PerformanceRecord.from_dict(base)


# ── the record file ──────────────────────────────────────────────────────────


def test_the_shipped_record_file_is_wellformed_and_declares_its_state() -> None:
    payload = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    assert payload["status"] in ("pending", "measured")
    assert isinstance(payload["records"], list)
    assert payload["reason"].strip(), "a pending record file must say why it is empty"


def test_the_shipped_record_file_publishes_no_fabricated_row() -> None:
    """With no funded provider the honest content is zero rows, never a zero score."""
    payload = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    if payload["status"] == "pending":
        assert payload["records"] == []
    for row in payload["records"]:
        assert row["samples"] > 0, "a row measured over no samples is not a measurement"


def test_records_load_from_the_shipped_file() -> None:
    assert isinstance(load_records(), tuple)


# ── the three states ─────────────────────────────────────────────────────────


def test_a_clearing_measurement_is_eligible() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.ELIGIBLE
    assert decision.allows_auto_close
    assert decision.measured


def test_a_measurement_below_the_precision_floor_blocks() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(auto_close_precision=0.71),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.BLOCKED
    assert not decision.allows_auto_close
    assert "0.71" in decision.reason


def test_a_measurement_over_too_few_samples_blocks() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(samples=11, auto_close_precision=1.0),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.BLOCKED
    assert "sample" in decision.reason.lower()


def test_no_matching_measurement_is_unmeasured_and_not_a_score_of_zero() -> None:
    decision = evaluate_eligibility(
        model="some-model-nobody-graded",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.UNMEASURED
    assert not decision.measured
    assert decision.precision is None, "an unmeasured configuration has no precision to report"
    assert decision.allows_auto_close, "additive by default: today's behaviour is preserved"


def test_the_strict_posture_denies_an_unmeasured_configuration() -> None:
    decision = evaluate_eligibility(
        model="some-model-nobody-graded",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
        require_measured=True,
    )

    assert decision.state is Eligibility.UNMEASURED
    assert not decision.allows_auto_close


def test_the_strict_posture_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "1")
    assert eligibility.require_measured() is True
    monkeypatch.setenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "0")
    assert eligibility.require_measured() is False
    monkeypatch.delenv("AISOC_AUTONOMY_REQUIRE_MEASURED", raising=False)
    assert eligibility.require_measured() is False


# ── what "the same configuration" means ──────────────────────────────────────


def test_a_prompt_edit_invalidates_the_measurement() -> None:
    """The lock exists so a prompt change is declared. Autonomy must honour it.

    A measurement taken on v2 says nothing about v3, and a model whose prompt
    changed under a measurement that stayed is exactly the drift the registry
    and its lock were built to make visible.
    """
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="3",
        prompt_sha256="d" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.UNMEASURED


def test_a_prompt_text_change_without_a_version_bump_also_invalidates() -> None:
    """Version and hash are both compared; the hash is the one that cannot be forgotten."""
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="e" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.UNMEASURED


def test_an_alert_class_is_not_measured_by_another_alert_class() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="endpoint",
        records=(_record(alert_class="cloud"),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.UNMEASURED


def test_a_stale_measurement_blocks_rather_than_quietly_counting() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(measured_at="2025-01-01T00:00:00+00:00"),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.BLOCKED
    assert "stale" in decision.reason.lower() or "old" in decision.reason.lower()


def test_a_class_specific_measurement_wins_over_a_tenant_wide_one() -> None:
    wide = _record(alert_class=None, auto_close_precision=0.99, samples=5000)
    narrow = _record(alert_class="cloud", auto_close_precision=0.70, samples=400)

    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(wide, narrow),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.state is Eligibility.BLOCKED
    assert decision.precision == pytest.approx(0.70)


def test_the_decision_carries_the_provenance_of_the_measurement_it_used() -> None:
    decision = evaluate_eligibility(
        model="llama3.1:8b-instruct-q4_K_M",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(_record(),),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    record = decision.as_dict()
    assert record["corpus_digest"].startswith("sha256:")
    assert record["code_revision"]
    assert record["measured_at"]
    assert record["samples"] == 400


def test_an_unmeasured_decision_renders_not_measured_and_never_a_number() -> None:
    from app.confidence.signals import UNMEASURED

    decision = evaluate_eligibility(
        model="nobody-graded-this",
        prompt_version="2",
        prompt_sha256="a" * 64,
        tenant_context="default",
        alert_class="cloud",
        records=(),
        now_iso="2026-10-27T00:00:00+00:00",
    )

    assert decision.render_precision() == UNMEASURED
    assert decision.as_dict()["auto_close_precision"] is None
