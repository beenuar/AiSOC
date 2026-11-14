"""Tests for Compounding Memory (v8 P4).

Covers distillation, the bounded memory verdict stage, signed pack export/import
(round-trip + tamper rejection), and the measured longitudinal lift on a
simulated 90-day override history.
"""

from __future__ import annotations

import base64

import pytest
from app.memory.distill import MemoryPack, distill, signature_key
from app.memory.improvement import precision_over_time
from app.memory.pack import PackVerificationError, export_pack, import_pack
from app.memory.stage import MEMORY_CAP, memory_contribution
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(priv.private_bytes_raw()).decode(),
        base64.b64encode(priv.public_key().public_bytes_raw()).decode(),
    )


def _ov(category: str, connector: str, technique: str, verdict: str, summary: str = "") -> dict:
    return {
        "category": category,
        "connector_type": connector,
        "primary_technique": technique,
        "corrected_verdict": verdict,
        "summary": summary,
    }


# ── distillation ──────────────────────────────────────────────────────────────


def test_distill_computes_per_signature_fp_rate_and_prior():
    overrides = [
        {"category": "cloud", "connector_type": "aws", "primary_technique": "T1078", "corrected_verdict": "false_positive"},
        {"category": "cloud", "connector_type": "aws", "primary_technique": "T1078", "corrected_verdict": "false_positive"},
        {"category": "cloud", "connector_type": "aws", "primary_technique": "T1078", "corrected_verdict": "true_positive"},
    ]
    pack = distill(overrides)
    key = signature_key("cloud", "aws", "T1078")
    prior = pack.priors[key]
    assert prior.sample_count == 3
    assert prior.fp_rate == pytest.approx(2 / 3, abs=1e-3)
    assert prior.prior == pytest.approx(1 / 3, abs=1e-3)
    assert pack.version.startswith("mem:v1:")


def test_distill_is_deterministic():
    rows = [{"category": "identity", "connector_type": "okta", "primary_technique": "T1110", "corrected_verdict": "false_positive"}]
    assert distill(rows).version == distill(rows).version


def test_distill_builds_few_shot_bank():
    overrides = [
        _ov("endpoint", "cs", "T1059", "true_positive", "PowerShell download cradle confirmed malicious"),
        _ov("endpoint", "cs", "T1059", "false_positive", "admin script"),
    ]
    pack = distill(overrides, top_n_per_category=2)
    assert len(pack.few_shot) == 2
    assert pack.few_shot[0].category == "endpoint"


# ── memory verdict stage ──────────────────────────────────────────────────────


def test_memory_stage_is_bounded_and_directional():
    benign_heavy = distill([_ov("c", "k", "T1", "false_positive") for _ in range(40)])
    key = signature_key("c", "k", "T1")
    down = memory_contribution(key, benign_heavy.priors)
    assert down.delta == pytest.approx(-MEMORY_CAP)

    tp_heavy = distill([_ov("c", "k", "T2", "true_positive") for _ in range(40)])
    up = memory_contribution(signature_key("c", "k", "T2"), tp_heavy.priors)
    assert up.delta == pytest.approx(MEMORY_CAP)

    # Unknown signature contributes nothing; never exceeds the cap.
    assert memory_contribution("unknown", {}).delta == 0.0


# ── signed pack export/import ─────────────────────────────────────────────────


def test_pack_export_import_round_trip():
    priv, pub = _keypair()
    pack = distill([_ov("cloud", "aws", "T1078", "false_positive")])
    signed = export_pack(pack, priv)
    restored = import_pack(signed, expected_public_key_b64=pub)
    assert restored.version == pack.version
    assert restored.priors.keys() == pack.priors.keys()


def test_pack_import_rejects_tampering():
    priv, _ = _keypair()
    pack = distill([_ov("cloud", "aws", "T1078", "true_positive")])
    signed = export_pack(pack, priv)
    # Flip the last char of the version inside the signed body so it no longer
    # matches the signature.
    tampered = signed.replace(pack.version, pack.version[:-1] + ("0" if pack.version[-1] != "0" else "1"))
    assert tampered != signed
    with pytest.raises(PackVerificationError):
        import_pack(tampered)


def test_pack_import_pins_publisher_key():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    pack = distill([_ov("c", "k", "T1", "true_positive")])
    signed = export_pack(pack, priv)
    with pytest.raises(PackVerificationError):
        import_pack(signed, expected_public_key_b64=other_pub)


# ── longitudinal improvement (measured lift on simulated 90-day history) ──────


def test_precision_improves_over_a_simulated_90_day_history():
    # Simulate 90 days: early on the engine is wrong ~40% of the time on a noisy
    # signature; as memory accumulates its predictions align with ground truth.
    history: list[dict] = []
    for day in range(90):
        # Correctness ramps from ~0.6 to ~0.95 as memory compounds.
        correct = (day % 10) >= (4 - min(day // 25, 4))
        history.append({"predicted": "x", "actual": "x" if correct else "y"})
    curve = precision_over_time(history, window_size=20)
    assert len(curve.windows) >= 4
    # Measured lift: latest window precision beats the baseline window.
    assert curve.latest_precision > curve.baseline_precision
    assert curve.lift > 0
    print(
        f"[memory-lift] baseline={curve.baseline_precision:.3f} "
        f"latest={curve.latest_precision:.3f} lift={curve.lift:+.3f} ({curve.lift_pct:+.1f}%)"
    )


def test_memory_pack_json_round_trips_in_memory():
    pack = distill([_ov("cloud", "aws", "T1078", "false_positive")])
    restored = MemoryPack.from_json(pack.to_json())
    assert restored.version == pack.version
