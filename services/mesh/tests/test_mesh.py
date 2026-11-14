"""Tests for the Federated Threat Intel Mesh (v8 P1).

Covers the privacy contract that gates the feature: k-anonymity, Ed25519
verification, PSI reveal-on-match, opt-out, the bounded verdict contribution,
the pre-publish preview, and a two-instance exchange.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.artifacts import IocSighting, VerdictSignature, verdict_signature_key
from app.consensus import MESH_CAP, mesh_contribution, mesh_preview
from app.crypto import generate_instance_key, ioc_hash, normalize_ioc, sign, verify
from app.hub import MeshHub

NOW = datetime.now(UTC).isoformat()


def _sighting(h: str) -> IocSighting:
    return IocSighting(ioc_hash=h, ioc_type="ip", severity="high", first_seen=NOW, last_seen=NOW)


# ── crypto ───────────────────────────────────────────────────────────────────


def test_ed25519_sign_verify_roundtrip():
    priv, pub = generate_instance_key()
    msg = b"hello mesh"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig)
    assert not verify(pub, b"tampered", sig)


def test_ioc_hash_is_deterministic_and_defangs():
    # PSI: the same indicator hashes identically across instances, even defanged.
    assert ioc_hash("domain", "Evil[.]com") == ioc_hash("domain", "evil.com")
    assert normalize_ioc("IP", " 1.2.3.4 ") == "ip:1.2.3.4"
    # Hash reveals nothing about the value.
    assert "evil" not in ioc_hash("domain", "evil.com")


# ── k-anonymity + PSI ─────────────────────────────────────────────────────────


def test_k_anonymity_hides_below_threshold():
    hub = MeshHub(k=3)
    h = ioc_hash("ip", "10.10.10.10")
    for _ in range(2):
        priv, pub = generate_instance_key()
        s = _sighting(h)
        assert hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    # 2 < k=3 → indistinguishable from unknown.
    assert hub.query_ioc(h) is None
    # Third distinct instance crosses the threshold.
    priv, pub = generate_instance_key()
    s = _sighting(h)
    hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    result = hub.query_ioc(h)
    assert result is not None
    assert result["instances"] == 3
    assert result["max_severity"] == "high"


def test_same_instance_cannot_inflate_consensus():
    hub = MeshHub(k=3)
    h = ioc_hash("ip", "10.0.0.1")
    priv, pub = generate_instance_key()
    for _ in range(10):  # same instance reports 10 times
        s = _sighting(h)
        hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    # Still one distinct instance → below k.
    assert hub.query_ioc(h) is None


def test_bad_signature_is_rejected():
    hub = MeshHub(k=1)
    priv, pub = generate_instance_key()
    _, other_pub = generate_instance_key()
    s = _sighting(ioc_hash("ip", "9.9.9.9"))
    # Signature made with priv but claimed under a different pubkey.
    assert not hub.publish_ioc(other_pub, s, sign(priv, s.signing_bytes()))


def test_opt_out_blocks_publish():
    hub = MeshHub(k=1)
    priv, pub = generate_instance_key()
    hub.opt_out(pub)
    s = _sighting(ioc_hash("ip", "8.8.8.8"))
    assert not hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    assert hub.is_opted_out(pub)


# ── verdict signatures + contribution ─────────────────────────────────────────


def test_verdict_signature_consensus_and_fp_rate():
    hub = MeshHub(k=2)
    key = verdict_signature_key("cloud", "aws_guardduty", "T1078")
    for _ in range(2):
        priv, pub = generate_instance_key()
        sig = VerdictSignature(
            signature_key=key,
            category="cloud",
            connector_type="aws_guardduty",
            primary_technique="T1078",
            verdict_counts={"false_positive": 9, "true_positive": 1},
            mean_confidence=0.3,
        )
        assert hub.publish_signature(pub, sig, sign(priv, sig.signing_bytes()))
    consensus = hub.query_signature(key)
    assert consensus["instances"] == 2
    assert consensus["fp_rate"] == pytest.approx(0.9)  # 18 FP / 20 total


def test_mesh_contribution_is_bounded_and_directional():
    # High FP consensus pulls DOWN, capped at -0.10.
    down = mesh_contribution({"instances": 40, "fp_rate": 1.0})
    assert down.delta == pytest.approx(-MESH_CAP)
    # Overwhelming TP consensus pulls UP, capped at +0.10.
    up = mesh_contribution({"instances": 40, "fp_rate": 0.0})
    assert up.delta == pytest.approx(MESH_CAP)
    # Below k-anonymity (None) contributes nothing.
    assert mesh_contribution(None).delta == 0.0
    # Never exceeds the cap regardless of inputs.
    for fp in (0.0, 0.25, 0.5, 0.75, 1.0):
        c = mesh_contribution({"instances": 10_000, "fp_rate": fp})
        assert -MESH_CAP <= c.delta <= MESH_CAP


def test_mesh_preview_never_reveals_raw_values():
    iocs = [_sighting(ioc_hash("domain", "evil.com"))]
    sigs = [VerdictSignature(signature_key="k", category="cloud", connector_type="aws", primary_technique="T1078")]
    preview = mesh_preview(iocs, sigs)
    blob = str(preview)
    assert "evil.com" not in blob
    assert preview["counts"]["ioc_sightings"] == 1
    assert any("raw IOC" in n for n in preview["never_shared"])


# ── two-instance exchange (integration) ───────────────────────────────────────


def test_two_instances_exchange_sightings():
    """Instance A and B independently see the same IOC; a third query (k=2)
    now benefits from their pooled sighting — the network effect."""
    hub = MeshHub(k=2)
    h = ioc_hash("hash", "deadbeef" * 8)
    for _ in range(2):
        priv, pub = generate_instance_key()
        s = IocSighting(ioc_hash=h, ioc_type="hash", severity="critical", first_seen=NOW, last_seen=NOW)
        assert hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    result = hub.query_ioc(h)
    assert result["instances"] == 2
    assert result["max_severity"] == "critical"
    stats = hub.stats()
    assert stats["instances_connected"] == 2
    assert stats["ioc_hashes_visible"] == 1


def test_receipts_audit_per_instance():
    hub = MeshHub(k=1)
    priv, pub = generate_instance_key()
    s = _sighting(ioc_hash("ip", "1.1.1.1"))
    hub.publish_ioc(pub, s, sign(priv, s.signing_bytes()))
    receipts = hub.receipts_for(pub)
    assert len(receipts) == 1
    assert receipts[0].kind == "ioc_sighting"
