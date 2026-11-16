"""Opt-out requires proof of key possession (#1944, carried in part).

``MeshHub.opt_out`` is a permanent publish denylist: every future artifact
from the named pubkey is rejected. The HTTP route used to take any
caller-named pubkey unverified, so an anonymous caller could permanently
silence any contributing instance — and dissolve its participation in every
k-anonymity cohort — by merely reading its public key off the mesh.

The withdrawal now carries an Ed25519 signature over the fixed domain string
``OPT_OUT_DOMAIN``, verified against the claimed pubkey. Domain separation
matters in both directions: an artifact signature must not work as an
opt-out, and an opt-out signature must not work as a publish.
"""

from __future__ import annotations

from app.artifacts import IocSighting
from app.crypto import generate_instance_key, sign
from app.hub import OPT_OUT_DOMAIN, MeshHub
from app.main import OptOut, app, opt_out
from fastapi import HTTPException
from fastapi.testclient import TestClient

_NOW = "2026-11-16T12:00:00Z"


def _sighting() -> IocSighting:
    return IocSighting(
        ioc_hash="a" * 64,
        ioc_type="ip",
        severity="high",
        first_seen=_NOW,
        last_seen=_NOW,
    )


def test_holder_of_the_key_can_withdraw() -> None:
    hub = MeshHub()
    priv, pub = generate_instance_key()
    assert hub.opt_out_signed(pub, sign(priv, OPT_OUT_DOMAIN)) is True
    assert hub.is_opted_out(pub)


def test_anyone_else_cannot() -> None:
    """The pre-fix defect: naming a victim's pubkey was enough."""
    hub = MeshHub()
    _victim_priv, victim_pub = generate_instance_key()
    attacker_priv, _attacker_pub = generate_instance_key()

    # No signature material at all (garbage), and a signature made with the
    # attacker's own key: both refused.
    assert hub.opt_out_signed(victim_pub, "bm90LWEtc2lnbmF0dXJl") is False
    assert hub.opt_out_signed(victim_pub, sign(attacker_priv, OPT_OUT_DOMAIN)) is False
    assert not hub.is_opted_out(victim_pub)


def test_an_artifact_signature_is_not_an_opt_out() -> None:
    """Domain separation: a signature the instance legitimately published
    (over an artifact's signing_bytes) must not be replayable as its own
    withdrawal."""
    hub = MeshHub()
    priv, pub = generate_instance_key()
    sighting = _sighting()
    artifact_sig = sign(priv, sighting.signing_bytes())
    assert hub.publish_ioc(pub, sighting, artifact_sig) is True

    assert hub.opt_out_signed(pub, artifact_sig) is False, "an artifact signature doubled as a withdrawal"
    assert not hub.is_opted_out(pub)


def test_route_refuses_unsigned_withdrawals() -> None:
    client = TestClient(app)
    _priv, pub = generate_instance_key()
    resp = client.post("/v1/opt-out", json={"instance_pubkey": pub, "signature": "aW52YWxpZA=="})
    assert resp.status_code == 403


def test_route_accepts_the_holders_withdrawal() -> None:
    client = TestClient(app)
    priv, pub = generate_instance_key()
    resp = client.post("/v1/opt-out", json={"instance_pubkey": pub, "signature": sign(priv, OPT_OUT_DOMAIN)})
    assert resp.status_code == 200
    assert resp.json() == {"opted_out": True}


def test_signature_field_is_required() -> None:
    client = TestClient(app)
    _priv, pub = generate_instance_key()
    resp = client.post("/v1/opt-out", json={"instance_pubkey": pub})
    assert resp.status_code == 422


def test_handler_refuses_via_http_exception() -> None:
    """Direct-call form of the route guard, for suites that avoid TestClient."""
    _priv, pub = generate_instance_key()
    try:
        opt_out(OptOut(instance_pubkey=pub, signature="aW52YWxpZA=="))
        raise AssertionError("unsigned withdrawal was accepted")
    except HTTPException as exc:
        assert exc.status_code == 403
