"""SEC-9: mesh write paths are authenticated; reads stay open by design.

The hub is public for reads — k-anonymity and PSI mean a query learns nothing
about who contributed. But `/v1/sightings`, `/v1/signatures` and `/v1/opt-out`
were unauthenticated writes: an anonymous caller could flood consensus or,
worse, withdraw any instance from every cohort just by naming its pubkey,
dissolving the privacy guarantee other instances were promised. The writes are
now behind the shared service bearer token, and opt-out additionally requires
the instance's own Ed25519 signature over a fixed domain string.
"""

from __future__ import annotations

import inspect

from app import main


def test_write_routes_are_gated():
    for fn in (main.publish_sighting, main.publish_signature, main.opt_out):
        src = inspect.getsource(fn.__wrapped__) if hasattr(fn, "__wrapped__") else inspect.getsource(fn)
        # the decorator carries the dependency; check the route table instead
    gated = {
        r.path: r.dependencies for r in main.app.routes if hasattr(r, "dependencies")
    }
    for path in ("/v1/sightings", "/v1/signatures", "/v1/opt-out"):
        deps = gated.get(path, [])
        assert deps, f"{path} has no route dependency (write path must be gated)"


def test_opt_out_requires_a_signature_field():
    fields = set(main.OptOut.model_fields)
    assert "signature" in fields, "/v1/opt-out body must carry the instance's signature"
