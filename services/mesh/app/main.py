"""Mesh hub — FastAPI application (v8 P1, port 8010).

The hub is itself open-source and can be self-run (the community hub runs at
mesh.tryaisoc.com). It only ever sees hashed IOCs and aggregate verdict
signatures, and enforces k-anonymity + Ed25519 verification before revealing
any consensus.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from app._health import install_health_routes
from app.artifacts import IocSighting, VerdictSignature
from app.hub import DEFAULT_K, MeshHub
# Vendored from the platform's shared service-to-service bearer auth
# (byte-identical to honeytokens/agents/etc., SERVICE_NAME=MESH). The hub is
# public for READS by design - k-anonymity and PSI mean a query learns nothing
# about who contributed - but the WRITE paths (publish, withdraw) are gated so
# an anonymous caller cannot flood consensus or revoke someone else's
# participation. See services/mesh/app/security/service_auth.py.
from app.security.service_auth import require_service_auth

app = FastAPI(title="AiSOC Mesh Hub", version="0.1.0")
_hub = MeshHub(k=int(os.environ.get("AISOC_MESH_K", DEFAULT_K)))

# Phase 2.6 liveness/readiness probes. The hub is in-memory with no external
# dependencies, so it is ready as soon as the process is up.
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-mesh")
_mark_ready()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "mesh"}


class IocPublish(BaseModel):
    instance_pubkey: str
    signature: str
    sighting: dict


class SigPublish(BaseModel):
    instance_pubkey: str
    signature: str
    verdict_signature: dict


class OptOut(BaseModel):
    instance_pubkey: str = Field(..., min_length=8)
    #: Ed25519 signature over the fixed domain string ``aisoc-mesh:opt-out:v1``
    #: (see ``app.hub.OPT_OUT_DOMAIN``), made with the instance's own key.
    #: Proves the withdrawal comes from the instance being withdrawn - an
    #: anonymous caller cannot dissolve other instances' k-anonymity cohorts.
    signature: str = Field(..., min_length=8)


@app.post("/v1/sightings", dependencies=[Depends(require_service_auth)])
def publish_sighting(body: IocPublish) -> dict:
    try:
        sighting = IocSighting(**body.sighting)
    except TypeError as exc:
        raise HTTPException(status_code=422, detail=f"invalid sighting: {exc}") from exc
    ok = _hub.publish_ioc(body.instance_pubkey, sighting, body.signature)
    if not ok:
        raise HTTPException(status_code=403, detail="rejected (bad signature or opted out)")
    return {"accepted": True}


# Reads are deliberately NOT gated: k-anonymity + PSI mean a query returns
# only aggregated consensus once >= k verified instances contributed, so an
# anonymous reader learns nothing that was not already promised to be public.
@app.get("/v1/sightings/{ioc_hash}")
def get_sighting(ioc_hash: str) -> dict:
    result = _hub.query_ioc(ioc_hash)
    if result is None:
        # Below k-anonymity or unknown — indistinguishable by design (PSI).
        raise HTTPException(status_code=404, detail="no consensus")
    return result


@app.post("/v1/signatures", dependencies=[Depends(require_service_auth)])
def publish_signature(body: SigPublish) -> dict:
    try:
        sig = VerdictSignature(**body.verdict_signature)
    except TypeError as exc:
        raise HTTPException(status_code=422, detail=f"invalid signature: {exc}") from exc
    ok = _hub.publish_signature(body.instance_pubkey, sig, body.signature)
    if not ok:
        raise HTTPException(status_code=403, detail="rejected (bad signature or opted out)")
    return {"accepted": True}


@app.get("/v1/signatures/{signature_key}")
def get_signature(signature_key: str) -> dict:
    result = _hub.query_signature(signature_key)
    if result is None:
        raise HTTPException(status_code=404, detail="no consensus")
    return result


@app.post("/v1/opt-out", dependencies=[Depends(require_service_auth)])
def opt_out(body: OptOut) -> dict:
    if not _hub.opt_out_signed(body.instance_pubkey, body.signature):
        raise HTTPException(status_code=403, detail="invalid opt-out signature")
    return {"opted_out": True}


@app.get("/v1/stats")
def stats() -> dict:
    return _hub.stats()
