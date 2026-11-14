"""Public, falsifiable benchmark API (t5-benchmark).

  GET  /benchmark/public/manifest        Hashable manifest of the live suite
  GET  /benchmark/public/leaderboard     Public leaderboard (no auth, no PII)
  POST /benchmark/public/submissions     Externally-run leaderboard submission

Design points:

* Endpoints are deliberately separate from the existing
  ``/benchmark/...`` paths in :mod:`app.api.marketplace_routes`. The
  public surface only exposes published columns; the internal
  marketplace surface continues to expose run-detail blobs that can
  contain notes a customer wouldn't want public.
* No auth on GETs — a recruiter or partner needs to be able to paste
  the URL and read it. The POST is rate-limited at the gateway and
  validated for integrity here.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.benchmark import (
    BenchmarkManifest,
    PublicSubmission,
    bench_manifest,
    list_public_leaderboard,
    record_submission,
)


router = APIRouter(prefix="/benchmark/public", tags=["benchmark-public"])


@router.get("/manifest")
def public_manifest_route() -> dict[str, Any]:
    """The canonical, hashable description of the live benchmark suite.

    Use the ``scenarios_sha256`` value to verify that a re-run on
    your own infrastructure exercised an identical input set.
    """
    manifest: BenchmarkManifest = bench_manifest()
    return manifest.to_dict()


@router.get("/leaderboard")
def public_leaderboard_route(
    limit: int = Query(default=50, ge=1, le=200),
    include_unverified: bool = Query(default=True),
    benchmark_version: Optional[str] = Query(default=None),
) -> dict[str, Any]:
    """Public leaderboard: top runs across providers + submitters.

    Internal runs are always ``verified=True``. External submissions
    show ``verified=False`` until an operator confirms a re-run on
    our infrastructure produced an equivalent score.
    """
    entries = list_public_leaderboard(
        limit=limit,
        include_unverified=include_unverified,
        benchmark_version=benchmark_version,
    )
    return {
        "manifest": bench_manifest().to_dict(),
        "count": len(entries),
        "include_unverified": include_unverified,
        "leaderboard": [e.to_dict() for e in entries],
    }


class SubmissionRequest(BaseModel):
    submitter: str = Field(min_length=1, max_length=120)
    submitter_email: str = Field(min_length=3, max_length=200)
    model_provider: str = Field(min_length=1, max_length=64)
    model_name: str = Field(min_length=1, max_length=200)
    aggregate_score: float = Field(ge=0.0, le=100.0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    total_latency_ms: int = Field(ge=0)
    scenarios_run: list[str] = Field(min_length=1)
    benchmark_version: str = Field(min_length=1, max_length=32)
    manifest_version: str = Field(min_length=1, max_length=32)
    scenarios_sha256: str = Field(min_length=64, max_length=64)
    signature: Optional[str] = Field(default=None, max_length=200)
    notes: str = Field(default="", max_length=2000)
    outcomes: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/submissions")
def submit_public_run(body: SubmissionRequest) -> dict[str, Any]:
    """Accept a leaderboard submission produced on a partner's own infra.

    The submission lands as ``verified=False`` until an operator
    re-runs the benchmark internally and flips the bit. The
    response carries the run id and a verification URL that
    partners can poll.
    """
    sub = PublicSubmission(
        submitter=body.submitter,
        submitter_email=body.submitter_email,
        model_provider=body.model_provider,
        model_name=body.model_name,
        aggregate_score=body.aggregate_score,
        pass_rate=body.pass_rate,
        total_latency_ms=body.total_latency_ms,
        scenarios_run=list(body.scenarios_run),
        outcomes=list(body.outcomes),
        benchmark_version=body.benchmark_version,
        manifest_version=body.manifest_version,
        scenarios_sha256=body.scenarios_sha256,
        signature=body.signature,
        notes=body.notes,
    )
    try:
        ack = record_submission(sub)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "run_id": ack.run_id,
        "verified": False,
        "submitter": ack.submitter,
        "verification_url": "/benchmark/public/leaderboard?limit=50",
        "expected_manifest": bench_manifest().to_dict(),
    }
