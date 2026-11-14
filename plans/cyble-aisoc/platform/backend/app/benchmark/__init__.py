"""Public, falsifiable AI-SOC benchmark surface (t5-benchmark).

Builds on top of the existing :mod:`app.marketplace.benchmark` runner
(t3g-mcp-marketplace) and adds the bits a *public* benchmark needs:

* A canonical, hashable scenario manifest. Anyone running the harness
  outside our infrastructure can compute the SHA-256 of the manifest
  they ran and compare it against the SHA-256 in the leaderboard row
  to confirm the two runs operated on identical inputs.
* A submission protocol: a partner submits a signed leaderboard row
  derived from a run they performed on their own infra; we record
  it as ``unverified`` until it is reproduced on our side.
* A public, unauthenticated leaderboard endpoint that exposes only
  the published columns (no tenant data, no internal ``notes``).
* A small CLI (`scripts/run_benchmark.py`, see below) that can be
  invoked offline to reproduce any leaderboard row.

The point is *falsifiability*: anyone with the source can re-run the
benchmark and get the same number, or fail to and tell us why.
"""

from app.benchmark.public import (
    BENCHMARK_MANIFEST_VERSION,
    BenchmarkManifest,
    PublicLeaderboardEntry,
    PublicSubmission,
    SubmissionAck,
    bench_manifest,
    list_public_leaderboard,
    record_submission,
    serialize_for_public,
    verify_submission_integrity,
)

__all__ = [
    "BENCHMARK_MANIFEST_VERSION",
    "BenchmarkManifest",
    "PublicLeaderboardEntry",
    "PublicSubmission",
    "SubmissionAck",
    "bench_manifest",
    "list_public_leaderboard",
    "record_submission",
    "serialize_for_public",
    "verify_submission_integrity",
]
