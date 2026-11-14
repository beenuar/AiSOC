"""Smoke test: public, falsifiable benchmark surface (t5-benchmark).

Covers:

* The manifest is deterministic and the SHA-256 stable across calls.
* Submission integrity validation rejects malformed inputs and
  accepts well-formed ones.
* A submission lands as ``verified=False`` on the public
  leaderboard, while internal runs land as ``verified=True``.
* The public leaderboard endpoint never returns the raw ``notes``
  field (which can carry submitter PII).
* The HMAC helper reproduces the same signature on identical inputs.
"""
from __future__ import annotations

import json
import os
import tempfile

os.environ.setdefault("AISOC_AUTH_DISABLED", "1")
os.environ.setdefault("AISOC_LLM_PROVIDER", "mock")
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-benchmark-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from datetime import datetime, timezone  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app.benchmark import (  # noqa: E402
    BENCHMARK_MANIFEST_VERSION,
    PublicSubmission,
    bench_manifest,
    list_public_leaderboard,
    record_submission,
    verify_submission_integrity,
)
from app.benchmark.public import sign_submission_body  # noqa: E402
from app.db import init_db, session_scope  # noqa: E402
from app.main import app  # noqa: E402
from app.marketplace.scenarios import BENCHMARK_VERSION  # noqa: E402
from app.models.benchmark import BenchmarkRun  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _manifest_smoke() -> None:
    init_db()
    m1 = bench_manifest()
    m2 = bench_manifest()
    _expect(m1.scenarios_sha256 == m2.scenarios_sha256, "manifest hash should be deterministic")
    _expect(len(m1.scenarios_sha256) == 64, "sha256 should be 64 hex chars")
    _expect(m1.benchmark_version == BENCHMARK_VERSION, "benchmark_version mismatch")
    _expect(m1.manifest_version == BENCHMARK_MANIFEST_VERSION, "manifest_version mismatch")
    _expect(len(m1.scenario_ids) >= 3, "expected at least three scenarios")


def _integrity_smoke() -> None:
    manifest = bench_manifest()
    bad = PublicSubmission(
        submitter="",
        submitter_email="not-an-email",
        model_provider="",
        model_name="",
        aggregate_score=120.0,
        pass_rate=2.0,
        total_latency_ms=-1,
        scenarios_run=[],
        manifest_version="9.9.9",
        scenarios_sha256=manifest.scenarios_sha256,
    )
    ok, errors = verify_submission_integrity(bad)
    _expect(not ok, "obviously bad submission should be rejected")
    _expect(len(errors) >= 5, f"expected several errors, got {errors}")

    good = PublicSubmission(
        submitter="acme-soc",
        submitter_email="bench@acme.example",
        model_provider="openai",
        model_name="gpt-4o-mini",
        aggregate_score=78.5,
        pass_rate=0.6,
        total_latency_ms=42_000,
        scenarios_run=list(manifest.scenario_ids),
        benchmark_version=manifest.benchmark_version,
        manifest_version=manifest.manifest_version,
        scenarios_sha256=manifest.scenarios_sha256,
        notes="run on us-east-1, no LLM cache",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    ok, errors = verify_submission_integrity(good)
    _expect(ok, f"valid submission rejected: {errors}")


def _signature_smoke() -> None:
    manifest = bench_manifest()
    sub = PublicSubmission(
        submitter="acme-soc",
        submitter_email="bench@acme.example",
        model_provider="openai",
        model_name="gpt-4o-mini",
        aggregate_score=88.0,
        pass_rate=0.8,
        total_latency_ms=12_345,
        scenarios_run=list(manifest.scenario_ids),
        benchmark_version=manifest.benchmark_version,
        manifest_version=manifest.manifest_version,
        scenarios_sha256=manifest.scenarios_sha256,
    )
    sig_a = sign_submission_body(sub, key="shared-secret")
    sig_b = sign_submission_body(sub, key="shared-secret")
    _expect(sig_a == sig_b, "deterministic submission signature should match")
    sig_c = sign_submission_body(sub, key="different-secret")
    _expect(sig_a != sig_c, "different keys should produce different signatures")


def _record_and_query_smoke() -> None:
    manifest = bench_manifest()
    sub = PublicSubmission(
        submitter="contoso-soc",
        submitter_email="contoso@example.com",
        model_provider="anthropic",
        model_name="claude-3.5-sonnet",
        aggregate_score=92.5,
        pass_rate=0.85,
        total_latency_ms=23_456,
        scenarios_run=list(manifest.scenario_ids),
        benchmark_version=manifest.benchmark_version,
        manifest_version=manifest.manifest_version,
        scenarios_sha256=manifest.scenarios_sha256,
        signature="abc123",
        notes="contains-PII@example.com — should not leak to public endpoint",
    )
    ack = record_submission(sub)
    _expect(ack.run_id != 0, "submission did not persist")

    entries = list_public_leaderboard(limit=10)
    matching = [e for e in entries if e.run_id == ack.run_id]
    _expect(len(matching) == 1, f"submitted row missing from leaderboard: {matching}")
    entry = matching[0]
    _expect(entry.submitter == "contoso-soc", "submitter not surfaced on entry")
    _expect(not entry.verified, "submission should land as verified=False")
    _expect(entry.scenarios_sha256 == manifest.scenarios_sha256, "sha mismatch on entry")


def _api_smoke() -> None:
    with TestClient(app) as client:
        r = client.get("/benchmark/public/manifest")
        _expect(r.status_code == 200, f"manifest 200 expected, got {r.status_code}")
        manifest_payload = r.json()
        _expect(
            manifest_payload["scenarios_sha256"],
            "manifest payload missing scenarios_sha256",
        )

        r = client.get("/benchmark/public/leaderboard")
        _expect(r.status_code == 200, f"leaderboard 200 expected, got {r.status_code}")
        body = r.json()
        _expect("manifest" in body, "leaderboard payload should include manifest")
        # Verify nothing in the payload leaks raw notes / PII.
        text = json.dumps(body)
        _expect(
            "contains-PII@example.com" not in text,
            "public payload leaked submission notes",
        )

        # Submit via API.
        m = manifest_payload
        sub_body = {
            "submitter": "wayne-enterprises",
            "submitter_email": "bench@wayne.example",
            "model_provider": "google",
            "model_name": "gemini-2.0-flash",
            "aggregate_score": 67.5,
            "pass_rate": 0.5,
            "total_latency_ms": 33_000,
            "scenarios_run": m["scenario_ids"],
            "benchmark_version": m["benchmark_version"],
            "manifest_version": m["manifest_version"],
            "scenarios_sha256": m["scenarios_sha256"],
            "signature": "abc",
            "notes": "third-party-run",
        }
        r = client.post("/benchmark/public/submissions", json=sub_body)
        _expect(r.status_code == 200, f"POST submission 200 expected, got {r.status_code} {r.text}")
        ack = r.json()
        _expect(ack["verified"] is False, "submission should ack verified=False")
        _expect(ack["run_id"], "submission ack missing run_id")

        # Reject a bad submission.
        bad = dict(sub_body)
        bad["aggregate_score"] = 200.0
        r = client.post("/benchmark/public/submissions", json=bad)
        _expect(
            r.status_code in (400, 422),
            f"bad submission should 400/422, got {r.status_code}",
        )


def _internal_run_marked_verified() -> None:
    """An internal benchmark row (no submission notes) is verified=True."""
    init_db()
    with session_scope() as session:
        row = BenchmarkRun(
            benchmark_version=BENCHMARK_VERSION,
            model_provider="mock",
            model_name="mock-deterministic",
            aggregate_score=80.0,
            pass_rate=0.7,
            total_latency_ms=1000,
            scenarios_run=["cl0p-moveit-exfil"],
            outcomes=[],
            notes="",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        run_id = row.id

    entries = list_public_leaderboard(limit=20)
    found = next((e for e in entries if e.run_id == run_id), None)
    _expect(found is not None, "internal run missing from public leaderboard")
    _expect(found.verified, "internal run should be verified=True")


def main() -> None:
    _manifest_smoke()
    _integrity_smoke()
    _signature_smoke()
    _record_and_query_smoke()
    _api_smoke()
    _internal_run_marked_verified()
    print("ok: public benchmark smoke")


if __name__ == "__main__":
    main()
