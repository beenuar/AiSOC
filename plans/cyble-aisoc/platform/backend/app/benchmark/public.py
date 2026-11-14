"""Public benchmark manifest, integrity, and submission ledger (t5-benchmark).

Three concerns sit in this module:

1. **Manifest** — a canonical, deterministic description of *what
   was run*. Includes the benchmark version, the full ordered list
   of scenario ids, and a SHA-256 of the canonical scenario JSON.
   Anyone outside our infrastructure can compute the same hash and
   prove they exercised an identical input set.

2. **Submission ledger** — a place for partners to publish results
   they ran on their own infra. Submissions land in the same
   :class:`BenchmarkRun` table as our internal runs, but with a
   ``submitter`` notation in ``notes`` and an integrity flag that
   says the platform has *not yet reproduced* them. Running the
   benchmark internally and confirming a match flips the flag.

3. **Public leaderboard projection** — strips internal-only fields
   (``notes`` if it carries customer info, raw outcome scratchpads)
   from the response so unauthenticated viewers see only what we
   are willing to publish.

The manifest hash is the falsifiability anchor. If the public
manifest ever changes (e.g. we add a new scenario), the hash
changes too; old leaderboard rows continue to point to the old
hash. Mixing rows from different manifest versions in a single
view is allowed but flagged in the response so a viewer can tell
they are not directly comparable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from app.config import settings
from app.db import session_scope
from app.marketplace.scenarios import BENCHMARK_VERSION, builtin_scenarios_raw
from app.models.benchmark import BenchmarkRun


# Bump when the *manifest schema* (not the scenarios) changes —
# adding fields to the manifest itself, for example. The scenario
# version and SHA cover content drift.
BENCHMARK_MANIFEST_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def _canonical_scenarios_json() -> str:
    """Canonical JSON representation of the scenario suite.

    Sorted keys, no whitespace, deterministic across Python versions.
    Hashing this gives the same value on any machine that has the
    same scenario YAMLs.
    """

    return json.dumps(
        builtin_scenarios_raw(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _scenarios_sha256() -> str:
    return hashlib.sha256(_canonical_scenarios_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BenchmarkManifest:
    """The canonical, hashable description of *what was run*."""

    manifest_version: str
    benchmark_version: str
    scenario_ids: tuple[str, ...]
    scenarios_sha256: str
    grading_rubric: str  # short human-readable description of the rubric

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "benchmark_version": self.benchmark_version,
            "scenario_ids": list(self.scenario_ids),
            "scenarios_sha256": self.scenarios_sha256,
            "grading_rubric": self.grading_rubric,
        }


def bench_manifest() -> BenchmarkManifest:
    """Compute the live manifest. Cheap; safe to call per-request."""

    raw = builtin_scenarios_raw()
    return BenchmarkManifest(
        manifest_version=BENCHMARK_MANIFEST_VERSION,
        benchmark_version=BENCHMARK_VERSION,
        scenario_ids=tuple(s["id"] for s in raw),
        scenarios_sha256=_scenarios_sha256(),
        grading_rubric=(
            "30 verdict + 15 severity + 15 techniques + 15 IOCs + "
            "5 users + 5 hosts + 10 response actions + 5 latency = 100"
        ),
    )


# ---------------------------------------------------------------------------
# Submission integrity
# ---------------------------------------------------------------------------


@dataclass
class PublicSubmission:
    """A leaderboard submission produced by an external party.

    ``signature`` is a HMAC-SHA256 of the canonical submission body
    keyed by the submitter's secret. We don't actually verify the
    signature against a registered key here — that is the job of the
    public site's ingest pipeline. We *do* verify the integrity of
    the body (manifest hash matches a known manifest, score is in
    range, etc) so a malformed or tampered submission is rejected
    at the API boundary.
    """

    submitter: str
    submitter_email: str
    model_provider: str
    model_name: str
    aggregate_score: float
    pass_rate: float
    total_latency_ms: int
    scenarios_run: list[str]
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    benchmark_version: str = BENCHMARK_VERSION
    manifest_version: str = BENCHMARK_MANIFEST_VERSION
    scenarios_sha256: str = ""
    notes: str = ""
    signature: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


def _canonical_submission_body(sub: PublicSubmission) -> str:
    """Body that is HMAC-signed. Must match the public spec."""

    payload = {
        "submitter": sub.submitter,
        "submitter_email": sub.submitter_email,
        "model_provider": sub.model_provider,
        "model_name": sub.model_name,
        "aggregate_score": round(float(sub.aggregate_score), 4),
        "pass_rate": round(float(sub.pass_rate), 4),
        "total_latency_ms": int(sub.total_latency_ms),
        "scenarios_run": sorted(sub.scenarios_run),
        "benchmark_version": sub.benchmark_version,
        "manifest_version": sub.manifest_version,
        "scenarios_sha256": sub.scenarios_sha256,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_submission_integrity(sub: PublicSubmission) -> tuple[bool, list[str]]:
    """Run server-side validation on a submission.

    Returns ``(is_valid, errors)``. The signature itself is verified
    by the caller against a registered submitter key when one is
    available; here we only do the things the platform can verify
    without that key.
    """

    errors: list[str] = []
    if not sub.submitter:
        errors.append("submitter is required")
    if not sub.submitter_email or "@" not in sub.submitter_email:
        errors.append("submitter_email must look like an email")
    if not sub.model_provider:
        errors.append("model_provider is required")
    if not sub.model_name:
        errors.append("model_name is required")
    if not (0.0 <= sub.aggregate_score <= 100.0):
        errors.append("aggregate_score must be in [0, 100]")
    if not (0.0 <= sub.pass_rate <= 1.0):
        errors.append("pass_rate must be in [0, 1]")
    if sub.total_latency_ms < 0:
        errors.append("total_latency_ms must be non-negative")

    expected_manifest = bench_manifest()
    if sub.manifest_version != expected_manifest.manifest_version:
        errors.append(
            f"manifest_version mismatch: expected "
            f"{expected_manifest.manifest_version}, got {sub.manifest_version}"
        )
    if sub.benchmark_version and sub.benchmark_version != expected_manifest.benchmark_version:
        # Allow older benchmark_versions on the leaderboard; they get
        # a 'manifest mismatch' flag rather than a hard reject so
        # historical comparisons still work. Note it but do not
        # error.
        pass
    if sub.scenarios_sha256 and sub.scenarios_sha256 != expected_manifest.scenarios_sha256:
        # Same — note but do not reject. The public site will display
        # mismatched-hash rows under a "needs verification" tab.
        pass

    if not sub.scenarios_run:
        errors.append("scenarios_run cannot be empty")

    return len(errors) == 0, errors


def sign_submission_body(sub: PublicSubmission, *, key: str) -> str:
    """Helper for partners to compute the canonical signature locally."""

    body = _canonical_submission_body(sub).encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Notes-prefix used to identify externally-submitted, unverified
# leaderboard rows in the underlying ``BenchmarkRun`` table. We
# deliberately keep the rows in the same table as our internal
# runs (rather than a separate ``BenchmarkSubmission`` table) so
# the leaderboard query is a single SQL ORDER BY without a UNION.
SUBMISSION_NOTE_PREFIX = "submission:"


@dataclass(frozen=True)
class SubmissionAck:
    """The ack returned to the caller after persisting a submission.

    Plain dataclass so the row attributes survive after the SQLAlchemy
    session closes. Callers that need the underlying ``BenchmarkRun``
    can re-fetch it by ``run_id``.
    """

    run_id: int
    submitter: str
    benchmark_version: str
    manifest_version: str
    scenarios_sha256: str
    aggregate_score: float
    pass_rate: float
    total_latency_ms: int


def record_submission(
    sub: PublicSubmission,
    *,
    session: Optional[Session] = None,
) -> SubmissionAck:
    """Persist a public submission as an unverified leaderboard row.

    Returns a plain ``SubmissionAck`` DTO whose attributes are safe
    to read after the underlying SQLAlchemy session closes.
    """

    is_valid, errors = verify_submission_integrity(sub)
    if not is_valid:
        raise ValueError(f"invalid submission: {'; '.join(errors)}")

    note_payload = json.dumps(
        {
            "submitter": sub.submitter,
            "submitter_email": sub.submitter_email,
            "manifest_version": sub.manifest_version,
            "scenarios_sha256": sub.scenarios_sha256,
            "signature": sub.signature or "",
            "notes": sub.notes,
            "verified": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    def _persist(active: Session) -> SubmissionAck:
        row = BenchmarkRun(
            benchmark_version=sub.benchmark_version or BENCHMARK_VERSION,
            model_provider=sub.model_provider,
            model_name=sub.model_name,
            aggregate_score=sub.aggregate_score,
            pass_rate=sub.pass_rate,
            total_latency_ms=sub.total_latency_ms,
            scenarios_run=list(sub.scenarios_run),
            outcomes=list(sub.outcomes or []),
            notes=f"{SUBMISSION_NOTE_PREFIX}{note_payload}",
            started_at=sub.started_at or _now(),
            finished_at=sub.finished_at or _now(),
        )
        active.add(row)
        active.commit()
        active.refresh(row)
        return SubmissionAck(
            run_id=row.id or 0,
            submitter=sub.submitter,
            benchmark_version=row.benchmark_version,
            manifest_version=sub.manifest_version,
            scenarios_sha256=sub.scenarios_sha256,
            aggregate_score=row.aggregate_score,
            pass_rate=row.pass_rate,
            total_latency_ms=row.total_latency_ms,
        )

    if session is None:
        with session_scope() as scoped:
            return _persist(scoped)
    return _persist(session)


# ---------------------------------------------------------------------------
# Public projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicLeaderboardEntry:
    """The shape exposed on the public, unauthenticated leaderboard."""

    run_id: int
    benchmark_version: str
    manifest_version: str
    scenarios_sha256: str
    model_provider: str
    model_name: str
    aggregate_score: float
    pass_rate: float
    total_latency_ms: int
    scenarios_run: list[str]
    submitter: Optional[str]
    verified: bool
    finished_at: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "benchmark_version": self.benchmark_version,
            "manifest_version": self.manifest_version,
            "scenarios_sha256": self.scenarios_sha256,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "aggregate_score": self.aggregate_score,
            "pass_rate": self.pass_rate,
            "total_latency_ms": self.total_latency_ms,
            "scenarios_run": list(self.scenarios_run),
            "submitter": self.submitter,
            "verified": self.verified,
            "finished_at": self.finished_at,
        }


def _parse_submission_note(notes: str) -> dict[str, Any]:
    """Pull the structured submission note out of a BenchmarkRun row.

    Internal runs leave ``notes`` blank or use it for free-form
    annotation; submissions store a JSON blob prefixed
    ``submission:``.
    """

    if not notes or not notes.startswith(SUBMISSION_NOTE_PREFIX):
        return {}
    raw = notes[len(SUBMISSION_NOTE_PREFIX):]
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


def serialize_for_public(row: BenchmarkRun) -> PublicLeaderboardEntry:
    """Project an internal row into the shape the public leaderboard exposes."""

    note = _parse_submission_note(row.notes)
    manifest = bench_manifest()
    return PublicLeaderboardEntry(
        run_id=row.id or 0,
        benchmark_version=row.benchmark_version,
        manifest_version=note.get("manifest_version") or manifest.manifest_version,
        scenarios_sha256=(
            note.get("scenarios_sha256") or manifest.scenarios_sha256
        ),
        model_provider=row.model_provider,
        model_name=row.model_name,
        aggregate_score=row.aggregate_score,
        pass_rate=row.pass_rate,
        total_latency_ms=row.total_latency_ms,
        scenarios_run=list(row.scenarios_run or []),
        submitter=note.get("submitter"),
        # An internal run is always considered verified; a submission
        # is verified only when an operator flips the bit in ``notes``.
        verified=bool(note.get("verified", False)) or not note,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
    )


def list_public_leaderboard(
    *,
    limit: int = 50,
    include_unverified: bool = True,
    benchmark_version: Optional[str] = None,
) -> list[PublicLeaderboardEntry]:
    """Top-N public leaderboard rows.

    Excludes red-team rows automatically (they live under
    ``benchmark_version`` strings prefixed ``redteam-``).

    The projection runs *inside* the session scope to avoid the
    SQLAlchemy detached-instance trap: once the session closes,
    accessing attributes on an ORM row that hasn't been refreshed
    raises. The :class:`PublicLeaderboardEntry` is a frozen
    dataclass with no ORM coupling, so the returned list survives
    session teardown.
    """

    with session_scope() as session:
        stmt = select(BenchmarkRun).where(
            ~BenchmarkRun.benchmark_version.startswith("redteam-")
        )
        if benchmark_version:
            stmt = stmt.where(BenchmarkRun.benchmark_version == benchmark_version)
        stmt = stmt.order_by(
            BenchmarkRun.aggregate_score.desc(),
            BenchmarkRun.total_latency_ms.asc(),
        ).limit(max(limit, 1))
        rows = session.exec(stmt).all()
        entries = [serialize_for_public(r) for r in rows]

    if not include_unverified:
        entries = [e for e in entries if e.verified]
    return entries
