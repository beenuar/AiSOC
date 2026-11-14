"""Cyble Academy persistence (t5-academy).

Two tables:

* :class:`AcademyProgress` — per-(user, lesson) completion record.
  Tracking per-lesson rather than per-course is deliberate: a learner
  who watches a video then quits is still credited for the lesson,
  and a course's completion percentage is just an aggregation over
  its lessons.

* :class:`AcademyCertificate` — one row per issued certification.
  Issued by :func:`app.academy.service.issue_certificate` after the
  learner clears every required quiz in the course at the configured
  passing score. The row is the durable record we link to from the
  public verification page (``/academy/certificates/{id}``).

We deliberately do *not* store the curriculum itself in the database —
the ``app/academy/curriculum/*.yaml`` files are the source of truth
and ship in the repo. That way the Cyble Academy team edits courses
in PRs reviewable by curriculum owners, and the platform reloads on
deploy. Mutating courses through the DB would mean curriculum drift
between environments and a write-path nobody asked for.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel, UniqueConstraint


class AcademyProgress(SQLModel, table=True):
    """Per-(user, lesson) completion + (optional) quiz score."""

    __tablename__ = "academy_progress"
    # A user can only have one record per lesson. Subsequent attempts
    # bump ``score`` and ``updated_at`` rather than inserting a new
    # row — keeps the table small and lets the dashboard count
    # ``COUNT(*) WHERE user=…`` for a learner's completed-lessons total.
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", "lesson_id", name="ux_progress_user_lesson"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    user_id: str = Field(index=True)
    course_id: str = Field(index=True)
    lesson_id: str = Field(index=True)

    # 0.0..1.0 for quiz lessons; 1.0 for "viewed" lessons that don't
    # have a quiz. The aggregator treats >= ``passing_score`` as
    # passed.
    score: float = Field(default=0.0)
    completed: bool = Field(default=False)

    # Free-form blob for the quiz grader (per-question outcome, time
    # spent, etc). Stored as text JSON to keep this table SQLite-
    # friendly without a JSON column dependency.
    detail: str = Field(default="{}")

    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AcademyCertificate(SQLModel, table=True):
    """One issued course certification."""

    __tablename__ = "academy_certificate"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", "course_id", name="ux_cert_user_course"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    user_id: str = Field(index=True)
    course_id: str = Field(index=True)

    # Public, opaque cert id surfaced at ``/academy/certificates/<this>``.
    # We use a short URL-safe token; the value is independent of the
    # primary key so the URL never leaks DB ordering.
    public_id: str = Field(unique=True, index=True)

    # The composite score (mean across required quizzes) the user
    # achieved at issuance. Stored so a recruiter can see "passed at
    # 92%" rather than just "passed".
    final_score: float = Field(default=0.0)
    course_version: str = Field(default="1.0.0")

    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Certificates are perpetual today (no expiry). Field kept here
    # so re-issuance for renewals is a column update, not a new
    # table.
    expires_at: Optional[datetime] = None
