"""Cyble Academy curriculum + grading service (t5-academy).

The Academy is two things:

1. **A static curriculum** authored as YAML files in
   ``app/academy/curriculum/``. The curriculum is loaded from disk at
   import time (cheap; <100 KB) and re-loaded on every call in tests
   so curriculum edits show up without a restart.

2. **A progress + certification ledger** persisted in
   :class:`AcademyProgress` and :class:`AcademyCertificate`. We track
   *per-lesson* progress so a learner who completes 3/4 lessons in a
   module gets credit for what they did; the course completion
   percentage is just an aggregation.

Why YAML on disk and not the DB? Curriculum is content, not user
data. Putting it in the repo means:

* Curriculum owners edit it in PRs that are reviewed.
* Every environment runs the same curriculum.
* Diffs between course versions show up in git, not in a DB
  migration.

The grader is intentionally simple — multiple-choice with one
correct answer per question, average of question outcomes. We can
add free-form / proctored questions later; the
:class:`QuizQuestion` shape leaves room for it.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

import yaml
from sqlmodel import Session, select

from app.models.academy import AcademyCertificate, AcademyProgress

# ---------------------------------------------------------------------------
# Curriculum DTOs (loaded from YAML — never persisted to the DB).
# ---------------------------------------------------------------------------


class LessonKind(str, Enum):
    """The shape of a lesson body.

    ``reading`` is the default — a static markdown/text body the
    learner reads. ``quiz`` lessons drive the grader and contribute
    to the course's ``final_score``.
    """

    reading = "reading"
    quiz = "quiz"


@dataclass(frozen=True)
class QuizQuestion:
    """A single multiple-choice question."""

    id: str
    prompt: str
    choices: tuple[tuple[str, str], ...]
    answer: str

    def is_correct(self, picked: str) -> bool:
        """Return True if ``picked`` matches the recorded answer."""

        return picked == self.answer


@dataclass(frozen=True)
class Lesson:
    id: str
    title: str
    kind: LessonKind
    estimated_minutes: int = 5
    body: str = ""
    questions: tuple[QuizQuestion, ...] = ()
    # Per-lesson passing score for quizzes. Falls back to the course
    # default if unset.
    passing_score: Optional[float] = None


@dataclass(frozen=True)
class Module:
    id: str
    title: str
    lessons: tuple[Lesson, ...]


@dataclass(frozen=True)
class Course:
    id: str
    title: str
    version: str
    audience: str
    description: str
    estimated_minutes: int
    passing_score: float
    modules: tuple[Module, ...]

    def lessons(self) -> Iterable[Lesson]:
        for module in self.modules:
            yield from module.lessons

    def lesson(self, lesson_id: str) -> Optional[Lesson]:
        for lesson in self.lessons():
            if lesson.id == lesson_id:
                return lesson
        return None

    def required_quizzes(self) -> tuple[Lesson, ...]:
        """The set of quiz lessons a learner must clear to certify."""

        return tuple(l for l in self.lessons() if l.kind == LessonKind.quiz)


# ---------------------------------------------------------------------------
# Runtime DTOs (returned to API consumers).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuizResult:
    """Outcome of grading one quiz attempt."""

    lesson_id: str
    score: float
    passed: bool
    per_question: dict[str, bool]


@dataclass(frozen=True)
class QuizAttempt:
    """The user-supplied input to :func:`grade_quiz`."""

    lesson_id: str
    answers: dict[str, str]


@dataclass(frozen=True)
class CourseProgress:
    """Aggregated learner progress for a single course."""

    course_id: str
    user_id: str
    completed_lessons: int
    total_lessons: int
    quiz_average: float
    passed_required_quizzes: bool
    certified: bool
    certificate_id: Optional[str]


# ---------------------------------------------------------------------------
# Curriculum loading
# ---------------------------------------------------------------------------


def _curriculum_dir() -> Path:
    return Path(__file__).resolve().parent / "curriculum"


def _coerce_questions(raw: list[dict]) -> tuple[QuizQuestion, ...]:
    out: list[QuizQuestion] = []
    for q in raw:
        choices = tuple((c["id"], c["label"]) for c in q.get("choices", []))
        out.append(
            QuizQuestion(
                id=str(q["id"]),
                prompt=str(q["prompt"]).strip(),
                choices=choices,
                answer=str(q["answer"]),
            )
        )
    return tuple(out)


def _coerce_lesson(raw: dict) -> Lesson:
    kind = LessonKind(raw.get("kind", "reading"))
    questions = _coerce_questions(raw.get("questions", [])) if kind == LessonKind.quiz else ()
    return Lesson(
        id=str(raw["id"]),
        title=str(raw["title"]),
        kind=kind,
        estimated_minutes=int(raw.get("estimated_minutes", 5)),
        body=str(raw.get("body", "")).strip(),
        questions=questions,
        passing_score=raw.get("passing_score"),
    )


def _coerce_course(raw: dict) -> Course:
    modules = tuple(
        Module(
            id=str(m["id"]),
            title=str(m["title"]),
            lessons=tuple(_coerce_lesson(l) for l in m.get("lessons", [])),
        )
        for m in raw.get("modules", [])
    )
    return Course(
        id=str(raw["id"]),
        title=str(raw["title"]),
        version=str(raw.get("version", "1.0.0")),
        audience=str(raw.get("audience", "")),
        description=str(raw.get("description", "")).strip(),
        estimated_minutes=int(raw.get("estimated_minutes", 30)),
        passing_score=float(raw.get("passing_score", 0.7)),
        modules=modules,
    )


def list_courses() -> list[Course]:
    """Return every course shipped in the curriculum directory.

    Courses are sorted by ``id`` for stable ordering in the catalog.
    """

    out: list[Course] = []
    for path in sorted(_curriculum_dir().glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not raw:
            continue
        out.append(_coerce_course(raw))
    return out


def load_course(course_id: str) -> Optional[Course]:
    """Look up a course by id. Returns ``None`` if unknown."""

    for course in list_courses():
        if course.id == course_id:
            return course
    return None


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------


def grade_quiz(course: Course, attempt: QuizAttempt) -> QuizResult:
    """Score a quiz attempt against the curriculum's recorded answers.

    Lessons that aren't quizzes raise ``ValueError`` — the caller is
    expected to look up the lesson via :meth:`Course.lesson` before
    grading.
    """

    lesson = course.lesson(attempt.lesson_id)
    if lesson is None:
        raise ValueError(f"unknown lesson '{attempt.lesson_id}' for course '{course.id}'")
    if lesson.kind != LessonKind.quiz:
        raise ValueError(f"lesson '{lesson.id}' is not a quiz")

    per_question: dict[str, bool] = {}
    for question in lesson.questions:
        picked = attempt.answers.get(question.id, "")
        per_question[question.id] = question.is_correct(picked)

    if not lesson.questions:
        score = 1.0
    else:
        score = sum(1.0 for ok in per_question.values() if ok) / len(lesson.questions)

    passing = lesson.passing_score if lesson.passing_score is not None else course.passing_score
    return QuizResult(
        lesson_id=lesson.id,
        score=score,
        passed=score >= passing,
        per_question=per_question,
    )


# ---------------------------------------------------------------------------
# Persistence: progress + certification
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _upsert_progress(
    session: Session,
    *,
    tenant_id: str,
    user_id: str,
    course_id: str,
    lesson_id: str,
    score: float,
    completed: bool,
    detail: dict,
) -> AcademyProgress:
    row = session.exec(
        select(AcademyProgress).where(
            AcademyProgress.tenant_id == tenant_id,
            AcademyProgress.user_id == user_id,
            AcademyProgress.lesson_id == lesson_id,
        )
    ).one_or_none()

    detail_json = json.dumps(detail, sort_keys=True)
    if row is None:
        row = AcademyProgress(
            tenant_id=tenant_id,
            user_id=user_id,
            course_id=course_id,
            lesson_id=lesson_id,
            score=score,
            completed=completed,
            detail=detail_json,
        )
        session.add(row)
    else:
        # Take the *best* score so a re-attempt can lift the learner
        # past the passing line but never drag them back down.
        row.score = max(row.score, score)
        row.completed = row.completed or completed
        row.detail = detail_json
        row.updated_at = _now()
    session.commit()
    session.refresh(row)
    return row


def record_lesson_progress(
    session: Session,
    *,
    tenant_id: str,
    user_id: str,
    course: Course,
    lesson_id: str,
    quiz_attempt: Optional[QuizAttempt] = None,
) -> tuple[AcademyProgress, Optional[QuizResult]]:
    """Mark a lesson complete and (for quiz lessons) score the attempt.

    Reading lessons mark themselves complete with a score of 1.0.
    Quiz lessons require ``quiz_attempt`` to be supplied; the
    learner is marked ``completed=True`` regardless of whether they
    passed (so the course progress reflects effort), but the
    certificate gate uses the *score* not the completion flag.
    """

    lesson = course.lesson(lesson_id)
    if lesson is None:
        raise ValueError(f"unknown lesson '{lesson_id}' for course '{course.id}'")

    if lesson.kind == LessonKind.quiz:
        if quiz_attempt is None:
            raise ValueError(f"quiz lesson '{lesson_id}' requires a quiz_attempt")
        result = grade_quiz(course, quiz_attempt)
        progress = _upsert_progress(
            session,
            tenant_id=tenant_id,
            user_id=user_id,
            course_id=course.id,
            lesson_id=lesson.id,
            score=result.score,
            completed=True,
            detail={
                "kind": "quiz",
                "per_question": result.per_question,
                "passed": result.passed,
            },
        )
        return progress, result

    progress = _upsert_progress(
        session,
        tenant_id=tenant_id,
        user_id=user_id,
        course_id=course.id,
        lesson_id=lesson.id,
        score=1.0,
        completed=True,
        detail={"kind": lesson.kind.value},
    )
    return progress, None


def _course_progress_rows(
    session: Session, *, tenant_id: str, user_id: str, course_id: str
) -> list[AcademyProgress]:
    return list(
        session.exec(
            select(AcademyProgress).where(
                AcademyProgress.tenant_id == tenant_id,
                AcademyProgress.user_id == user_id,
                AcademyProgress.course_id == course_id,
            )
        )
    )


def user_progress(
    session: Session, *, tenant_id: str, user_id: str, course: Course
) -> CourseProgress:
    """Aggregate this learner's current progress in ``course``."""

    rows = {r.lesson_id: r for r in _course_progress_rows(
        session, tenant_id=tenant_id, user_id=user_id, course_id=course.id
    )}

    total = sum(1 for _ in course.lessons())
    completed = sum(1 for r in rows.values() if r.completed)

    quizzes = course.required_quizzes()
    if quizzes:
        scores = [rows[q.id].score for q in quizzes if q.id in rows]
        quiz_avg = sum(scores) / len(quizzes) if quizzes else 0.0
        passed_required = len(scores) == len(quizzes) and all(
            (rows[q.id].score >= (q.passing_score or course.passing_score)) for q in quizzes
        )
    else:
        quiz_avg = 1.0
        passed_required = True

    cert = session.exec(
        select(AcademyCertificate).where(
            AcademyCertificate.tenant_id == tenant_id,
            AcademyCertificate.user_id == user_id,
            AcademyCertificate.course_id == course.id,
        )
    ).one_or_none()

    return CourseProgress(
        course_id=course.id,
        user_id=user_id,
        completed_lessons=completed,
        total_lessons=total,
        quiz_average=quiz_avg,
        passed_required_quizzes=passed_required,
        certified=cert is not None,
        certificate_id=cert.public_id if cert else None,
    )


def issue_certificate(
    session: Session, *, tenant_id: str, user_id: str, course: Course
) -> Optional[AcademyCertificate]:
    """Issue a certificate if the learner has cleared every required quiz.

    Returns ``None`` if the learner is not yet eligible. Idempotent:
    re-issuing on an already-certified user returns the existing row.
    """

    progress = user_progress(session, tenant_id=tenant_id, user_id=user_id, course=course)
    if not progress.passed_required_quizzes:
        return None

    existing = session.exec(
        select(AcademyCertificate).where(
            AcademyCertificate.tenant_id == tenant_id,
            AcademyCertificate.user_id == user_id,
            AcademyCertificate.course_id == course.id,
        )
    ).one_or_none()
    if existing:
        return existing

    cert = AcademyCertificate(
        tenant_id=tenant_id,
        user_id=user_id,
        course_id=course.id,
        public_id=secrets.token_urlsafe(16),
        final_score=progress.quiz_average,
        course_version=course.version,
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


def verify_certificate(
    session: Session, *, public_id: str
) -> Optional[AcademyCertificate]:
    """Look up a certificate by its public id (used by the verify page)."""

    return session.exec(
        select(AcademyCertificate).where(AcademyCertificate.public_id == public_id)
    ).one_or_none()
