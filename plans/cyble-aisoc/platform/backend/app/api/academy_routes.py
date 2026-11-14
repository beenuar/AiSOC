"""Cyble Academy — REST surface (t5-academy).

  GET  /academy/courses                         List of available courses.
  GET  /academy/courses/{course_id}             Full curriculum.
  GET  /academy/courses/{course_id}/progress    My progress + cert state.
  POST /academy/courses/{course_id}/progress    Mark a lesson complete /
                                                submit a quiz attempt.
  POST /academy/courses/{course_id}/certify     Issue a certificate (idempotent).
  GET  /academy/certificates/{public_id}        Public verification page.

Progress + certification are scoped by ``(tenant_id, user_id)``. The
public verification endpoint deliberately requires NO auth — a
recruiter must be able to paste the URL into a browser and see the
issued credential. The verification payload only exposes the
course id, the issuance timestamp, and the final score; we never
leak the learner's tenant or any other PII.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.academy import (
    Course,
    QuizAttempt,
    grade_quiz,
    issue_certificate,
    list_courses,
    load_course,
    record_lesson_progress,
    user_progress,
    verify_certificate,
)
from app.academy.service import LessonKind
from app.db import get_session
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/academy", tags=["academy"])


def _course_to_summary(course: Course) -> dict[str, Any]:
    return {
        "id": course.id,
        "title": course.title,
        "version": course.version,
        "audience": course.audience,
        "description": course.description,
        "estimated_minutes": course.estimated_minutes,
        "passing_score": course.passing_score,
        "module_count": len(course.modules),
        "lesson_count": sum(1 for _ in course.lessons()),
        "quiz_count": len(course.required_quizzes()),
    }


def _course_to_detail(course: Course) -> dict[str, Any]:
    out = _course_to_summary(course)
    out["modules"] = [
        {
            "id": m.id,
            "title": m.title,
            "lessons": [
                {
                    "id": l.id,
                    "title": l.title,
                    "kind": l.kind.value,
                    "estimated_minutes": l.estimated_minutes,
                    "body": l.body,
                    "passing_score": l.passing_score,
                    "questions": [
                        {
                            "id": q.id,
                            "prompt": q.prompt,
                            # We deliberately strip the answer field on
                            # GET — the curriculum YAML carries it but
                            # exposing it via the API would let a
                            # learner see the answer key. The grader
                            # below has access to the full curriculum.
                            "choices": [
                                {"id": cid, "label": label} for cid, label in q.choices
                            ],
                        }
                        for q in l.questions
                    ],
                }
                for l in m.lessons
            ],
        }
        for m in course.modules
    ]
    return out


@router.get("/courses")
def list_courses_route() -> dict[str, Any]:
    """Public catalog of Academy courses."""
    courses = list_courses()
    return {
        "count": len(courses),
        "courses": [_course_to_summary(c) for c in courses],
    }


@router.get("/courses/{course_id}")
def get_course(course_id: str) -> dict[str, Any]:
    """Full curriculum for one course (sans answer keys)."""
    course = load_course(course_id)
    if course is None:
        raise HTTPException(status_code=404, detail=f"course '{course_id}' not found")
    return _course_to_detail(course)


@router.get("/courses/{course_id}/progress")
def get_my_progress(
    course_id: str,
    ctx: TenantContext = Depends(require_tenant),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """The caller's progress on ``course_id``."""
    course = load_course(course_id)
    if course is None:
        raise HTTPException(status_code=404, detail=f"course '{course_id}' not found")
    progress = user_progress(
        session,
        tenant_id=ctx.active_tenant_id,
        user_id=ctx.subject,
        course=course,
    )
    return {
        "course_id": progress.course_id,
        "user_id": progress.user_id,
        "completed_lessons": progress.completed_lessons,
        "total_lessons": progress.total_lessons,
        "completion_pct": (
            round(progress.completed_lessons / progress.total_lessons, 3)
            if progress.total_lessons
            else 0.0
        ),
        "quiz_average": round(progress.quiz_average, 3),
        "passed_required_quizzes": progress.passed_required_quizzes,
        "certified": progress.certified,
        "certificate_id": progress.certificate_id,
    }


class LessonProgressRequest(BaseModel):
    lesson_id: str = Field(min_length=1)
    answers: Optional[dict[str, str]] = None


@router.post("/courses/{course_id}/progress")
def post_progress(
    course_id: str,
    body: LessonProgressRequest,
    ctx: TenantContext = Depends(require_tenant),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Record completion of a lesson; for quiz lessons, grade the attempt."""
    course = load_course(course_id)
    if course is None:
        raise HTTPException(status_code=404, detail=f"course '{course_id}' not found")
    lesson = course.lesson(body.lesson_id)
    if lesson is None:
        raise HTTPException(
            status_code=404,
            detail=f"lesson '{body.lesson_id}' not found in course '{course_id}'",
        )

    attempt: Optional[QuizAttempt] = None
    if lesson.kind == LessonKind.quiz:
        if not body.answers:
            raise HTTPException(
                status_code=400,
                detail="quiz lessons require an 'answers' map (question_id -> choice_id)",
            )
        attempt = QuizAttempt(lesson_id=lesson.id, answers=body.answers)

    progress, result = record_lesson_progress(
        session,
        tenant_id=ctx.active_tenant_id,
        user_id=ctx.subject,
        course=course,
        lesson_id=body.lesson_id,
        quiz_attempt=attempt,
    )

    payload: dict[str, Any] = {
        "lesson_id": progress.lesson_id,
        "completed": progress.completed,
        "score": progress.score,
    }
    if result is not None:
        payload["quiz_result"] = {
            "score": result.score,
            "passed": result.passed,
            "per_question": result.per_question,
        }
    return payload


@router.post("/courses/{course_id}/certify")
def certify_route(
    course_id: str,
    ctx: TenantContext = Depends(require_tenant),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Issue a certificate for the caller if they've passed the course."""
    course = load_course(course_id)
    if course is None:
        raise HTTPException(status_code=404, detail=f"course '{course_id}' not found")
    cert = issue_certificate(
        session,
        tenant_id=ctx.active_tenant_id,
        user_id=ctx.subject,
        course=course,
    )
    if cert is None:
        progress = user_progress(
            session,
            tenant_id=ctx.active_tenant_id,
            user_id=ctx.subject,
            course=course,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "message": "not yet eligible — required quizzes not passed",
                "course_id": course.id,
                "passed_required_quizzes": progress.passed_required_quizzes,
                "quiz_average": round(progress.quiz_average, 3),
                "passing_score": course.passing_score,
            },
        )
    return {
        "course_id": cert.course_id,
        "course_version": cert.course_version,
        "public_id": cert.public_id,
        "issued_at": cert.issued_at.isoformat(),
        "final_score": round(cert.final_score, 3),
        "verify_url": f"/academy/certificates/{cert.public_id}",
    }


@router.get("/certificates/{public_id}")
def verify_certificate_route(
    public_id: str,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Public verification of a certificate by its public id.

    Deliberately unauthenticated. The response carries only the
    minimum a third party needs to confirm the credential is real:
    course identifier, version, issuance date, and final score.
    """
    cert = verify_certificate(session, public_id=public_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="certificate not found")
    course = load_course(cert.course_id)
    return {
        "public_id": cert.public_id,
        "course_id": cert.course_id,
        "course_title": course.title if course else cert.course_id,
        "course_version": cert.course_version,
        "issued_at": cert.issued_at.isoformat(),
        "final_score": round(cert.final_score, 3),
        # Intentionally exclude tenant_id and user_id — recruiters
        # don't need them and they're PII-adjacent.
        "valid": True,
    }
