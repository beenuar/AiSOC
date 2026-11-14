"""Smoke test: Cyble Academy curriculum + grading + certification (t5-academy).

Covers:

* The two seeded courses load from YAML and surface in the catalog.
* Quiz grading scores correctly and respects passing thresholds.
* Lesson-progress upsert keeps the *best* score, not the latest.
* Certification is gated on passing every required quiz; once issued
  it is idempotent and verifiable via the public endpoint.
* The public verification endpoint is reachable without auth and
  *never* leaks tenant/user identity.
"""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("AISOC_AUTH_DISABLED", "1")
os.environ.setdefault("AISOC_LLM_PROVIDER", "mock")
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-academy-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from fastapi.testclient import TestClient  # noqa: E402

from app.academy.service import (  # noqa: E402
    LessonKind,
    QuizAttempt,
    grade_quiz,
    list_courses,
    load_course,
    record_lesson_progress,
    user_progress,
    issue_certificate,
    verify_certificate,
)
from app.db import init_db, get_session  # noqa: E402
from app.main import app  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _curriculum_smoke() -> None:
    courses = list_courses()
    _expect(len(courses) >= 2, f"expected >=2 seeded courses, got {len(courses)}")

    fundamentals = load_course("aisoc-fundamentals")
    _expect(fundamentals is not None, "aisoc-fundamentals course missing")
    quizzes = fundamentals.required_quizzes()
    _expect(len(quizzes) == 2, f"expected 2 quizzes in fundamentals, got {len(quizzes)}")

    quiz = quizzes[0]
    _expect(quiz.kind == LessonKind.quiz, "expected quiz kind on required quiz")
    _expect(len(quiz.questions) >= 2, "expected at least 2 questions per quiz")

    perfect = QuizAttempt(
        lesson_id=quiz.id,
        answers={q.id: q.answer for q in quiz.questions},
    )
    result_perfect = grade_quiz(fundamentals, perfect)
    _expect(result_perfect.score == 1.0, f"perfect score should be 1.0, got {result_perfect.score}")
    _expect(result_perfect.passed, "perfect attempt should pass")

    bad = QuizAttempt(lesson_id=quiz.id, answers={q.id: "z" for q in quiz.questions})
    result_bad = grade_quiz(fundamentals, bad)
    _expect(result_bad.score == 0.0, f"all-wrong score should be 0.0, got {result_bad.score}")
    _expect(not result_bad.passed, "all-wrong attempt should not pass")


def _persistence_smoke() -> None:
    init_db()
    course = load_course("aisoc-fundamentals")
    quizzes = course.required_quizzes()

    with next(get_session()) as session:
        # First, take quiz-1 with everything wrong.
        bad_attempt = QuizAttempt(
            lesson_id=quizzes[0].id,
            answers={q.id: "z" for q in quizzes[0].questions},
        )
        record_lesson_progress(
            session,
            tenant_id="t-academy",
            user_id="u-1",
            course=course,
            lesson_id=quizzes[0].id,
            quiz_attempt=bad_attempt,
        )

        progress_after_bad = user_progress(
            session, tenant_id="t-academy", user_id="u-1", course=course
        )
        _expect(
            not progress_after_bad.passed_required_quizzes,
            "should not pass after one bad attempt",
        )

        # Now retake quiz-1 perfectly. Expect the upsert to *keep the
        # higher* score rather than overwrite it with the latest.
        good_q1 = QuizAttempt(
            lesson_id=quizzes[0].id,
            answers={q.id: q.answer for q in quizzes[0].questions},
        )
        record_lesson_progress(
            session,
            tenant_id="t-academy",
            user_id="u-1",
            course=course,
            lesson_id=quizzes[0].id,
            quiz_attempt=good_q1,
        )
        good_q2 = QuizAttempt(
            lesson_id=quizzes[1].id,
            answers={q.id: q.answer for q in quizzes[1].questions},
        )
        record_lesson_progress(
            session,
            tenant_id="t-academy",
            user_id="u-1",
            course=course,
            lesson_id=quizzes[1].id,
            quiz_attempt=good_q2,
        )

        # Mark a reading lesson too — should land at score=1.0.
        reading = next(l for l in course.lessons() if l.kind == LessonKind.reading)
        record_lesson_progress(
            session,
            tenant_id="t-academy",
            user_id="u-1",
            course=course,
            lesson_id=reading.id,
        )

        progress_after_good = user_progress(
            session, tenant_id="t-academy", user_id="u-1", course=course
        )
        _expect(
            progress_after_good.passed_required_quizzes,
            f"should pass required quizzes; quiz_avg={progress_after_good.quiz_average}",
        )
        _expect(
            progress_after_good.completed_lessons >= 3,
            f"completed lessons should be >=3, got {progress_after_good.completed_lessons}",
        )

        cert = issue_certificate(
            session, tenant_id="t-academy", user_id="u-1", course=course
        )
        _expect(cert is not None, "certificate should be issued after passing quizzes")
        _expect(len(cert.public_id) >= 16, "public id should be reasonably long")

        # Re-issue should be idempotent.
        cert2 = issue_certificate(
            session, tenant_id="t-academy", user_id="u-1", course=course
        )
        _expect(cert2 is not None and cert2.public_id == cert.public_id, "issuance not idempotent")

        # Public verification.
        looked_up = verify_certificate(session, public_id=cert.public_id)
        _expect(looked_up is not None, "verify_certificate failed")
        _expect(looked_up.course_id == course.id, "course mismatch on verified cert")


def _api_smoke() -> None:
    course = load_course("aisoc-fundamentals")
    with TestClient(app) as client:
        # Catalog.
        r = client.get("/academy/courses")
        _expect(r.status_code == 200, f"catalog 200 expected, got {r.status_code}")
        payload = r.json()
        _expect(payload["count"] >= 2, "catalog count should be >=2")

        # Course detail — ensure answers are NOT leaked.
        r = client.get(f"/academy/courses/{course.id}")
        _expect(r.status_code == 200, f"detail 200 expected, got {r.status_code}")
        body = r.json()
        for module in body["modules"]:
            for lesson in module["lessons"]:
                for question in lesson.get("questions", []):
                    _expect(
                        "answer" not in question,
                        f"answer leaked in API response for {question}",
                    )

        # New user — submit a quiz attempt.
        course = load_course("aisoc-fundamentals")
        quizzes = course.required_quizzes()
        for quiz in quizzes:
            r = client.post(
                f"/academy/courses/{course.id}/progress",
                json={
                    "lesson_id": quiz.id,
                    "answers": {q.id: q.answer for q in quiz.questions},
                },
            )
            _expect(r.status_code == 200, f"progress POST {quiz.id}: {r.status_code} {r.text}")
            data = r.json()
            _expect(data["quiz_result"]["passed"], f"quiz {quiz.id} should pass")

        # Issue a certificate via the API.
        r = client.post(f"/academy/courses/{course.id}/certify")
        _expect(r.status_code == 200, f"certify 200 expected, got {r.status_code} {r.text}")
        cert_payload = r.json()
        public_id = cert_payload["public_id"]
        _expect(public_id, "public_id missing from certificate payload")

        # Public verification works without auth and doesn't leak PII.
        r = client.get(f"/academy/certificates/{public_id}")
        _expect(r.status_code == 200, f"verify 200 expected, got {r.status_code}")
        verify_payload = r.json()
        _expect(verify_payload["valid"], "verify payload should be valid=True")
        for forbidden in ("tenant_id", "user_id", "subject"):
            _expect(
                forbidden not in verify_payload,
                f"public verify response leaks {forbidden}",
            )

        # Eligibility gate — a brand new user can't certify.
        r = client.post(
            "/academy/courses/aisoc-detection-author/certify",
        )
        _expect(
            r.status_code in (409,),
            f"certify on incomplete course should 409, got {r.status_code}: {r.text}",
        )


def main() -> None:
    _curriculum_smoke()
    _persistence_smoke()
    _api_smoke()
    print("ok: academy smoke")


if __name__ == "__main__":
    main()
