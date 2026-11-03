"""Read a tenant's standing triage questions out of Postgres.

Wave 2, Phase 4.3. The compiler and the answerer live in
:mod:`app.context.triage_questions`; this is the half that puts them on the
triage hot path.

The paragraph that used to be here described the console as already writing
the rows this reads. It did not, and that sentence is what made the gap
invisible: `triage_questions` had a reader on the hot path of every alert and
**no writer anywhere** — no route, no ORM model, no console page, no seed —
so `for_tenant()` returned empty for every tenant forever and the prompt
block was always absent. A reader auditing this file concluded the write half
had shipped, which is the more damaging direction for a stale claim. The
writer now exists, at `POST /api/v1/triage-questions` in the API service
(`app/api/v1/endpoints/triage_questions.py`), and
`tests/integration/test_triage_questions_round_trip.py` drives a write through it and
reads the row back through this store against real Postgres — because a unit
test of either half passes whether or not the other one exists.

Fail-soft, deliberately. A question that cannot be loaded must not stop an
alert being triaged: the worst case here is an analyst not seeing an answer
they would have liked, and the alternative — refusing triage because a
side-channel is unavailable — is worse. A load failure serves the last known
questions rather than silently dropping a tenant's set during a brief
outage, which is the same choice `business_context` makes and for the same
reason.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import structlog

from app.context.triage_questions import QuestionError, TriageQuestion, compile_question

logger = structlog.get_logger(__name__)

#: Long enough that triage does not read Postgres per alert, short enough
#: that a question an analyst just saved is answered on this shift.
CACHE_TTL_SECONDS = 60.0

#: A bound on what one tenant can push into the loader. `answer_all` applies
#: the per-alert bound of its own; this one stops a pathological row count
#: becoming a per-alert query cost.
MAX_QUESTIONS_PER_TENANT = 200

_SELECT = """
    SELECT id::text AS id, alert_type, label, field, op, value
      FROM triage_questions
     WHERE tenant_id = $1 AND enabled
     ORDER BY created_at
     LIMIT $2
"""


class TriageQuestionStore:
    """Per-tenant question sets, cached briefly, never raising."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, list[TriageQuestion]]] = {}
        #: Set by tests and the replay path; replaces the Postgres read.
        self._seeded: list[TriageQuestion] | None = None

    def seed(self, questions: list[TriageQuestion]) -> None:
        self._seeded = list(questions)

    def clear_cache(self) -> None:
        self._cache.clear()

    async def for_tenant(self, tenant_id: str | None) -> list[TriageQuestion]:
        if self._seeded is not None:
            return self._seeded
        if not tenant_id:
            return []

        cached = self._cache.get(tenant_id)
        now = time.monotonic()
        if cached is not None and now - cached[0] < CACHE_TTL_SECONDS:
            return cached[1]

        dsn = os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or ""
        dsn = dsn.strip().replace("postgresql+asyncpg://", "postgresql://")
        if not dsn:
            return []

        try:
            import asyncpg  # noqa: PLC0415 — optional at import time

            conn = await asyncpg.connect(dsn, timeout=5.0)
            try:
                rows = await conn.fetch(_SELECT, uuid.UUID(tenant_id), MAX_QUESTIONS_PER_TENANT)
            finally:
                await conn.close()
        except Exception as exc:  # noqa: BLE001 — never break triage
            logger.warning("triage_questions.load_failed", tenant_id=tenant_id, error=str(exc))
            return cached[1] if cached else []

        questions: list[TriageQuestion] = []
        for row in rows:
            raw: dict[str, Any] = dict(row)
            # `value` is JSONB and asyncpg hands it back as the encoded text
            # unless a codec is registered, so `"eq"` against the string
            # `'"office"'` would never match the decoded `office` the
            # evidence carries. Decoded here rather than by registering a
            # global codec, which would change every other query in whatever
            # process imports this.
            if isinstance(raw.get("value"), str | bytes):
                try:
                    raw["value"] = json.loads(raw["value"])
                except (TypeError, ValueError):
                    logger.warning("triage_questions.value_not_json", question_id=raw.get("id"))
                    continue
            try:
                questions.append(compile_question(raw))
            except QuestionError as exc:
                # One malformed row must not cost the tenant their other
                # questions, and it is logged by id so it can be found.
                logger.warning("triage_questions.row_rejected", question_id=raw.get("id"), error=str(exc))

        self._cache[tenant_id] = (now, questions)
        return questions


__all__ = ["CACHE_TTL_SECONDS", "MAX_QUESTIONS_PER_TENANT", "TriageQuestionStore"]
