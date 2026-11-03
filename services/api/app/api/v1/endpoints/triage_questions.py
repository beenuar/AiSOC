"""The questions a tenant's analysts ask of every alert.

Migration 154 created ``triage_questions``. The agents triage worker reads it
on **every alert** through ``app/context/triage_questions_store.py``, and the
compiler and answerer beside it are tested over 21 cases. Nothing wrote it: no
route, no ORM model, no console page, no seed. ``for_tenant()`` returned empty
for every tenant forever and the prompt block was always absent — and the
store's own docstring asserted the writer existed ("without it the console
writes questions to `triage_questions` that no triage decision ever reads"),
so a reader auditing that file concluded the write half had shipped.

This is the write half.

The column split is the security property and this surface must not blur it.
``label`` is free tenant text that decides nothing and reaches a model only
inside an ``<UNTRUSTED_DATA>`` envelope, quoted, beside an answer computed
without it. ``field`` / ``op`` / ``value`` is a closed-schema lookup over the
evidence bundle and is what actually produces the answer. There is no column
whose contents are interpreted, and nothing here lets a tenant write one.

``op`` is validated against the same closed set the migration's CHECK
constraint and the agents compiler use. A comparator nothing implements —
``neq`` being the recorded instance — parses, saves, and silently never
matches, so a bad one is a 422 naming the field rather than a question that
answers "no" to everything forever.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.api.v1.deps import AuthUser
from app.db.rls import TenantDBSession

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/triage-questions", tags=["triage-questions"])

#: Mirrors the migration's CHECK and ``triage_questions.QUESTION_OPS``.
#: ``check_business_context_grammar.py`` holds the producers level; this list
#: exists so a bad comparator is a 422 and not a driver error.
_OPS = ("eq", "ne", "contains", "startswith", "endswith", "in", "not_in", "exists", "not_exists")
_UNARY = ("exists", "not_exists")

#: The same dotted-path shape the migration's CHECK enforces.
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")

MAX_QUESTIONS_PER_TENANT = 200


class QuestionIn(BaseModel):
    alert_type: str = Field(default="*", max_length=200, description="'*' matches every alert type")
    label: str = Field(min_length=1, max_length=200, description="Free text for the analyst. Never interpreted.")
    field_path: str = Field(alias="field", max_length=200)
    op: str
    value: Any = None
    enabled: bool = True

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _validate(self) -> QuestionIn:
        if self.op not in _OPS:
            raise ValueError(f"op must be one of {_OPS}; a comparator nothing implements saves and then matches nothing")
        if not _FIELD_RE.match(self.field_path):
            raise ValueError(
                f"{self.field_path!r} is not an evidence field path. Use a dotted name such as "
                "'identity.travel.in_progress' or 'network.ip.is_office'"
            )
        if self.op in _UNARY:
            # Normalised rather than rejected: the migration's CHECK requires
            # NULL here, and a caller supplying a value for `exists` has
            # written something harmless rather than something wrong.
            self.value = None
        elif self.value is None:
            raise ValueError(f"op {self.op!r} needs a value")
        return self


class QuestionOut(QuestionIn):
    id: str
    created_at: datetime
    updated_at: datetime


_SELECT = """
    SELECT id::text AS id, alert_type, label, field, op, value, enabled, created_at, updated_at
      FROM triage_questions
     WHERE tenant_id = CAST(:tenant_id AS uuid)
     ORDER BY alert_type, created_at
"""

_INSERT = """
    INSERT INTO triage_questions (tenant_id, alert_type, label, field, op, value, enabled, created_by)
    VALUES (
        CAST(:tenant_id AS uuid), :alert_type, :label, :field, :op,
        CAST(:value AS jsonb), :enabled, CAST(:created_by AS uuid)
    )
    ON CONFLICT (tenant_id, alert_type, field, op) DO UPDATE SET
        label = EXCLUDED.label,
        value = EXCLUDED.value,
        enabled = EXCLUDED.enabled,
        updated_at = NOW()
    RETURNING id::text AS id, alert_type, label, field, op, value, enabled, created_at, updated_at
"""


def _row_to_out(row: Any) -> QuestionOut:
    return QuestionOut(
        id=row["id"],
        alert_type=row["alert_type"],
        label=row["label"],
        field=row["field"],
        op=row["op"],
        value=row["value"],
        enabled=row["enabled"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.get("", response_model=list[QuestionOut])
async def list_triage_questions(user: AuthUser, db: TenantDBSession) -> list[QuestionOut]:
    """Every question this tenant has declared, enabled or not."""
    await user.require_permission_db("settings:read", db)
    rows = (await db.execute(text(_SELECT), {"tenant_id": str(user.tenant_id)})).mappings().all()
    return [_row_to_out(r) for r in rows]


@router.post("", response_model=QuestionOut, status_code=status.HTTP_201_CREATED)
async def upsert_triage_question(payload: QuestionIn, user: AuthUser, db: TenantDBSession) -> QuestionOut:
    """Declare a question, or update the one with the same lookup.

    Upsert rather than insert, because the table's own uniqueness is
    ``(tenant_id, alert_type, field, op)``: two identical lookups under
    different labels would both be answered and both rendered, which reads to
    an analyst as corroboration from one fact. Re-posting a lookup therefore
    edits its label rather than raising.
    """
    await user.require_permission_db("settings:write", db)
    tenant_id = str(user.tenant_id)

    count = (
        await db.execute(
            text("SELECT count(*) FROM triage_questions WHERE tenant_id = CAST(:tenant_id AS uuid)"),
            {"tenant_id": tenant_id},
        )
    ).scalar_one()
    existing = (
        await db.execute(
            text(
                """
                SELECT 1 FROM triage_questions
                 WHERE tenant_id = CAST(:tenant_id AS uuid)
                   AND alert_type = :alert_type AND field = :field AND op = :op
                """
            ),
            {"tenant_id": tenant_id, "alert_type": payload.alert_type, "field": payload.field_path, "op": payload.op},
        )
    ).first()
    if existing is None and int(count) >= MAX_QUESTIONS_PER_TENANT:
        # The reader bounds its own query at the same number. Refusing here
        # rather than silently writing a row the worker will never load is the
        # difference between a 422 and a question that is configured and inert.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"this tenant already has {count} questions and the triage reader loads at most "
                f"{MAX_QUESTIONS_PER_TENANT}; disable or delete one before adding another"
            ),
        )

    import json  # noqa: PLC0415 — only needed on the write path

    row = (
        (
            await db.execute(
                text(_INSERT),
                {
                    "tenant_id": tenant_id,
                    "alert_type": payload.alert_type,
                    "label": payload.label,
                    "field": payload.field_path,
                    "op": payload.op,
                    "value": None if payload.value is None else json.dumps(payload.value),
                    "enabled": payload.enabled,
                    "created_by": str(user.user_id),
                },
            )
        )
        .mappings()
        .one()
    )
    await db.commit()
    logger.info(
        "triage_question.saved",
        tenant_id=tenant_id,
        alert_type=payload.alert_type,
        field=payload.field_path,
        op=payload.op,
    )
    return _row_to_out(row)


@router.delete("/{question_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_triage_question(question_id: str, user: AuthUser, db: TenantDBSession) -> None:
    """Remove a question.

    404 and not 403 on another tenant's id: a 403 would make this route an
    existence oracle over every tenant's question ids, byte-identical to a
    genuine miss.
    """
    await user.require_permission_db("settings:write", db)
    result = await db.execute(
        text(
            """
            DELETE FROM triage_questions
             WHERE tenant_id = CAST(:tenant_id AS uuid) AND id = CAST(:id AS uuid)
            """
        ),
        {"tenant_id": str(user.tenant_id), "id": question_id},
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such triage question")
    await db.commit()
    logger.info("triage_question.deleted", tenant_id=str(user.tenant_id), question_id=question_id)
