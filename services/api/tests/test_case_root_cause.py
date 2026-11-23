"""A case's root cause is an evidence-backed record, not a prose field.

What was wrong
--------------
The only root-cause artifact anywhere was ``root_cause_hypothesis`` — a free
string on the forensic agent's run state, rendered into the report and the
console as-is. There was no case-level record, no status distinguishing a
*determined* root cause from a model's guess, no citations, and the
post-mortem had no root-cause section at all. A reader could not tell "we
walked the chain back to the phishing mail at 09:02, here is the ledger
entry" apart from "the model wrote a plausible sentence".

What this asserts
-----------------
* A root-cause record carries a status: ``determined`` / ``hypothesis`` /
  ``undetermined``.
* **``determined`` requires at least one cited event**, and every citation
  names an Investigation Ledger entry by ``(run_id, seq)`` — the ledger's
  own stable address. A determined record with no citations is refused.
* ``undetermined`` must name the telemetry that was missing — "we could not
  know" has to say what would have made it knowable.
* Citations are verified against the ledger: naming a ``(run_id, seq)`` that
  does not exist is refused, because a citation that resolves to nothing is
  decoration.
* The record is tenant-scoped through the same explicit-predicate convention
  the cases family uses, and reads/writes go through the real route
  handlers.
* The post-mortem renders the record and **labels a hypothesis as a
  hypothesis**; a case with no record gets an honest "no root-cause record"
  state, never an invented one.

Harness style mirrors ``test_case_comment_resolution_contract.py``: endpoint
functions called directly with a mocked ``DBSession``. The RLS and
real-Postgres half lives in ``tests/isolation/test_case_root_cause_live.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import cases as cases_ep
from app.services import case_root_cause as svc
from app.services.case_root_cause import (
    RootCauseCitationIn,
    RootCauseRecordIn,
)
from fastapi import HTTPException

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")
CASE_ID = uuid.UUID("cccccccc-0000-0000-0000-00000000000c")
RUN_ID = uuid.UUID("dddddddd-0000-0000-0000-00000000000d")


def _principal(tenant: uuid.UUID = TENANT) -> MagicMock:
    principal = MagicMock()
    principal.tenant_id = tenant
    principal.user_id = uuid.uuid4()
    principal.email = "analyst@aisoc.internal"
    return principal


class _Result:
    def __init__(self, rows: list[Any] | None = None, one: Any | None = None) -> None:
        self._rows = rows or []
        self._one = one

    def fetchone(self) -> Any:
        return self._one

    def fetchall(self) -> list[Any]:
        return self._rows

    def scalar(self) -> Any:
        return self._one

    def mappings(self) -> _Result:
        return self


def _db(responses: list[Any]) -> AsyncMock:
    """A DBSession whose execute() returns the queued responses in order."""
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=responses)
    db.commit = AsyncMock()
    return db


def _case_row() -> MagicMock:
    row = MagicMock()
    row.id = CASE_ID
    row.tenant_id = TENANT
    row.status = "investigating"
    return row


def _citation(seq: int = 1, **overrides: Any) -> RootCauseCitationIn:
    payload: dict[str, Any] = {
        "run_id": RUN_ID,
        "seq": seq,
        "source": "ledger",
        "event_time": datetime(2026, 11, 20, 9, 2, tzinfo=UTC),
        "description": "Initial phishing delivery to j.doe (message id <m-1>)",
    }
    payload.update(overrides)
    return RootCauseCitationIn(**payload)


class TestRecordValidation:
    """The service-level contract, independent of transport."""

    def test_determined_requires_at_least_one_citation(self) -> None:
        with pytest.raises(svc.RootCauseValidationError, match="at least one cited event"):
            svc.validate_record(
                RootCauseRecordIn(
                    status="determined",
                    summary="Phishing mail delivered the loader.",
                    citations=[],
                )
            )

    def test_undetermined_must_name_the_missing_telemetry(self) -> None:
        with pytest.raises(svc.RootCauseValidationError, match="missing telemetry"):
            svc.validate_record(
                RootCauseRecordIn(
                    status="undetermined",
                    summary="Could not establish initial access.",
                    citations=[],
                    missing_telemetry=None,
                )
            )

    def test_hypothesis_needs_no_citations_but_keeps_any_it_has(self) -> None:
        record = RootCauseRecordIn(
            status="hypothesis",
            summary="Likely credential stuffing from the staging leak.",
            citations=[_citation()],
        )
        svc.validate_record(record)  # does not raise

    def test_determined_with_citations_passes(self) -> None:
        svc.validate_record(
            RootCauseRecordIn(
                status="determined",
                summary="Walked back to the 09:02 delivery.",
                citations=[_citation(seq=0), _citation(seq=2)],
            )
        )


@pytest.mark.asyncio
class TestUpsertRoute:
    async def test_citations_must_resolve_to_ledger_entries(self) -> None:
        # Case lookup succeeds; the ledger existence check finds only 1 of 2.
        db = _db(
            [
                _Result(one=_case_row()),  # case fetch
                _Result(one=MagicMock(n=1)),  # ledger count: 1 of 2 exists
            ]
        )
        body = RootCauseRecordIn(
            status="determined",
            summary="s",
            citations=[_citation(seq=0), _citation(seq=99)],
        )
        with pytest.raises(HTTPException) as exc:
            await cases_ep.put_case_root_cause(case_id=CASE_ID, body=body, db=db, user=_principal())
        assert exc.value.status_code == 422
        assert "ledger" in str(exc.value.detail).lower()

    async def test_unknown_case_is_404(self) -> None:
        db = _db([_Result(one=None)])
        body = RootCauseRecordIn(status="hypothesis", summary="s", citations=[])
        with pytest.raises(HTTPException) as exc:
            await cases_ep.put_case_root_cause(case_id=CASE_ID, body=body, db=db, user=_principal())
        assert exc.value.status_code == 404

    async def test_contract_violations_are_422_with_the_rule_named(self) -> None:
        db = _db([_Result(one=_case_row())])
        body = RootCauseRecordIn(status="determined", summary="s", citations=[])
        with pytest.raises(HTTPException) as exc:
            await cases_ep.put_case_root_cause(case_id=CASE_ID, body=body, db=db, user=_principal())
        assert exc.value.status_code == 422
        assert "cited event" in str(exc.value.detail)


class TestPostmortemSection:
    def test_the_postmortem_labels_a_hypothesis_as_a_hypothesis(self) -> None:
        from app.services.case_postmortem import build_root_cause_section

        section = build_root_cause_section(
            {
                "status": "hypothesis",
                "summary": "Likely credential stuffing.",
                "missing_telemetry": None,
                "citations": [],
            }
        )
        assert section is not None
        assert section.status == "hypothesis"
        assert "hypothesis" in section.label.lower()
        assert "determined" not in section.label.lower()

    def test_a_determined_record_carries_its_citations(self) -> None:
        from app.services.case_postmortem import build_root_cause_section

        section = build_root_cause_section(
            {
                "status": "determined",
                "summary": "Phishing delivery at 09:02.",
                "missing_telemetry": None,
                "citations": [
                    {
                        "run_id": str(RUN_ID),
                        "seq": 0,
                        "source": "ledger",
                        "event_time": "2026-11-20T09:02:00+00:00",
                        "description": "Initial delivery",
                    }
                ],
            }
        )
        assert section is not None
        assert section.status == "determined"
        assert len(section.citations) == 1
        assert section.citations[0]["seq"] == 0

    def test_no_record_is_an_honest_absence(self) -> None:
        from app.services.case_postmortem import build_root_cause_section

        section = build_root_cause_section(None)
        assert section is not None
        assert section.status == "no_record"
        assert "no root-cause record" in section.label.lower()

    def test_undetermined_names_what_was_missing(self) -> None:
        from app.services.case_postmortem import build_root_cause_section

        section = build_root_cause_section(
            {
                "status": "undetermined",
                "summary": "Initial access not established.",
                "missing_telemetry": "No VPN logs for the window; firewall logs rotated.",
                "citations": [],
            }
        )
        assert section is not None
        assert "VPN logs" in (section.missing_telemetry or "")
