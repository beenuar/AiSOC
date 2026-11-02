"""Do-not-regress guard for the investigation-detail ledger fallback.

Two bugs, same root: agents keeps investigation runs in a process-local dict
(`_runs`, "swap for Redis in production") that empties on every restart. The
detail route proxied ONLY to agents, so after a restart every historical run
404'd while the sibling list route (which falls back to the Postgres ledger)
still showed it. And even once detail returned, the Recon / Forensic / Response
tabs rendered bare headers with no body, because those blocks live only in the
volatile `_runs` and were never persisted as artifacts.

The fix reconstructs both from the append-only ledger: run metadata + report_md
from `investigation_runs`/`investigation_artifacts`, and the recon/forensic/
responder blocks + audit trail from the `investigation_events` llm_response rows
the investigator pipeline already writes. These tests assert that behaviour so an
upstream merge that drops the fallback (or reverts it to a bare proxy) fails CI
rather than silently reintroducing empty tabs in production.

Asserted against behaviour, not source text: a fallback that is present but
wired to the wrong tenant, or that returns an envelope without the phase blocks,
would satisfy a grep and still show empty tabs.
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.endpoints import cases


def _user() -> Any:
    return MagicMock(tenant_id=uuid.uuid4())


def _proxy(status_code: int, payload: Any = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=payload if payload is not None else {})
    resp.text = text
    return resp


def _event(seq: int, agent: str, kind: str, response_obj: Any = None, summary: str | None = None) -> MagicMock:
    """A ledger InvestigationEvent row.

    Mirrors the real shape: for kind='llm_response' the payload is an already
    deserialised envelope whose 'response' is a JSON *string* (the column is
    jsonb; only the inner agent output stays stringified).
    """
    ev = MagicMock()
    ev.seq = seq
    ev.agent = agent
    ev.kind = kind
    ev.summary = summary
    ev.ts = None
    if kind == "llm_response":
        ev.payload = {"response": json.dumps(response_obj)}
    else:
        ev.payload = {}
    return ev


def _db_returning(events: list[Any]) -> MagicMock:
    db = MagicMock()
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=events)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)
    db.execute = AsyncMock(return_value=result)
    return db


class TestTheDetailRouteFallsBackToTheLedger:
    @pytest.mark.asyncio
    async def test_an_agents_miss_is_served_from_the_ledger_not_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The reported bug: cold `_runs` made every historical run 404.

        Pre-fix this raised HTTPException(404). The route must reconstruct the
        run from Postgres instead, and the reconstruction must carry the phase
        blocks — an envelope without recon/forensic/responder is exactly the
        'headers but no explanation' symptom, so assert them here.
        """
        case_uuid = uuid.uuid4()
        run_id = str(uuid.uuid4())
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=case_uuid))
        monkeypatch.setattr(cases, "_agents_proxy", AsyncMock(return_value=_proxy(404, text="run not found")))

        recon = {"summary": "recon summary", "iocs": ["1.2.3.4"], "mitre_techniques": ["T1056"]}
        forensic = {"summary": "forensic summary", "root_cause_hypothesis": "log tampering", "confidence": 0.1}
        responder = {"summary": "response summary", "recommended_actions": ["isolate host"]}
        events = [
            _event(1, "ReconAgent", "llm_response", recon),
            _event(2, "ForensicAgent", "llm_response", forensic),
            _event(3, "ResponderAgent", "llm_response", responder),
        ]

        ledger_row = MagicMock()
        ledger_row.id = uuid.UUID(run_id)
        ledger_row.case_id = str(case_uuid)
        ledger_row.status = "completed"
        ledger_row.model_used = "qwen"
        ledger_row.iterations = 3
        ledger_row.total_tokens = 100
        ledger_row.started_at = None
        ledger_row.completed_at = None
        ledger_row.error = None

        run_scalars = MagicMock()
        run_scalars.first = MagicMock(return_value=ledger_row)
        run_result = MagicMock()
        run_result.scalars = MagicMock(return_value=run_scalars)

        event_scalars = MagicMock()
        event_scalars.all = MagicMock(return_value=events)
        event_result = MagicMock()
        event_result.scalars = MagicMock(return_value=event_scalars)

        db = MagicMock()
        # first execute -> ledger run row; second -> phase events (inside _ledger_phase_blocks)
        db.execute = AsyncMock(side_effect=[run_result, event_result])

        out = await cases.case_investigation_run(case_id="INC-1", run_id=run_id, db=db, user=_user())

        assert out["status"] == "completed"
        assert out["recon"]["iocs"] == ["1.2.3.4"], "recon tab would render empty"
        assert out["forensic"]["root_cause_hypothesis"] == "log tampering", "forensic tab would render empty"
        assert out["responder"]["recommended_actions"] == ["isolate host"], "response tab would render empty"
        assert len(out["audit_log"]) == 3, "timeline tab would render empty"

    @pytest.mark.asyncio
    async def test_a_run_the_ledger_does_not_own_still_404s(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The fallback must not turn into an open read.

        If agents misses AND the ledger has no row for this tenant+case, the
        404 stands — otherwise a caller could enumerate other tenants' runs.
        """
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=uuid.uuid4()))
        monkeypatch.setattr(cases, "_agents_proxy", AsyncMock(return_value=_proxy(404, text="nope")))
        monkeypatch.setattr(cases, "_ledger_investigation_run", AsyncMock(return_value=None))

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await cases.case_investigation_run(case_id="INC-1", run_id=str(uuid.uuid4()), db=MagicMock(), user=_user())
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_a_live_agents_run_is_returned_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The fallback must not shadow the live path (agents warm = source of truth)."""
        case_uuid = uuid.uuid4()
        payload = {"id": "r-1", "case_id": str(case_uuid), "status": "running"}
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=case_uuid))
        monkeypatch.setattr(cases, "_agents_proxy", AsyncMock(return_value=_proxy(200, payload)))

        out = await cases.case_investigation_run(case_id="INC-1", run_id="r-1", db=MagicMock(), user=_user())
        assert out == payload


class TestPhaseBlocksReconstruction:
    @pytest.mark.asyncio
    async def test_latest_llm_response_per_agent_wins(self) -> None:
        """Agents may retry; the last structured output is authoritative."""
        events = [
            _event(1, "ReconAgent", "llm_response", {"summary": "first", "iocs": ["old"]}),
            _event(2, "ReconAgent", "llm_response", {"summary": "second", "iocs": ["new"]}),
        ]
        recon, _forensic, _responder, audit = await cases._ledger_phase_blocks(_db_returning(events), uuid.uuid4(), uuid.uuid4())
        assert recon["iocs"] == ["new"], "stale retry output would win"
        assert len(audit) == 2

    @pytest.mark.asyncio
    async def test_a_malformed_llm_response_degrades_to_the_phase_summary(self) -> None:
        """A non-JSON agent output must not crash the tab; fall back to summary."""
        events = [
            _event(1, "ReconAgent", "llm_response", None),  # payload response not valid JSON object
            _event(2, "ReconAgent", "recon", None, summary="phase summary survived"),
        ]
        events[0].payload = {"response": "not json at all"}
        recon, _f, _r, _a = await cases._ledger_phase_blocks(_db_returning(events), uuid.uuid4(), uuid.uuid4())
        assert recon.get("summary") == "phase summary survived", "tab would be blank with no fallback"
