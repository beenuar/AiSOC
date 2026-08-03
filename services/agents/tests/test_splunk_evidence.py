"""#570 — bounded, read-only Splunk evidence tool for the investigation graph.

Verifies the query is time/entity-bounded and allow-listed, credentials come
from the vault (never a prompt) and never leak into findings/queries, a
failure/timeout is treated as *missing evidence* (escalates to needs_review),
and results are cited (redacted + hashed) in the investigation. The Splunk REST
call is mocked (fake httpx client) so it runs in agents CI with no live server.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.agents import investigation_agent as ia
from app.agents.dispositions import FALSE_POSITIVE, NEEDS_REVIEW
from app.investigator import splunk_evidence as se
from app.investigator.splunk_evidence import (
    SplunkCreds,
    SplunkEvidenceClient,
    SplunkEvidenceResult,
    build_evidence_spl,
    collect_splunk_evidence,
)
from app.models.state import AgentStatus, InvestigationState

pytestmark = pytest.mark.asyncio

TOKEN = "s3cr3t-splunk-token-should-never-leak"


def _state(**raw) -> InvestigationState:
    base = {
        "id": "22222222-2222-2222-2222-222222222222",
        "connector_id": "00000000-0000-0000-0000-0000000000c1",
        "connector_type": "splunk",
        "username": "svc-backup",
        "hostname": "WIN-DC01",
        "src_ip": "10.20.30.40",
        "event_time": "2026-07-12T08:00:00Z",
    }
    base.update(raw)
    return InvestigationState(incident_id=uuid4(), tenant_id=uuid4(), alert_summary="cred dump", raw_alert=base, status=AgentStatus.RUNNING)


# ── SPL builder (pure) ───────────────────────────────────────────────────────


async def test_build_evidence_spl_is_time_and_entity_bounded():
    spl = build_evidence_spl(
        {"username": "svc-backup", "hostname": "WIN-DC01", "src_ip": "10.0.0.5", "file_hash": "a" * 64},
        index="main",
        max_results=50,
    )
    assert spl is not None
    assert spl.startswith("search index=main (")
    assert 'user="svc-backup"' in spl
    assert 'host="WIN-DC01"' in spl
    assert 'src_ip="10.0.0.5"' in spl
    assert "| head 50" in spl  # bounded result count


async def test_build_evidence_spl_none_without_pivot():
    assert build_evidence_spl({"severity": "high"}) is None


async def test_spl_values_are_quote_escaped():
    # An adversary-controlled username with a quote must not break out of the
    # SPL string (allow-listed construction).
    spl = build_evidence_spl({"username": 'a" OR host="*'})
    assert spl is not None
    assert '\\"' in spl  # the inner quote is escaped
    assert 'user="a\\" OR host=\\"*"' in spl


async def test_time_window_is_bounded():
    earliest, latest = se._time_window({"event_time": "2026-07-12T08:00:00Z"})
    # epoch strings, 2 * window hours apart
    span_hours = (int(latest) - int(earliest)) / 3600
    assert span_hours == pytest.approx(2 * se._WINDOW_HOURS, abs=0.01)


# ── credential resolution + collection ───────────────────────────────────────


async def test_collect_not_applicable_without_connector():
    # No DB in tests => resolve returns None => not a Splunk alert => no-op.
    result = await collect_splunk_evidence(_state(connector_id=None))
    assert result.applicable is False
    assert result.queried is False


async def test_collect_success_cites_redacted_hashed_evidence(monkeypatch):
    async def _creds(_state):
        return SplunkCreds(base_url="https://splunk.local:8089", token=TOKEN, ssl_verify=True, index="main")

    class _FakeClient:
        def __init__(self, creds, **kwargs):  # noqa: ANN001, ANN003
            self._creds = creds

        async def search(self, spl, *, earliest, latest):  # noqa: ANN001
            return [{"_time": "2026-07-12T07:59:00Z", "host": "WIN-DC01", "user": "svc-backup", "action": "lsass_access"}]

    monkeypatch.setattr(se, "resolve_splunk_credentials", _creds)
    monkeypatch.setattr(se, "_make_client", lambda creds: _FakeClient(creds))

    state = _state()
    result = await collect_splunk_evidence(state)

    assert result.applicable is True
    assert result.queried is True
    assert result.result_count == 1
    # Evidence cited in findings with a content hash…
    joined = "\n".join(state.findings)
    assert "Splunk evidence: 1 surrounding event" in joined
    assert "digest=" in joined
    # …and the credential NEVER appears in findings or the query.
    assert TOKEN not in joined
    assert result.query is not None and TOKEN not in result.query


async def test_collect_query_failure_is_missing_evidence(monkeypatch):
    async def _creds(_state):
        return SplunkCreds(base_url="https://splunk.local:8089", token=TOKEN)

    class _BoomClient:
        def __init__(self, creds, **kwargs):  # noqa: ANN001, ANN003
            pass

        async def search(self, *a, **k):  # noqa: ANN002, ANN003
            raise TimeoutError("splunk timed out")

    monkeypatch.setattr(se, "resolve_splunk_credentials", _creds)
    monkeypatch.setattr(se, "_make_client", lambda creds: _BoomClient(creds))

    state = _state()
    result = await collect_splunk_evidence(state)
    assert result.applicable is True
    assert result.queried is False
    assert result.error is not None
    assert any("missing evidence" in f.lower() for f in state.findings)
    assert TOKEN not in "\n".join(state.findings)


# ── bounded REST client (mocked httpx) ───────────────────────────────────────


async def test_client_issues_bounded_oneshot_request(monkeypatch):
    captured: dict = {}

    class _FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"_time": "t", "host": "h"}, {"_time": "t2", "host": "h2"}]}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            captured["init"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, headers=None, data=None):  # noqa: ANN001
            captured["url"] = url
            captured["headers"] = headers
            captured["data"] = data
            return _FakeResp()

    monkeypatch.setattr(se.httpx, "AsyncClient", _FakeAsyncClient)

    creds = SplunkCreds(base_url="https://splunk.local:8089", token=TOKEN, ssl_verify=False)
    client = SplunkEvidenceClient(creds, max_results=50)
    results = await client.search("search index=main (host=\"h\") | head 50", earliest="-6h", latest="now")

    assert len(results) == 2
    assert captured["url"].endswith("/services/search/jobs")
    assert captured["data"]["exec_mode"] == "oneshot"  # read-only oneshot
    assert captured["data"]["count"] == "50"  # bounded
    assert captured["data"]["earliest_time"] == "-6h"
    assert captured["data"]["latest_time"] == "now"
    # verify=False threaded to httpx; token in the header only (never returned).
    assert captured["init"].get("verify") is False
    assert captured["headers"]["Authorization"] == f"Bearer {TOKEN}"


# ── investigation-agent escalation on missing evidence ───────────────────────


async def test_investigation_escalates_to_needs_review_on_missing_evidence(monkeypatch):
    async def _missing(_state):
        return SplunkEvidenceResult(applicable=True, queried=False, error="timeout")

    monkeypatch.setattr(ia, "collect_splunk_evidence", _missing)
    # Force the base scorer to a dismissive verdict; the #570 guard must upgrade it.
    monkeypatch.setattr(ia, "score_investigation", lambda state: (0.9, ["scored fp"], FALSE_POSITIVE))

    state = InvestigationState(incident_id=uuid4(), tenant_id=uuid4(), alert_summary="x", raw_alert={"connector_type": "splunk"})
    result = await ia.run_investigation(state)
    assert result.verdict == NEEDS_REVIEW


async def test_investigation_keeps_verdict_when_evidence_present(monkeypatch):
    async def _ok(_state):
        return SplunkEvidenceResult(applicable=True, queried=True, result_count=3)

    monkeypatch.setattr(ia, "collect_splunk_evidence", _ok)
    monkeypatch.setattr(ia, "score_investigation", lambda state: (0.9, ["scored fp"], FALSE_POSITIVE))

    state = InvestigationState(incident_id=uuid4(), tenant_id=uuid4(), alert_summary="x", raw_alert={"connector_type": "splunk"})
    result = await ia.run_investigation(state)
    # Evidence was successfully gathered → the scorer's verdict stands.
    assert result.verdict == FALSE_POSITIVE
