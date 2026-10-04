"""Phase 4's acceptance bar, and the three ways it could pass vacuously.

The bar: investigating a recorded CrowdStrike detection, with Splunk and
CrowdStrike mocked, reaches at least three pivots across both sources, and the
ledger shows every call.

What this test covers and what it does not
------------------------------------------
This runs the **agent** in process with a scripted model, against the API's
agent-tool surface mocked at the HTTP boundary. It proves the agent binds the
customer tools, pivots across both sources, distinguishes a failed read from
an empty one, and records every call into the run's audit log, which the
orchestrator persists to the Investigation Ledger.

It does **not** prove the joins beyond that boundary, and the decomposition is
recorded here rather than left implicit, because this repository has twice
shipped a cross-service route whose unit test asserted the URL the *client*
produced rather than the URL the *service* serves, and passed.

* that the URL the agent builds is one the API serves: proven by
  ``services/api/tests/test_agent_tools.py``, which parses the API's own
  router wiring with ``ast`` and was checked against the pre-fix value from
  both sides;
* that a read reaches a vendor: proven by
  ``services/actions/tests/test_investigation_reads_phase4.py`` against
  vendor-shaped payloads on the real HTTP path;
* that the whole chain runs over HTTP against live services: **not proven.**
  There is no end-to-end test for this surface. ``GAP_CLOSURE_PROGRESS.md``
  records it as the one open item of Phase 4, with the shape it would take.
  Three proven links are not the same claim as one end-to-end run, which is
  the lesson D8 and D16 both record.

Three vacuous passes this test refuses
--------------------------------------
* **Three pivots on one source.** The bar says across both, so the assertion
  counts distinct sources, not distinct tool names.
* **Three pivots that all failed.** A tool that answered "could not check" is
  not a pivot. ``_classify_pivots`` already drops ``available: false``, and
  this asserts the dropped one is absent from the pivot list rather than
  trusting it.
* **A ledger with a summary and no calls.** The audit log is asserted to hold
  one ``TOOL_CALL`` entry per call in the trace, with the tool name, so a run
  that recorded its narrative and lost its evidence fails.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import respx
from app.investigator.deep_investigation import run_deep_investigation
from app.models.state import InvestigationState

API = "http://api:8000"
BACKENDS = f"{API}/api/v1/agent-tools/backends"
SEARCH = f"{API}/api/v1/agent-tools/siem-search"
READ = f"{API}/api/v1/agent-tools/vendor-read"
LAKE = f"{API}/api/v1/graph/investigate/query"
#: Two context lookups the driver makes on any deployment that has a service
#: credential. They were unreachable while the agents service had none, which
#: is the defect fix-pass item 1.1 closed, so they are mocked here rather than
#: left to fail the run with "not mocked".
MCP_SERVERS = f"{API}/api/v1/mcp-servers/resolved"
TENANT_SKILLS = f"{API}/api/v1/tenant-skills/resolved/active"


# --------------------------------------------------------------- the alert

#: A recorded CrowdStrike detection, in the shape fusion writes onto an alert
#: row. **Synthetic**: the field names are CrowdStrike's and the values are
#: invented.
CROWDSTRIKE_DETECTION: dict[str, Any] = {
    "title": "Suspicious PowerShell execution detected on WS-42",
    "severity": "high",
    "source": "CrowdStrike Falcon",
    "connector_type": "crowdstrike",
    "hostname": "WS-42",
    "user_name": "ACME\\svc_deploy",
    "process_name": "powershell.exe",
    "hash_sha256": "9f2c" + "a" * 60,
    "source_ip": "203.0.113.9",
}


def _state() -> InvestigationState:
    """The state class the *production* caller passes.

    `agents/investigation_agent.py` calls `run_deep_investigation(state)` with
    an `app.models.state.InvestigationState`, not the `InvestigatorState` in
    `app.investigator.state`. Two classes, similar names, different fields:
    only the second has an `audit_log`, and only the first has
    `mitre_mappings`, which is what the driver reads to select a strategy.
    Constructing the wrong one here would have tested a path production never
    takes, and would have hidden a ledger write that is a no-op in
    production.
    """
    return InvestigationState(
        incident_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        tenant_id="11111111-1111-1111-1111-111111111111",
        alert_summary=CROWDSTRIKE_DETECTION["title"],
        raw_alert=dict(CROWDSTRIKE_DETECTION),
        mitre_mappings=["T1059.001"],
    )


# ---------------------------------------------------------- the scripted model


@dataclass
class _ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class _ScriptedModel:
    """A model that calls a fixed sequence of tools, then answers.

    Deterministic on purpose. The bar is about whether the *agent* can reach
    both sources and record what it did, and grading that against a live
    model's choices would make the test a measurement of the model. The
    prompts the model was handed are captured so the coverage notes and the
    untrusted-data instruction can be asserted to have actually arrived.
    """

    script: list[list[_ToolCall]]
    final: str = "PowerShell on WS-42 fetched a payload; the hash is present on two other hosts."
    prompts: list[str] = field(default_factory=list)
    turn: int = 0
    bound_tools: list[str] = field(default_factory=list)

    def bind_tools(self, schemas: list[dict[str, Any]]) -> _ScriptedModel:
        self.bound_tools = [s["function"]["name"] for s in schemas]
        return self

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.prompts.append("\n".join(str(getattr(m, "content", "")) for m in messages))
        index = self.turn
        self.turn += 1
        if index < len(self.script):
            calls = [{"name": c.name, "args": c.args, "id": f"call-{index}-{n}"} for n, c in enumerate(self.script[index])]
            return _Reply(content="", tool_calls=calls)
        return _Reply(content=self.final, tool_calls=[])

    # `safe_ainvoke` calls `.ainvoke` on whatever `bind_tools` returned, so
    # the bound object has to answer both. Returning self keeps the captured
    # prompts and the turn counter in one place.
    async def astream(self, messages: list[Any]) -> Any:  # pragma: no cover - not used
        raise NotImplementedError


@dataclass
class _Reply:
    content: str
    tool_calls: list[dict[str, Any]]
    response_metadata: dict[str, Any] = field(default_factory=dict)
    usage_metadata: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------ the mocked API


def _mock_api(*, siem_rows: list[dict[str, Any]], edr_detections: list[dict[str, Any]], edr_host_fails: bool = False) -> None:
    """The API surface, answering as the real routes do.

    Both vendors are mocked *behind* the API rather than at their own HTTP
    boundaries, because in production this service never speaks to a vendor:
    it posts to the API, which owns the vault and the tenant session. Mocking
    CrowdStrike's own API here would be mocking a call this service does not
    make. The vendor boundary is covered in `services/actions`, against
    vendor-shaped payloads.
    """
    respx.get(BACKENDS).mock(
        return_value=httpx.Response(
            200,
            json={
                "siem_search": {
                    "enabled": True,
                    "backends": [{"source": "splunk", "name": "Prod Splunk"}],
                    "indicator_types": {},
                },
                "vendor_reads": [
                    {"capability": "get_host", "vendor": "crowdstrike", "connector": "Falcon"},
                    {"capability": "get_detections", "vendor": "crowdstrike", "connector": "Falcon"},
                ],
                "registry_reachable": True,
                "registry_error": "",
            },
        )
    )

    respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "outcome": "ok",
                "row_count": len(siem_rows),
                "rows": siem_rows,
                "sources": [{"source": "splunk", "name": "Prod Splunk", "status": "ok", "rows": len(siem_rows)}],
            },
        )
    )

    def read(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        capability = body.get("capability")
        if capability == "get_host":
            if edr_host_fails:
                # A vendor failure, which must reach the model as "could not
                # check" and must NOT count as a pivot.
                return httpx.Response(
                    200,
                    json={
                        "capability": "get_host",
                        "status": "failed",
                        "executed": False,
                        "detail": "CrowdStrike read failed: 503",
                        "details": {},
                    },
                )
            return httpx.Response(
                200,
                json={
                    "capability": "get_host",
                    "status": "executed",
                    "executed": True,
                    "vendor_id": "crowdstrike",
                    "summary": "WS-42: Windows, containment normal",
                    "details": {"found": True, "platform": "Windows", "containment_status": "normal", "hostname": "WS-42"},
                },
            )
        return httpx.Response(
            200,
            json={
                "capability": "get_detections",
                "status": "executed",
                "executed": True,
                "vendor_id": "crowdstrike",
                "summary": f"{len(edr_detections)} recent detection(s) on WS-42",
                "details": {"found": True, "hostname": "WS-42", "count": len(edr_detections), "detections": edr_detections},
            },
        )

    respx.post(READ).mock(side_effect=read)

    # The lake answers too, so the run is realistic: in production the model
    # has both and picks. A lake-only run would not test the bar.
    respx.post(LAKE).mock(
        return_value=httpx.Response(
            200,
            json={"tool": "process_activity", "available": True, "rows": [{"process": "powershell.exe", "host": "WS-42"}]},
        )
    )


@pytest.fixture(autouse=True)
def _agent_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_API_URL", API)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "fixpass-service-token")
    monkeypatch.setenv("AISOC_DEEP_INVESTIGATION", "true")


@pytest.fixture(autouse=True)
def _context_lookups() -> None:
    """The per-tenant context the driver resolves on a credentialed deployment.

    Both are empty answers, not absent ones: this file is about customer
    tools, and an empty skill set and an empty MCP registry are what a tenant
    that has configured neither actually returns.
    """
    respx.get(MCP_SERVERS).mock(return_value=httpx.Response(200, json={"servers": []}))
    respx.get(TENANT_SKILLS).mock(return_value=httpx.Response(200, json={"skills": []}))


@pytest.fixture
def ledger_rows(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture what the driver hands the ledger, at the ledger's own boundary.

    Patched on ``app.investigator.ledger``, which is the module the driver
    imports and calls, so this observes the real call rather than a copy of
    the intent. There is no Postgres in a unit suite, and ``record_event``
    returns ``None`` without one, so without this the ledger assertions would
    be vacuously satisfied by a function that did nothing.

    ``resolve_tenant`` is stubbed too, because it is the gate the driver
    checks before writing anything: leaving it to return ``None`` would make
    every ledger assertion pass over zero rows.
    """
    from app.investigator import ledger as ledger_module

    rows: list[dict[str, Any]] = []

    async def _resolve(tenant_ref: str) -> uuid.UUID:
        return uuid.UUID("11111111-1111-1111-1111-111111111111")

    async def _record(**kwargs: Any) -> uuid.UUID:
        rows.append(kwargs)
        return uuid.uuid4()

    monkeypatch.setattr(ledger_module, "resolve_tenant", _resolve)
    monkeypatch.setattr(ledger_module, "record_event", _record)
    return rows


# ------------------------------------------------------------------ the bar


@pytest.mark.asyncio
@respx.mock
async def test_the_phase_4_acceptance_bar(ledger_rows: list[dict[str, Any]]) -> None:
    """Three pivots across both sources, with the ledger showing every call."""
    _mock_api(
        siem_rows=[
            {"host": "WS-17", "process_name": "powershell.exe", "_source": "splunk"},
            {"host": "WS-31", "process_name": "powershell.exe", "_source": "splunk"},
        ],
        edr_detections=[{"detection_id": "ldt-1", "severity": "high", "tactic": "Execution"}],
    )
    model = _ScriptedModel(
        script=[
            [_ToolCall("edr_host_details", {"hostname": "WS-42"})],
            [_ToolCall("edr_host_detections", {"hostname": "WS-42"})],
            [_ToolCall("siem_indicator_search", {"indicator_type": "sha256", "value": CROWDSTRIKE_DETECTION["hash_sha256"]})],
            [_ToolCall("process_activity", {"hostname": "WS-42"})],
        ]
    )

    result = await run_deep_investigation(_state(), llm=model)

    assert result.error is None, result.error
    assert result.strategy_id == "endpoint-suspicious-process"

    # --- at least three pivots ---
    assert result.distinct_pivots >= 3, result.pivots

    # --- across BOTH sources, which is the part a tool-name count would miss.
    customer = {"edr_host_details", "edr_host_detections", "siem_indicator_search"}
    used_customer = customer & set(result.pivots)
    used_lake = {"process_activity"} & set(result.pivots)
    assert len(used_customer) >= 2, f"only {used_customer} of the customer's tools were reached"
    assert used_lake, "the lake was not consulted, so this was not a run across both sources"

    # --- the customer's tools were actually advertised, and only the
    #     configured ones. A CrowdStrike-only tenant must not be offered the
    #     identity or cloud tools.
    assert set(result.customer_tools) == {"siem_indicator_search", "edr_host_details", "edr_host_detections"}
    assert "identity_user_activity" not in model.bound_tools
    assert "cloud_audit_lookup" not in model.bound_tools
    # And the lake tools are still there: this is an addition, not a swap.
    assert "process_activity" in model.bound_tools
    assert "fleet_ioc_hunt" in model.bound_tools

    # --- the ledger shows every call ---
    #
    # Asserted on the rows the driver handed the ledger, captured at the
    # ledger's own function boundary. Every call in the trace has to appear,
    # with its tool name and arguments, at a sequence number that cannot
    # collide with the graph runner's: `record_event` carries
    # `ON CONFLICT (run_id, seq) DO NOTHING`, so a collision is a silently
    # dropped row, which is worse than an error because the ledger still
    # looks complete.
    called = [entry["tool"] for entry in result.tool_trace]
    assert len(called) == 4
    assert [row["kind"] for row in ledger_rows] == ["tool_call"] * 4
    assert [row["payload"]["tool"] for row in ledger_rows] == called
    assert result.ledger_rows == 4
    seqs = [row["seq"] for row in ledger_rows]
    assert seqs == sorted(seqs) and len(set(seqs)) == 4
    assert min(seqs) >= 10_000, "a tool-call seq below the graph runner's range would be dropped on conflict"
    # The arguments travel, because "the ledger shows every call" means the
    # call and not just its name: an auditor asking which host was read has
    # to be able to answer it.
    assert ledger_rows[0]["payload"]["args"] == {"hostname": "WS-42"}
    assert ledger_rows[2]["payload"]["args"]["indicator_type"] == "sha256"
    assert all(row["payload"]["result_preview"] for row in ledger_rows)

    # --- the prompt told the model what it was looking at ---
    prompt = model.prompts[0]
    assert "Prod Splunk" in prompt or "splunk" in prompt
    assert "UNTRUSTED" in prompt or "untrusted" in prompt.lower()
    assert "could_not_check" in prompt


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_vendor_read_does_not_count_as_a_pivot() -> None:
    """The bar must not be reachable by calling tools that all failed."""
    _mock_api(siem_rows=[], edr_detections=[], edr_host_fails=True)
    model = _ScriptedModel(script=[[_ToolCall("edr_host_details", {"hostname": "WS-42"})]])

    result = await run_deep_investigation(_state(), llm=model)

    assert "edr_host_details" not in result.pivots
    assert "edr_host_details" in result.unavailable_data
    assert result.distinct_pivots == 0
    assert result.reached_depth is False

    # And the gap reaches the findings as a gap rather than as a clean host.
    findings = " ".join(result.findings())
    assert "Coverage gap" in findings
    assert "unknown rather than clear" in findings


@pytest.mark.asyncio
@respx.mock
async def test_a_tenant_with_no_customer_tools_gets_the_gap_in_its_findings() -> None:
    """A lake-only tenant must say so rather than look thorough."""
    respx.get(BACKENDS).mock(
        return_value=httpx.Response(
            200,
            json={
                "siem_search": {"enabled": True, "backends": [], "indicator_types": {}},
                "vendor_reads": [],
                "registry_reachable": True,
                "registry_error": "",
            },
        )
    )
    respx.post(LAKE).mock(return_value=httpx.Response(200, json={"available": True, "rows": []}))
    model = _ScriptedModel(script=[[_ToolCall("process_activity", {"hostname": "WS-42"})]])

    result = await run_deep_investigation(_state(), llm=model)

    assert result.customer_tools == []
    assert "siem_indicator_search" not in model.bound_tools
    findings = " ".join(result.findings())
    assert "no SIEM connected" in findings
    assert "Sources consulted beyond the AiSOC event lake" in findings


@pytest.mark.asyncio
@respx.mock
async def test_an_unreachable_api_does_not_silently_shrink_the_investigation() -> None:
    """The worst failure mode: fewer tools, no explanation, same confidence."""
    respx.get(BACKENDS).mock(side_effect=httpx.ConnectError("refused"))
    respx.post(LAKE).mock(return_value=httpx.Response(200, json={"available": True, "rows": []}))
    model = _ScriptedModel(script=[[_ToolCall("process_activity", {"hostname": "WS-42"})]])

    result = await run_deep_investigation(_state(), llm=model)

    assert result.customer_tools == []
    findings = " ".join(result.findings())
    assert "could not determine" in findings
    assert "UNKNOWN, not absent" in findings
    # The note has to be in the prompt as well as in the findings, or the
    # model reasons without it and only the reader is told.
    assert "could not determine" in model.prompts[0]
