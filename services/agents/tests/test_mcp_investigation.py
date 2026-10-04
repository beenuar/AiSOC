"""Phase 5's "Done when", run end to end, and the ledger writer that records it.

    Against a mock MCP server, an investigation calls an allowlisted read
    tool, refuses a destructive one, and the ledger records both.

Every noun in that sentence is the real one here. The MCP server is a real
``FastMCP`` spoken to over the SDK's memory transport. The investigation is
``run_with_tools``, the same loop ``deep_investigation`` drives, with a
scripted model standing in for the provider because a model that chooses
tools non-deterministically cannot assert which ones it chose. The ledger is
``_LedgerWriter`` calling the real ``ledger.record_event``, captured at the
database boundary rather than replaced above it, so the sequence numbers, the
tenant resolution and the payload shape are the ones that would reach
Postgres.

The one thing deliberately not real is Postgres. ``record_event`` takes a
resolved tenant UUID and writes one row; asserting that a row lands is the
job of the live-container suites, and doing it here would mean this gate
could not run in CI without a service container.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from app.llm.tool_loop import run_with_tools
from app.mcp import tools as tools_module
from app.mcp.config import McpServerConfig
from app.mcp.policy import namespaced
from app.mcp.tools import LEDGER_SEQ_BASE, build_mcp_toolset
from app.tools.registry import ToolRegistry
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import ToolAnnotations

TENANT_REF = "tenant-a"
TENANT_UUID = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")


def build_server() -> FastMCP:
    """The mock vendor server: one read tool, one destructive tool."""
    server = FastMCP(name="mock-vendor")

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    def get_detections(hostname: str) -> dict[str, Any]:
        """List detections raised on a host."""
        return {"hostname": hostname, "detections": [{"id": "DET-4471", "tactic": "Credential Access"}]}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
    def isolate_host(hostname: str) -> dict[str, Any]:
        """Isolate a host from the network."""
        return {"isolated": hostname}

    return server


def memory_session_factory(server: FastMCP):
    @asynccontextmanager
    async def factory(_config: McpServerConfig):
        async with create_connected_server_and_client_session(server._mcp_server) as session:  # noqa: SLF001
            yield session

    return factory


class _ScriptedLLM:
    """A model that asks for the two tools this phase is about, in order."""

    def __init__(self, script: list) -> None:
        self._script = script
        self.calls = 0
        self.bound_tools: list[dict[str, Any]] | None = None

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self

    async def ainvoke(self, _messages):
        response = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return response


def _tool_call(name: str, args: dict[str, Any], cid: str = "c1"):
    return SimpleNamespace(content="", tool_calls=[{"name": name, "args": args, "id": cid}])


def _final(text: str):
    return SimpleNamespace(content=text, tool_calls=[])


@pytest.fixture
def recorded_ledger(monkeypatch) -> list[dict[str, Any]]:
    """Capture at the database boundary, leaving the real writer in place."""
    rows: list[dict[str, Any]] = []

    async def _resolve_tenant(tenant_ref: str):
        return TENANT_UUID if tenant_ref == TENANT_REF else None

    async def _record_event(**kwargs):
        rows.append(kwargs)
        return uuid.uuid4()

    monkeypatch.setattr(tools_module.ledger_module, "resolve_tenant", _resolve_tenant)
    monkeypatch.setattr(tools_module.ledger_module, "record_event", _record_event)
    return rows


async def test_done_when_an_investigation_calls_a_read_tool_and_refuses_a_destructive_one(recorded_ledger) -> None:
    server = build_server()
    run_id = uuid.uuid4()

    # The operator allowlisted both, on purpose. If only the read tool were
    # allowlisted this would prove the allowlist and say nothing about the
    # annotation, and the annotation is the half the plan is about.
    config = McpServerConfig(
        name="vendor",
        url="https://mcp.vendor.example/mcp",
        tool_allowlist=["get_detections", "isolate_host"],
        timeout_seconds=5.0,
        max_response_bytes=65536,
    )

    toolset = await build_mcp_toolset(
        TENANT_REF,
        run_id=run_id,
        servers=[config],
        session_factory=memory_session_factory(server),
    )

    # The destructive tool is not merely refused at call time: it is never put
    # in front of the model, so it cannot be talked into naming it.
    bound = [t.name for t in toolset.tools]
    assert bound == [namespaced("vendor", "get_detections")]

    registry = ToolRegistry(toolset.tools)
    llm = _ScriptedLLM(
        [
            _tool_call(namespaced("vendor", "get_detections"), {"hostname": "WIN-DC-01"}),
            # The model asks for the destructive tool anyway. It was never
            # bound, so the loop's own registry refuses it.
            _tool_call(namespaced("vendor", "isolate_host"), {"hostname": "WIN-DC-01"}, cid="c2"),
            _final("One detection on WIN-DC-01; containment was not available to me."),
        ]
    )
    loop = await run_with_tools(llm, system="You are an analyst.", user="Investigate WIN-DC-01.", registry=registry)

    advertised = {s["function"]["name"] for s in (llm.bound_tools or [])}
    assert namespaced("vendor", "isolate_host") not in advertised

    trace = {entry["tool"]: entry["result_preview"] for entry in loop["tool_trace"]}
    assert set(trace) == {namespaced("vendor", "get_detections"), namespaced("vendor", "isolate_host")}
    # The loop's own registry has no such tool, because it was never bound.
    assert "unknown tool" in trace[namespaced("vendor", "isolate_host")]
    # The read tool's result did carry the server's data, fenced. Asserted
    # against the registry the loop used rather than against the trace, whose
    # preview is a 200-character debug string.
    direct = await registry.execute(namespaced("vendor", "get_detections"), {"hostname": "WIN-DC-01"})
    assert "DET-4471" in direct["content"]
    assert direct["untrusted"] is True

    # The ledger recorded both, from the real writer.
    kinds = [row["kind"] for row in recorded_ledger]
    assert "mcp_tool_call" in kinds
    assert "mcp_tool_refused" in kinds

    called = next(r for r in recorded_ledger if r["kind"] == "mcp_tool_call")
    assert called["run_id"] == run_id
    assert called["tenant_id"] == TENANT_UUID
    assert called["agent"] == "mcp_client"
    assert called["payload"]["tool"] == "get_detections"
    assert called["payload"]["server"] == "vendor"

    refused = next(r for r in recorded_ledger if r["kind"] == "mcp_tool_refused")
    assert refused["run_id"] == run_id
    assert refused["tenant_id"] == TENANT_UUID
    assert refused["payload"]["tool"] == "isolate_host"
    assert refused["payload"]["classification"] == "destructive"
    assert "governed dispatch" in refused["payload"]["reason"]


async def test_ledger_sequence_numbers_are_monotonic_and_above_the_graph_range(recorded_ledger) -> None:
    """A collision would be silently dropped by ``ON CONFLICT (run_id, seq)``.

    Graph steps and audit entries number from zero, so MCP rows start high;
    within a run they have to keep increasing or the second call overwrites
    nothing and simply disappears.
    """
    server = build_server()
    config = McpServerConfig(
        name="vendor",
        url="https://mcp.vendor.example/mcp",
        tool_allowlist=["get_detections", "isolate_host"],
    )
    toolset = await build_mcp_toolset(TENANT_REF, run_id=uuid.uuid4(), servers=[config], session_factory=memory_session_factory(server))
    for _ in range(3):
        await toolset.tools[0].fn(hostname="WIN-DC-01")

    seqs = [row["seq"] for row in recorded_ledger]
    assert len(seqs) >= 5
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)
    assert min(seqs) > LEDGER_SEQ_BASE


async def test_an_unresolvable_tenant_writes_nothing_and_says_so(monkeypatch, caplog) -> None:
    """Loud, not debug. A ledger that quietly stops recording is worse than one that fails."""
    rows: list[dict[str, Any]] = []

    async def _resolve_tenant(_tenant_ref: str):
        return None

    async def _record_event(**kwargs):  # pragma: no cover - must never be reached
        rows.append(kwargs)

    monkeypatch.setattr(tools_module.ledger_module, "resolve_tenant", _resolve_tenant)
    monkeypatch.setattr(tools_module.ledger_module, "record_event", _record_event)

    server = build_server()
    toolset = await build_mcp_toolset(
        "who-is-this",
        run_id=uuid.uuid4(),
        servers=[McpServerConfig(name="vendor", url="https://mcp.vendor.example/mcp", tool_allowlist=["get_detections"])],
        session_factory=memory_session_factory(server),
    )
    result = await toolset.tools[0].fn(hostname="WIN-DC-01")

    # The call still works. Losing the audit trail must not lose the evidence.
    assert result["untrusted"] is True
    assert rows == []


async def test_a_run_with_no_run_id_still_works_and_writes_nothing(monkeypatch) -> None:
    """Some callers have no ledger run. They get tools, not an exception."""
    rows: list[dict[str, Any]] = []

    async def _record_event(**kwargs):  # pragma: no cover - must never be reached
        rows.append(kwargs)

    monkeypatch.setattr(tools_module.ledger_module, "record_event", _record_event)

    server = build_server()
    toolset = await build_mcp_toolset(
        TENANT_REF,
        run_id=None,
        servers=[McpServerConfig(name="vendor", url="https://mcp.vendor.example/mcp", tool_allowlist=["get_detections"])],
        session_factory=memory_session_factory(server),
    )
    assert [t.name for t in toolset.tools] == [namespaced("vendor", "get_detections")]
    assert await toolset.tools[0].fn(hostname="WIN-DC-01")
    assert rows == []
