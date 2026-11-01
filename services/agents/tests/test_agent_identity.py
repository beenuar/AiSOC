"""AiSOC's own agents get an identity, a scope and an audit row.

Depth plan wave 2, Phase 7.3 — parity 6.7's first half: "Give each internal
agent its own identity, with short-lived credentials and least-privilege
tool scopes, visible in the audit log."

The gap
-------
`ToolRegistry.execute(name, args)` ran any registered tool for any caller.
There was no identity, no scope and no audit row, so:

* a prompt-injected triage agent could call a containment tool it has no
  business holding, and the registry would run it;
* nothing in the ledger said which agent called which tool, so the question
  an incident asks — what did this agent do — had no answer;
* and the platform that sells AI-estate governance was running its own
  agents with the one property it flags on a customer's: no identity.

What "short-lived" means here, and what it does not
----------------------------------------------------
A credential bounded to one investigation run with a wall-clock expiry.
It is **not** a bearer token to another service: these agents call Python
functions in their own process, so a network credential would be theatre.
What it has to survive is the in-process threat — a model that has been
steered into asking for a tool outside its grant — and that is a scope
check at the one chokepoint every tool call passes through.

The negative controls matter more than the positives here. A scope system
that grants everything, or expires nothing, passes every happy-path test.
"""

from __future__ import annotations

import time

import pytest
from app.security.agent_identity import (
    AGENT_TOOL_SCOPES,
    KNOWN_TOOLS,
    ScopeDenied,
    issue_identity,
)
from app.tools.registry import Tool, ToolRegistry


def _tool(name: str) -> Tool:
    return Tool(name=name, description=name, parameters={"type": "object", "properties": {}}, fn=lambda: {"ok": name})


@pytest.fixture
def registry() -> ToolRegistry:
    # Real tool names: `lookup_technique` is in the triage scope,
    # `process_activity` is an investigator-only pivot and is therefore the
    # out-of-scope case for a triage identity. Inventing names here would
    # make the test pass against a scope table that grants nothing real.
    return ToolRegistry([_tool("lookup_technique"), _tool("extract_iocs"), _tool("process_activity")])


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_every_shipped_agent_has_a_declared_scope():
    """An agent missing from the table would otherwise default to something.

    Defaulting open makes the scope decorative; defaulting closed breaks
    that agent silently at run time. Requiring a declaration is the only
    option that fails at review instead.
    """
    assert AGENT_TOOL_SCOPES, "no agent scopes are declared at all"
    for agent, scopes in AGENT_TOOL_SCOPES.items():
        assert isinstance(scopes, frozenset), f"{agent}: scopes must be a frozenset"
        assert scopes, f"{agent}: an empty scope set is almost certainly a mistake, not least privilege"


def test_the_scopes_are_least_privilege_and_not_all_the_same():
    """If every agent holds every tool, the scope is a comment.

    The triage agent reads; the response agent acts. A table where those
    two are equal has not expressed a privilege boundary.
    """
    sets = list(AGENT_TOOL_SCOPES.values())
    assert len({frozenset(s) for s in sets}) > 1, "every agent holds the same tools, which is not least privilege"


def test_an_identity_is_bound_to_one_run_and_expires():
    identity = issue_identity("triage", run_id="run-1", ttl_seconds=60)
    assert identity.agent == "triage"
    assert identity.run_id == "run-1"
    assert not identity.expired()
    assert identity.expires_at > time.time()


def test_an_expired_identity_says_so():
    identity = issue_identity("triage", run_id="run-1", ttl_seconds=-1)
    assert identity.expired()


def test_an_unknown_agent_cannot_be_issued_an_identity():
    """Minting an identity for a name with no scope would grant it nothing
    and then fail at every call, which reads as a broken tool rather than
    as an undeclared agent."""
    with pytest.raises(ValueError, match="unknown agent"):
        issue_identity("not-an-agent", run_id="run-1")


# ---------------------------------------------------------------------------
# The scope is enforced at the one chokepoint
# ---------------------------------------------------------------------------


async def test_a_tool_inside_the_scope_runs(registry: ToolRegistry):
    identity = issue_identity("triage", run_id="run-1")
    result = await registry.execute("lookup_technique", {}, identity=identity)
    assert result == {"ok": "lookup_technique"}


async def test_a_tool_outside_the_scope_is_refused(registry: ToolRegistry):
    """The whole point. A triage agent does not hold containment.

    Refused as a structured error rather than an exception, because the
    loop's contract is that a tool failure reaches the model instead of
    aborting the run — but the error names the scope so an operator can
    tell a denial from a tool that broke.
    """
    identity = issue_identity("triage", run_id="run-1")
    result = await registry.execute("process_activity", {}, identity=identity)
    assert "error" in result
    assert "scope" in result["error"].lower()


async def test_an_expired_identity_is_refused(registry: ToolRegistry):
    """Otherwise "short-lived" is a field nobody reads.

    A run that outlives its credential is the case this catches: a stalled
    investigation resuming hours later must re-issue, not continue.
    """
    identity = issue_identity("triage", run_id="run-1", ttl_seconds=-1)
    result = await registry.execute("lookup_technique", {}, identity=identity)
    assert "error" in result
    assert "expired" in result["error"].lower()


async def test_a_call_with_no_identity_is_refused_by_default(registry: ToolRegistry):
    """Default-deny, which is the only safe direction.

    An optional identity defaulting to "allow" means every existing call
    site keeps working and the control protects nothing — the exact shape
    of the `Annotated[Any, require_permission(...)]` routes that read as
    gated and enforced nothing.
    """
    result = await registry.execute("lookup_technique", {})
    assert "error" in result
    assert "identity" in result["error"].lower()


def test_scope_denied_is_raised_by_the_checker_itself():
    """The registry converts it; the checker raises it.

    Two callers need different behaviour — the loop wants a structured
    error, a direct caller wants an exception — and one of them having to
    parse the other's string is how a denial gets mistaken for a result.
    """
    identity = issue_identity("triage", run_id="run-1")
    with pytest.raises(ScopeDenied):
        identity.require("process_activity")


# ---------------------------------------------------------------------------
# Visible in the audit log
# ---------------------------------------------------------------------------


async def test_every_call_writes_an_audit_row_including_the_denials(registry: ToolRegistry):
    """Parity 6.7 says "visible in the audit log", and a denial is the row
    an incident actually wants: an agent reaching for a tool it does not
    hold is the signal, and a log that records only successes cannot show
    it."""
    rows: list[dict] = []
    registry.audit_sink = rows.append
    identity = issue_identity("triage", run_id="run-1")

    await registry.execute("lookup_technique", {}, identity=identity)
    await registry.execute("process_activity", {}, identity=identity)

    assert len(rows) == 2
    allowed, denied = rows
    assert allowed["agent"] == "triage" and allowed["tool"] == "lookup_technique" and allowed["allowed"] is True
    assert denied["agent"] == "triage" and denied["tool"] == "process_activity" and denied["allowed"] is False
    assert all(r["run_id"] == "run-1" for r in rows)


async def test_the_audit_row_never_carries_the_tool_arguments(registry: ToolRegistry):
    """Arguments carry alert content — hostnames, user names, raw text.

    An audit log is read by more people than an alert is, and a tool-call
    log that copies the arguments becomes a second, wider copy of the
    evidence.
    """
    rows: list[dict] = []
    registry.audit_sink = rows.append
    identity = issue_identity("triage", run_id="run-1")

    await registry.execute("lookup_technique", {"query": "user=ceo@example.com password=hunter2"}, identity=identity)

    assert "hunter2" not in str(rows[0])
    assert "ceo@example.com" not in str(rows[0])


async def test_an_audit_sink_that_raises_does_not_break_the_tool_call(registry: ToolRegistry):
    """A logging failure must not take the investigation with it.

    The inverse — swallowing the tool result because the audit sink was
    down — is the kind of coupling that turns an observability outage into
    an outage.
    """

    def explode(_row: dict) -> None:
        raise RuntimeError("sink down")

    registry.audit_sink = explode
    identity = issue_identity("triage", run_id="run-1")
    assert await registry.execute("lookup_technique", {}, identity=identity) == {"ok": "lookup_technique"}


# ---------------------------------------------------------------------------
# The scope table names real tools
# ---------------------------------------------------------------------------


def test_every_scoped_tool_name_is_a_tool_something_registers():
    """A scope naming tools that do not exist grants nothing and refuses
    everything real.

    The first draft of `AGENT_TOOL_SCOPES` listed `search_logs`,
    `query_lake` and `graph_blast_radius`. No registry registers any of
    them. That is the same class of mistake as a detection rule clausing on
    a field no connector emits, and just as invisible: a scope full of
    plausible names reads as careful.

    Walked against the real registries rather than against `KNOWN_TOOLS`
    alone, so the written-out list cannot drift from them either.
    """
    scoped = {tool for scope in AGENT_TOOL_SCOPES.values() for tool in scope}
    missing = sorted(scoped - _registered_tool_names())
    assert not missing, f"scoped but registered by nothing: {missing}"


def _registered_tool_names() -> set[str]:
    from app.tools.customer_tools import SIEM_SEARCH_TOOL, VENDOR_READ_TOOLS
    from app.tools.investigation import investigation_tools
    from app.tools.registry import default_registry

    return (
        set(default_registry("t").names()) | {tool.name for tool in investigation_tools("t")} | {SIEM_SEARCH_TOOL} | set(VENDOR_READ_TOOLS)
    )


def test_every_registered_tool_is_reachable_by_some_agent():
    """The other direction, which is the one that caught the real bug.

    Checking only "every scoped name is registered" passes on a scope
    table that omits six tools: nothing is named that does not exist, and
    six real tools are reachable by nobody. The deep-investigation
    acceptance bar then drops from three pivots to one, and the symptom —
    a thinner investigation — looks like a model problem rather than an
    authorization one.

    That is the one-directional-gate failure this repository keeps
    finding: the graph-schema drift check compared Go against YAML and
    never YAML against Go, and reported OK while eleven labels were
    missing.
    """
    scoped = {tool for scope in AGENT_TOOL_SCOPES.values() for tool in scope}
    unreachable = sorted(_registered_tool_names() - scoped)
    assert not unreachable, (
        f"registered but in no agent's scope, so nothing can call them: {unreachable}. "
        "Add them to the agent that should hold them, or delete the tool."
    )


def test_known_tools_covers_everything_the_scopes_name():
    scoped = {tool for scope in AGENT_TOOL_SCOPES.values() for tool in scope}
    assert not sorted(scoped - KNOWN_TOOLS)


def test_no_agent_scope_contains_a_tool_that_changes_an_estate():
    """AiSOC's own agents propose; `services/actions` executes.

    Putting a containment verb in this table would create a second, weaker
    door to the same operation — one with no capability contract and no
    approval tier.
    """
    acting = {"isolate_host", "disable_user", "block_indicator", "kill_process", "revoke_session", "delete_file"}
    for agent, scope in AGENT_TOOL_SCOPES.items():
        assert not (scope & acting), f"{agent} holds an estate-changing tool: {sorted(scope & acting)}"


async def test_a_granted_mcp_tool_becomes_callable_without_extending_the_expiry():
    """The one legitimate way a scope grows.

    A tenant's MCP tools are discovered at run time, so they cannot be in
    a static table; `app/mcp/policy.py` classifies and refuses the
    destructive ones before this is reached. The expiry and credential id
    carry over, so a grant cannot silently lengthen the credential's life
    and the granted calls still join to the same run.
    """
    base = issue_identity("investigation", run_id="run-1")
    granted = base.with_granted_tools({"tenant_wiki_search"})

    assert granted.may("tenant_wiki_search")
    assert not base.may("tenant_wiki_search")
    assert granted.expires_at == base.expires_at
    assert granted.credential_id == base.credential_id
