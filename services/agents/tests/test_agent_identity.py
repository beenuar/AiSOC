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
    AgentIdentity,
    ScopeDenied,
    issue_identity,
)
from app.tools.registry import Tool, ToolRegistry


def _tool(name: str) -> Tool:
    return Tool(name=name, description=name, parameters={"type": "object", "properties": {}}, fn=lambda: {"ok": name})


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry([_tool("search_logs"), _tool("get_mitre_technique"), _tool("isolate_host")])


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
    result = await registry.execute("search_logs", {}, identity=identity)
    assert result == {"ok": "search_logs"}


async def test_a_tool_outside_the_scope_is_refused(registry: ToolRegistry):
    """The whole point. A triage agent does not hold containment.

    Refused as a structured error rather than an exception, because the
    loop's contract is that a tool failure reaches the model instead of
    aborting the run — but the error names the scope so an operator can
    tell a denial from a tool that broke.
    """
    identity = issue_identity("triage", run_id="run-1")
    result = await registry.execute("isolate_host", {}, identity=identity)
    assert "error" in result
    assert "scope" in result["error"].lower()


async def test_an_expired_identity_is_refused(registry: ToolRegistry):
    """Otherwise "short-lived" is a field nobody reads.

    A run that outlives its credential is the case this catches: a stalled
    investigation resuming hours later must re-issue, not continue.
    """
    identity = issue_identity("triage", run_id="run-1", ttl_seconds=-1)
    result = await registry.execute("search_logs", {}, identity=identity)
    assert "error" in result
    assert "expired" in result["error"].lower()


async def test_a_call_with_no_identity_is_refused_by_default(registry: ToolRegistry):
    """Default-deny, which is the only safe direction.

    An optional identity defaulting to "allow" means every existing call
    site keeps working and the control protects nothing — the exact shape
    of the `Annotated[Any, require_permission(...)]` routes that read as
    gated and enforced nothing.
    """
    result = await registry.execute("search_logs", {})
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
        identity.require("isolate_host")


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

    await registry.execute("search_logs", {}, identity=identity)
    await registry.execute("isolate_host", {}, identity=identity)

    assert len(rows) == 2
    allowed, denied = rows
    assert allowed["agent"] == "triage" and allowed["tool"] == "search_logs" and allowed["allowed"] is True
    assert denied["agent"] == "triage" and denied["tool"] == "isolate_host" and denied["allowed"] is False
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

    await registry.execute("search_logs", {"query": "user=ceo@example.com password=hunter2"}, identity=identity)

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
    assert await registry.execute("search_logs", {}, identity=identity) == {"ok": "search_logs"}
