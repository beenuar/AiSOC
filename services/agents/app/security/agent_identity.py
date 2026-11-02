"""An identity, a scope and an expiry for each of AiSOC's own agents.

Depth plan wave 2, Phase 7.3 — parity 6.7's first half: "Give each internal
agent its own identity, with short-lived credentials and least-privilege
tool scopes, visible in the audit log."

Why this exists
---------------
``ToolRegistry.execute(name, args)`` ran any registered tool for any caller.
There was no identity, no scope and no audit row, which meant three things:

* a triage agent steered by injected text into asking for a containment
  tool would have it run, because nothing compared the request against what
  that agent is allowed to hold;
* the question an incident asks of an agent — *what did it do* — had no
  answer in the ledger, because no row named the caller;
* and the platform that flags "no person is linked, nobody is accountable"
  on a customer's AI estate was running its own agents with exactly that
  property.

What "short-lived" means here, and what it does not
----------------------------------------------------
A credential bound to one investigation run with a wall-clock expiry. It is
deliberately **not** a bearer token to another service: these agents call
Python functions inside their own process, so a network credential would be
ceremony rather than a control, and this repository has shipped enough of
those to be wary of one more.

What the control has to survive is the in-process threat — a model steered
into requesting a tool outside its grant — and the only place that can be
stopped is the one chokepoint every tool call passes through. The expiry
earns its place separately: a run that stalls and resumes hours later must
re-issue rather than continue on a credential nobody has re-authorised.

Why the scopes are a table and not a decorator
-----------------------------------------------
Because the interesting operation is reading them side by side. "Which
agents can run a containment tool" is a question a reviewer asks of the
whole system, and a table answers it in one screen; decorators scattered
across twelve modules do not. The table is also what makes
``test_the_scopes_are_least_privilege_and_not_all_the_same`` possible: if
every agent held every tool the scope would be a comment, and that is
checkable here and nowhere else.

Unknown agents are refused rather than defaulted
-------------------------------------------------
Defaulting an undeclared agent to "everything" makes the control
decorative. Defaulting it to "nothing" breaks that agent silently at run
time, in production, on whatever path first reached for a tool. Refusing to
mint an identity at all fails at the point a human can still see it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

#: Default credential lifetime. Long enough for a deep investigation,
#: short enough that a stalled run re-issues rather than continuing on a
#: grant nobody re-authorised.
DEFAULT_TTL_SECONDS = 1800

#: Which tools each of AiSOC's own agents may call.
#:
#: Read as a privilege boundary, not as a dependency list: these are the
#: tools an agent is *permitted* to reach, and the set is deliberately
#: unequal across agents. The triage and investigation agents read; only
#: the response agent reaches anything that changes an estate, and it does
#: so through the governed action path, which applies its own capability
#: contract and approval tier on top of this.
#:
#: A tool absent from every set here is reachable by nobody, which is the
#: correct default for a tool nobody has thought about.
#: Every tool name AiSOC's own registries actually register.
#:
#: Written out rather than imported, because importing the registries here
#: would make this module depend on the investigator, the sandbox client and
#: the MITRE corpus just to answer "what is a valid tool name". The cost of
#: writing them out is drift, and that is paid for by
#: `test_every_scoped_tool_name_is_a_tool_something_registers`, which walks
#: the registries and fails if a name here is not among them.
#:
#: This mattered: the first draft of the table below listed `search_logs`,
#: `query_lake` and `graph_blast_radius`, none of which any registry
#: registers. A scope naming tools that do not exist grants nothing and
#: refuses everything real — the same class of mistake as a detection rule
#: clausing on a field no connector emits, and just as invisible, because a
#: scope full of plausible names reads as careful.
KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        # default_registry
        "lookup_file_hash",
        "extract_iocs",
        "map_to_mitre",
        "lookup_technique",
        "enrich_ioc",
        # investigator customer tools (typed, lake-backed pivots)
        "process_activity",
        "historical_execution",
        "network_connections",
        "authentication_events",
        "fleet_ioc_hunt",
        "entity_timeline",
        "technique_activity",
        "process_tree",
        "mailbox_activity",
        "oauth_grants",
        "persistence_mechanisms",
        # Wave-2 1.1 and 1.5, registered unconditionally in
        # `default_registry`: what this identity could do at the moment it
        # acted, and what changed shortly before it did. Read-only, and
        # both answer "unknown, and here is why" rather than a silent zero
        # when no snapshot covers the question.
        "identity_effective_permissions",
        "changes_before_alert",
        # Customer-estate read tools (`app/tools/customer_tools.py`). These
        # reach the customer's own vendors through the governed read path
        # rather than AiSOC's lake, which is why the investigator holds
        # them and nothing else does.
        "siem_indicator_search",
        "cloud_audit_lookup",
        "edr_host_details",
        "edr_host_detections",
        "endpoint_telemetry_sightings",
        "identity_user_activity",
    }
)

#: Which tools each of AiSOC's own agents may call.
#:
#: Read as a privilege boundary, not as a dependency list. The sets are
#: deliberately unequal: triage is the agent most exposed to
#: attacker-controlled text and holds the least, while the investigator
#: holds the deep pivots because that is its job.
#:
#: Note what is *not* here: nothing in this table changes an estate. AiSOC's
#: own agents propose; execution goes through `services/actions`, which
#: applies a capability contract and an approval tier of its own. Putting a
#: containment verb in this table would create a second, weaker door to the
#: same operation.
#:
#: A tool in `KNOWN_TOOLS` and in no scope here is reachable by nobody,
#: which is the correct default for a tool nobody has thought about.
AGENT_TOOL_SCOPES: dict[str, frozenset[str]] = {
    # Reads alert context, extracts indicators, looks up techniques. Holds
    # no pivot that reaches customer telemetry, because this is the agent
    # an injected alert talks to first.
    "triage": frozenset({"extract_iocs", "map_to_mitre", "lookup_technique", "enrich_ioc"}),
    # The recursive investigator: everything triage holds, plus the typed
    # lake-backed pivots and the sandbox lookup.
    "investigation": frozenset(
        {
            "extract_iocs",
            "map_to_mitre",
            "lookup_technique",
            "enrich_ioc",
            "lookup_file_hash",
            "process_activity",
            "historical_execution",
            "network_connections",
            "authentication_events",
            "fleet_ioc_hunt",
            "entity_timeline",
            "technique_activity",
            "process_tree",
            "mailbox_activity",
            "oauth_grants",
            "persistence_mechanisms",
            # The two halves of "what could this identity do, and what
            # changed before it did". The investigator rather than triage:
            # both take typed entity fields, but the scope table keeps the
            # agent most exposed to attacker-controlled text at its minimum.
            "identity_effective_permissions",
            "changes_before_alert",
            "siem_indicator_search",
            "cloud_audit_lookup",
            "edr_host_details",
            "edr_host_detections",
            "endpoint_telemetry_sightings",
            "identity_user_activity",
        }
    ),
    # Hunting sweeps the fleet and reads timelines; it does not enrich
    # against third parties, which is a per-tenant opt-in with its own key.
    "hunt": frozenset(
        {
            "extract_iocs",
            "lookup_technique",
            "fleet_ioc_hunt",
            "entity_timeline",
            "technique_activity",
            "historical_execution",
            "siem_indicator_search",
        }
    ),
    # Proposes a disposition and a containment plan. Reads what it needs to
    # justify one; executes nothing here.
    "respond": frozenset({"lookup_technique", "entity_timeline", "process_tree", "network_connections"}),
    # Detection engineering drafts rules from technique coverage.
    "detect": frozenset({"map_to_mitre", "lookup_technique", "technique_activity", "historical_execution"}),
}


class ScopeDenied(RuntimeError):
    """A tool was requested outside the caller's scope, or after expiry.

    An exception rather than a sentinel because a direct caller must not be
    able to mistake a denial for a result. ``ToolRegistry`` converts it into
    the structured ``{"error": ...}`` its loop contract requires, which is a
    conversion at one place rather than every caller parsing a string.
    """


@dataclass(frozen=True)
class AgentIdentity:
    """One agent, one run, one expiry, one scope."""

    agent: str
    run_id: str
    expires_at: float
    scopes: frozenset[str]
    #: Distinguishes two concurrent runs of the same agent in the audit log.
    credential_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def expired(self, *, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def may(self, tool: str) -> bool:
        return not self.expired() and tool in self.scopes

    def require(self, tool: str, *, now: float | None = None) -> None:
        """Raise unless this identity may call ``tool`` right now."""
        if self.expired(now=now):
            raise ScopeDenied(
                f"the credential for agent {self.agent!r} on run {self.run_id!r} has expired; re-issue it rather than extending it"
            )
        if tool not in self.scopes:
            raise ScopeDenied(f"tool {tool!r} is outside the scope of agent {self.agent!r}")

    def with_granted_tools(self, tools: frozenset[str] | set[str] | list[str]) -> AgentIdentity:
        """A copy of this identity extended with tools another control approved.

        The one legitimate way the scope grows, and it exists for MCP: a
        tenant's MCP servers are discovered at run time, so their tool names
        cannot be in a static table. They are not ungoverned — `app/mcp/
        policy.py` classifies each one and refuses the destructive ones
        before this is ever called — so this is one control handing its
        verdict to the other rather than a hole in either.

        The expiry and the credential id are carried over deliberately: a
        grant must not silently extend the credential's life, and the audit
        rows for the granted tools must join to the same run.
        """
        return _granted(self, frozenset(str(t) for t in tools))

    def audit_row(self, tool: str, *, allowed: bool, reason: str | None = None) -> dict[str, object]:
        """One row for the audit log. Never the tool's arguments.

        Arguments carry alert content — hostnames, account names, raw text
        lifted from a vendor payload. An audit log is read by more people
        than an alert is, so a tool-call log that copied the arguments
        would become a second, wider copy of the evidence.
        """
        row: dict[str, object] = {
            "agent": self.agent,
            "run_id": self.run_id,
            "credential_id": self.credential_id,
            "tool": tool,
            "allowed": allowed,
            "at": time.time(),
        }
        if reason:
            row["reason"] = reason
        return row


def _granted(identity: AgentIdentity, tools: frozenset[str]) -> AgentIdentity:
    return AgentIdentity(
        agent=identity.agent,
        run_id=identity.run_id,
        expires_at=identity.expires_at,
        scopes=identity.scopes | tools,
        credential_id=identity.credential_id,
    )


def issue_identity(agent: str, *, run_id: str, ttl_seconds: int | None = None) -> AgentIdentity:
    """Mint a short-lived identity for one of AiSOC's own agents.

    Refuses an agent with no declared scope. See the module docstring for
    why that is a refusal and not a default in either direction.
    """
    scopes = AGENT_TOOL_SCOPES.get(agent)
    if scopes is None:
        raise ValueError(
            f"unknown agent {agent!r}: declare its tool scope in AGENT_TOOL_SCOPES. Known agents: {', '.join(sorted(AGENT_TOOL_SCOPES))}."
        )
    ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    return AgentIdentity(agent=agent, run_id=run_id, expires_at=time.time() + ttl, scopes=scopes)
