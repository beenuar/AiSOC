"""The adapter protocol: what any SOC agent must implement to be graded.

Pillar 4. A benchmark a vendor cannot run against their own product is a
self-report. The existing harness grades the in-tree agent by importing it,
which means the numbers are only ever about AiSOC — and a scoreboard with one
entrant is a marketing page.

This is the boundary that makes it a standard instead. An agent is anything
that takes an incident and returns a verdict, so the protocol is deliberately
small: four fields in, five fields out, no imports from this repository
required. A vendor implements it in twenty lines against their own API and
gets graded on the same corpus by the same code.

Three deliberate exclusions:

* **No tool interface.** How an agent reaches evidence is its business. The
  benchmark supplies the incident and the telemetry corpus and grades the
  answer; prescribing the tools would grade architecture rather than
  outcomes, and would exclude every agent that does not look like ours.
* **No prompt.** Same reason.
* **No partial credit for effort.** An agent that called forty tools and
  concluded wrongly scores as wrongly as one that guessed. Depth is reported
  separately because it explains a score; it is not a score.

What *is* prescribed is the shape of the answer, because the metrics depend
on it — specifically on being able to tell a confident wrong answer from an
abstention, and a cited indicator from an invented one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class BenchmarkIncident:
    """One incident to investigate.

    Supplied verbatim to the agent. ``telemetry`` is the events the agent may
    reason over, so an agent with no live estate can still be graded — the
    corpus is the estate.
    """

    incident_id: str
    title: str
    description: str
    severity: str
    raw_alert: dict[str, Any] = field(default_factory=dict)
    telemetry: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "raw_alert": self.raw_alert,
            "telemetry": self.telemetry,
        }


@dataclass
class AgentVerdict:
    """What an agent returns. Every field earns its place in a metric.

    ``abstained`` exists because "I do not know" is a correct answer that a
    forced-choice benchmark punishes, and punishing it trains agents to
    guess. An abstention scores neither right nor wrong, and the abstention
    rate is published alongside accuracy so the two cannot be traded off
    invisibly.
    """

    #: malicious | suspicious | benign | unknown
    disposition: str = "unknown"

    #: 0.0-1.0. Used for calibration, not for credit: a confidently wrong
    #: answer is worse than a hedged one and the metrics say so.
    confidence: float = 0.0

    #: ATT&CK technique ids the agent attributes to the incident.
    techniques: list[str] = field(default_factory=list)

    #: Concrete indicators the agent's reasoning relies on — addresses,
    #: hashes, hostnames, accounts. Graded against the evidence it was given.
    #: This is how hallucination is measured rather than estimated.
    cited_indicators: list[str] = field(default_factory=list)

    #: Actions the agent would take. Graded for containment appropriateness.
    proposed_actions: list[str] = field(default_factory=list)

    #: Free-text reasoning. Not scored directly; retained so a result can be
    #: read by a human who disagrees with the score.
    narrative: str = ""

    #: True when the agent declined to reach a verdict.
    abstained: bool = False

    #: Optional, and reported rather than scored. An agent that reached the
    #: right answer in one step is not worse than one that took twelve.
    tool_calls: int = 0
    distinct_tools: int = 0
    latency_ms: int = 0
    tokens: int = 0
    usd_cost: float = 0.0

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentVerdict:
        """Build from a JSON response, tolerating an incomplete one.

        Missing fields default rather than raise: an adapter under
        development should score badly, not crash the run. A crash is
        indistinguishable from a harness bug, and the entrant will assume it
        is ours.
        """
        return cls(
            disposition=str(payload.get("disposition", "unknown")).lower(),
            confidence=float(payload.get("confidence", 0.0) or 0.0),
            techniques=[str(t).upper() for t in (payload.get("techniques") or [])],
            cited_indicators=[str(i) for i in (payload.get("cited_indicators") or [])],
            proposed_actions=[str(a) for a in (payload.get("proposed_actions") or [])],
            narrative=str(payload.get("narrative", "")),
            abstained=bool(payload.get("abstained", False)),
            tool_calls=int(payload.get("tool_calls", 0) or 0),
            distinct_tools=int(payload.get("distinct_tools", 0) or 0),
            latency_ms=int(payload.get("latency_ms", 0) or 0),
            tokens=int(payload.get("tokens", 0) or 0),
            usd_cost=float(payload.get("usd_cost", 0.0) or 0.0),
        )


@runtime_checkable
class SOCAgent(Protocol):
    """Implement this to be graded.

    One method. Everything else about the agent — model, tools, prompts,
    architecture — is out of scope by design.
    """

    name: str
    version: str

    async def investigate(self, incident: BenchmarkIncident) -> AgentVerdict:
        """Investigate one incident and return a verdict.

        Must not raise. An agent that cannot reach a verdict should return
        ``AgentVerdict(abstained=True)`` with a narrative explaining why: the
        benchmark distinguishes "declined" from "crashed", and an exception
        is scored as a crash.
        """
        ...


class HTTPAgent:
    """Adapter for an agent behind an HTTP endpoint.

    The path most entrants will take: point the benchmark at a URL, get
    graded. Posts the incident as JSON and reads an ``AgentVerdict``-shaped
    response.

    A failed call is an abstention with the failure named, not an exception.
    A harness that dies on one bad response grades nothing, and the entrant
    reasonably assumes the fault is ours.
    """

    def __init__(
        self,
        url: str,
        *,
        name: str = "http-agent",
        version: str = "unknown",
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.url = url
        self.name = name
        self.version = version
        self.headers = headers or {}
        self.timeout_seconds = timeout_seconds

    async def investigate(self, incident: BenchmarkIncident) -> AgentVerdict:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(self.url, json=incident.as_dict(), headers=self.headers)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            return AgentVerdict(
                abstained=True,
                narrative=(f"adapter error: {type(exc).__name__}: {exc}. " f"Scored as an abstention, not as a wrong answer."),
            )

        if not isinstance(payload, dict):
            return AgentVerdict(
                abstained=True,
                narrative=f"adapter returned {type(payload).__name__}, expected an object",
            )
        return AgentVerdict.from_dict(payload)
