"""Investigation Ledger — the step-by-step record of one investigation run.

The shape here mirrors the production `investigation_events` ledger
written by [`services/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents)
so that an analyst who learns the sandbox can read a real ledger
without re-learning the schema. Differences from production:

  * No persistence. The ledger lives in memory for the duration of
    one CLI invocation; the production ledger writes to Postgres.
  * No prompt/response capture. The sandbox uses a deterministic stub
    in place of the real LLM, so `prompt` / `response` fields hold a
    short descriptor of the decision rather than the full LLM text.
  * No tool dispatch. Tool calls are simulated as
    "would-call(<name>, <args>)" entries so the funnel still reads
    naturally without spinning up the connector / action stack.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass
class LedgerStep:
    """One step in the investigation funnel.

    Attributes:
        step: 0-indexed step number across the whole run.
        agent: Which of the four production agents emitted this step.
            One of: `DetectAgent`, `TriageAgent`, `HuntAgent`,
            `RespondAgent`, or `Orchestrator` (the funnel wrapper).
        funnel_stage: The four-stage automation maturity funnel:
            `detect | triage | hunt | respond`.
        action: A human-readable verb (e.g. "Correlate authentication
            events", "Compute confidence band", "Recommend response").
        rationale: One sentence summarising why the agent did this.
        evidence: Key/value evidence chips. Maps to the production
            Investigation Rail's "Related entities" panel.
        tool_calls: Tools the agent would invoke (sandboxed; not
            executed). Each entry is `{"name": ..., "args": {...}}`.
        decision: Optional summary of the step's outcome — confidence
            band, recommended action, or routing decision.
        latency_ms: Wall-clock duration of the step inside the
            simulator. Production ledger captures real LLM latency;
            the sandbox uses synthetic deterministic numbers.
        timestamp_utc: ISO-8601 timestamp at step emission.
    """

    step: int
    agent: str
    funnel_stage: str
    action: str
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    decision: str | None = None
    latency_ms: int = 0
    timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Ledger:
    """Append-only ordered list of :class:`LedgerStep` entries."""

    def __init__(self) -> None:
        self._steps: list[LedgerStep] = []

    def __iter__(self) -> Iterable[LedgerStep]:
        return iter(self._steps)

    def __len__(self) -> int:
        return len(self._steps)

    def append(
        self,
        *,
        agent: str,
        funnel_stage: str,
        action: str,
        rationale: str,
        evidence: dict[str, Any] | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        decision: str | None = None,
        latency_ms: int = 0,
    ) -> LedgerStep:
        step = LedgerStep(
            step=len(self._steps),
            agent=agent,
            funnel_stage=funnel_stage,
            action=action,
            rationale=rationale,
            evidence=evidence or {},
            tool_calls=tool_calls or [],
            decision=decision,
            latency_ms=latency_ms,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )
        self._steps.append(step)
        return step

    def to_dict(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._steps]

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def render_human(self, *, out: Any = None) -> None:
        """Render the ledger to a stream in the format buyers see in /alerts/[id].

        Plain text so it copies cleanly into a GitHub issue, a Slack
        message, or a screenshot. Colour codes are skipped when stdout
        isn't a TTY (e.g., piping to a file).
        """

        if out is None:
            out = sys.stdout
        use_colour = bool(getattr(out, "isatty", lambda: False)())

        def c(code: str, text: str) -> str:
            return f"\x1b[{code}m{text}\x1b[0m" if use_colour else text

        # Header so a reader who scrolled past the boot logs can still
        # tell what they're looking at.
        out.write(c("1;36", "Investigation Ledger") + "\n")
        out.write(
            f"  {len(self._steps)} steps · "
            f"{sum(s.latency_ms for s in self._steps)} ms total · "
            "synthetic offline run (no LLM, no Docker)\n\n"
        )

        for s in self._steps:
            stage_label = {
                "detect": c("34", "DETECT"),
                "triage": c("33", "TRIAGE"),
                "hunt": c("35", "HUNT"),
                "respond": c("32", "RESPOND"),
            }.get(s.funnel_stage, s.funnel_stage.upper())
            out.write(
                f"{c('1', f'Step {s.step:>2}')}  {stage_label}  "
                f"{c('2', s.agent)}  {c('2', f'({s.latency_ms} ms)')}\n"
            )
            out.write(f"  Action     {s.action}\n")
            out.write(f"  Rationale  {s.rationale}\n")
            if s.evidence:
                for k, v in s.evidence.items():
                    out.write(f"  · {k}: {v}\n")
            for tc in s.tool_calls:
                out.write(
                    f"  → would-call {c('36', tc['name'])}"
                    f"({json.dumps(tc.get('args', {}), default=str)})\n"
                )
            if s.decision:
                out.write(f"  {c('1', 'Decision')}   {s.decision}\n")
            out.write("\n")
