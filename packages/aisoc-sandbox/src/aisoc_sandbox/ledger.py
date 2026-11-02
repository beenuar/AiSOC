"""Investigation Ledger — the step-by-step record of one investigation run.

The shape here mirrors the production `investigation_events` ledger
written by [`services/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents)
so that an analyst who learns the sandbox can read a real ledger
without re-learning the schema. Differences from production:

  * No persistence. The ledger lives in memory for the duration of
    one CLI invocation; the production ledger writes to Postgres.
  * No model. There is no LLM anywhere in this package, so there is no
    prompt and no response to capture. Every sentence the sandbox emits
    is arithmetic over the scenario's events.
  * No tool dispatch. Tool calls are the *shape* of the call the live
    pipeline would make, rendered as "would-call(<name>, <args>)" and
    carrying `executed: false`. Nothing is dispatched.
  * Values the sandbox cannot compute are :class:`NotComputed`, never a
    plausible stand-in.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

#: Printed wherever a verdict is read, not only in the header. A reader
#: who scrolled to the Decision line has already passed the banner, and
#: the reported defect was read exactly that way.
SYNTHETIC_NOTICE = "synthetic offline run: no LLM, no network, nothing executed"


@dataclass(frozen=True)
class NotComputed:
    """A value this run did not compute, carrying the reason it did not.

    The repository's standing rule is that an unmeasurable value renders
    as an honest empty state and never as a confident number. The sibling
    trap is just as costly and easier to miss: three console formatters
    once had an "unavailable" escape hatch that *excluded* zero, so
    hardcoded zeros rendered as `0%` under a "Live" label. So this is not
    `None` and not `0` — it is a distinct type that survives both the
    human render and `asdict`, and it refuses to be mistaken for a
    measurement in either.

    ``status`` is a field rather than a class constant so that
    ``dataclasses.asdict`` carries the marker into the JSON output; a
    bare ``{"reason": ...}`` would lose it.
    """

    reason: str
    status: str = "not_computed"

    def __str__(self) -> str:
        return f"not computed in the sandbox — {self.reason}"


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
        rationale: What the agent computed and from what. Anything the
            sandbox could not compute is stated as such rather than
            filled in.
        evidence: Key/value evidence chips. Maps to the production
            Investigation Rail's "Related entities" panel. A value the
            run could not compute is a :class:`NotComputed`.
        tool_calls: The shape of the calls the live pipeline makes —
            never a record that one happened. Each entry is
            `{"name": ..., "args": {...}, "executed": False}`.
        decision: Optional summary of the step's outcome. Carries
            :data:`SYNTHETIC_NOTICE` wherever it states a finding, so
            the disclaimer sits at the point the verdict is read.
        latency_ms: Wall-clock duration of the step inside the
            simulator — a real measurement of this process, not a
            stand-in for production LLM latency.
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
        # tell what they're looking at. It is not sufficient on its own —
        # see the Decision lines, which carry the notice too.
        out.write(c("1;36", "Investigation Ledger") + "\n")
        out.write(f"  {len(self._steps)} steps · {sum(s.latency_ms for s in self._steps)} ms total · {SYNTHETIC_NOTICE}\n\n")

        for s in self._steps:
            stage_label = {
                "detect": c("34", "DETECT"),
                "triage": c("33", "TRIAGE"),
                "hunt": c("35", "HUNT"),
                "respond": c("32", "RESPOND"),
            }.get(s.funnel_stage, s.funnel_stage.upper())
            out.write(f"{c('1', f'Step {s.step:>2}')}  {stage_label}  {c('2', s.agent)}  {c('2', f'({s.latency_ms} ms)')}\n")
            out.write(f"  Action     {s.action}\n")
            out.write(f"  Rationale  {_wrap(s.rationale)}\n")
            for key, value in s.evidence.items():
                out.write(_render_evidence(key, value))
            for tc in s.tool_calls:
                out.write(f"  → would-call {c('36', str(tc.get('name')))}({json.dumps(tc.get('args', {}), default=str)})  [not executed]\n")
            if s.decision:
                out.write(f"  {c('1', 'Decision')}   {_wrap(s.decision, indent=14)}\n")
            out.write("\n")


def _wrap(text: str, *, indent: int = 13, width: int = 96) -> str:
    """Soft-wrap a sentence so the rationale stays readable in a terminal.

    The rationales now carry their arithmetic, which makes them longer
    than the one-liners they replaced. A wrapped paragraph is the price
    of a reader being able to check the number.
    """

    pad, line, lines = " " * indent, "", []
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return f"\n{pad}".join(lines)


def _render_evidence(key: str, value: Any, *, bullet: str = "  · ") -> str:
    """One evidence chip, with the nested shapes the signals emit.

    A :class:`NotComputed` renders through its own ``__str__`` so the
    reason travels with the absence. A list of signal dicts gets one
    labelled line each rather than a dumped repr.
    """

    if isinstance(value, list) and value and all(isinstance(v, dict) and "name" in v and "status" in v for v in value):
        out = [f"{bullet}{key}:"]
        for entry in value:
            out.append(f"      [{entry['status']}] {entry['name']}: {_wrap(str(entry.get('summary', '')), indent=10)}")
        return "\n".join(out) + "\n"
    return f"{bullet}{key}: {_wrap(str(value), indent=6)}\n"
