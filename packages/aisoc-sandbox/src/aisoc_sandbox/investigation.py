"""The four-stage investigation funnel — Detect → Triage → Hunt → Respond.

This module is the simulator-equivalent of
[`services/agents/app/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/agents)
collapsed into one file. It exists so a reader can read the whole
funnel in 5 minutes and see exactly what every step does.

Each stage is implemented as a free function that takes the
:class:`Scenario`, the :class:`Ledger` (which it appends to) and the
signals computed from the scenario's events. The :class:`Investigation`
class wires them up; :func:`run_investigation` is the CLI's high-level
entry point.

What the sandbox will and will not say
--------------------------------------
There is no LLM here and there never was. What this module used to do
instead was worse than having nothing: it held one fixed rationale per
MITRE technique, scored confidence as ``{severity} + 4 x techniques``,
and read the L0–L4 automation tier out of a dict keyed on severity. All
three inputs come from the file the *user* supplies, so the output
followed the label rather than the events — a benign login tagged
``T1078`` came back "the geo pivot between sequential events is
physically impossible", and genuine impossible travel relabelled
``info`` came back "L4 — fully autonomous closure, auto-execute
eligible". Several of the canned sentences also asserted measurements
nothing had taken ("exceeds the per-tenant Welford-online baseline by
more than three standard deviations").

That is the same family this repository has deleted repeatedly —
``_synthetic_reply`` cycling canned paragraphs about an estate it never
read, ``AlertDetailView``'s catch block rendering an invented APT
verdict as ``status: completed`` — and the precedent is that such code
is removed rather than reworded.

So the funnel now holds to two rules:

* Anything it asserts, it computed. :mod:`aisoc_sandbox.signals` derives
  what is genuinely derivable from the event payload — impossible travel
  is a distance over an elapsed time — and the narration is assembled
  from the signals that were actually computed.
* Anything it cannot compute is :class:`~aisoc_sandbox.ledger.NotComputed`
  with the reason attached. Not a plausible integer, and not a zero.

Deliberately absent, because the sandbox has no basis for any of them:
a confidence score, an automation tier, an approval posture, a
related-case count, an entity risk score, and a hunt match count.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

from ._corpus import LIVE_ENGINE_EXECUTABLE_RULES, LIVE_ENGINE_WINDOWED_RULES
from .ledger import SYNTHETIC_NOTICE, Ledger, NotComputed
from .scenarios import Scenario
from .signals import Signal, compute_signals, technique_support


class EvidenceNarrator:
    """Turns the computed signals into the sentence the ledger prints.

    Named for what it does. It holds no table of sentences keyed on
    anything the input declares — that table *was* the defect — and it
    cannot be called without the signals, so a narration that is not
    traceable to a computation over the events is not expressible here.

    Every clause it emits either repeats a :class:`Signal` summary (each
    of which carries its own arithmetic) or states that something was
    not computed.
    """

    def explain(self, *, signals: list[Signal], support: dict[str, list[str]], declared_techniques: list[str]) -> str:
        computed = [s for s in signals if s.status != "not_computable"]
        skipped = [s for s in signals if s.status == "not_computable"]

        parts = ["Derived from the event payload — not from the declared severity and not from the MITRE tag."]
        parts.extend(f"{s.name}: {s.summary}" for s in computed)
        if skipped:
            parts.append(
                f"Not computable from this payload: {', '.join(s.name for s in skipped)} — see the evidence chips for why each one could not be computed."
            )

        if support["supported"]:
            parts.append(f"Declared technique(s) {', '.join(support['supported'])} are supported by a signal that fired.")
        if support["unsupported"]:
            parts.append(
                f"Declared technique(s) {', '.join(support['unsupported'])} are NOT supported by anything computed here:"
                " a signal bearing on them was computed and did not fire."
            )
        if support["no_signal"]:
            parts.append(
                f"The sandbox computes no signal bearing on {', '.join(support['no_signal'])}, so it has nothing to say about that tag either way."
            )
        if not declared_techniques:
            parts.append("The scenario declares no MITRE technique.")

        # Stated differently depending on what fired, because the two
        # mistakes a reader could make here are opposite ones. With
        # nothing firing the risk is reading silence as an all-clear;
        # with something firing it is reading a fact about the events as
        # a disposition the sandbox never reached.
        if any(s.holds for s in signals):
            parts.append(
                "No verdict is reached: the signals above are facts about these events, not a disposition, and there is no model in this package to form one."
            )
        else:
            parts.append(
                "No verdict is reached: there is no model in this package, and a signal that did not fire is not evidence that the alert is benign."
            )
        return " ".join(parts)


@dataclass
class Investigation:
    """One investigation run."""

    scenario: Scenario
    ledger: Ledger
    narrator: EvidenceNarrator

    def run(self) -> Ledger:
        """Walk the four-stage funnel; populate the ledger.

        Signals are computed once, up front, and handed to every stage
        that makes a statement. No stage may reach a finding by any
        other route — which is the structural half of the fix, since a
        stage that cannot see the events cannot have been describing
        them.
        """

        signals = compute_signals(self.scenario.events)
        support = technique_support(self.scenario.mitre_techniques, signals)

        _stage_detect(self.scenario, self.ledger, signals)
        _stage_triage(self.scenario, self.ledger, self.narrator, signals, support)
        _stage_hunt(self.scenario, self.ledger, signals)
        _stage_respond(self.scenario, self.ledger, signals)
        return self.ledger


# ---------------------------------------------------------------------------
# Stage 1 — Detect. "What arrived, and what does the payload claim?"
# ---------------------------------------------------------------------------


def _stage_detect(s: Scenario, ledger: Ledger, signals: list[Signal]) -> None:
    t0 = time.perf_counter()
    ledger.append(
        agent="DetectAgent",
        funnel_stage="detect",
        action="Read the alert payload and index what it declares",
        rationale=(
            f"{len(s.events)} event(s) ingested. No detection rule ran: this package ships no detection engine,"
            f" so the technique(s) and severity below are values the scenario file declares, not the output of a match."
            f" The live engine loads {LIVE_ENGINE_EXECUTABLE_RULES:,} executable rules plus {LIVE_ENGINE_WINDOWED_RULES}"
            f" sliding-window rules and would evaluate the events against them."
        ),
        evidence={
            "events_ingested": len(s.events),
            "mitre_techniques_declared_by_input": s.mitre_techniques,
            "severity_declared_by_input": s.severity,
            "detection_rules_evaluated_here": "0 — the sandbox ships no detection engine",
            "live_engine_ruleset_size": f"{LIVE_ENGINE_EXECUTABLE_RULES:,} executable + {LIVE_ENGINE_WINDOWED_RULES} windowed (the full stack, at this package's version)",
            "signals_the_sandbox_can_compute": [sig.name for sig in signals],
            **{f"entity:{k}": v for k, v in s.entities.items()},
        },
        tool_calls=[
            {"name": "rules.match", "args": {"technique_set": s.mitre_techniques}, "executed": False},
            {"name": "fusion.score", "args": {"window_minutes": 15}, "executed": False},
        ],
        decision=f"Alert opened at severity={s.severity}, the value the input declares. The sandbox does not compute severity and does not revise it.",
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 2 — Triage. "What do the events actually show?"
#
# The stage the reported defect lived in. It no longer takes the severity
# or the technique as an input to any finding: both are echoed as
# *declarations*, and every statement comes from `signals`.
# ---------------------------------------------------------------------------


def _stage_triage(
    s: Scenario,
    ledger: Ledger,
    narrator: EvidenceNarrator,
    signals: list[Signal],
    support: dict[str, list[str]],
) -> None:
    t0 = time.perf_counter()
    computed = [sig for sig in signals if sig.status != "not_computable"]
    fired = [sig for sig in signals if sig.holds]

    ledger.append(
        agent="TriageAgent",
        funnel_stage="triage",
        action="Compute what the events support, and name what cannot be computed",
        rationale=narrator.explain(signals=signals, support=support, declared_techniques=s.mitre_techniques),
        evidence={
            "signals": [asdict(sig) for sig in signals],
            "technique_support": support,
            "confidence_score": NotComputed(
                "there is no model and no scoring function in this package; the live TriageAgent's score comes"
                " from the model's own calibrated output, which is why one cannot be produced offline"
            ),
            "related_cases_30d": NotComputed(
                "there is no case store here; the live TriageAgent searches Qdrant over the tenant's closed cases"
            ),
            "entity_risk": NotComputed(
                "risk-based alerting scores are computed by services/fusion against a per-tenant behavioural baseline the sandbox has no access to"
            ),
        },
        tool_calls=[
            {"name": "qdrant.semantic_search", "args": {"k": 5, "collection": "cases"}, "executed": False},
            {"name": "graph.neighbours", "args": {"depth": 2}, "executed": False},
        ],
        decision=(
            f"{len(computed)} of {len(signals)} signal(s) computed from the events; {len(fired)} fired."
            f" Confidence score: not computed. Verdict: not reached — {SYNTHETIC_NOTICE}."
        ),
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 3 — Hunt. "Did the same actor touch anything else?"
#
# It did not look, so it must not report a result. The previous decision
# line read "Pivot complete; no additional compromised entities surfaced",
# which is a negative finding from a sweep that never ran — the same
# defect as a confident zero.
# ---------------------------------------------------------------------------


def _stage_hunt(s: Scenario, ledger: Ledger, signals: list[Signal]) -> None:
    t0 = time.perf_counter()
    pivots = list(s.entities.values())

    ledger.append(
        agent="HuntAgent",
        funnel_stage="hunt",
        action="Show the pivot the live HuntAgent would run across the data lake",
        rationale=(
            f"The live HuntAgent translates a natural-language hypothesis into ES|QL / SPL / KQL and sweeps the"
            f" warm tier for the primary entity. No sweep happened here: the sandbox holds no events beyond the"
            f" {len(s.events)} in this payload, so there is nothing to pivot into and no result to report."
        ),
        evidence={
            "pivot_entities": pivots,
            "hunt_query_languages": ["ES|QL", "SPL", "KQL"],
            "events_available_to_search": len(s.events),
            "matches_found": NotComputed(
                "no sweep ran; the sandbox has no event store, while the live HuntAgent queries the ClickHouse lake"
            ),
            "additional_compromised_entities": NotComputed(
                "unknown rather than zero: nothing was searched, so 'none found' would describe the sandbox and not the estate"
            ),
        },
        tool_calls=[
            {
                "name": "nl_to_query.translate",
                "args": {"hypothesis": f"any activity by {next(iter(pivots), 'actor')} in last 24h"},
                "executed": False,
            },
            {"name": "lake.query", "args": {"language": "ES|QL", "lookback_hours": 24, "row_cap": 1000}, "executed": False},
        ],
        decision=f"Pivot not performed. Shown: the entities the live HuntAgent would sweep on — {SYNTHETIC_NOTICE}.",
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 4 — Respond. "What would be proposed, and who decides?"
#
# Nothing here is read off the severity label. The L0–L4 tier and the
# approval posture are per-tenant policy the live stack resolves from the
# capability contract and the approval matrix; reading them off a string
# in the input file is what let a self-declared `info` select "fully
# autonomous closure".
# ---------------------------------------------------------------------------


def _stage_respond(s: Scenario, ledger: Ledger, signals: list[Signal]) -> None:
    t0 = time.perf_counter()
    actions = s.recommended_actions or _default_actions(s)

    ledger.append(
        agent="RespondAgent",
        funnel_stage="respond",
        action="Show the response the live RespondAgent would propose",
        rationale=(
            "The live stack grades every action against its capability contract — risk, reversibility, a"
            " verification probe — and an approval matrix of confidence against blast radius, under the tenant's"
            " own L0–L4 autonomy policy. The sandbox has no tenant, no policy and no confidence score, so it"
            " determines no tier and no approval posture. The actions below are the ones the scenario names, or"
            " a default set derived from its entities; none is dispatched."
        ),
        evidence={
            "recommended_action_count": len(actions),
            "actions_executed": "0 — the sandbox dispatches nothing, under any severity",
            "automation_maturity_tier": NotComputed(
                "the L0–L4 tier is per-tenant autonomy policy resolved by services/actions; it is never read off"
                " an alert's self-declared severity, which is what this package used to do"
            ),
            "approval_posture": NotComputed(
                "resolved by the approval matrix from confidence against blast radius, neither of which this run has"
            ),
            "signals_that_fired": [sig.name for sig in signals if sig.holds],
        },
        tool_calls=[{**action, "executed": False} for action in actions],
        decision=(
            f"{len(actions)} action(s) shown as the shape RespondAgent would propose. None executed; no autonomy"
            f" tier and no approval posture determined — {SYNTHETIC_NOTICE}."
        ),
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Helpers — keep the stage functions readable above.
# ---------------------------------------------------------------------------


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _default_actions(s: Scenario) -> list[dict[str, Any]]:
    primary = next(iter(s.entities.values()), None)
    return [
        {"name": "case.create", "args": {"title": s.title, "severity": s.severity}},
        {
            "name": "user.suspend" if primary else "alert.acknowledge",
            "args": {"user": primary} if primary else {"reason": "no entity to act on"},
        },
        {"name": "case.notify", "args": {"channel": "slack", "audience": "soc-on-call"}},
    ]


# ---------------------------------------------------------------------------
# High-level orchestrator used by the CLI.
# ---------------------------------------------------------------------------


def run_investigation(scenario: Scenario, *, ledger: Ledger | None = None) -> Ledger:
    """Run the four-stage funnel against ``scenario`` and return the ledger.

    Args:
        scenario: The :class:`Scenario` to investigate.
        ledger: Optional pre-existing ledger to append to. If omitted,
            a fresh one is created.

    Returns:
        The populated :class:`Ledger`.
    """

    # NB: we use `is None` rather than `ledger or Ledger()` because
    # `Ledger.__len__` returns 0 for empty ledgers, which makes a fresh
    # `Ledger()` falsy under `or` and silently swaps in a throwaway
    # instance — the caller's ledger then never gets mutated.
    inv = Investigation(
        scenario=scenario,
        ledger=ledger if ledger is not None else Ledger(),
        narrator=EvidenceNarrator(),
    )
    return inv.run()
