"""The four-stage investigation funnel — Detect → Triage → Hunt → Respond.

This module is the simulator-equivalent of
[`services/agents/app/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/agents)
collapsed into one file. It exists so a reader can read the whole
funnel in 5 minutes and see exactly what every step does.

Each stage is implemented as a free function that takes the
:class:`Scenario` and the :class:`Ledger` (which it appends to). The
:class:`Investigation` class wires them up; :func:`run_investigation`
is the CLI's high-level entry point.

The "LLM" used here is :class:`DeterministicReasoner`, a tiny
template-driven stub. The real agents call out to OpenAI / Anthropic /
Ollama via LiteLLM with a guarded prompt contract — see
``services/agents/app/services/llm_safety.py``. The sandbox does not
make any network calls.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .ledger import Ledger
from .scenarios import Scenario


class DeterministicReasoner:
    """Deterministic, offline stand-in for the real LLM.

    Returns canned but contextual rationales keyed off the scenario's
    MITRE techniques. The output deliberately reads like a real LLM
    response (one sentence, present tense, references the evidence)
    so a buyer comparing the sandbox to the live demo can't tell the
    rendered ledger apart at a glance — except the latencies are
    smaller and the byte-stable output makes the demo reproducible.
    """

    _RATIONALES: dict[str, str] = {
        "T1078": "Authenticated session signals look legitimate at the protocol layer, but the geo pivot between sequential events is physically impossible — classic credential takeover.",
        "T1078.004": "Cloud account use without a paired federated-IDP factor and from an unrecognised ASN suggests the credential is being replayed from the attacker's environment.",
        "T1110": "Brute-force or password-spray pattern: the time-density of failed authentications exceeds the per-tenant Welford-online baseline by more than three standard deviations.",
        "T1566": "Phishing landed: the click happened inside the standard credential-harvest window from email delivery, and the destination domain registered less than 14 days ago.",
        "T1567": "Exfiltration over a web service: outbound volume to an uncategorised cloud endpoint dominates the host's egress for the hour and clusters with known dropbox-style staging.",
        "T1098": "Privilege escalation via account manipulation: a role-binding change happened outside the normal change-management window and the actor has no recent admin activity.",
        "T1496": "Resource hijacking signature: CPU saturation co-occurs with outbound mining-pool connections and the workload's parent isn't the orchestrator that normally spawns it.",
        "T1486": "Mass-file-write entropy matches the known LockBit signature; file-extension churn rate ≥ 80/sec across multiple directories.",
        "T1059": "Command-and-scripting interpreter ran a base64-decoded script that the host's allowlist would have blocked under the org's WDAC policy.",
        "T1552": "Credentials accessed in plaintext from a session-token cache that should have been encrypted-at-rest under the platform's KMS profile.",
        "T1555": "Credential store dump detected — the access pattern matches known infostealer behaviour against the OS-native keystore.",
        "T1071": "Application-layer C2 channel: the beacon interval is jittered around a 60-second mean with a constant-volume header, consistent with malleable-profile traffic.",
    }
    _GENERIC = "Behaviour pattern matches a known MITRE technique and exceeds the baseline confidence threshold."

    def explain(self, *, technique: str | None) -> str:
        if technique is None:
            return self._GENERIC
        # The real agents sometimes get a sub-technique (T1078.004) and
        # sometimes the parent (T1078); fall back to the parent if the
        # specific one isn't in the table.
        if technique in self._RATIONALES:
            return self._RATIONALES[technique]
        parent = technique.split(".", 1)[0]
        return self._RATIONALES.get(parent, self._GENERIC)


@dataclass
class Investigation:
    """One investigation run."""

    scenario: Scenario
    ledger: Ledger
    reasoner: DeterministicReasoner

    def run(self) -> Ledger:
        """Walk the four-stage funnel; populate the ledger."""

        _stage_detect(self.scenario, self.ledger, self.reasoner)
        _stage_triage(self.scenario, self.ledger, self.reasoner)
        _stage_hunt(self.scenario, self.ledger, self.reasoner)
        _stage_respond(self.scenario, self.ledger, self.reasoner)
        return self.ledger


# ---------------------------------------------------------------------------
# Stage 1 — Detect. "Did something happen?"
# ---------------------------------------------------------------------------

def _stage_detect(s: Scenario, ledger: Ledger, _r: DeterministicReasoner) -> None:
    t0 = time.perf_counter()
    ledger.append(
        agent="DetectAgent",
        funnel_stage="detect",
        action="Match incoming events against detection ruleset",
        rationale=(
            f"{len(s.events)} event(s) ingested; matched detection ruleset"
            f" against MITRE techniques {', '.join(s.mitre_techniques) or '(none)'}."
        ),
        evidence={
            "events_ingested": len(s.events),
            "mitre_techniques": s.mitre_techniques,
            "severity_at_intake": s.severity,
            **{f"entity:{k}": v for k, v in s.entities.items()},
        },
        tool_calls=[
            {"name": "rules.match", "args": {"rule_count": "800+", "technique_set": s.mitre_techniques}},
            {"name": "fusion.score", "args": {"window_minutes": 15}},
        ],
        decision=f"Open alert at severity={s.severity}",
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 2 — Triage. "Is it real, and how confident are we?"
# ---------------------------------------------------------------------------

def _stage_triage(s: Scenario, ledger: Ledger, r: DeterministicReasoner) -> None:
    t0 = time.perf_counter()
    primary_technique = s.mitre_techniques[0] if s.mitre_techniques else None
    rationale = r.explain(technique=primary_technique)

    confidence = _confidence_band(severity=s.severity, technique_count=len(s.mitre_techniques))
    ledger.append(
        agent="TriageAgent",
        funnel_stage="triage",
        action="Score alert confidence + cross-reference with prior cases",
        rationale=rationale,
        evidence={
            "primary_technique": primary_technique,
            "related_cases_30d": _synthetic_related_cases(s.id),
            "rba_entity_risk": _synthetic_entity_risk(s.entities),
        },
        tool_calls=[
            {"name": "qdrant.semantic_search", "args": {"k": 5, "collection": "cases"}},
            {"name": "graph.neighbours", "args": {"depth": 2}},
        ],
        decision=f"Confidence: {confidence['band']} ({confidence['score']}/100)",
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 3 — Hunt. "Did the same actor touch anything else?"
# ---------------------------------------------------------------------------

def _stage_hunt(s: Scenario, ledger: Ledger, _r: DeterministicReasoner) -> None:
    t0 = time.perf_counter()
    technique = s.mitre_techniques[0] if s.mitre_techniques else "T0000"

    ledger.append(
        agent="HuntAgent",
        funnel_stage="hunt",
        action="Pivot from primary entity across the data lake",
        rationale=(
            "Sweep for the primary entity across the last 24 h of warm-tier"
            f" events; correlate against MITRE technique {technique}."
        ),
        evidence={
            "pivot_entities": list(s.entities.values()),
            "lookback_hours": 24,
            "hunt_query_languages": ["ES|QL", "SPL", "KQL"],
            "matches_found": _synthetic_hunt_matches(s.id),
        },
        tool_calls=[
            {"name": "nl_to_query.translate", "args": {"hypothesis": f"any activity by {next(iter(s.entities.values()), 'actor')} in last 24h"}},
            {"name": "lake.query", "args": {"language": "ES|QL", "row_cap": 1000}},
        ],
        decision="Pivot complete; no additional compromised entities surfaced beyond the alert payload.",
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Stage 4 — Respond. "What do we do about it, and at what blast radius?"
# ---------------------------------------------------------------------------

def _stage_respond(s: Scenario, ledger: Ledger, _r: DeterministicReasoner) -> None:
    t0 = time.perf_counter()
    actions = s.recommended_actions or _default_actions(s)
    ledger.append(
        agent="RespondAgent",
        funnel_stage="respond",
        action="Propose graduated response under blast-radius gate",
        rationale=(
            "Recommend the least-invasive containment that closes the"
            " confidence-weighted risk; escalate only with human"
            " approval for high-blast-radius actions (per L0–L4 model)."
        ),
        evidence={
            "automation_maturity_tier": _automation_tier(s.severity),
            "blast_radius_gate": "human_approval_required" if s.severity in ("high", "critical") else "auto_below_high",
            "recommended_action_count": len(actions),
        },
        tool_calls=actions,
        decision=(
            f"{len(actions)} action(s) proposed; "
            + (
                "awaiting analyst approval before execution."
                if s.severity in ("high", "critical")
                else "auto-execute eligible under current L0–L4 tier."
            )
        ),
        latency_ms=_ms(t0),
    )


# ---------------------------------------------------------------------------
# Helpers — keep the stage functions readable above.
# ---------------------------------------------------------------------------

def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _confidence_band(*, severity: str, technique_count: int) -> dict[str, Any]:
    base = {"info": 30, "low": 45, "medium": 60, "high": 75, "critical": 88}[severity]
    score = min(100, base + 4 * technique_count)
    band = "low" if score < 50 else "medium" if score < 75 else "high"
    return {"score": score, "band": band}


def _synthetic_related_cases(sid: str) -> int:
    # Stable per-scenario but believable. Production fetches from
    # Qdrant; we just hash the id.
    return abs(hash(sid)) % 7


def _synthetic_entity_risk(entities: dict[str, str]) -> dict[str, int]:
    # Risk score 0-100 per entity. Deterministic.
    return {k: 30 + (abs(hash(v)) % 60) for k, v in entities.items()}


def _synthetic_hunt_matches(sid: str) -> int:
    return abs(hash(f"hunt:{sid}")) % 4


def _automation_tier(severity: str) -> str:
    return {
        "info": "L4 — fully autonomous closure",
        "low": "L3 — auto-respond with audit",
        "medium": "L2 — proposed actions, human confirms",
        "high": "L1 — recommendations only, human executes",
        "critical": "L1 — recommendations only, human executes",
    }[severity]


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
        reasoner=DeterministicReasoner(),
    )
    return inv.run()
