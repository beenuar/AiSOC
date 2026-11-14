"""Swarm-vs-single eval gate (v8 P3).

Publishes both numbers and asserts the swarm beats single-agent mode on the
investigation-completeness macro by >= 10% while staying under a cost ceiling.

HONESTY: `investigation_completeness` here is a **substrate self-consistency**
macro — the fraction of an incident's relevant hypotheses that were considered.
A single agent pursues only its top prior; the swarm considers up to five, so on
genuinely multi-hypothesis incidents its completeness is structurally higher.
This is NOT a live-LLM accuracy claim (same framing as the rest of the eval
harness). The synthetic incident set is labelled synthetic.
"""

from __future__ import annotations

from app.swarm.debate import hold_debate, investigation_completeness
from app.swarm.swarm import DEFAULT_PER_AGENT_TOKEN_BUDGET, run_swarm_sync

# Synthetic multi-hypothesis incidents: each lists the hypotheses a thorough
# analyst would consider ("relevant"). Deterministic; clearly synthetic.
SYNTHETIC_INCIDENTS = [
    {
        "signal": {
            "alert_summary": "Ransomware encryption + shadow copy deletion, plus SMB lateral movement and mimikatz",
            "raw": "lockbit .lockbit vssadmin credential dump psexec",
            "techniques": ["T1486", "T1490", "T1021.002", "T1003"],
        },
        "relevant": {"ransomware_staging", "lateral_movement"},
    },
    {
        "signal": {
            "alert_summary": "Large off-hours download by svc-backup then exfiltration over dns tunneling with c2 beacon",
            "raw": "exfiltration dns tunneling cobalt strike beacon large file off-hours",
            "techniques": ["T1048", "T1071.004", "T1567"],
        },
        "relevant": {"insider_exfil", "c2_beacon"},
    },
    {
        "signal": {
            "alert_summary": "Shadow-copy deletion and beacon jitter to command and control after credential dump",
            "raw": "vssadmin ransom note c2 beacon jitter mimikatz lateral movement smb",
            "techniques": ["T1486", "T1071", "T1003", "T1021"],
        },
        "relevant": {"ransomware_staging", "c2_beacon", "lateral_movement"},
    },
]

MIN_LIFT = 0.10  # swarm must beat single by >= 10% (absolute) on completeness
COST_CEILING_TOKENS = 5 * DEFAULT_PER_AGENT_TOKEN_BUDGET  # <= 5 agents * budget


def _single_agent_considered(signal: dict) -> list[str]:
    """Single-agent mode pursues only the single top-scoring hypothesis."""
    results = run_swarm_sync(signal, max_agents=5)
    top = max(results, key=lambda r: r.support_score)
    return [top.key]


def _swarm_considered(signal: dict) -> tuple[list[str], int]:
    results = run_swarm_sync(signal, max_agents=5)
    hold_debate(results)  # exercise the debate node
    # The swarm explores the full hypothesis space it ran — that breadth is
    # exactly what raises investigation completeness over single-agent mode.
    considered = [r.key for r in results]
    tokens = sum(r.tokens_spent for r in results)
    return considered, tokens


def test_swarm_beats_single_on_completeness_under_cost_ceiling():
    single_scores: list[float] = []
    swarm_scores: list[float] = []
    max_tokens = 0

    for incident in SYNTHETIC_INCIDENTS:
        signal = incident["signal"]
        relevant = incident["relevant"]

        single = investigation_completeness(_single_agent_considered(signal), relevant)
        considered, tokens = _swarm_considered(signal)
        swarm = investigation_completeness(considered, relevant)

        single_scores.append(single)
        swarm_scores.append(swarm)
        max_tokens = max(max_tokens, tokens)

    single_macro = sum(single_scores) / len(single_scores)
    swarm_macro = sum(swarm_scores) / len(swarm_scores)
    lift = swarm_macro - single_macro

    # Publish both numbers (visible in CI logs).
    print(f"[swarm-vs-single] single={single_macro:.3f} swarm={swarm_macro:.3f} lift={lift:+.3f} max_tokens={max_tokens}")

    assert swarm_macro > single_macro, "swarm must not regress vs single-agent"
    assert lift >= MIN_LIFT, f"swarm lift {lift:.3f} below required {MIN_LIFT}"
    assert max_tokens <= COST_CEILING_TOKENS, f"swarm tokens {max_tokens} exceed ceiling {COST_CEILING_TOKENS}"
