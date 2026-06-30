---
title: The four AiSOC agents
sidebar_label: Four agents
sidebar_position: 2
---

# The four AiSOC agents

AiSOC ships with **exactly four** named agents, one per stage of how a SOC
team actually thinks about an incident:

| Agent       | Role in the SOC pipeline                                     |
|-------------|--------------------------------------------------------------|
| **Detect**  | Fuse raw signals from connected sources into incidents       |
| **Triage**  | Decide *what* matters and *how urgent* it is                 |
| **Hunt**    | Ask new questions across the data, not just the alerts you got |
| **Respond** | Plan and (with approval) execute containment + recovery      |

The number four is deliberate. The internal codebase has more than a dozen
agent modules, and each of those modules is still a healthy unit of code —
but the *public* surface is just these four. Everything else is a
**capability** of one of them.

> **Sub-agents are capabilities of Triage, not first-class agents.**
> Phishing, identity, cloud, and insider analysis are routed through
> `TriageAgent`. They live in `app.agents.{phishing,identity,cloud,insider_threat}_agent`
> internally, but they're never promoted to the four-agent surface in
> docs, the UI, the landing page, or the SDK. If you find yourself writing
> "the five AiSOC agents", something has drifted.

---

## Detect — fusion, entity-risk, and native detections

`DetectAgent` wraps the detection plane: rule-based, ML-scored, and
graph-aware signals get deduplicated, correlated, and labelled before they
ever reach a human.

| Capability         | Where it lives                                                                |
|--------------------|-------------------------------------------------------------------------------|
| Fusion             | `services/fusion/app/services/fusion_engine.py`                               |
| Entity-risk (RBA)  | `services/fusion/app/services/entity_risk.py` (4-tier severity ladder)        |
| Native detections  | `detections/` corpus + `services/api/app/services/detection_engine.py`        |

> **Status: in flight.** The branded class exists today and self-describes
> through `DetectAgent.describe()`, but a live `DetectAgent.process(...)`
> entry point that drives the cross-service fusion pipeline from inside
> the agents service is in progress under T2.5. Until it ships, callers
> use the fusion service's HTTP API directly.

```python
from app.agents import DetectAgent

DetectAgent.describe()
# {
#   "name": "Detect",
#   "description": "...",
#   "capabilities": ["fusion", "entity_risk", "native_detections"],
#   "internal_modules": [...]
# }
```

---

## Triage — first responder + four sub-capabilities

`TriageAgent` is the first agent every alert meets.

It runs the LLM-based auto-triage classifier first
(`run_auto_triage`): high-confidence false-positive or benign verdicts
auto-close the alert; everything else escalates into the right
**capability** based on the alert payload.

```python
from app.agents import TriageAgent

await TriageAgent.auto_triage(state)            # LLM-based classification
await TriageAgent.heuristic_triage(state)       # offline / air-gapped path

# Capability dispatch — sub-agents are addressed by name, not by class:
await TriageAgent.analyse(state, capability="phishing")
await TriageAgent.analyse(state, capability="identity")
await TriageAgent.analyse(state, capability="cloud")
await TriageAgent.analyse(state, capability="insider")
```

| Capability   | Looks for                                                              | Internal module                              |
|--------------|------------------------------------------------------------------------|----------------------------------------------|
| `phishing`   | URL/sender/header/attachment indicators in email-style alerts           | `app.agents.phishing_agent`                  |
| `identity`   | Impossible travel, brute-force, MFA bypass, privilege escalation       | `app.agents.identity_agent`                  |
| `cloud`      | Storage exposure, IAM anomalies, infrastructure drift                  | `app.agents.cloud_agent`                     |
| `insider`    | Exfiltration, off-hours access, USB usage, personal-account egress     | `app.agents.insider_threat_agent`            |

The capability registry is the source of truth — `TriageAgent.capabilities`
is what the docs site, the onboarding tour, and the eval harness all
introspect. New capabilities go through it; nothing new is added to the
top-level four agents.

---

## Hunt — Hunt-as-Code engine + NL hunt surface

`HuntAgent` wires together the two ways an analyst issues a hunt today:

* **Hunt-as-Code** — YAML hypotheses in `hunts/`, loaded by
  `app.hunt.HuntCorpus`, scheduled by `HuntScheduler`, matched by
  `HuntEngine`. Each match is a first-class artefact alongside the
  Investigation Ledger.
* **Natural-language queries** — `app.nl_query.translate()` parses an
  English question into a structured intermediate representation and
  renders ES|QL, KQL, and SPL simultaneously. The translator is
  deterministic by default so the air-gapped story stays intact; an
  optional LLM enhancement path layers on top with grammar fall-backs.

```python
from app.agents import HuntAgent

# Hunt-as-Code
engine = HuntAgent.engine()                    # → app.hunt.HuntEngine
corpus = HuntAgent.corpus()                    # → loaded HuntCorpus

# Natural-language hunt
result = HuntAgent.translate(
    "show me failed logins from 10.0.0.1 in the last 2 hours"
)
result.esql, result.kql, result.spl, result.explanation
```

---

## Respond — plan, gate, execute

`RespondAgent` builds the **containment → eradication → recovery** plan.
Plans are generated dry-run by default; they only become real actions
once they're promoted through the SOAR exec endpoints in
`services/api/app/api/v1/endpoints/actions.py` or approved via ChatOps in
`services/slack-bot/`. Autonomy thresholds gate every promotion (e.g.
`block_ip ≥ 0.90`, `close_alert ≥ 0.60`, configurable per-tenant).

```python
from app.agents import RespondAgent

plan = await RespondAgent.plan(state_dict)
# Plan ships with:
#   recommended_actions[]   — prioritised, with risk + rationale
#   containment_steps[]
#   eradication_steps[]
#   recovery_steps[]
#   estimated_effort_hours
#   risk_level              — low | medium | high | critical
#   dry_run                 — always True from the planner
```

The Investigation Ledger captures every prompt, tool call, and decision
the planner made so the response is replayable and auditable end-to-end.

---

## Back-compat aliases

Internal callers (and any external integration that already imports the
old names) continue to work. The aliases resolve to the new façade:

| Legacy import                | Resolves to                               |
|------------------------------|-------------------------------------------|
| `AutoTriageAgent`            | `TriageAgent` (subclass)                  |
| `PhishingAgent`              | Capability shim → `TriageAgent.capabilities["phishing"]` |
| `IdentityAgent`              | Capability shim → `TriageAgent.capabilities["identity"]` |
| `CloudAgent`                 | Capability shim → `TriageAgent.capabilities["cloud"]`    |
| `InsiderThreatAgent`         | Capability shim → `TriageAgent.capabilities["insider"]`  |
| `ResponderAgent`             | `RespondAgent` (subclass)                 |

New code should import the four branded classes directly. Aliases will
remain importable for the v8.x line; deprecation timing tracks in
`docs/roadmap/v8-progress.md`.

---

## Why exactly four

The buyer-facing pitch — and the internal benchmark gates — assume the
public agent count is fixed. Adding a fifth name forces every surface
that lists agents (landing page, hero copy, docs, sales deck, eval
harness scoreboard, MCP tool descriptions) to update in lock-step. By
keeping the four-agent contract enforced by a test
(`services/agents/tests/test_four_agent_facade.py`), CI fails the moment
the surface drifts — a fifth `*Agent` symbol added to `app.agents.__all__`
without explicit intent will trip the gate.

Capability count, by contrast, is allowed to grow. New analysis
specialisations land as new entries in `TriageAgent.capabilities` (or as
new helpers under `HuntAgent` / `RespondAgent`) without touching the
top-level taxonomy.
