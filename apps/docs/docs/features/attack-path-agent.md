---
sidebar_position: 3
title: Attack-path investigation agent
description: How AiSOC's investigation graph adds an attack-path step that walks the knowledge graph, scores blast radius, and proposes containment actions on the highest-value pivots.
---

# Attack-path investigation agent

When the investigation agent finishes its analysis of a case, it has a story but not a map. The attack-path agent takes the case, walks the knowledge graph, finds the chain of entities that links the alert to its blast radius, and turns that into concrete containment proposals.

## Where it sits in the workflow

The orchestrator graph (`services/agents/app/graph/workflow.py`) runs:

```
ingest → triage → investigation → attack_path → END
```

The attack-path node runs *after* the investigation agent, so it inherits the case's findings and can layer graph-derived insights on top. It is purely additive: if the graph service has nothing to say (no path, no neighbors), the node records that and exits without modifying the proposed-action queue.

## What it does, step by step

1. **Calls the graph API.** `GET /api/v1/graph/attack-path/{case_id}` returns the path of entities and relationships that the case touches, plus a MITRE tactic chain extracted from the relationship types.
2. **Summarizes the graph.** Records node counts by type (user, host, asset, ip, etc.), edge counts, and the tactic chain into `state.threat_intel["attack_path"]`. This becomes part of the case's durable record.
3. **Scores blast radius for pivot entities.** For every host or service-account on the path, the agent calls `GET /api/v1/graph/blast-radius/{type}/{id}` to compute how many downstream entities depend on it. High blast radius means a single containment action has high impact.
4. **Proposes isolation actions.** For the top pivot entities (those above a configurable blast-radius threshold), the agent emits a `ProposedAction` with type `isolate_host` (or the equivalent for the entity type), an `ActionRisk` band, and the parameters needed to execute — `entity_type`, `entity_id`, `blast_radius_score`.

These proposed actions land in the same queue as everything else the investigation produced, so the existing approval flow (auto-approve for low-risk, human-in-the-loop for high-risk) governs whether they execute.

## Why the graph and not just rules

Three reasons the agent reads from the graph instead of running rules over the raw alert:

1. **Lateral movement is a graph problem.** A SIEM rule can tell you a user authenticated from a new IP. Only a graph can tell you that user has access to seven critical hosts, three of which talk to the database tier.
2. **Blast radius is a graph property.** You can't compute it by counting log lines. You compute it by walking edges.
3. **The same graph powers the SOC analyst's UI.** The agent and the human are looking at the same data structure, which means an analyst can audit *why* the agent proposed a specific isolation in seconds, not minutes.

## Output contract

Inside `InvestigationState`, the agent adds:

- One or more `Finding` entries summarizing the path and the high-blast pivots.
- Zero or more `ProposedAction` entries with `action_type="isolate_host"` (or the appropriate verb for the entity type) and a `risk` band.
- A compact summary at `state.threat_intel["attack_path"]`:

```json
{
  "node_count": 12,
  "edge_count": 18,
  "tactic_chain": ["initial_access", "credential_access", "lateral_movement"],
  "high_blast_pivots": [
    {
      "label": "Host",
      "name": "build-server-01",
      "entity_type": "host",
      "entity_id": "host-1f9...",
      "blast_radius_score": 47
    }
  ]
}
```

Downstream consumers (the case timeline, the response queue, the analytics layer) read from this summary rather than re-walking the graph.

## When it stays silent

The agent records nothing in the proposed-action queue if:

- The graph service returned 404 (no path discoverable for this case yet — common for very new cases or low-fidelity alerts).
- All pivot blast-radius scores are below the threshold.
- The case has no entities to walk from.

Silence is correct behavior. The agent is not required to fire on every case.

## Where it lives in the code

- Agent entry point: `services/agents/app/agents/attack_path_agent.py`
- Graph client tool: `services/agents/app/tools/graph.py`
- LangGraph wiring: `services/agents/app/graph/workflow.py`
- Tests: `services/agents/tests/test_attack_path_agent.py`
- Underlying graph endpoints: `services/api/app/api/v1/endpoints/graph.py`
- Graph service: `services/api/app/services/graph_service.py`
