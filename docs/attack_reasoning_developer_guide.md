# MITRE ATT&CK-Based Attack Reasoning — Developer Guide (v0)

## Status

**This is a v0 ("seeded heuristics") release.** The five-agent LangGraph pipeline is real, the MITRE ATT&CK corpus loader (`app.tools.mitre_full`) is real, and every agent honestly reports `found = false` when a technique or actor is not in the loaded corpus. But two pieces of intelligence inside the engine are intentionally small, hardcoded tables that ship as the v0 baseline:

1. **Next-technique progression** (`_PROGRESSION_MAP` in `attack_reasoner.py`) — currently four entries (`T1566 → T1059/T1078`, `T1059 → T1071/T1003`, `T1078 → T1003/T1021`, `T1003 → T1021/T1041`).
2. **Technique → actor hint table** (`_TECHNIQUE_ACTOR_HINT` in `attack_reasoner.py`) — currently four entries (`T1059 → G0016`, `T1566 → G0050`, `T1078 → G0007`, `T1003 → G0009`).

Both tables are gated behind clear `# v0 STUB` comments so they are easy to find and replace. The intended next step is to walk ATT&CK STIX relationship objects (`uses`, `subtechnique-of`, etc.) which the corpus loader already provides — see "Replacing the v0 stubs" below.

## Architecture

The system is a five-stage LangGraph workflow over a single Pydantic state object (`AttackReasoningState`):

| Stage | Class | Method | What it does |
|-------|-------|--------|--------------|
| 1 | `TechniqueAnalyzer` | `analyze_indicators` | Keyword search the MITRE corpus using `description / context / name` fields on each indicator. Records identified techniques + per-technique confidence scores. |
| 2 | `PathPredictor` | `predict_paths` | Calls `predict_next_techniques()` against the v0 progression map. Single source of truth shared with the REST endpoint. |
| 3 | `MitigationAdvisor` | `recommend_mitigations` | Pulls mitigations directly from the loaded corpus for every identified or predicted technique. Skips techniques the corpus does not have. |
| 4 | `ActorProfiler` | `profile_actors` | Scores candidate actors via `_TECHNIQUE_ACTOR_HINT`, then enriches with `get_actor()`. Skips hint-table entries when the actor isn't in the corpus rather than fabricating a profile. |
| 5 | `TacticalAdvisor` | `provide_recommendations` | Generates kill-chain phase recommendations, mitigation recommendations, and high-confidence-actor recommendations. Deduplicates with `dict.fromkeys` to keep output deterministic. |

## State

```python
class AttackReasoningState(BaseModel):
    incident_id: Optional[str] = None
    observed_indicators: List[Dict[str, Any]] = []
    identified_techniques: List[Dict[str, Any]] = []
    predicted_techniques: List[Dict[str, Any]] = []
    kill_chain_analysis: Dict[str, List[str]] = {}
    threat_actors: List[Dict[str, Any]] = []
    mitigations: List[Dict[str, Any]] = []
    tactical_recommendations: List[str] = []
    confidence_scores: Dict[str, float] = {}
    status: str = "running"
```

`status` becomes `"completed"` when `TacticalAdvisor` finishes, or `"failed"` if `reason_about_attack` catches an unhandled exception (the failure message is appended to `tactical_recommendations`).

## API endpoints

| Method | Path | Body / param | Description |
|--------|------|--------------|-------------|
| POST | `/api/v1/attack-reasoning/analyze` | `{ incident_id, observed_indicators }` | Run the full five-stage workflow. |
| POST | `/api/v1/attack-reasoning/predict-next-techniques` | `{ identified_techniques: [str] }` | Stage 2 only. Uses the same `_PROGRESSION_MAP` as the LangGraph node. |
| GET | `/api/v1/attack-reasoning/technique/{technique_id}` | path | Returns `{ "technique": <corpus details> }` or 404. |
| GET | `/api/v1/attack-reasoning/actor/{actor_id}` | path | Returns `{ "actor": <details>, "techniques": [...] }` or 404. Use MITRE actor IDs (e.g. `G0016`), not display names like `APT29`. |

Both POST endpoints are validated by Pydantic request models — malformed bodies return HTTP 422.

### Example

```bash
curl -X POST http://localhost:8000/api/v1/attack-reasoning/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-2026-001",
    "observed_indicators": [
      {"type": "process", "value": "powershell.exe",
       "context": "command and scripting interpreter execution"}
    ]
  }'
```

## Programmatic usage

```python
from app.attack_reasoning.attack_reasoner import (
    reason_about_attack,
    predict_next_techniques,
)

# Full workflow
state = await reason_about_attack(
    "INC-2026-001",
    [{"type": "process", "value": "powershell.exe",
      "context": "command and scripting interpreter execution"}],
)
print(state.identified_techniques)
print(state.tactical_recommendations)

# Just the v0 path predictor
print(predict_next_techniques(["T1566"]))
# -> [{'id': 'T1059', ...}, {'id': 'T1078', ...}]
```

## Replacing the v0 stubs

Both stub tables live next to each other near the top of `attack_reasoner.py` so they're trivial to find and swap:

- **Path prediction:** Replace `_PROGRESSION_MAP` (and adjust `predict_next_techniques`) to walk ATT&CK relationship objects from the loaded corpus. The corpus loader already pulls `relationship` STIX objects — exposing a `get_related_techniques(technique_id, kind="commonly-followed-by")` helper from `mitre_full` is the cleanest seam.
- **Actor profiling:** Replace `_TECHNIQUE_ACTOR_HINT` with a query against the actor index already built by `mitre_full` (each actor STIX object lists the techniques it uses). The shape returned by `ActorProfiler` does not need to change — just the input lookup.

When you replace either table, please:

1. Keep `predict_next_techniques()` as the single public entry point so the REST endpoint and the LangGraph node never drift.
2. Keep the `# v0 STUB` markers gone — don't leave fallback hardcoded data behind.
3. Update this guide to describe the new mechanism honestly.

## Testing

```bash
cd services/agents
pytest tests/test_attack_reasoning.py        # agent-level behavioral tests
pytest tests/test_attack_reasoning_api.py    # HTTP integration tests
```

The unit tests assert the v0 progression map's behavior directly (`T1566 → {T1059, T1078}`), so any regression that breaks the contract surfaces immediately. The API tests reject `500` responses and only accept `200` or `404` for lookup endpoints — so silent crashes can't sneak through.

## Limitations and known gaps

- **No learned model.** Path prediction and actor scoring are heuristics, not ML.
- **Keyword search only.** `TechniqueAnalyzer` does free-text matching against the corpus — it doesn't use semantic embeddings even when Qdrant is configured. Adding semantic recall is a natural next step.
- **No write-back to `state.case`.** Findings produced here are returned to the caller but not persisted; the calling investigator is responsible for storing them.
- **Confidence is not calibrated.** The 0.6 / 0.7 thresholds and the `0.6 + 0.1 * len(tactic_names)` heuristic are placeholders.

## Further reading

- [MITRE ATT&CK](https://attack.mitre.org/)
- [LangGraph](https://langchain-ai.github.io/langgraph/)
- [AiSOC architecture](../README.md)
