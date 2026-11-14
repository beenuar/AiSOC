# Cyble AiSOC — Agent Topology & Architecture Deep Dive

**Version:** 2.0 | **Date:** May 2026
**Last updated:** 2026-05-20 (v8.0 four-agent façade, LangGraph orchestrator, three-tier memory, L0–L4 maturity model)
**Production version:** v7.3.1 (github.com/beenuar/AiSOC)
**Part of:** [cyble-aisoc-plan.md](../cyble-aisoc-plan.md)

---

## Changelog

| Date | Change |
|---|---|
| 2026-05-20 | DetectAgent.process() wired to FusionEngine via cross-service HTTP (PR #198) |
| 2026-05-19 | v8.0 four-agent façade shipped: DetectAgent, TriageAgent, HuntAgent, RespondAgent |
| 2026-05-19 | L0–L4 automation maturity model added |
| 2026-05-19 | Three-tier agent memory: session / working / institutional |
| 2026-05-19 | HuntAgent natural-language surface (English → ES|QL / SPL / KQL) |
| 2026-05-19 | LangGraph investigator (~600-line state machine) |
| 2026-04 | Initial agent topology document (v1.0, five-agent prototype) |

---

## 1. Full Agent Topology Diagram

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                         CYBLE AiSOC AGENT MESH v8.0                             ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║   EXTERNAL SOURCES                                                                ║
║   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐             ║
║   │  EDR/XDR   │   │    SIEM    │   │  Cloud APIs│   │  Identity  │             ║
║   │ (50 vendors│   │            │   │ (AWS/Azure │   │ (Okta/AD/  │             ║
║   │  wave-1/2) │   │            │   │  GCP/GH)   │   │  EntraID)  │             ║
║   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘             ║
║         └─────────────────┴─────────────────┴───────────────┘                    ║
║                                   │ Connectors (Python)                           ║
║                           ┌───────▼────────┐                                     ║
║                           │  Ingest (Go)   │ OCSF normalization                  ║
║                           │  Enrichment    │ IOC + Shodan + UEBA + Cyble CTI     ║
║                           └───────┬────────┘                                     ║
║                                   │                                               ║
║                     ┌─────────────▼──────────────┐                               ║
║                     │       Apache Kafka          │ ◄── event spine               ║
║                     │   (event bus, pub/sub)      │                               ║
║                     └─────┬──────────────────┬────┘                               ║
║                           │                  │                                    ║
║              ┌────────────▼──────┐    ┌──────▼────────────┐                     ║
║              │  FusionEngine     │    │  Rule Engine       │                     ║
║              │  (Python · ML)    │    │  Sigma · YARA      │                     ║
║              │  Dedup · Scoring  │    │  KQL · OCSF-native │                     ║
║              │  ConfidenceScorer │    │  (eval() removed;  │                     ║
║              └────────┬──────────┘    │  AST-only parser)  │                     ║
║                        │              └──────┬─────────────┘                     ║
║                        │                     │                                    ║
║                        └──────────┬──────────┘                                   ║
║                                   │                                               ║
║                 ╔═════════════════▼══════════════════╗                           ║
║                 ║     AI AGENT MESH (LangGraph)      ║                           ║
║                 ╠════════════════════════════════════╣                           ║
║                 ║                                    ║                           ║
║                 ║  ┌─────────────────────────────┐  ║                           ║
║                 ║  │  DetectAgent (NEW v8.0)      │  ║                           ║
║                 ║  │  Raw alert classification    │  ║                           ║
║                 ║  │  → routes to FusionEngine    │  ║                           ║
║                 ║  │    via HTTP (PR #198)        │  ║                           ║
║                 ║  └──────────────┬──────────────┘  ║                           ║
║                 ║                 │                  ║                           ║
║                 ║  ┌──────────────▼──────────────┐  ║                           ║
║                 ║  │  TriageAgent (NEW v8.0)      │  ║                           ║
║                 ║  │  Tier-1 verdict:             │  ║                           ║
║                 ║  │  BENIGN / SUSPICIOUS /       │  ║                           ║
║                 ║  │  MALICIOUS / ESCALATE        │  ║                           ║
║                 ║  └──────────────┬──────────────┘  ║                           ║
║                 ║                 │ escalate         ║                           ║
║                 ║  ┌──────────────▼──────────────┐  ║                           ║
║                 ║  │  Investigator (LangGraph)    │  ║                           ║
║                 ║  │  ~600-line state machine     │  ║                           ║
║                 ║  │  Evidence: SIEM timeline,    │  ║                           ║
║                 ║  │  EDR telemetry, threat intel,│  ║                           ║
║                 ║  │  attack-chain → Neo4j        │  ║                           ║
║                 ║  └──────────────┬──────────────┘  ║                           ║
║                 ║                 │                  ║                           ║
║                 ║         HITL GATEWAY               ║                           ║
║                 ║         (Console / Slack /         ║                           ║
║                 ║          Teams / Responder PWA)    ║                           ║
║                 ║                 │ approved         ║                           ║
║                 ║  ┌──────────────▼──────────────┐  ║                           ║
║                 ║  │  RespondAgent (NEW v8.0)     │  ║                           ║
║                 ║  │  Blast-radius aware          │  ║                           ║
║                 ║  │  L0–L4 maturity gated        │  ║                           ║
║                 ║  │  Containment playbooks       │  ║                           ║
║                 ║  └──────────────┬──────────────┘  ║                           ║
║                 ║                 │                  ║                           ║
║                 ║  ┌──────────────▼──────────────┐  ║                           ║
║                 ║  │  ReporterAgent               │  ║                           ║
║                 ║  │  Narrative + Compliance      │  ║                           ║
║                 ║  │  artifacts + Memory write    │  ║                           ║
║                 ║  └─────────────────────────────┘  ║                           ║
║                 ║                                    ║                           ║
║                 ║  ┌─────────────────────────────┐  ║                           ║
║                 ║  │  HuntAgent (out-of-band)     │  ║                           ║
║                 ║  │  English → ES|QL/SPL/KQL     │  ║                           ║
║                 ║  │  Never writes raw queries    │  ║                           ║
║                 ║  │  Schedule + save hunts       │  ║                           ║
║                 ║  └─────────────────────────────┘  ║                           ║
║                 ╚════════════════════════════════════╝                           ║
║                                                                                   ║
║   THREE-TIER AGENT MEMORY                                                         ║
║   ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────────┐   ║
║   │ Session (L1)    │  │ Working (L2)    │  │ Institutional (L3)           │   ║
║   │ In-process LRU  │  │ Redis 24h TTL   │  │ PostgreSQL + pgvector         │   ║
║   │ Hot lookups     │  │ Cross-call state│  │ Permanent episodic recall     │   ║
║   └─────────────────┘  └─────────────────┘  │ Similarity search + RAG      │   ║
║                                              └──────────────────────────────┘   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. Agent Specifications

### 2.1 DetectAgent (v8.0, added 2026-05-19)

**Replaces:** Direct ingest path (alerts previously went straight to TriageAgent)

**Responsibility:** Receives raw alerts from any source (Kafka consumer, REST ingest, osquery). Routes every alert through FusionEngine via cross-service HTTP (`POST /process` on `services/fusion`) before handing off downstream. Ensures dedup, ML scoring, confidence labelling, and RBA apply uniformly regardless of how the alert arrived.

**Wiring added (2026-05-20, PR #198):** `DetectAgent.process()` now calls `FusionEngine` via `httpx.AsyncClient`. If the fusion service is unreachable, the agent falls back to pass-through with a `fusion_bypassed: true` flag so analysts know the alert hasn't been ML-scored.

**Allowed tools:** `ingest.classify_alert`, `fusion.process_alert`, `ioc.enrich`

**Output contract:**
```python
class DetectOutput(BaseModel):
    alert_id: str
    fusion_score: float          # 0.0–1.0 from FusionEngine
    confidence: int              # 0–100 ConfidenceScorer output
    severity: Literal["info","low","medium","high","critical"]
    fusion_bypassed: bool        # true if FusionEngine unreachable
    handoff: Literal["TriageAgent"]
```

---

### 2.2 TriageAgent (v8.0 rebrand; previously TriagerAgent)

**Responsibility:** Tier-1 classification using alert context + FusionEngine scores. Returns a verdict without calling external systems beyond a single IOC reputation check. Target p95 latency: <15 s.

**Verdicts:** `BENIGN` (close silently) · `FP_CANDIDATE` (analyst review) · `SUSPICIOUS` (escalate to Investigator) · `MALICIOUS` (fast-track Investigator + RespondAgent)

**Allowed tools:** `siem.get_raw_events`, `edr.get_process_tree`, `cti.ioc_lookup`, `idp.get_user_risk`

**Output contract:**
```python
class TriageOutput(BaseModel):
    verdict: Literal["BENIGN","FP_CANDIDATE","SUSPICIOUS","MALICIOUS"]
    confidence: int              # 0–100
    evidence_summary: str
    mitre_techniques: list[str]  # e.g. ["T1059.001", "T1566.001"]
    handoff: Literal["close","HITL","InvestigatorNode"] | None
```

---

### 2.3 Investigator (LangGraph state machine)

**Responsibility:** Multi-step evidence gathering. The most complex agent — approximately 600 lines of LangGraph state machine code with four parallel tool-call branches.

**State nodes:**
1. `timeline_query` — pulls 72-hour SIEM event window
2. `process_tree` — full process ancestry from EDR
3. `lateral_movement_check` — graph query to Neo4j for adjacent hosts
4. `threat_intel_enrich` — Cyble CTI + MISP + OTX enrichment
5. `user_risk_assess` — UEBA baseline deviation
6. `attack_chain_build` — writes ranked attack-chain timeline to Neo4j
7. `investigation_complete` — emits `InvestigationReport`

**Max iterations:** 12 steps (hard cap; soft warning at 8)

**Allowed tools:** `siem.query_spl`, `siem.timeline_query`, `edr.get_process_tree`, `edr.get_file_events`, `edr.get_network_connections`, `cti.ioc_lookup`, `cti.darkweb_search`, `cti.asm_lookup`, `neo4j.query`, `ueba.get_baseline`, `idp.get_user_sessions`

---

### 2.4 RespondAgent (v8.0 rebrand; previously ResponderAgent)

**Responsibility:** Blast-radius-aware containment. Every proposed action is pre-scored for blast radius (number of unique users, hosts, or SaaS sessions affected). Actions above the tenant's configured blast-radius threshold always require HITL even at L4.

**L0–L4 maturity gate:**

| Level | Auto-execute threshold | Requires approval |
|---|---|---|
| L0 | Nothing | Everything |
| L1 | READ only | All mutations |
| L2 | WRITE-REVERSIBLE only | WRITE-SIGNIFICANT, DESTRUCTIVE |
| L3 | WRITE-SIGNIFICANT if `blast_radius ≤ 3` | DESTRUCTIVE, large blast-radius |
| L4 | All if confidence ≥ per-action threshold | Blast-radius override |

**Playbook library:** `isolate_host`, `revoke_sessions`, `disable_account`, `quarantine_file`, `block_ip`, `block_domain`, `ticket_create`, `notify_slack`, `notify_teams`, `rotate_secret`, `snapshot_volume` (forensic), `reimage_host` (DESTRUCTIVE, always HITL)

**Output contract:**
```python
class RespondOutput(BaseModel):
    actions_taken: list[ActionRecord]
    actions_pending_hitl: list[ActionRecord]
    blast_radius: int
    maturity_level_applied: Literal["L0","L1","L2","L3","L4"]
    handoff: Literal["ReporterAgent"]
```

---

### 2.5 ReporterAgent

**Responsibility:** Writes the case narrative, stores episodic memory for future recall, emits compliance artifacts, and triggers weekly digest. Unchanged in v8.0 except it now receives `RespondOutput` instead of the old `ResponderOutput` type.

**Outputs:** case narrative (Markdown), IOC list, MITRE ATT&CK heatmap delta, Jira/ServiceNow ticket update, compliance artifact (SOC 2 / HIPAA / PCI-DSS evidence packet).

---

### 2.6 HuntAgent (v8.0 rebrand; previously Hunter)

**Responsibility:** Out-of-band, hypothesis-driven threat hunting. Accepts natural-language hypotheses and translates to ES|QL / SPL / KQL via structured template selection — never writes raw query strings directly. Hunts can be saved and scheduled.

**Added 2026-05-19:** `/hunt` surface in the console exposes the full natural-language interface; `/api/v1/hunts/{id}/schedule` enables recurring hunts.

**Allowed tools:** `siem.query_spl`, `siem.query_esql`, `siem.query_kql`, `edr.get_process_tree`, `edr.get_network_connections`, `cti.darkweb_search`, `cti.asm_lookup`, `cti.brand_lookup`, `cti.vuln_lookup`

---

## 3. Three-Tier Agent Memory (added 2026-05)

Each agent has access to all three tiers simultaneously:

### L1 — Session Memory (in-process LRU)
- **Store:** In-process LRU dict, up to 512 entries per agent instance
- **TTL:** Lives for the duration of the case run (minutes)
- **Contents:** Hot lookups (IOC reputation, tool results from earlier steps)
- **Prototype equivalent:** `scratchpad.py` key-value store

### L2 — Working Memory (Redis)
- **Store:** Redis, 24-hour TTL per key
- **Contents:** Cross-call state (e.g. "we already blocked this IP in step 3"), investigation hypothesis chain, partial results for long-running investigations
- **Key pattern:** `aisoc:case:{case_id}:agent:{agent_id}:{key}`

### L3 — Institutional Memory (PostgreSQL + pgvector)
- **Store:** PostgreSQL `memory` table + pgvector extension for similarity search
- **TTL:** Permanent
- **Contents:** Past case outcomes, approved playbook sequences, false-positive patterns, analyst feedback
- **Recall pattern:** `SELECT * FROM memory WHERE embedding <-> $1 < 0.3 ORDER BY embedding <-> $1 LIMIT 10`
- **Written by:** ReporterAgent at case close
- **Used by:** TriageAgent (FP recall), HuntAgent (past hunt outcomes), Investigator (similar past investigations)

---

## 4. L0–L4 Automation Maturity Model (added 2026-05-19)

Tenant administrators configure a single maturity level via `PUT /api/v1/tenant/config`:

```json
{
  "maturity_level": "L2",
  "confidence_thresholds": {
    "block_ip": 0.90,
    "isolate_host": 0.92,
    "disable_account": 0.95,
    "close_alert": 0.60
  },
  "max_blast_radius_auto": 3
}
```

| Level | Name | Auto-execute | HITL required |
|---|---|---|---|
| L0 | Manual | Nothing | Every action |
| L1 | Assisted | Nothing (AI advises only) | Every mutation |
| L2 | Semi-autonomous | WRITE-REVERSIBLE (`revoke_sessions`, `block_ip`, `quarantine_file`) | WRITE-SIGNIFICANT, DESTRUCTIVE |
| L3 | Supervised autonomous | WRITE-SIGNIFICANT if `blast_radius ≤ max_blast_radius_auto` | DESTRUCTIVE; large blast-radius |
| L4 | Fully autonomous | All actions if confidence ≥ per-action threshold | Blast-radius > threshold; audit gate |

All decisions are logged to the immutable audit trail regardless of level.

---

## 5. Agent Contracts & Handoff Protocol

### BaseAgent interface
```python
class BaseAgent(ABC):
    role: str
    allowed_tools: list[str]
    max_steps: int = 8
    memory_tiers: list[Literal["session","working","institutional"]]

    async def process(self, context: AgentContext) -> AgentOutput: ...
    async def call_tool(self, tool_id: str, params: dict) -> ToolResult: ...
    async def require_hitl(self, action: ActionRecord) -> bool: ...
    async def trace_step(self, step: AgentStep) -> None: ...
```

### Handoff envelope
```python
class Handoff(BaseModel):
    to: Literal["TriageAgent","InvestigatorNode","RespondAgent","ReporterAgent","HITL","close"]
    reason: str
    confidence: int    # 0–100
    priority: Literal["low","medium","high","critical"]
    blast_radius: int  # estimated scope, used by RespondAgent gating
```

### Session lifecycle
```
AlertIngested
    │
    ▼
DetectAgent.process()
    │  DetectOutput
    ▼
TriageAgent.process()
    │  verdict: MALICIOUS → escalate
    ▼
Investigator (LangGraph, ≤12 steps)
    │  InvestigationReport
    ▼
HITL Gateway [async wait, timeout 8h]
    │  analyst approved
    ▼
RespondAgent.process()
    │  RespondOutput
    ▼
ReporterAgent.process()
    │  case closed, memory written
    ▼
case.status = CLOSED
```

---

## 6. Failure Modes & Reliability Targets

| Agent | SLO | Failure mode | Recovery |
|---|---|---|---|
| DetectAgent | p99 < 2s | FusionEngine unreachable | Pass-through + `fusion_bypassed: true` flag |
| TriageAgent | p95 < 15s | LLM timeout | Fallback to rule-based verdict with `confidence: 40` |
| Investigator | p95 < 90s | Tool error in step N | Retry ×2 with backoff; skip tool and note in evidence |
| RespondAgent | p95 < 30s | Action rejected by downstream | Mark action `FAILED`, continue with remaining actions |
| ReporterAgent | p99 < 10s | Memory write failure | Log error, continue; memory catch-up job runs every 15m |
| HuntAgent | p95 < 45s | Query timeout | Return partial results with `partial: true` flag |

Iteration caps (hard): DetectAgent: 1 step · TriageAgent: 4 steps · Investigator: 12 steps · RespondAgent: 6 steps · ReporterAgent: 3 steps · HuntAgent: 8 steps.

All agents: circuit-breaker on any external tool failing 3× in 60s. Dead-letter queue via Kafka for any case the agent mesh cannot close within 4h.

---

## 7. MCP Server (services/mcp/, added 2026-05)

The MCP server exposes 13 AiSOC tools over stdio for Claude Desktop, Cursor, Continue, and Cody:

| Tool | Description |
|---|---|
| `list_cases` | List open cases with filters |
| `get_case` | Get full case detail including attack chain |
| `triage_case` | Run TriageAgent on a case |
| `investigate_case` | Run Investigator on a case |
| `approve_action` | Approve a HITL-pending action |
| `reject_action` | Reject a HITL-pending action |
| `run_hunt` | Execute a hypothesis-driven hunt |
| `list_alerts` | List raw alerts with filters |
| `get_ioc` | Look up an IOC in all threat intel sources |
| `query_attack_chain` | Get the ranked attack-chain timeline for a case |
| `list_detections` | List active detection rules |
| `tune_detection` | Add suppression or allow-list to a noisy rule |
| `get_stats` | SOC performance metrics |

---

## 8. Cross-tenant Security Model (updated 2026-05-20)

Every storage read and write enforces tenant isolation at two independent layers:

1. **Row-level security (RLS):** PostgreSQL RLS policy; `current_setting('app.tenant_id')` is set at connection-checkout time from the JWT claims. Queries that omit `tenant_id` predicates are rejected by RLS and never return rows from other tenants.

2. **Application-layer enforcement (added 2026-05-20, PR #197):** Every FastAPI dependency that touches `/alerts`, `/cases`, `/investigations`, `/threat-intel`, and LLM credentials validates that the decoded JWT `tenant_id` matches the resource's stored `tenant_id`. This is a belt-and-suspenders guard against RLS bypass.

3. **Nightly RBAC regression gate (`cross-tenant-rbac.yml`):** CI job injects a `tenant_a` JWT and verifies that zero rows belonging to `tenant_b` are returned across all data-bearing endpoints. A dropped `tenant_id` predicate fails the gate.

---

*Last updated: 2026-05-20 · Document version: 2.0 · Production version: v7.3.1 · tryaisoc.com*
