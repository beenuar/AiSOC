# Architecture

Every box in every diagram below corresponds to code in this repository, and
links to it. Where a component exists but is not used, it says so rather than
being quietly drawn in.

---

## What happens when AiSOC receives one security event

Follow a single event. This is the whole system, in order.

**1. Something sends telemetry.** Either a connector polls a vendor API on a
schedule, or a tool pushes to the ingest HTTP API directly:

```bash
curl -X POST http://localhost:8081/v1/ingest/batch \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-ID: <your-tenant>' \
  -d '{"connector_id":"edr-1","connector_type":"crowdstrike","source_format":"json",
       "events":[{"severity":"high","title":"Encoded PowerShell from Office",
                  "host":"WIN-FIN-01","process_name":"powershell.exe",
                  "parent_process":"winword.exe"}]}'
```

**2. Ingest normalizes it.** [`services/ingest`](../../services/ingest) maps
the vendor payload onto a common OCSF-shaped envelope using a per-connector
profile. A connector with no profile falls through to a vendor-neutral
generic profile — the event still flows, but entity extraction is weaker.

**3. It enters the event spine.** Ingest publishes to the Kafka topic
`aisoc.raw_events`. This is the boundary that makes everything downstream
independent: anything can consume the spine without ingest knowing about it.

**4. Fusion consumes it and evaluates detections.**
[`services/fusion`](../../services/fusion) runs the 833 executable rules
against the event. Separately it decides whether the event is *promotable* —
a vendor finding (OCSF category 2) or anything at severity ≥ high becomes an
alert; routine telemetry does not.

**5. Fusion correlates.** A new alert is matched against open incidents using
a correlation key of `{tenant}:{entity}:{tactic}`. It either joins an
existing incident or opens a new one, so ten related alerts become one thing
an analyst looks at.

**6. The alert is written to Postgres** and published to
`aisoc.alerts.fused`.

**7. Two consumers pick it up.**
[`services/realtime`](../../services/realtime) pushes it to the console over
WebSocket. [`services/agents`](../../services/agents) auto-triages it with an
LLM — a verdict, a confidence, and proposed actions.

**8. The agent's work is written to the Investigation Ledger** — every
prompt, tool call and citation, so a verdict can be audited rather than
trusted.

**9. Response stays governed.** Nothing executes automatically. An action is
proposed; a human with the right permission approves it; the result is
verified against the vendor rather than assumed from an HTTP 200.

> **Where it stops.** Step 9 has no automatic trigger — there is no code path
> that dispatches a response without a human. That is deliberate, and it is
> the honest boundary of "autonomous" in this project.

---

## Diagram 1 — the shape of it

```mermaid
flowchart TD
    sources["Security tools<br/>EDR · cloud · identity · network"]
    ingest["Ingestion + normalization"]
    spine["Event spine (Kafka)"]
    detect["Detection · correlation"]
    alerts["Alerts + incidents"]
    ai["AI investigation"]
    cases["Cases + Investigation Ledger"]
    respond["Governed response"]
    analyst["SOC analyst"]

    sources --> ingest --> spine --> detect --> alerts --> ai --> cases --> respond
    cases --> analyst
    analyst -->|approves| respond
```

---

## Diagram 2 — actual services

Only services that exist and run. Dashed boxes are the `full` profile.

```mermaid
flowchart LR
    subgraph core ["CORE profile — default"]
        ing["services/ingest<br/>Go · :8080"]
        kaf[("Kafka<br/>aisoc.raw_events")]
        fus["services/fusion<br/>Python · :8003"]
        pg[("PostgreSQL")]
        rds[("Redis")]
        api["services/api<br/>Python · :8000"]
        rt["services/realtime<br/>TS · :8086"]
        agt["services/agents<br/>Python · :8084"]
        web["apps/web<br/>Next.js · :3000"]
    end

    subgraph full ["full profile — optional"]
        ch[("ClickHouse<br/>event lake")]
        neo[("Neo4j<br/>entity graph")]
        qd[("Qdrant<br/>embeddings")]
        enr["services/enrichment"]
        conn["services/connectors"]
        ti["services/threatintel"]
    end

    conn -.->|"polls vendors"| ing
    ing --> kaf
    kaf --> fus
    fus --> pg
    fus --> kafd[("Kafka<br/>aisoc.alerts.fused")]
    fus --> rds
    fus -.-> ch
    fus -.-> enr
    kafd --> rt
    kafd --> agt
    agt --> pg
    api --> pg
    api -.-> ch
    api -.-> neo
    ti -.-> qd
    web --> api
    web --> rt
```

---

## Diagram 3 — who owns which data

```mermaid
flowchart TB
    subgraph req ["Required"]
        pg["PostgreSQL<br/><br/>alerts · incidents · cases<br/>users · tenants · detection rules<br/>audit log · investigation ledger"]
        rds["Redis<br/><br/>correlation windows<br/>dedup keys<br/>investigation run state"]
        kaf["Kafka<br/><br/>aisoc.raw_events<br/>aisoc.alerts.fused"]
    end

    subgraph opt ["Optional (full profile)"]
        ch["ClickHouse<br/><br/>every normalized event<br/>backs /lake/sql and hunt"]
        neo["Neo4j<br/><br/>entity graph<br/>blast radius"]
        qd["Qdrant<br/><br/>IOC and actor embeddings"]
    end
```

**Why each one, and what breaks without it:**

| Store | Why it is not replaceable by Postgres | Without it |
|---|---|---|
| **PostgreSQL** | — | Nothing works. |
| **Redis** | Correlation needs expiring keys at event rate; TTL semantics and throughput are the point. | No correlation; every alert becomes its own incident. |
| **Kafka** | Decouples producers from consumers and lets a slow consumer fall behind without dropping events or blocking ingest. | No spine; fusion, realtime and agents would each need a direct call from ingest. |
| **ClickHouse** | Columnar scans over hundreds of millions of events. Postgres cannot do this at cost. | No event lake, no hunting over raw telemetry. **Alerting is unaffected.** |
| **Neo4j** | Multi-hop traversal ("what else did this identity touch") is a join explosion in SQL. | No graph context or blast radius. Alerting unaffected. |
| **Qdrant** | Vector similarity for IOC and actor matching. | No semantic threat-intel matching. |

**OpenSearch is started by the `full` profile and nothing reads from it.**
It is recorded in [the reality audit](../audit/REPOSITORY_REALITY.md) as
unused rather than drawn here as though it were part of the design.

---

## Diagram 4 — AI investigation

```mermaid
sequenceDiagram
    participant K as Kafka aisoc.alerts.fused
    participant A as services/agents
    participant C as LLM input contract
    participant M as Model
    participant L as Investigation Ledger
    participant H as Analyst

    K->>A: fused alert
    A->>A: gather evidence (alert, entities, prior verdicts)
    A->>C: proposed prompt
    C-->>A: refuse if it contains raw logs or secrets
    C->>M: validated prompt
    M-->>A: verdict + confidence + cited indicators
    A->>A: groundedness check
    Note over A: an indicator the evidence<br/>never contained demotes<br/>the verdict to human review
    A->>L: prompt, tool calls, citations, verdict
    A->>H: proposed actions (never executed)
    H->>H: approve, with permission + separation of duties
```

Three properties worth naming, because each is enforced in code:

- **The contract runs before the request.** A prompt about to carry raw OCSF,
  vendor log lines or secret-shaped values is refused, not logged after the
  fact.
- **Citations are checked against the evidence.** A verdict citing an
  indicator that was never in the evidence is demoted rather than auto-closed.
- **Approval is authorized, not just recorded.** The approver must hold the
  action's permission tier and must not be the requester.

---

## Diagram 5 — connector to alert

```mermaid
flowchart TD
    A["Connector polls vendor API<br/>(or a tool pushes to /v1/ingest)"] --> B{"Profile for<br/>this connector?"}
    B -->|yes| C["Vendor-specific mapping"]
    B -->|no| D["Generic profile<br/>weaker entity extraction"]
    C --> E["OCSF-shaped envelope"]
    D --> E
    E --> F[("Kafka aisoc.raw_events")]
    F --> G["Detection engine<br/>833 executable rules"]
    F --> H{"Promotable?<br/>category 2, or severity >= high"}
    G -->|rule fires| I["Alert"]
    H -->|yes| I
    H -->|no| J["Lake only (full profile)<br/>hunted, not alerted"]
    I --> K{"Matches an open<br/>incident?"}
    K -->|yes| L["Joins that incident"]
    K -->|no| M["Opens a new incident"]
    L --> N[("PostgreSQL alerts")]
    M --> N
    N --> O[("Kafka aisoc.alerts.fused")]
```

---

## Deployment profiles

One architecture, three profiles of it — not three architectures.

| Profile | Command | Services | RAM | What you get |
|---|---|---|---|---|
| **core** | `make up` | 10 | ~6 GB | Ingest → detect → correlate → alert → triage → console. The full alerting pipeline. |
| **full** | `make up-full` | 30 | ~12 GB | Core plus event lake, entity graph, vector store, enrichment, connectors, LLM gateway. |
| **demo** | `make up && make demo` | 10 | ~6 GB | Core plus clearly-labelled synthetic data. |

CORE is not a toy. It is the smallest deployment that can take a real event
and produce a real alert, which is the thing the product is for.

**Two flags travel with the `full` profile.** The lake writer and the
graph writer target stores that exist only there, so in CORE they default off
rather than retrying against a host that is not running:

```bash
AISOC_LAKE_WRITER_ENABLED=true AISOC_GRAPH_ENABLED=true \
  docker compose --profile full up -d
```

`make up-full` sets both for you, and the integration workflow sets the same
pair — so the documented command and the tested command are the same command.

---

## Verifying any of this

```bash
make up && make smoke
```

`make smoke` posts one event to the ingest API and follows it through Kafka,
fusion, detection, promotion and Postgres, then reads it back from the public
API. It reaches past nothing. Each stage reports PASS or FAIL separately, so
a break names the boundary that broke.

Source: [`tests/e2e/golden_pipeline/`](../../tests/e2e/golden_pipeline/).
