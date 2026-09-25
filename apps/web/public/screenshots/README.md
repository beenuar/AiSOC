# `apps/web/public/screenshots/` — real console captures

Every image here is a screenshot of a running AiSOC deployment. None is a
mockup, a design comp, or a demo-mode capture.

**Nothing in this directory was taken with `make demo`.** The synthetic demo
dataset exists and is legitimate, but a screenshot of it presented as the
product working on real data would be the exact thing this repository has a
standing rule against. If a capture is ever added from demo mode, it must say
so in the table below and in every caption that uses it.

## How these were produced

```bash
cp .env.example .env
make up          # CORE: 14 long-running services, no credentials of any kind
make smoke       # one real event through the real spine
```

Then telemetry was pushed through the documented ingest API
(`POST /v1/ingest/batch`) and the console was driven with Playwright at
1440×900, signed in as the administrator `make up` created.

One detail, so the record is exact: these were captured immediately before
ingest authentication landed, so the pushes carried no token. That changed what
the *door* requires and nothing about what came through it — normalization,
detection, promotion, correlation and triage are the same code either way.
Re-capturing now would need `make ingest-token` first.

What is real in these images, stated precisely:

- **The deployment.** Fourteen containers, the images built from this
  repository, Postgres/Kafka/Qdrant/Ollama running locally.
- **The pipeline.** Normalization, detection, promotion, correlation and
  alerting were all performed by the running services. No row was seeded into
  the database.
- **The threat intelligence.** 1,725 CISA Known Exploited Vulnerabilities
  entries, fetched from the public catalogue at capture time. Not ours, not
  synthetic, unmodified.
- **The AI verdict.** Produced by the bundled local `llama3.2:3b-instruct-q4_K_M`
  through the LiteLLM gateway, with real token counts and latency in the
  Investigation Ledger. Not a hosted provider — no key was configured, and
  none has ever been exercised here.
- **The empty and degraded states.** Genuinely empty and genuinely degraded.
  They are as much of the product as the populated ones.

What is *authored* rather than observed: the security events themselves. They
were written by hand to be representative and pushed through the ingest API.
They are not a real intrusion and no caption may imply they are.

## The captures

| File | Surface | What is worth seeing |
|---|---|---|
| `dashboard.png` | `/dashboard` | Operations funnel over real counts. `MTTR` reads *not measured · no cases closed* rather than `0`. |
| `alerts-queue.png` | `/alerts` | Twelve alerts the pipeline produced, each attributed to the connector that fed it. |
| `investigation-rail.png` | `/alerts` → row | The rail's Story view. Progression says *no ATT&CK tactic is mapped … that is a gap in the detection's metadata rather than a statement about the activity.* |
| `ai-triage-verdict.png` | `/alerts` → row → Details | A real local-model verdict: `true positive`, confidence 80/100, groundedness *not assessed*, and the model's own rationale verbatim. |
| `threat-intel-kev.png` | `/threat-intel` | 1,725 real KEV entries; the page distinguishes the catalogue size from the page it is showing. |
| `soc-operations.png` | `/dashboards/operations` | Pipeline health against a tenant with no connectors — *"Nothing is feeding the pipeline yet, so an empty alert queue is expected."* |
| `connectors.png` | `/connectors` | The connector surface with nothing connected. |
| `connector-wizard.png` | `/connectors` → Add connector | The catalogue, reporting **84 connector types available** — the generated count, not a hand-typed one. |
| `attack-graph.png` | `/graph` | The entity graph over real ingested telemetry, with Neo4j running. |
| `attack-graph-core-degraded.png` | `/graph` | The same page in CORE, where Neo4j is not running: it names the failure (`API 503 … /api/v1/graph`) instead of drawing an invented graph. |
| `federated-search.png` | `/federated-search` | Honest empty state — no SIEM connected, and it says which four it would query. |
| `playbooks.png` | `/playbooks` | The playbook library. |
| `playbook-editor.png` | `/playbooks/{id}` → Add step | The step palette. Twenty-one tiles, from a twenty-two-member vocabulary: `approval` is withheld because the engine has no pause/resume. |
| `detection-rules.png` | `/detection` | The detection rule surface. |
| `hunt.png` | `/hunt` | The hunt workbench. |
| `cases-empty.png` | `/cases` | No cases, said plainly. |

## Refreshing them

`.github/workflows/console-visuals.yml` can regenerate console tiles on a
schedule, but it drives the **seeded demo stack**. Anything it produces is
demo-mode output and must be labelled as such wherever it appears — which is
why the captures above were taken by hand against a real CORE stack instead.
