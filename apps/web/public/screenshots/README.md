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
make up          # CORE: 16 long-running services, no credentials of any kind
make smoke       # one real event through the real spine
```

The console was then driven with Playwright at 1440×900, signed in as the
administrator `make up` created, and the security events were loaded through
the setup wizard's **Load sample data**, which pushes them through the same
documented ingest endpoint a real connector uses rather than inserting rows.
The console attributes every resulting alert to `aisoc_sample`, which is
visible in the captures themselves — that label is the point, not decoration.

What is real in these images, stated precisely:

- **The deployment.** Sixteen containers, the images built from this
  repository, Postgres/Kafka/Qdrant/Ollama running locally.
- **The pipeline.** Normalization, detection, promotion, correlation and
  alerting were all performed by the running services. No row was seeded into
  the database.
- **The threat intelligence.** 1,754 CISA Known Exploited Vulnerabilities
  entries, fetched from the public catalogue at capture time. Not ours, not
  synthetic, unmodified.
- **The AI verdict.** Produced by the bundled local `llama3.2:3b-instruct-q4_K_M`
  through the LiteLLM gateway, with real token counts and latency in the
  Investigation Ledger. Not a hosted provider — no key was configured, and
  none has ever been exercised here.
- **The empty and degraded states.** Genuinely empty and genuinely degraded.
  They are as much of the product as the populated ones.

What is *authored* rather than observed: the security events themselves. They
are the labelled `aisoc_sample` set, written to be representative and pushed
through the ingest API. They are not a real intrusion and no caption may imply
they are.

## The captures

Unless a row says otherwise, every image below was captured from a v20.1.0
stack on 2026-10-22 and the console footer in it reads `v20.1.0`.

| File | Surface | What is worth seeing |
|---|---|---|
| `dashboard.png` | `/dashboard` | Operations funnel over real counts. `MTTR` reads *not measured · no cases closed* rather than `0`. |
| `alerts-queue.png` | `/alerts` | The five alerts the pipeline produced, each attributed to the `aisoc_sample` source that fed it. |
| `investigation-rail.png` | `/alerts` → row | The rail's Story view. Progression says *No ATT&CK tactic is mapped to this alert … that is a gap in the detection's metadata rather than a statement about the activity.* |
| `ai-triage-verdict.png` | `/alerts` → row → Details | A real local-model verdict: `true positive`, confidence 85/100, groundedness *not assessed*, and the model's own rationale verbatim. |
| `threat-intel-kev.png` | `/threat-intel` | 1,754 real KEV entries; the page distinguishes the catalogue size from the hundred rows it is showing. |
| `soc-operations.png` | `/dashboards/operations` | Pipeline health against a tenant with no connectors — *"Nothing is feeding the pipeline yet, so an empty alert queue is expected."* |
| `connector-wizard.png` | `/connectors` | The connector surface with nothing connected: counters at zero rather than hidden, and `Universal capture (push)` offered for vendors with no connector of their own. |
| `attack-graph.png` | `/graph` | The entity graph over real ingested telemetry, with Neo4j running. **A v10.0.0 capture, not v20.1.0** — the populated view needs the `full` profile, so this is the most recent one recorded. The console chrome is a release behind; the graph is not. |
| `attack-graph-core-degraded.png` | `/graph` | The same page in CORE, where Neo4j is not running: it names the failure (`API 503 … /api/v1/graph`) instead of drawing an invented graph. |
| `federated-search.png` | `/federated-search` | Honest empty state — no SIEM connected, and it says which four it would query. |
| `playbooks.png` | `/playbooks` | The playbook library: 63 playbooks, split into 51 shipped pack entries and 12 custom. |
| `playbook-editor.png` | `/playbooks/{id}` | A shipped pack open in the editor — nine steps as an ordered list and as the graph that runs. Step 6 is `Wait for human approval`, which the palette withheld until `approval` became a durable pause. |
| `detection-rules.png` | `/detection` | The rule surface, reporting the catalogue figure (2,614) and `0 authored here` — the catalogue is a different measurement from the executable-rule count the README quotes. |
| `hunt.png` | `/hunt` | The hunt workbench: plain English on the left, the generated KQL on the right. |
| `cases-empty.png` | `/cases` | No cases, said plainly. |

## Refreshing them

`.github/workflows/console-visuals.yml` can regenerate console tiles on a
schedule, but it drives the **seeded demo stack**. Anything it produces is
demo-mode output and must be labelled as such wherever it appears — which is
why the captures above were taken by hand against a real CORE stack instead.

Two things to do in the same commit as a refresh, because both have already
been missed once:

1. **Re-read the captions.** The v20.1.0 refresh replaced the images under
   captions written for the previous ones, leaving the technical guide
   claiming twelve alerts over a picture of five and a "step palette" over a
   picture of a playbook. A screenshot and the sentence under it are one
   claim.
2. **Run `make papers`.** `apps/web/content/papers/` embeds these files, so a
   refresh leaves every committed PDF showing the old console.
   `scripts/render_white_paper.py --check` now digests each paper's markdown
   *and the figures it embeds*, so it will tell you — it could not before, and
   that is how a published PDF kept showing a console two releases old.
