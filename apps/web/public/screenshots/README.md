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

- **The deployment.** Sixteen containers on `make up`, the images built from
  this repository, Postgres/Kafka/Qdrant/Ollama running locally. The single
  attack-graph tile that needs Neo4j was captured from the same release under
  `make up-full`, noted in its row below.
- **The pipeline.** Normalization, detection, promotion, correlation,
  entity-risk rollup and alerting were all performed by the running services.
  No row was seeded into the database.
- **The threat intelligence.** 1,782 CISA Known Exploited Vulnerabilities
  entries, fetched from the public catalogue at capture time. Not ours, not
  synthetic, unmodified.
- **The AI verdict.** Produced by the bundled local `llama3.2:3b-instruct-q4_K_M`
  through the LiteLLM gateway, with real token counts and latency in the
  Investigation Ledger — measured at ~1,245 prompt tokens and ~25 s per
  triage on CPU for these events. Not a hosted provider — no key was
  configured, and none has ever been exercised here.
- **The cases.** The two open cases were created from their alerts through the
  console's own escalate / add-to-case flow, and the related-cases panel
  resolves them from a genuinely shared alert — not a seeded relationship.
- **The empty and degraded states.** Genuinely empty and genuinely degraded.
  They are as much of the product as the populated ones.

What is *authored* rather than observed: the security events themselves. They
are the labelled `aisoc_sample` set, written to be representative and pushed
through the ingest API. They are not a real intrusion and no caption may imply
they are.

## The captures

Unless a row says otherwise, every image below was captured from a v23.5.0
stack on 2026-11-18 and the console footer in it reads `v23.5.0`. The stack
also carried the two fixes shipped in the same pull request as this refresh
(the generated threat-intel service token reaching both ends, and the
`?status=open` case filter), without which the cases tiles could not have been
produced honestly.

| File | Surface | What is worth seeing |
|---|---|---|
| `dashboard.png` | `/dashboard` | Operations funnel over real counts. `MTTD` and `MTTR` read *not measured* rather than `0`; signal/noise is a real 80%. |
| `alerts-queue.png` | `/alerts` → Alerts tab | The five alerts the pipeline produced, each attributed to the `aisoc_sample` source that fed it, every one `triaged` by the local model. |
| `entity-risk-queue.png` | `/alerts` → Entities tab | **New in v23.5.0.** The risk-based queue rolls each alert up to the entity it touched and shows, under every row, the hosts that entity was *seen on* — `j.doe@example.com` on `WS-FINANCE-04`, `sso-gateway-01` carrying two alerts — the feature this release added. |
| `investigation-rail.png` | `/alerts` → row | The rail's Story view beside the queue. Evidence counts (`aisoc_sample`, Connector, Host, Rule, User) and a fusion confidence of `56/100`; Progression says *No ATT&CK tactic is mapped … a gap in the detection's metadata rather than a statement about the activity.* |
| `ai-triage-verdict.png` | `/alerts` → row → Details | A real local-model verdict: `true positive`, triage confidence 80/100, groundedness *not assessed*, and the model's own rationale verbatim — naming the host, the 0.00 vendor risk score and why it escalated anyway. |
| `threat-intel-kev.png` | `/threat-intel` | 1,782 real KEV entries; the page distinguishes the catalogue size from the hundred rows it is showing. |
| `soc-operations.png` | `/dashboards/operations` | Pipeline health, *"Every panel is driven by a live API response; a panel with no data says so rather than showing a placeholder."* Connector fleet empty, `Nothing rejected` over the window. |
| `connector-wizard.png` | `/connectors` | The connector surface with nothing connected: counters at zero rather than hidden, and `Universal capture (push)` offered for vendors with no connector of their own. |
| `cases.png` | `/cases` | A real caseload: four cases, two open and two closed, counted by status, each with its linked alert count. |
| `case-related-cases.png` | `/cases/{id}` → Overview | **New in v23.5.0.** The related-cases panel surfaces the sibling investigation that shares an alert — ranked by shared alerts then observables — beside the case's own timeline, linked alert and tasks. |
| `attack-graph.png` | `/graph` | **Captured under `make up-full` on the same v23.5.0 release**, Neo4j live: the entity graph over real ingested telemetry — users, hosts, IPs and network paths, colour-coded by type, auto-refreshing as events arrive. The populated view needs the `full` profile; this is a genuine v23.5.0 capture, not a back-level one. |
| `attack-graph-core-degraded.png` | `/graph` | The same page in CORE, where Neo4j is not running: it names the failure (*not part of this deployment … bring it up with `make up-full`*, `HTTP 503`) instead of drawing an invented graph. |
| `federated-search.png` | `/federated-search` | Honest empty state — no SIEM connected, and it says which it would query. |
| `playbooks.png` | `/playbooks` | The playbook library: 64 playbooks, split into 52 shipped pack entries and 12 custom, filterable by MITRE tactic and integration. |
| `playbook-editor.png` | `/playbooks/{id}` | A shipped pack open in the editor — its steps as an ordered list and as the graph that runs, including the `Wait for human approval` durable pause. |
| `detection-rules.png` | `/detection` | The rule surface, reporting the catalogue figure (3,045 loaded by the engine) and `0 authored here` — the catalogue is a different measurement from the executable-rule count the README quotes. |
| `hunt.png` | `/hunt` | The hunt workbench: plain English turned into runnable ES\|QL by the HuntAgent, with an honest *the event lake runs in the `full` profile* note where CORE has no ClickHouse to execute it against. |

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
