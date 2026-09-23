<div align="center">

<img src="apps/web/public/logo-mark.svg" alt="AiSOC" width="120" />

# AiSOC

**An open-source, self-hostable AI Security Operations Center.** It ingests your security telemetry, detects and correlates threats, investigates them with AI agents whose reasoning is fully auditable, and proposes responses a human approves.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-9.0.0-f59e0b?style=flat-square)](CHANGELOG.md)
[![CI](https://img.shields.io/github/actions/workflow/status/beenuar/AiSOC/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/beenuar/AiSOC/codeql.yml?branch=main&label=CodeQL&style=flat-square)](https://github.com/beenuar/AiSOC/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/beenuar/AiSOC/badge)](https://securityscorecards.dev/viewer/?uri=github.com/beenuar/AiSOC)

[Docs](https://beenuar.github.io/AiSOC/) · [Architecture](docs/architecture/README.md) · [What actually works](docs/audit/REPOSITORY_REALITY.md) · [Discussions](https://github.com/beenuar/AiSOC/discussions)

</div>

---

## What AiSOC does

```
   Your security tools  (EDR, cloud, identity, network, SIEM)
             |
             v
   ┌──────────────────────────────────────────────────────┐
   │  normalize -> detect -> correlate -> investigate -> respond  │
   └──────────────────────────────────────────────────────┘
             |
             v
   SOC analyst: one incident, with the evidence and the reasoning
```

An alert arrives. AiSOC works out whether it matters, groups it with related
signals, investigates it with an AI agent whose every prompt and tool call is
recorded, and proposes an action. A human approves before anything executes.

## Quick start

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
make up
```

Then **prove it actually works** — this is the part that matters:

```bash
make smoke
```

That posts one real event to the ingest API and follows it through Kafka,
detection, correlation and Postgres, then reads the resulting alert back out
of the public API. Every stage reports PASS or FAIL:

```
[PASS] raw telemetry accepted by ingest
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
```

Open **http://localhost:3000** (API docs at **http://localhost:8000/docs**).

Something wrong? `make doctor` checks every dependency and tells you what to
run next. Requires Docker with ~6 GB of RAM.

## Try it without connecting anything

```bash
make demo
```

> **The demo dataset is synthetic.** It exists to show the pipeline shape, not
> to represent real activity. Every row it writes is marked
> `is_synthetic = true` in the database and labelled in the console. It is not
> a benchmark, a customer, or a real incident.

## Connect real data

Two ways in. Push, from anything that can make an HTTP request:

```bash
curl -X POST http://localhost:8081/v1/ingest/batch \
  -H 'Content-Type: application/json' -H 'X-Tenant-ID: <tenant>' \
  -d '{"connector_id":"edr-1","connector_type":"crowdstrike","source_format":"json",
       "events":[{"severity":"high","title":"Encoded PowerShell from Office",
                  "host":"WIN-FIN-01","process_name":"powershell.exe"}]}'
```

Or pull, by configuring one of **84 click-and-connect data connectors** in
**Settings → Connectors** (needs the `full` profile). Those with
vendor-specific normalization and live setup docs include Splunk, Microsoft
Sentinel, Elastic, CrowdStrike, Okta, AWS (GuardDuty / CloudTrail / Security
Hub), Wiz, and Kubernetes audit logs. The full list is in the
[connector docs](https://beenuar.github.io/AiSOC/docs/connectors/api-coverage).

A connector without a vendor profile still ingests through a generic mapping —
events flow, but entity extraction is weaker.

## How it works

See **[docs/architecture/README.md](docs/architecture/README.md)** — it walks
one event through the whole system and every box in its diagrams links to the
code that implements it.

The short version: ingest normalizes to a common shape → Kafka carries it →
fusion runs 833 executable detection rules and decides what becomes an alert →
correlation groups related alerts into one incident → an agent investigates
and writes its reasoning to the Investigation Ledger → a human approves any
response.

## Deployment profiles

One architecture, three profiles of it.

| Profile | Command | Services | RAM | What you get |
|---|---|---|---|---|
| **core** | `make up` | 10 | ~6 GB | The full alerting pipeline: ingest → detect → correlate → alert → triage → console |
| **full** | `make up-full` | 30 | ~12 GB | Core plus event lake, entity graph, vector store, enrichment, scheduled connectors |
| **demo** | `make up && make demo` | 10 | ~6 GB | Core plus labelled synthetic data |

CORE is not a cut-down toy — it is the smallest deployment that takes a real
event and produces a real alert.

## Real vs synthetic data

This matters more than any feature, so it is stated plainly.

| Kind | Where | How you can tell |
|---|---|---|
| **Real** | Your connectors and the ingest API | `is_synthetic = false` (the default) |
| **Demo** | `make demo` | `is_synthetic = true`, labelled in the console |
| **Benchmark** | `services/agents/tests/eval_data/` | Every published row carries `substrate: true` |
| **Test fixtures** | `tests/`, `**/tests/` | Never shipped in an image |

**Production never silently falls back to synthetic data.** When a backend is
unreachable the console shows an error, not an invented investigation. That
was not always true — see [the reality audit](docs/audit/REPOSITORY_REALITY.md)
for the five places it was wrong and how each was fixed.

## AI agents

Agents triage alerts and investigate incidents. What they can and cannot do:

- **They read** the alert, its correlated siblings, entity context, and prior
  verdicts for the same signature.
- **They call typed tools** — lake queries, graph traversals, enrichment
  lookups. The model chooses a tool and passes arguments; it never writes SQL.
- **Everything is logged** to the Investigation Ledger: prompts, tool calls,
  citations, the verdict, and token cost.
- **Grounding is checked.** A verdict citing an indicator the evidence never
  contained is demoted to human review rather than auto-closed.
- **A prompt is validated before it is sent.** Raw logs, OCSF payloads and
  secret-shaped values are refused, not redacted after the fact.
- **Nothing executes without a human.** Response actions are proposed. An
  approver must hold the required permission tier and must not be the person
  who requested the action.

Without a model provider key, agents run a deterministic offline path and say
so. They do not fabricate a verdict.

## Project maturity

| Capability | Status | Tested | Production ready |
|---|---|---|---|
| Ingest → detect → correlate → alert | Stable | E2E + unit | Yes |
| Detection engine (833 executable rules) | Stable | Fixture replay + unit | Yes |
| Alert correlation into incidents | Stable | Unit | Yes |
| REST API + web console | Stable | Unit + integration | Yes |
| AI triage + Investigation Ledger | Beta | Unit + substrate eval | Yes, copilot mode |
| Event lake + hunting (ClickHouse) | Beta | Unit | Yes, `full` profile |
| Entity graph (Neo4j) | Beta | Unit | Yes, `full` profile |
| Governed response actions | Beta | Unit | Human-approved only |
| Scheduled connectors | Beta | Contract tests | `full` profile |
| UEBA | Beta | Unit | `full` profile |
| Package distribution (npm/PyPI) | Ready, unpublished | `release.yml` builds and packs all eight on every tag | Install from source — the upload is blocked on registry credentials, which is an account action |

## What AiSOC is not

- **Not a drop-in SIEM replacement.** It correlates and investigates; it does
  not replace long-term log retention and compliance search.
- **Not able to see telemetry you have not connected.** There is no magic
  discovery.
- **Not autonomous by default.** Response requires explicit policy
  authorization and a human approver.
- **Demo incidents are not real incidents**, and benchmark corpora are not
  customer telemetry.
- **Benchmark numbers are substrate self-consistency measures**, not live
  agent accuracy, and are labelled as such wherever published.

## Troubleshooting

`make doctor` diagnoses the deployment and prints the command to run next.
The five most common failures:

| Symptom | Cause | Fix |
|---|---|---|
| `port is already allocated` | Something else on 5432/6379/9092/3000 | `make doctor` names the port; stop it or edit the host port |
| Kafka reports healthy but nothing flows | Docker VM out of disk — Kafka corrupts its log dir and still passes its healthcheck | `docker system prune -af`, then `make clean && make up` |
| `make smoke` fails at "became an alert" | fusion is down or not consuming | `docker compose logs fusion \| tail -60` |
| Console loads but is empty | No data yet — this is correct | `make smoke`, or `make demo` |
| Services restart-loop on 8 GB machines | Not enough RAM for `full` | Use `make up` (core) |

## Security

Secrets live in `.env` and are never committed; connector credentials are
encrypted at rest with a per-deployment key. Tenant isolation is enforced at
the query layer in every store, not by convention. RBAC gates every mutating
route. Prompts are validated before they leave the deployment, and you can
bring your own model key or run entirely local models. Report vulnerabilities
via [SECURITY.md](SECURITY.md).

## Developing

```bash
make test        # unit tests for every service
make smoke       # the golden pipeline, against a running stack
make stats       # recount every figure this README publishes
```

Guides: [add a connector](https://beenuar.github.io/AiSOC/docs/plugins/hello-plugin) ·
[add a detection](https://beenuar.github.io/AiSOC/docs/detections/hello-hunt) ·
[plugin lifecycle](https://beenuar.github.io/AiSOC/docs/plugins/lifecycle) ·
[contributing](CONTRIBUTING.md)

Every number in this README is produced by `scripts/project_stats.py` and
checked in CI, so a figure cannot drift from the tree without a red build.

## Roadmap · Contributing · License

[ROADMAP.md](ROADMAP.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · MIT
