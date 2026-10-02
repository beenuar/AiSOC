<div align="center">

<img src="apps/web/public/logo-mark.svg" alt="AiSOC" width="120" />

# AiSOC

**An open-source, self-hostable AI Security Operations Center.** It ingests your security telemetry, detects and correlates threats, investigates them with AI agents whose reasoning is fully auditable, and proposes responses a human approves.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-15.0.0-f59e0b?style=flat-square)](CHANGELOG.md)
[![CI](https://img.shields.io/github/actions/workflow/status/beenuar/AiSOC/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/beenuar/AiSOC/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/beenuar/AiSOC/codeql.yml?branch=main&label=CodeQL&style=flat-square)](https://github.com/beenuar/AiSOC/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/beenuar/AiSOC/badge)](https://securityscorecards.dev/viewer/?uri=github.com/beenuar/AiSOC)

[Docs](https://beenuar.github.io/AiSOC/) · [Architecture](docs/architecture/README.md) · [What actually works](docs/audit/REPOSITORY_REALITY.md) · [Discussions](https://github.com/beenuar/AiSOC/discussions)

</div>

---

## What AiSOC does

Telemetry arrives from your security tools. AiSOC normalizes it, runs the 2603 executable rules of
its 6991-rule library, groups what fires into incidents, investigates each one with an AI agent whose
every prompt and tool call is recorded, and proposes an action. New threat intelligence re-sweeps the
history you already collected, and a human approves before anything reaches a vendor.

## What it looks like running

<a href="apps/web/public/demo/demo.mp4"><img src="apps/web/public/demo/hero.gif" alt="AiSOC on one host: make up brings the stack up and prints the sign-in address, the console shows real CISA KEV rows, a pushed event becomes an alert, and the cost dashboard reports the tokens triage spent" /></a>

**[Watch the full three minutes](apps/web/public/demo/demo.mp4)** — install to AI verdict on one
server against the published images, terminal waits shortened and the recording saying so on screen.
The stills below are earlier runs under the same rules: no seeded rows, no demo mode, no mockups.
([step by step](apps/docs/docs/deployment/walkthrough.mdx) · [what is real](apps/web/public/screenshots/README.md))

| | |
|---|---|
| <img src="apps/web/public/screenshots/alerts-queue.png" alt="Alerts queue" /> | <img src="apps/web/public/screenshots/ai-triage-verdict.png" alt="AI triage verdict in the Investigation Rail" /> |
| **Alerts** — each attributed to the connector that fed it. | **Automated triage** — the bundled local model's verdict, confidence and rationale, verbatim. |
| <img src="apps/web/public/screenshots/threat-intel-kev.png" alt="Threat intelligence page showing CISA KEV entries" /> | <img src="apps/web/public/screenshots/soc-operations.png" alt="SOC operations dashboard with honest empty states" /> |
| **Threat intelligence** — the real CISA KEV catalog, minutes after boot, with no API key. | **SOC operations** — with nothing connected yet, and it says so rather than showing a placeholder. |

## Quick start

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
make up
```

Needs Docker Compose v2 with **8 GB memory and 20 GB free disk in the Docker VM**, plus `python3`
(3.9+) and `bash`; `make doctor` checks all of it and
[Installation](https://beenuar.github.io/AiSOC/docs/installation#requirements) says what each number
was measured against. The first run downloads a ~2 GB model into a volume only `make clean` clears.

`make up` also creates `.env` and generates the **fourteen** secrets in it — the credential vault, the
session signing key, five service-to-service credentials and four datastore passwords — then creates
an administrator and prints its password, generated on your machine, shown once and stored nowhere.
Copy it, or mint another with `make bootstrap ARGS=--reset-password`.

**A port already in use does not stop the install.** AiSOC publishes on a free one, names what held
the old one, and moves the console address with it — measured on a bare clone with 5432 and 11434
both taken, 64 seconds to a signed-in console.

Then **prove it works**. `make smoke` posts one real event to the ingest API and follows it through
Kafka, detection, correlation and Postgres, then reads the alert back out of the public API. Every
stage reports PASS or FAIL:

```
$ make smoke
[PASS] raw telemetry accepted by ingest
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
PASS: 10/10 stages
```

Sign in at the address `make up` printed. A tenant with nothing connected lands on a **setup
wizard** rather than an all-zero dashboard, and its state is read from your own data so it stays
right if you connect a source through the API. The spec is
[`docs/openapi.yaml`](docs/openapi.yaml) — interactive docs are off in this production-class stack.
Stuck? `make doctor`, which on a host where you have not run `make up` yet says exactly that.

## Try it without connecting anything

Press **Load sample data** in the wizard. Five scenarios take the same ingest path a real connector uses — not inserted rows — so watching them become alerts means watching the pipeline work. They span low to critical on purpose, because a first run where everything is a crisis teaches you nothing about how triage separates signal from routine. They are attributed to `AiSOC` in the source column, refuse to load into a tenant that already has real alerts, and do **not** mark setup complete. ([what each step proves](https://beenuar.github.io/AiSOC/docs/console/getting-started)) For the larger fixed corpus used by demos and evals, `make demo` loads a **synthetic** dataset — the pipeline shape, never a benchmark, a customer or an incident. Every row is `is_synthetic = true` and labelled in the console.

## Connect real data

Push, with a credential from `make ingest-token` (the tenant comes from it, not a header):

```bash
curl -X POST http://localhost:8081/v1/ingest/batch \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $AISOC_INGEST_TOKEN" \
  -d '{"connector_id":"edr-1","connector_type":"crowdstrike","events":[{"severity":"high",
       "title":"Encoded PowerShell from Office","host":"WIN-FIN-01"}]}'
```

Or pull, by configuring one of **84 click-and-connect data connectors** in **Settings → Connectors**
(needs the `full` profile) — Splunk, Sentinel, Elastic, CrowdStrike, Okta, AWS and Kubernetes audit
among those with vendor-specific normalization and setup docs
([coverage](https://beenuar.github.io/AiSOC/docs/connectors/api-coverage)). Without a vendor profile
a connector still ingests through a generic mapping that resolves host, user and source IP.

## How it works

Ingest normalizes to a common shape and Kafka carries it, then
fusion runs 2603 executable detection rules, of 6991 on disk, applies **your tenant's own tuning**
on top — the disables, floors and suppressions the console writes, so a rule you turned off actually
stops firing — and decides what becomes an alert. Correlation groups related alerts, an agent investigates and writes its reasoning
to the Investigation Ledger, and a playbook may start from the result. Separately, new threat
intelligence sweeps the lake for sightings you already collected, and a hypothesis becomes a hunt
without anyone writing a query — the model fills a closed schema and every value it supplies is
bound as a parameter, so it cannot express a query at all.

**A playbook triggered by an alert previews before it acts.** Three switches must agree — the
deployment, the tenant, and the playbook — and every default is off; anything less runs in preview
with its plan attached to the alert. An approval step inside one is a durable pause: the run suspends
to Postgres, survives a restart, resumes from the step after the approval, and expires with a
recorded outcome rather than hanging.

**Executable is earned, not declared.** A rule enters the compiled ruleset only after a vendor-shaped
event has been replayed through the real connector and this engine and that rule was *watched to
fire* — never inferred from a directory or an `enabled:` flag. The proof can fail: `--prove-gate`
reverts the Windows connector and requires all 1,687 Windows rules to go silent. It means the rule is
reachable, not that it detects an attack. 119 still cannot fire on any connector, counted by family
rather than hidden. ([how, and why 1,362 were refused](docs/detections/sigma-compilation.md))

**[docs/architecture/README.md](docs/architecture/README.md)** walks that path one step at a time —
eleven steps, five diagrams, every box linking to the code that implements it — and
[mirrors to the docs portal](https://beenuar.github.io/AiSOC/docs/architecture).

## Deployment profiles

| Profile | Command | Services | RAM | What you get |
|---|---|---|---|---|
| **core** | `make up` | 16 | ~8 GB | The full alerting pipeline: ingest → detect → correlate → alert → triage → console, plus the LLM gateway, a local model, the CISA KEV threat feed, and the connector and response services the agent's vendor tools reach |
| **full** | `make up-full` | 22 | ~12 GB | Core plus event lake, entity graph, full-text search, enrichment |
| **demo** | `make up && make demo` | 16 | ~8 GB | Core plus labelled synthetic data |

CORE is the smallest deployment that takes a real event and produces a real alert, and **it needs no
credentials to do either.**

**The model ships with the gateway.** Ollama runs a pinned ~2 GB `llama3.2:3b-instruct-q4_K_M`
sized for CPU-only inference, so `make up` produces real triage verdicts with real token counts in
the Investigation Ledger — not a stub. It is not a frontier model: over 50 alerts it gave triage
usable output 44 times before the reply was constrained to JSON and 50 after
([method](scripts/measure_triage_reliability.py)), and the rail labels which path answered. Upgrade
by setting `OPENAI_API_KEY` and the model pins. **No hosted provider has ever been exercised
here** — there is no funded key, so per-model rows read *not measured* rather than zero.
([ADR-0006](docs/decisions/0006-llm-gateway-in-core.md))

**One real external feed ships too.** `services/threatintel` polls the CISA Known Exploited
Vulnerabilities catalog — public, no API key — into the console's Threat Intelligence page: the one
thing in a fresh install that is neither synthetic nor yours.

## Real vs synthetic data

| Kind | Where | How you can tell |
|---|---|---|
| **Real** | Your connectors and the ingest API | `is_synthetic = false` (the default) |
| **Real, and not yours** | The CISA KEV feed on the Threat Intelligence page | Every row carries `source: cisa-kev`; it is the public catalog, unmodified |
| **Sample** | The wizard's **Load sample data** | Source column reads `AiSOC`; RFC 5737 / RFC 2606 reserved addresses only |
| **Demo** | `make demo` | `is_synthetic = true`, labelled in the console |
| **Benchmark** | `services/agents/tests/eval_data/` | Every published row carries `substrate: true` |
| **Test fixtures** | `tests/`, `**/tests/` | Never shipped in an image |

**Production never silently falls back to synthetic data.** An unreachable backend makes the console
name the failure, not invent an investigation, and an unmeasured figure reads *not measured*, never
`0`. That was not always true — [the reality audit](docs/audit/REPOSITORY_REALITY.md) records where
it was wrong and how it was fixed.

## AI agents

Agents triage alerts and investigate incidents. What they can and cannot do:

- **They read** the alert, its correlated siblings, entity context, and prior verdicts for the same signature.
- **They call typed tools** — lake queries, graph traversals, enrichment lookups. The model chooses a tool and passes arguments; it never writes SQL.
- **Everything is logged** to the Investigation Ledger: prompts, tool calls, citations, the verdict, and token cost.
- **Grounding is checked.** A verdict citing an indicator the evidence never contained is demoted to human review rather than auto-closed.
- **A prompt is validated before it is sent.** Raw logs, OCSF payloads and secret-shaped values are refused, not redacted after the fact.
- **No vendor is touched without a human**, unless a tenant has explicitly granted autonomy for that verb. Every response step is graded against its own capability contract at dispatch, so approving a playbook never authorises whatever its steps happen to contain, and an approver must hold the required permission tier and must not be the person who requested the action.

## Project maturity

| Capability | Status | Tested | Production ready |
|---|---|---|---|
| Ingest → detect → correlate → alert | Stable | E2E + unit | Yes |
| Detection engine (2603 executable rules) of 6991 | Stable | Replay proof | Yes |
| Alert correlation into incidents | Stable | Unit | Yes |
| REST API + web console | Stable | Unit + integration | Yes |
| AI triage + Investigation Ledger | Beta | Unit + substrate eval + local-model run | Yes, copilot mode |
| Event lake + hunting (ClickHouse) | Beta | Unit | Yes, `full` profile |
| Retro-hunts when new intel arrives | Beta | Unit + live ClickHouse replay | Yes, `full` profile |
| 68-hunt YAML library, replayed against synthetic events | Alpha | Unit + boundary gate | `full` profile. The NL hunting agent is **not wired** — nothing outside its own test imports it, and the scheduler reads a synthetic corpus rather than tenant data (parity 6.1) |
| SCIM 2.0, white-label, usage metering | Beta | Unit + Okta/Entra sequences | Yes |
| Entity graph (Neo4j) | Beta | Unit | Yes, `full` profile |
| Governed response actions | Beta | Unit | Human-approved only |
| Alert-triggered playbooks, with a durable approval pause | Beta | Unit + live Postgres suspend/resume | Yes — three opt-ins deep, preview by default |
| Per-tenant detection tuning in the live engine | Beta | Unit + live overlay read | Yes |
| Scheduled connectors | Beta | Contract tests | `full` profile |
| UEBA | Beta | Unit + live migration round-trip | `full` profile |
| Package distribution (npm/PyPI) | Ready, unpublished | `release.yml` builds and packs all eight on every tag | Install from source — the upload is blocked on registry credentials, which is an account action |

## What AiSOC is not

- **Not a drop-in SIEM replacement.** It correlates and investigates; it does
  not replace long-term log retention and compliance search.
- **Not able to see telemetry you have not connected.** There is no discovery.
- **Not autonomous by default.** Response requires explicit policy
  authorization and a human approver.
- **Demo and sample incidents are not real incidents**, and benchmark numbers are substrate
  self-consistency measures rather than live agent accuracy — labelled as such wherever published.

## Troubleshooting

`make doctor` checks host tools, memory and disk, every port, each datastore by *querying* it rather
than asking whether its container is up, and whether `.env` still holds placeholders — then prints
the command to run next. A container killed by a full Docker VM is named as that, not reported as
the service that happened to die. The six failures it is most often right about are tabulated under
[Installation](https://beenuar.github.io/AiSOC/docs/installation#the-six-most-common-failures).

## Security

Secrets are generated per deployment and never committed; connector credentials are encrypted at
rest. Services connect to Postgres as a DML-only role, so the row-level-security policies actually
apply to them, and tenant isolation is enforced at the query layer in every store. RBAC gates every
mutating route, ingest is authenticated, and the default install sends no prompt anywhere — the
model runs beside it.

**A service with no credential refuses to serve rather than serving unauthenticated**, and `make up`
generates every secret it needs. The [changelog](CHANGELOG.md) records each fixed vulnerability;
report via [SECURITY.md](SECURITY.md).

## Developing

```bash
make test        # unit tests for every service
make smoke       # the golden pipeline, against a running stack
make stats       # recount every figure this README publishes
```

Guides: [add a connector](https://beenuar.github.io/AiSOC/docs/plugins/hello-plugin) ·
[add a detection](https://beenuar.github.io/AiSOC/docs/detections/hello-hunt) ·
[plugin lifecycle](https://beenuar.github.io/AiSOC/docs/plugins/lifecycle) ·
[contributing](CONTRIBUTING.md). Every count above is recounted from the tree by `make stats`, and
CI fails if this README disagrees with it.

## Roadmap · Contributing · License

[ROADMAP.md](ROADMAP.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · MIT
