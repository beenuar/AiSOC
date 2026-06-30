# aisoc-sandbox

> Run an AiSOC agent investigation **offline in under 30 seconds**. No Docker, no API key, no network.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](https://github.com/beenuar/AiSOC/blob/main/LICENSE)
[![PyPI release](https://img.shields.io/badge/pypi-coming%20in%20v8.0-f59e0b)](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md)

`aisoc-sandbox` is the quickest possible on-ramp to [AiSOC](https://github.com/beenuar/AiSOC). It walks one alert fixture through a four-stage agent funnel — **Detect → Triage → Hunt → Respond** — using a deterministic offline reasoner in place of a real LLM, and prints the resulting Investigation Ledger to your terminal.

It is the simulator-equivalent of the production [`services/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents) graph, collapsed into a single zero-dependency Python package. **When you're ready to run the real stack: `pnpm aisoc:demo` from a fresh clone of [AiSOC](https://github.com/beenuar/AiSOC).**

## Why this exists

The production AiSOC stack needs Postgres, Kafka, Redis, an LLM API key, and ~5 minutes to boot. That's the right cost for a buyer evaluating against their own alert data — but it's the wrong cost for a developer who just wants to see how the agent reasons before they commit their evening.

This package collapses the boot time to **< 5 seconds** and the disk footprint to **< 50 KB**. The trade-off is that the reasoning is deterministic and the tools are simulated (not executed); see "Differences from the production stack" below.

## Install

```bash
# Today (from this monorepo):
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC && pip install -e packages/aisoc-sandbox

# v8.0+ (once aisoc-sandbox lands on PyPI):
pip install aisoc-sandbox
# or, for one-off use without polluting your site-packages:
pipx run aisoc-sandbox demo
```

Python 3.10+ on Linux / macOS / Windows. Zero runtime dependencies.

## Quick start

```bash
# Walk the default scenario (lateral-movement) through the funnel
aisoc-sandbox demo

# Pick a different bundled scenario
aisoc-sandbox demo --scenario aws-credential-exfil

# Use your own scenario JSON
aisoc-sandbox demo --file ./my-alert.json

# Machine-readable output
aisoc-sandbox demo --scenario phishing-payload --json | jq

# What scenarios are bundled?
aisoc-sandbox scenarios
```

## Bundled scenarios

Five scenarios ship with the package; each one is a single JSON file under [`src/aisoc_sandbox/scenarios/`](./src/aisoc_sandbox/scenarios) and is small enough to read end-to-end:

| ID | Title | MITRE | Severity |
|---|---|---|---|
| `lateral-movement` | Impossible-travel Okta sign-in | T1078, T1078.004 | high |
| `aws-credential-exfil` | IAM keys used from new ASN, then `s3:GetObject` flood | T1552, T1567, T1078.004 | critical |
| `phishing-payload` | Click-through to credential-harvest page | T1566, T1566.002 | high |
| `kubernetes-privesc` | Namespace SA bound to `cluster-admin` | T1098, T1078 | critical |
| `github-token-theft` | PAT leaked, six private repos cloned in 11 s | T1078, T1555, T1567 | high |

## What you'll see

Each `aisoc-sandbox demo` run emits a four-step ledger:

```
Investigation Ledger
  4 steps · 12 ms total · synthetic offline run (no LLM, no Docker)

Step  0  DETECT  DetectAgent  (3 ms)
  Action     Match incoming events against detection ruleset
  Rationale  2 event(s) ingested; matched detection ruleset against MITRE techniques T1078, T1078.004.
  · events_ingested: 2
  · mitre_techniques: ['T1078', 'T1078.004']
  · severity_at_intake: high
  · entity:user: alice@example.com
  → would-call rules.match({"rule_count": "800+", ...})
  → would-call fusion.score({"window_minutes": 15})
  Decision   Open alert at severity=high

Step  1  TRIAGE  TriageAgent  (3 ms)
  Action     Score alert confidence + cross-reference with prior cases
  Rationale  Authenticated session signals look legitimate at the protocol layer, but the geo pivot between sequential events is physically impossible — classic credential takeover.
  ...
```

The shape mirrors the production Investigation Rail at [`/alerts/[id]`](https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/console/investigation-rail.md). The four stages, the evidence chips, and the "Decision" lines are the same — only the LLM rationale and tool execution are simulated.

## Library use

The package's surface is small enough to embed:

```python
from aisoc_sandbox import load_scenario, run_investigation

scenario = load_scenario("aws-credential-exfil")
ledger = run_investigation(scenario)

# Iterate the steps
for step in ledger:
    print(step.step, step.agent, step.action, step.decision)

# Or render to a stream (TTY-aware colour)
ledger.render_human()

# Or serialise
print(ledger.to_json())
```

## Differences from the production stack

| | `aisoc-sandbox` | Production `services/agents/` |
|---|---|---|
| LLM | Deterministic template-driven stub | OpenAI / Anthropic / Ollama via LiteLLM |
| Tool calls | Simulated as "would-call(name, args)" | Dispatched to connector / action services |
| Persistence | In-memory; one CLI invocation | Postgres `investigation_events` table |
| Latency | Synthetic per-stage numbers | Real LLM + tool latency |
| Boot time | < 5 s | ~5 min cold, ~3.5 min warm |
| Dependencies | None | Postgres + Kafka + Redis + LLM API key |

This is on purpose. The sandbox is the **on-ramp**, not a replacement: it gives you 30-second visibility into how the funnel hangs together so you can decide whether the full demo is worth the 5-minute boot.

## License

MIT — see the [repo LICENSE](https://github.com/beenuar/AiSOC/blob/main/LICENSE).
