# aisoc-sandbox

> Run an AiSOC agent investigation **offline in under 30 seconds**. No Docker, no API key, no network.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](https://github.com/beenuar/AiSOC/blob/main/LICENSE)
[![PyPI release](https://img.shields.io/pypi/v/aisoc-sandbox?color=22c55e)](https://pypi.org/project/aisoc-sandbox/)

`aisoc-sandbox` is the quickest possible on-ramp to [AiSOC](https://github.com/beenuar/AiSOC). It walks one alert fixture through a four-stage agent funnel — **Detect → Triage → Hunt → Respond** — and prints the resulting Investigation Ledger to your terminal, offline, with no model behind it.

It is the simulator-equivalent of the production [`services/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents) graph, collapsed into a single zero-dependency Python package. **When you're ready to run the real stack: `git clone https://github.com/beenuar/AiSOC && cd AiSOC && make up`.**

## Why this exists

The production AiSOC stack needs Postgres, Kafka, Redis and a few minutes to boot. That's the right cost for a buyer evaluating against their own alert data — but it's the wrong cost for a developer who just wants to see the shape of the thing before they commit their evening. (It does **not** need an API key: the stack ships a local model and runs triage with no credentials.)

This package collapses the boot time to **< 5 seconds** and the disk footprint to **< 50 KB**.

## What it will not tell you

**This is not a triage engine, and it is built so it cannot be mistaken for one.** There is no model in the wheel, so there is nothing here that can form a verdict. What the sandbox prints is one of exactly two things:

* **Something it computed from your events.** Impossible travel is a great-circle distance divided by an elapsed time, so the sandbox does that division and the answer follows the events. Same for event rate, origin diversity, and a domain age the payload itself records. Each signal prints its own arithmetic, so you can check it.
* **An explicit `not computed in the sandbox`, with the reason.** A confidence score, an L0–L4 automation tier, an approval posture, a related-case count, an entity risk score and a hunt match count are all absent — not estimated, not defaulted, and never rendered as a zero. A sweep that did not run reports `unknown`, because it did not find nothing, it looked nowhere.

It did not always work this way, and the history is the best explanation of the rule. A community reviewer fed the demo a harmless login — same user, same address, New York both times, eight hours apart, tagged `T1078` — and it answered *"the geo pivot between sequential events is physically impossible"*, high confidence, **83/100**. Relabelling genuine impossible-travel events `info` returned *"L4 — fully autonomous closure"* and *"auto-execute eligible"*. The cause was that the rationale came from a fixed table keyed on the MITRE technique, the score was `severity + 4 x techniques`, and the tier was a dict keyed on severity — all three read from strings the *input file* declared, and none of the three could see the events. A verdict that follows the label rather than the evidence is worse than no verdict, so all three were deleted rather than reworded.

A CI gate (`scripts/check_sandbox_honesty.py`) now refuses output that asserts a finding the package did not compute, and refuses the *shape* too: a table mapping a technique id or a severity name to a sentence or a score cannot be reintroduced, in this module or a new one.

## Install

```bash
pip install aisoc-sandbox
aisoc-sandbox demo

# Or without installing anything permanently:
pipx run aisoc-sandbox demo

# Or from a clone of the monorepo, to run it against your own changes:
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC && pip install -e packages/aisoc-sandbox
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
  4 steps · 3 ms total · synthetic offline run: no LLM, no network, nothing executed

Step  0  DETECT  DetectAgent  (1 ms)
  Action     Read the alert payload and index what it declares
  Rationale  2 event(s) ingested. No detection rule ran: this package ships no detection engine, so the
             technique(s) and severity below are values the scenario file declares, not the output of a
             match. The live engine loads 2,538 executable rules plus 76 sliding-window rules and would
             evaluate the events against them.
  · mitre_techniques_declared_by_input: ['T1078', 'T1078.004']
  · severity_declared_by_input: high
  · detection_rules_evaluated_here: 0 — the sandbox ships no detection engine
  → would-call rules.match({"technique_set": ["T1078", "T1078.004"]})  [not executed]
  Decision   Alert opened at severity=high, the value the input declares. The sandbox does not compute
              severity and does not revise it.

Step  1  TRIAGE  TriageAgent  (1 ms)
  Action     Compute what the events support, and name what cannot be computed
  Rationale  Derived from the event payload — not from the declared severity and not from the MITRE tag.
             geo_velocity: alice@example.com appears at Saint Petersburg, RU 0.13 h after New York, US —
             6,888.5 km apart, implied speed 53,115.6 km/h, above the 1,000 km/h threshold. ...
  · signals:
      [holds] geo_velocity: ... implied speed 53,115.6 km/h, above the 1,000 km/h threshold.
      [does_not_hold] event_burst: 2 timestamped events span 466.9 s; the densest 60 s window holds 1.
      [not_computable] recorded_domain_age: No event records a `domain_age_days` field, and the
          sandbox has no network to look one up.
  · confidence_score: not computed in the sandbox — there is no model and no scoring function in this
      package; the live TriageAgent's score comes from the model's own calibrated output
  ...
```

Change the second sign-in to New York and the same payload reports `0.0 km apart, implied speed 0.0 km/h — the same place ... These events do not show impossible travel`, with the `T1078` tag reported as **not supported by anything computed here**. That is the point of the rewrite: the verdict follows the events, and the tag is treated as an unverified claim by whoever wrote the file.

The shape mirrors the production Investigation Rail at [`/alerts/[id]`](https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/console/investigation-rail.md) — the four stages, the evidence chips and the "Decision" lines are the same. What differs is not cosmetic: the production rail carries a model's reasoning and the results of tools that ran, and this carries arithmetic and a list of things it could not work out.

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
| Model | **None.** Arithmetic over the events, or an explicit "not computed" | OpenAI / Anthropic / Ollama via LiteLLM |
| Verdict / disposition | Never reached | Produced, with a calibrated confidence score |
| Confidence score | Not computed — nothing to calibrate from | Emitted by `TriageAgent` |
| Automation tier (L0–L4) | Not computed — no tenant, no policy | Resolved from the capability contract + approval matrix |
| Detection rules | None loaded; the techniques are what the input declares | 2,538 executable + 76 windowed |
| Tool calls | Call *shapes*, each marked `executed: false` | Dispatched to connector / action services |
| Hunt sweep | Not performed; matches read "unknown", never 0 | ES\|QL / SPL / KQL against the ClickHouse lake |
| Persistence | In-memory; one CLI invocation | Postgres `investigation_events` table |
| Latency | Real timings for this process | Real LLM + tool latency |
| Boot time | < 5 s | ~5 min cold, ~3.5 min warm |
| Dependencies | None | Postgres + Kafka + Redis (a local model ships with the stack; no API key needed) |

This is on purpose. The sandbox is the **on-ramp**, not a replacement: it gives you 30-second visibility into how the funnel hangs together and what a ledger looks like, so you can decide whether the full stack is worth the boot. Anything in the right-hand column that it cannot do, it says so rather than approximating.

## License

MIT — see the [repo LICENSE](https://github.com/beenuar/AiSOC/blob/main/LICENSE).
