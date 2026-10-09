# Working in this repository

AiSOC is an open-source, AI-assisted Security Operations Center: telemetry comes
in from your own security tools, gets normalized, matched against a detection
corpus, correlated into alerts, triaged by an agent, and acted on through
governed response verbs. It runs on your own infrastructure — cloud or
on-premises — under the MIT license.

This file is for anyone changing the code, human or AI. It is the short version;
each section points at the thing that is authoritative. If this file and the
tree disagree, **the tree is right and this file is a bug**.

## Get it running

```bash
make up        # CORE profile: 16 long-running services, ~8 GB memory, ~20 GB disk
make doctor    # what is up, what is not, and what to do about it
make smoke     # the golden pipeline, eight stages, end to end
```

`make up` generates real secrets into `.env`, creates an administrator and
prints its password once. There is no step where you hand-edit a compose file.
`make up-full` adds the rest (21 services, ~12 GB) and switches on the lake
writer and the entity graph.

A first run shows real data with no credentials configured: the CISA Known
Exploited Vulnerabilities catalogue is a genuine public feed that needs no API
key, and a small local model does the triage.

## The shape of the system

One event's journey, which is the thing worth understanding first:

```
connector  →  services/ingest  →  Kafka raw_events  →  services/fusion  →  Postgres alerts
  polls a      normalizes to       the spine            archives to the       + services/realtime
  vendor       OCSF, projects                           lake, matches         pushes to the console
  API          actor/action/                            detections,           ↓
               resource/location                        correlates,        services/agents
                                                        promotes           triages with an LLM
                                                                              ↓
                                                                        services/actions
                                                                        executes a governed verb
```

Each hop is a service in `services/`. The stores are Postgres (operational),
ClickHouse (the event lake), Neo4j (the entity graph), Qdrant (vectors), Redis
and Kafka.

Fuller treatment: [`docs/architecture/README.md`](docs/architecture/README.md)
and the [architecture page](https://beenuar.github.io/AiSOC/docs/architecture)
on the docs site.

## Where things live

| Path | What is in it |
| --- | --- |
| `services/` | The backend services above, one directory each |
| `apps/web` | The Next.js console |
| `apps/docs` | The documentation site |
| `packages/` | Published SDKs, the benchmark harness, the offline sandbox |
| `detections/` | **Generated** detection YAML — see the warning below |
| `schemas/event_catalog/` | Vendor event types mapped to a normalized action and a sensitivity |
| `plugins/` | One marketplace manifest per connector |
| `scripts/` | The CI gates. Most are runnable alone and most have `--self-test` |
| `infra/` | Compose overlays, Terraform, Grafana dashboards |
| `plans/` | Locked planning documents. **Do not edit these.** |

## Conventions that are easy to guess wrong

- **`detections/*.yaml` is generated output.** The engine loads
  `services/fusion/app/data/detection_ruleset.json`, compiled from Python spec
  modules. Editing the YAML changes nothing that runs.
- **The severity ladder is exactly five tiers** — `info | low | medium | high |
  critical`. A vendor that publishes a distinct `critical` must map to
  `critical`, never be collapsed into `high`. Confidence is a separate 0–100
  integer and is not severity.
- **A connector's normalized envelope nests the vendor payload under
  `raw_event`**, not `raw`. Twenty-six connectors once used `raw`, missed the
  canonical-envelope check, and were silently misattributed and never promoted.
- **A new connector needs one registration**, in `_CONNECTOR_CLASSES` in
  `services/connectors/app/connectors/__init__.py`. Everything else is
  discovery.
- **The tenant is never a parameter a caller or a model can set.** It comes from
  the authenticated principal, or for service-to-service calls from a header.
  Three gates enforce this.
- **Secrets in connector config are vault-encrypted** at the application layer;
  `services/api` owns the write path.

## Figures, and how to re-derive them

Never copy a number out of prose — it goes stale silently and several have. Each
of these regenerates:

| Figure | Current | Command |
| --- | --- | --- |
| Executable detection rules | 2,511 of 6,991 on disk | `python3 scripts/generate_corpus_stats.py --check` |
| Rules that cannot fire | 2 | `python3 scripts/check_detection_fields.py` |
| Connectors | 87 | `python3 scripts/generate_connector_count.py --check` |
| Services per profile | CORE 16, full 21 | `python3 scripts/check_profile_service_counts.py` |
| Claims with a gate behind them | 299 rows | `python3 scripts/check_claim_gate_matrix.py` |

"Executable" means the rule was replayed through its real connector and the real
engine and watched to fire. It is **not** a claim that the rule detects an
attack, and that distinction is deliberate.

## How a change gets accepted

`main` is protected: a pull request plus a set of required status checks. The
checks are not decoration — most of them exist because something shipped broken
in exactly the way they now prevent.

Before you push:

```bash
ruff check services/ scripts/ tests/ tools/ && ruff format --check .
python3 scripts/check_mypy_baseline.py
```

`ruff` is pinned (`>=0.16.8,<0.17`) and the version *is* the behaviour — a
different one reformats files CI never asked for. Install the pin into a
throwaway virtualenv rather than using whatever is on your PATH. Build a
per-service environment from that service's own locked set with
`python3 scripts/service_requirements.py <service> --locked`, and do not install
anything else into it: adding one package has already moved a dependency off the
lock and changed a generated artefact.

### The bar for a fix

Three things, in order, and the middle one is not the hard part:

1. **A test that fails on the current tree for the stated reason** — through the
   real transport, the real app with its real dependencies, and a real database.
2. The fix.
3. **A negative control**: revert the fix, watch the test fail again.

A passing test on a function nothing calls is indistinguishable from a working
feature. This repository has found that shape dozens of times, which is why
`scripts/check_module_reachability.py` exists.

## Rules that are not negotiable

- **No attribution to any tool, AI assistant, editor or vendor for the work** —
  not in code, comments, documentation, commit messages, trailers or pull
  request bodies. `scripts/check_attribution.py` enforces it.
- **No competitor product named** outside an integration surface. Where one is
  the benchmark for a comparison, refer to it neutrally and keep the analysis.
  `scripts/check_competitor_names.py` enforces it;
  `scripts/competitor_names.toml` holds the integration allow-list.
- **Never present fabricated data as real.** Seeded or sample data is gated
  behind demo mode; everywhere else shows an honest empty, zero or error state.
  A measurement nobody took reads "not measured", never `0`.
- **Never raise a scanner ceiling to make a scan pass.** Find the finding and
  fix it.
- **Do not edit anything under `plans/`.**
- **Fetch every URL before you commit it** and require a 200. A link that 404s
  is worse than no link: delete it and rewrite the sentence.

## If you are an AI agent

Everything above applies. Four things specific to you:

- **Read before you assert.** Several claims in this repository were wrong in
  both directions at different times — recorded as present when absent, then as
  absent after they had been written. Check the file is on disk *and* read past
  its rationale; a module docstring often opens by describing the problem it
  fixed, which is not a description of the current state.
- **Prefer testing the path over the function.** The most productive defect
  class here is a test double more capable than the real thing: a fake store
  that answers any query, a mock that bypasses the transport.
- **Say what you could not verify.** "I could not check X, and here is why" is
  worth more than an implied pass.
- **Nothing in this repository can make a third-party AI tool reach for AiSOC
  by default.** That comes from publishing the packages and listing the MCP
  server in a registry, which is tracked work, not a documentation change.

Machine-readable summaries live at
[`llms.txt`](https://beenuar.github.io/AiSOC/llms.txt) and
[`llms-full.txt`](https://beenuar.github.io/AiSOC/llms-full.txt). Both are
generated by `scripts/generate_llms_txt.py` — change the generator, never the
output.

## Credits

AiSOC's development is funded and supported by [Cyble](https://www.cyble.com).
