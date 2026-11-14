---
id: real-vs-synthetic
title: Real vs synthetic data
sidebar_label: Real vs synthetic data
---

# Real vs synthetic data

Every row in a running AiSOC is one of five kinds, and each kind is
distinguishable from the console and the API — this table moved here from the
README front page, unchanged in substance, when the release that redefined the
published evaluation semantics needed that space.

| Kind | Where | How you can tell |
|---|---|---|
| **Real** | Your connectors and the ingest API | `is_synthetic = false` (the default) |
| **Real, and not yours** | The CISA KEV feed on the Threat Intelligence page | Every row carries `source: cisa-kev`; it is the public catalog, unmodified |
| **Sample** | The wizard's **Load sample data** | Source column reads `AiSOC`; RFC 5737 / RFC 2606 reserved addresses only |
| **Demo** | `make demo` | `is_synthetic = true`, labelled in the console |
| **Benchmark / fixtures** | `services/agents/tests/eval_data/`, `**/tests/` | Published rows carry `substrate: true`; fixtures never ship in an image |

**Production never silently falls back to synthetic data.** An unreachable
backend makes the console name the failure rather than invent an
investigation, and an unmeasured figure reads *not measured*, never `0`. It
was not always so: [the reality audit](https://github.com/beenuar/AiSOC/blob/main/docs/audit/REPOSITORY_REALITY.md)
has each case.

The same discipline governs the published numbers themselves — which model
actually served an evaluation, what sits in each metric's denominator, and
what a replay was allowed to know — described on the
[benchmark methodology page](../benchmark.md).
