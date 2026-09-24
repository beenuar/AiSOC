---
title: LLM gateway (LiteLLM)
description: Route every live LLM call through a single LiteLLM gateway — assign local or hosted models per task by alias, and get centralized latency/token/cost/error metrics — without changing AiSOC code.
---

# LLM gateway (LiteLLM)

AiSOC runs several distinct LLM workloads — triage, recon, investigation, the
contextual copilot, summaries, reports, and natural-language generation. The
**LiteLLM gateway** is the single entry point for every *live* LLM call these
workloads make. AiSOC asks for a **logical task alias**; the gateway decides
which real provider and model that alias resolves to.

```
AiSOC task ──▶ alias (e.g. "aisoc-triage") ──▶ LiteLLM ──▶ real model
```

This gives operators two things without any AiSOC code change:

1. **Per-task model assignment.** Point `aisoc-triage` at a cheap local model
   and `aisoc-investigation` at a strong hosted one — or swap either at any time
   — by editing one config file.
2. **Centralized observability.** LiteLLM exports per-task latency, tokens,
   cost, errors, retries, and fallbacks on `/metrics`, scraped by the bundled
   Prometheus (job `aisoc-litellm`). This complements the
   [Investigation Ledger](../concepts/llmops.md), which records *what the agent
   decided*; the gateway records *what each model call cost and how it behaved*.

The gateway sits in front of the LLM tier of the
[multi-model router](../concepts/model-router.md). When no live model is
reachable, AiSOC still degrades to its **deterministic offline path** — the
gateway is never on the critical path for a baseline triage.

## Task aliases

The shipped aliases mirror AiSOC's workloads. They live in
`infra/litellm/config.yaml`:

| Alias                 | Workload                                   | Shipped default   |
| --------------------- | ------------------------------------------ | ----------------- |
| `aisoc-triage`        | Auto-triage of fused alerts (high volume)  | `gpt-4o-mini`     |
| `aisoc-recon`         | Recon / enrichment reasoning               | `gpt-4o-mini`     |
| `aisoc-investigation` | Deep multi-step investigation              | `gpt-4o`          |
| `aisoc-copilot`       | Contextual analyst copilot                 | `gpt-4o-mini`     |
| `aisoc-summary`       | Alert / incident summaries                 | `gpt-4o-mini`     |
| `aisoc-report`        | Analyst-facing report write-ups            | `gpt-4o`          |
| `aisoc-nl`            | NL→query / NL→detection translation        | `gpt-4o-mini`     |

The "shipped default" is only the *example* mapping in the config — the whole
point is that you change it. The alias names stay constant.

## Enable the gateway

The `litellm` service is part of the `full` profile in `docker-compose.yml`, and
routing to it is already wired. Put your provider key in `.env` and bring the
profile up:

```bash
OPENAI_API_KEY=<your-real-provider-key>    # the gateway uses this to reach the upstream model
LITELLM_MASTER_KEY=<a-strong-key>          # AiSOC authenticates to the gateway with this
```

```bash
docker compose --profile full up -d
```

That is the whole configuration. `docker-compose.yml` sets `LLM_GATEWAY_URL` on
the `api` and `agents` services, and both services' resolvers read it for any
`aisoc-<role>` alias — an alias resolves nowhere else, so the gateway is the
only correct destination for one. The bearer token is resolved with the route:
when AiSOC picks the gateway itself it sends `LITELLM_MASTER_KEY`, never a
provider key, which the gateway would reject as an invalid proxy token.

To send AiSOC somewhere else — a gateway on another host, or your own
OpenAI-compatible endpoint — set `OPENAI_BASE_URL` (or `LLM_BASE_URL`) and it
outranks `LLM_GATEWAY_URL` for every role.

### Calling a provider directly, with no gateway

Pin each role to a concrete provider model. A concrete pin is **not** rerouted
to the gateway, so this keeps working with `LLM_GATEWAY_URL` set:

```bash
AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini
AISOC_MODEL_PIN_INVESTIGATION=gpt-4o
# … one per role: triage, recon, investigation, copilot, summary, report, nl
OPENAI_MODEL=gpt-4o-mini                   # the BYOK / "explain this alert" path, direct too
```

With neither the gateway nor pin overrides configured, AiSOC uses its
deterministic offline path, which reports zero model calls and zero tokens
rather than presenting a heuristic as triage.

### A model the gateway does not define is an error, not a fallback

Two failures used to be indistinguishable from "no LLM available", because both
arrived as an exception a caller turned into a deterministic result:

- An `aisoc-<role>` alias sent to a provider default, which does not know the
  name. AiSOC now raises `UnroutableModelError` naming the alias and the remedy
  instead of building a client destined to fail.
- A concrete model sent to the gateway, which answers `Invalid model name`.
  `preflight_llm()` reports this at boot, in both directions, and
  `scripts/check_llm_model_routing.py` fails the build when a model named in
  `.env.example` or `docker-compose.yml` is not one `infra/litellm/config.yaml`
  defines — or when the gateway defines an alias no role requests.

`OPENAI_MODEL` applies to the BYOK / "explain this alert" path **only**. It is
never a task role's model: the auto-triage worker layers a tenant's BYOK
configuration over the role pin, and only the fields the *tenant* set are
treated as overrides, so an environment default cannot displace an alias.

### Embeddings

The MITRE RAG path calls an embedding endpoint, and `infra/litellm/config.yaml`
declares chat aliases only — so embeddings deliberately do **not** follow chat
traffic to the gateway. They have their own pair of variables,
`AISOC_EMBEDDING_BASE_URL` and `AISOC_EMBEDDING_MODEL` (default
`text-embedding-3-large`), and default to the provider. The routing gate checks
that exclusion in both directions.

## Re-point a task to a local model

Duplicate the alias in `infra/litellm/config.yaml` with a local backend. The
alias name **must stay the same** so AiSOC is unaware of the swap:

```yaml
- model_name: aisoc-triage
  litellm_params:
    model: ollama/llama3.1
    api_base: http://ollama:11434
```

Commented Ollama, vLLM, and Anthropic examples ship in the config. For a fully
offline deployment, see [air-gapped operation](./air-gapped.md), which fronts a
local Ollama.

## Observe

- **Metrics:** `curl http://localhost:4000/metrics` (or the Grafana/Prometheus
  stack under the `monitoring` profile) shows `litellm_*` counters broken down
  by task alias and model.
- **Health:** `curl http://localhost:4000/health/liveliness`.

## Notes

- Host port `4000` is bound to `127.0.0.1` only, like the rest of the stack.
- No provider key is ever written to `infra/litellm/config.yaml` — aliases
  resolve credentials from the process environment (`os.environ/...`).
