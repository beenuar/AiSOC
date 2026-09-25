# ADR-0006 — The LLM gateway belongs in the CORE profile

- **Status:** accepted
- **Date:** 2026-09-24
- **Supersedes:** the `profiles: ["full"]` marking on the `litellm` service in `docker-compose.yml`

## Context

`litellm` was a `full`-profile service, on the stated reasoning that the
gateway is "only needed when a provider key is configured".

The reasoning skipped a step. Every task role in this product resolves to an
`aisoc-<role>` alias, and an alias means something to the bundled gateway and
to nothing else (`services/agents/app/llm/routing.py`). So a CORE deployment
could not do AI triage **with** a key either. Before PR #829 the alias went to
`api.openai.com`, which 404s, and the caller's `except` rendered that as "no
LLM available". After #829 it fails with a connection error naming the absent
gateway — honest, and still broken.

CORE is what `make up` starts, what the quickstart walks a new evaluator
through, and what the README calls "the smallest deployment that takes a real
event and produces a real alert". The README's own profile table said CORE
gave you "triage". An evaluator following the documented path could not see
the product's central claim work, and would not have been told why.

This is a real trade-off, not an obvious fix: the repository's stated
principle is that CORE is the smallest *genuinely useful* deployment, and
every service added to it is paid for by every self-hoster.

## What was measured, rather than assumed

The convenient framing is "one lightweight container". That is false, and the
numbers matter to the decision:

| | Measured |
|---|---|
| `ghcr.io/berriai/litellm:main-stable` image | **1.67 GB** |
| Idle resident memory | **451 MiB** |
| For comparison — `aisoc-core-api` / `aisoc-agents` images | 1.31 GB / 1.69 GB |
| CORE service count | 10 → **11** |

451 MiB is roughly 7.5% of CORE's ~6 GB budget. The gateway is comparable in
size to the services already in CORE; it is not free.

Two other properties were verified rather than taken from a comment:

- **It boots with no provider key.** Running the bundled
  `infra/litellm/config.yaml` with `OPENAI_API_KEY=` and `ANTHROPIC_API_KEY=`
  empty, the container reaches `running`, serves all seven aliases, and
  answers `/health/liveliness` with `"I'm alive!"`. So adding it to CORE
  cannot break a keyless install.
- **It is the only party that can report a cost.** The real per-call figure
  comes off the gateway's response headers (`x-litellm-response-cost`,
  `x-litellm-model-name`); a provider called directly returns no such header.

## Decision

**Move `litellm` into CORE**, unconditionally — no `profiles:` key, so it
starts with `docker compose up` and `make up`. `full` is unchanged, because a
service in no profile is included in every profile run.

### Why not leave it in `full`

Because then the documented first run cannot demonstrate the product's central
claim, and the only honest fix would be to stop claiming CORE does triage —
which trades a broken capability for a diminished one. The evaluator still
never sees the AI.

### Why not start it conditionally when a key is present

A `Makefile` conditional (`--profile llm` when `OPENAI_API_KEY` is set) looks
strictly better and is not, for two reasons:

1. **It relocates the manual step rather than removing it.** An operator who
   runs `make up`, then adds a key to `.env`, has a running stack with no
   gateway and must know to re-run `make up`. Supplying a key should make AI
   work, not make AI work *after* you remember a second command.
2. **It makes `make up` and `docker compose up` disagree.** The compose file
   is the documented alternative to Make; a conditional that lives only in the
   Makefile means the same repository behaves differently depending on which
   documented command you ran. Two paths that disagree about what is running
   is a defect class this repository has repeatedly had to dig out.

### Why not route the evaluator somewhere else

Sending a new user to `full` (30 services, ~12 GB) to see the headline feature
inverts the on-ramp: the profile that exists to be the easy first run stops
being the one that shows the product. And it does not fix the underlying
statement — CORE would still be documented as doing triage it cannot do.

## Consequences

- CORE gains a container: 11 services, and the README's RAM figure moves from
  ~6 GB to ~6.5 GB. Both numbers are corrected in the profile table rather
  than left stale.
- AI triage works in CORE the moment an operator supplies a provider key, with
  no further step and no profile change.
- With no key, behaviour is unchanged: the gateway idles, and AiSOC uses its
  deterministic path. The documentation says this plainly rather than implying
  AI is running.
- The default install can now report a **measured** LLM cost. Previously a
  CORE deployment had no gateway, so the cost figure was structurally
  unmeasurable there — see `services/agents/app/core/gateway_cost.py`.
- Self-hosters who genuinely never want the gateway can stop that one service;
  nothing else depends on it, and every caller degrades to the deterministic
  path.

## Corrected alongside this

While editing the profile table, the `full` row's service count was checked
against the tree and was wrong: `make up-full` runs `--profile full`, which is
**21** services. The published 30 is the count with `full` *plus* the
`monitoring`, `chatops`, `extras` and `osquery` profiles — which `make up-full`
does not start. Corrected rather than left, since the table is being edited
anyway and a published number that is not true is the thing this repository
keeps having to find.

## Addendum — the gateway without a model was half the fix

*Added when `ollama` was promoted into CORE.*

This ADR moved the gateway and stopped there, and the consequence list above
says so in plain sight: "AI triage works in CORE the moment an operator
supplies a provider key". Read against the problem statement — an evaluator
following the documented path cannot see the product's central claim work —
that is the same failure one step further along. The evaluator now has a
gateway that routes correctly to a provider they do not have an account with.
`make up` still produced no AI.

The missing half was a model, and one was already in the tree: the air-gapped
overlay (`infra/compose/docker-compose.airgap.yml`) has run Ollama with a
pinned `llama3.2:3b-instruct-q4_K_M` — ~2 GB, quantized, sized for CPU-only
inference in 8 GB of RAM — and the full triage path has been proven end to end
against it. It was reachable only by choosing an overlay named for air-gapped
deployments, which nobody evaluating the product on a laptop is looking for.

**Decision: promote `ollama` and its one-shot `ollama-pull` into CORE.** A
default `make up` now does real AI triage — real tokens, real generated text,
a real cost figure off the gateway's headers — with no account and no key.

Three details worth recording, because each was a choice:

- **`litellm` waits on `ollama-pull` completing, not on `ollama` being
  healthy.** A gateway that is up before the weights exist answers the first
  triage request with "model not found", and the first request is the one a new
  user makes.
- **The aliases read their backend from the environment** rather than naming a
  model inline, so `infra/litellm/config.yaml` no longer has to be edited to
  move to a hosted provider — it is `OPENAI_API_KEY` plus two model variables
  in `.env`. The mounted config stays the place to go for *per-alias*
  divergence, which is what it is actually good at.
- **A 3B quantized model is not a frontier model,** and the README says so
  rather than implying the local default is equivalent. The upgrade is
  signposted in the same paragraph as the claim.

### What it costs, measured

Same method as the gateway's numbers above, on the same machine, with the
whole of CORE running.

| | Before | After |
|---|---|---|
| CORE services | 11 | **14** (plus a one-shot `ollama-pull`) |
| Images, unique layers | 8.11 GB | **16.46 GB** |
| Images, sum of sizes | 11.47 GB | **20.03 GB** |
| Model weights (named volume) | — | **2.02 GB** |
| Resident memory, whole stack | 1.72 GiB | **4.84 GiB** |

Per added service: `ollama` **6.92 GB** image / **9.6 MiB** idle,
`threatintel` **1.40 GB** / **219 MiB**, `qdrant` **245 MB** / **79 MiB**.

Ollama's 6.92 GB image is the single largest thing in CORE and its 9.6 MiB
idle figure is the misleading half of the truth: the model is mapped in on
first inference and the container measured **2.96 GiB** while serving a
request. That, not the idle number, is why the README's memory figure moved
from ~6.5 GB to 8 GB and its disk figure to 20 GB. The trade is real and the
numbers are published so a self-hoster can judge it rather than discover it.
