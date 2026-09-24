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
