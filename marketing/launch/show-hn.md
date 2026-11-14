# Show HN draft

> Review against the benchmark page before posting. Keep it plain — no
> superlatives, no unbacked numbers.

> **Before posting:** `aisoc` is built and packed on every tag but has never
> been uploaded — `npx aisoc` does not resolve today, and the blocker is an
> npm credential rather than code. Either publish first, or replace the
> command in the copy below with the from-clone form
> (`pnpm --filter aisoc build && node packages/aisoc-lite/dist/cli.js triage --demo`).
> `packages/aisoc-lite/README.md` carries the same caveat.

## Title

```
Show HN: AiSOC – open-source AI SOC; triage a batch of alerts in 60s with `npx aisoc`
```

## Body

```
Hi HN — I've been building AiSOC, an open-source, self-hostable AI SOC
(security operations center). The whole thing is MIT-licensed: the agent, the
detection substrate, and the console.

The fastest way to see what it does, with zero setup:

    npx aisoc triage --demo

That runs a bundled, fully-deterministic 200-alert fixture through the same
triage verdict engine the full stack uses, and prints a table of verdicts
(escalate / review / suppress) plus a one-line summary. No account, no Docker,
no API key, no network. It finishes in well under a second.

Two things I wanted to get right, because they're what I'd want from a security
tool:

1. Deterministic by default. The verdict engine is a plain, readable scoring
   function — no LLM call required. An LLM "band" is optional and only runs if
   you pass your own API key, which is used to call the provider directly and is
   never proxied through any server we run. Every "viral" surface (the CLI, the
   free web tools, the shareable replays) works with zero keys.

2. Honest evals. There's a public eval harness that gates every PR. It's
   explicit about what's a real measurement vs. a substrate self-consistency
   check over a synthetic dataset — the benchmark page spells out exactly what
   each suite does and doesn't prove. The `--demo` number above is a synthetic
   fixture demonstrating the mechanism, not a claim about your environment.

The full stack (connectors → OCSF normalize → Kafka → fusion → auto-triage →
governed response, with an Investigation Ledger that logs every agent prompt,
tool call, and rationale) is a `docker compose up` away, and there's a
zero-dependency Python sandbox (`pip install -e packages/aisoc-sandbox`) if you
don't want Docker.

Repo: https://github.com/beenuar/AiSOC
Benchmark methodology: https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/benchmark.md

Happy to answer anything about the architecture, the eval design, or where it's
still rough (autonomous response defaults to copilot/dry-run; live-LLM
benchmark rows are a funded weekly job, not per-PR).
```

## First-comment (technical depth)

```
A bit more on the verdict engine, since that's the part people will poke at:

triage scoring is an additive weight stack (vendor risk score, critical/high
keyword hits, IOC field count, MITRE technique count, host presence), clamped
to [0.05, 0.95], mapped to four bands. It's ~200 lines and pinned by a
calibration test (Brier + ECE thresholds) against a 200-incident synthetic
corpus. The CLI ports it to TypeScript with a parity test so a CLI verdict
lands in the same band the server would assign.

It is deliberately not a black box, and deliberately not claiming certainty.
The LLM band layers on top for the ambiguous middle; the deterministic floor is
what gates CI.
```

## Do / don't

- **Do** link the benchmark page and name the copilot/dry-run default up front.
- **Do** invite architecture/eval scrutiny.
- **Don't** post precision/recall numbers that aren't on the benchmark page.
- **Don't** call it "autonomous" without the copilot-default caveat.
