# Product Hunt assets

> **Before posting:** `aisoc` is built and packed on every tag but has never
> been uploaded — `npx aisoc` does not resolve today, and the blocker is an
> npm credential rather than code. Either publish first, or replace the
> command in the copy below with the from-clone form
> (`pnpm --filter aisoc build && node packages/aisoc-lite/dist/cli.js triage --demo`).
> `packages/aisoc-lite/README.md` carries the same caveat.

## Name

AiSOC

## Tagline (≤ 60 chars)

```
Open-source AI SOC you can read, fork, and self-host
```

Alternatives:
- `Triage your security alerts in 60 seconds — open source`
- `The AI SOC whose every decision is logged and replayable`

## Description (≤ 260 chars)

```
AiSOC is an open-source, self-hostable AI security operations center. Triage a
batch of alerts to verdicts in 60s with `npx aisoc triage --demo` — no key, no
Docker. Every agent decision is logged and replayable. MIT-licensed: read,
fork, or replace the agent.
```

## Maker's first comment

```
Hey PH 👋

I built AiSOC because "AI SOC" products are all closed boxes — you can't see
why the agent made a call, and you can't run the evals yourself.

AiSOC is the opposite:
• `npx aisoc triage --demo` gives you a verdict on 200 alerts in under a second,
  deterministic, no key, no install.
• Every agent step (prompt, tool call, evidence, rationale) is stored in an
  Investigation Ledger and replayable — you can even publish a redacted replay
  as a public link.
• A public eval harness gates every PR, and it's honest about what's a real
  measurement vs. a synthetic self-consistency check.
• Free browser tools (rule translator, ATT&CK coverage grader) with no login.

It's MIT-licensed and self-hostable — your data never leaves your perimeter
(hosted-LLM evidence is pseudonymized by default; a local-model path is fully
air-gapped).

Would love feedback from anyone running a SOC. What would make you trust an
open agent over a closed one?
```

## Gallery (in order)

1. The `npx aisoc triage --demo` terminal result (the hero).
2. A public investigation replay (`/r/demo-lockbit`) mid-scrub.
3. The Investigation Ledger in the console.
4. The ATT&CK coverage grader with an A–F grade card.
5. The architecture diagram (from the README).

## Topics

Security · Developer Tools · Open Source · Artificial Intelligence

## Links

- Website: https://tryaisoc.com
- GitHub: https://github.com/beenuar/AiSOC
- Benchmark: https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/benchmark.md
