# AiSOC press kit

Everything a writer, conference organizer, or partner needs to represent AiSOC
accurately. Please keep quotes and stats consistent with the
[benchmark page](../../apps/docs/docs/benchmark.md).

## Boilerplate

**One sentence:**

> AiSOC is an open-source, self-hostable AI security operations center whose
> agent decisions are logged step-by-step and replayable, gated by a public
> eval harness, and MIT-licensed.

**One paragraph:**

> AiSOC is an open-source (MIT) AI SOC that ingests security events, correlates
> them, runs AI-driven investigation, and surfaces the result in a SOC console.
> Unlike closed-source AI SOC products, the agent and the substrate are open:
> every prompt, tool call, piece of evidence, and rationale is stored in an
> Investigation Ledger and replayable, and a public eval harness gates every
> change. The wedge CLI is `npx aisoc triage --demo` — but `aisoc` is ready and
> unpublished, so that command does not resolve yet; run it from a clone with
> `pnpm --filter aisoc build && node packages/aisoc-lite/dist/cli.js triage --demo`. No
> account, no Docker, no API key — or self-host the full stack so no data leaves
> your perimeter.

## Fast facts

- **License:** MIT
- **Try it:** `npx aisoc triage --demo` (deterministic, offline, <1s) — **not
  yet on npm**; from a clone, `pnpm --filter aisoc build && node packages/aisoc-lite/dist/cli.js triage --demo`
- **Live demo:** https://tryaisoc.com
- **Source:** https://github.com/beenuar/AiSOC
- **Orchestrator:** ~600-line LangGraph in `services/agents/`
- **Default response posture:** copilot / dry-run (human approval required)
- **Data residency:** self-hosted; hosted-LLM evidence pseudonymized by default; air-gapped local-model path available

## Logo kit

Source marks live in the repo (SVG, scalable):

- Logo mark: [`apps/web/public/logo-mark.svg`](../../apps/web/public/logo-mark.svg)
- Social/OG card: [`apps/web/public/og-image.svg`](../../apps/web/public/og-image.svg)

Usage: don't recolor the mark; keep clear space equal to the mark's height on
all sides; on dark backgrounds use the mark as-is.

## Naming

- Product name is **AiSOC** (capital A-i-S-O-C). Not "AISOC", not "Aisoc".
- Not affiliated with, and not to be compared by name to, any specific
  commercial vendor in our materials.

## Contact

Open a [GitHub Discussion](https://github.com/beenuar/AiSOC/discussions) for
press or partnership inquiries.
