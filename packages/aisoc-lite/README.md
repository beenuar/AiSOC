# `aisoc` — the 60-second SOC wedge

Triage a batch of security alerts to verdicts — **true positive**, **needs review**, or **suppress as noise** — in seconds, offline, with zero credentials.

```bash
npx aisoc triage --demo
```

```
✓ AiSOC triaged 200 alerts: 12 TP, 171 FP suppressed (85.5% noise), 17 need review — in 0.1s [deterministic · no LLM]
```

**`aisoc` is ready, unpublished, so the command above does not resolve today.**
`release.yml` builds and packs it on every tag, but npm configures trusted
publishing on a package's settings page and a package that has never been
published has no settings page — the first upload needs a token, which is an
account action rather than a code change. Until then, run it from a clone:
`pnpm --filter aisoc build && node packages/aisoc-lite/dist/cli.js triage --demo`.

This is the zero-install front door to [AiSOC](https://github.com/beenuar/AiSOC), the open-source, self-hostable AI SOC. The full Docker stack is a ~3.5-minute commitment; this CLI gets you a verdict in under a minute.

## Why it's trustworthy

- **Deterministic by default.** The verdict engine is a faithful port of AiSOC's production triage scorer (`services/agents/app/confidence/scoring.py`). No LLM key required; identical input always produces identical output.
- **BYO-key, never proxied.** Pass `--llm` and your own `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` to refine the ambiguous middle. The key is read from your environment and used to call the provider directly — it never touches an AiSOC server.
- **Telemetry is opt-in and aggregate-only.** Off by default. See [TELEMETRY.md](./TELEMETRY.md).
- **Tiny dependency surface.** One runtime dependency (`picocolors`). It's a security tool; every dependency is a liability.

## Commands

| Command | What it does |
|---|---|
| `aisoc triage --demo` | Zero-credential, deterministic 200-alert demo. Finishes in seconds. |
| `aisoc triage --file alerts.jsonl` | Triage a local JSONL / JSON alert export (Splunk, Sentinel, Elastic ECS, CrowdStrike shapes auto-detected). |
| `aisoc triage --attention-only --share` | Hide suppressed noise; write a postable report card (Markdown + SVG). |
| `aisoc translate <rule> --from sigma --to spl,kql` | Translate a detection rule across Sigma / SPL / KQL / ES\|QL / YARA-L2 / UDM. |
| `aisoc up` | Boot the full local demo stack from a pinned Compose bundle (needs Docker). |

### Triage options

```
--demo            Zero-credential deterministic demo (200 alerts)
--file <path>     Triage a local JSONL / JSON alert export
--source <name>   demo | jsonl | splunk | sentinel | elastic | crowdstrike
--limit <n>       Cap the number of alerts triaged
--max-rows <n>    Cap table rows printed (default 20; escalations first)
--attention-only  Show only escalate + review (hide suppressed noise)
--llm             Refine the ambiguous middle with YOUR own LLM key (never proxied)
--json            Machine-readable JSON output
--share [path]    Write a redacted report card (Markdown + SVG)
--telemetry       Opt IN to aggregate-only telemetry (default OFF)
--no-telemetry    Force telemetry off
```

## Feeding your own alerts

Export your alerts to newline-delimited JSON (one object per line) or a JSON array. Common field spellings from Splunk, Microsoft Sentinel, Elastic ECS, and CrowdStrike are auto-detected:

```bash
aisoc triage --file alerts.jsonl --attention-only
```

An alert record can be as simple as:

```json
{"id": "A-1", "title": "PowerShell spawned by Word", "severity": "high", "risk_score": 0.7, "techniques": ["T1059.001"], "src_ip": "10.0.0.5"}
```

## Verdict bands

The deterministic scorer maps each alert to a confidence in `[0.05, 0.95]` and a band:

| Confidence | Verdict | Recommendation |
|---|---|---|
| ≥ 0.80 | `true_positive` | escalate |
| ≥ 0.60 | `likely_true_positive` | escalate |
| ≥ 0.40 | `needs_review` | review |
| < 0.40 | `likely_benign` | suppress |

These bands and the underlying weight stack are pinned by tests to match the AiSOC server, so a CLI verdict lands where the full stack would put it at triage.

## Use it as a library

```ts
import { triageBatch, loadJsonl } from "aisoc";

const alerts = await loadJsonl("alerts.jsonl");
const { summary, verdicts } = triageBatch(alerts);
console.log(summary.headline);
```

## License

MIT — part of the [AiSOC](https://github.com/beenuar/AiSOC) project.
